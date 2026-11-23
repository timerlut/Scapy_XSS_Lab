
import argparse
import gzip
import re
import zlib
from collections import defaultdict
from urllib.parse import parse_qs, urlsplit

from scapy.all import IP, TCP, Raw, rdpcap, sniff, wrpcap


DEFAULT_INTERFACE = r"\Device\NPF_Loopback"


def capture_traffic(interface, packet_filter, timeout, output):
    """Capture packets and save them to a PCAP file."""
    print(f"Interface: {interface}")
    print(f"Filter: {packet_filter}")
    print(f"Capture duration: {timeout} seconds")

    packets = sniff(
        iface=interface,
        filter=packet_filter,
        timeout=timeout,
        store=True
    )

    if not packets:
        print("No packets captured.")
        return

    wrpcap(output, packets)
    print(f"Captured packets: {len(packets)}")
    print(f"Saved to: {output}")


def decode_body(body, headers):
    """Decode a compressed HTTP body when possible."""
    encoding = headers.get("content-encoding", "").lower()

    try:
        if "gzip" in encoding:
            return gzip.decompress(body)

        if "deflate" in encoding:
            try:
                return zlib.decompress(body)
            except zlib.error:
                return zlib.decompress(body, -zlib.MAX_WBITS)
    except (OSError, zlib.error):
        print("[!] Could not decompress HTTP body.")

    return body


def parse_http_headers(header_text):
    """Convert HTTP header lines into a dictionary."""
    headers = {}

    lines = header_text.split("\r\n")

    for line in lines[1:]:
        if ":" not in line:
            continue

        name, value = line.split(":", 1)
        headers[name.strip().lower()] = value.strip()

    return headers


def extract_messages(data):
    """
    Extract complete HTTP messages from a TCP byte stream.

    Supports:
    - Content-Length
    - Chunked transfer encoding
    - Responses without Content-Length
    """
    messages = []
    position = 0

    while position < len(data):
        header_end = data.find(b"\r\n\r\n", position)

        if header_end == -1:
            break

        header_bytes = data[position:header_end]

        header_text = header_bytes.decode(
            "iso-8859-1",
            errors="replace"
        )

        first_line = header_text.split("\r\n", 1)[0]

        if not (
            first_line.startswith("HTTP/")
            or re.match(
                r"^[A-Z]+\s+\S+\s+HTTP/\d",
                first_line
            )
        ):
            break

        headers = parse_http_headers(header_text)
        body_start = header_end + 4

        if "chunked" in headers.get(
            "transfer-encoding", ""
        ).lower():

            body, next_position = extract_chunked_body(
                data,
                body_start
            )

            if next_position is None:
                break

        else:
            content_length = headers.get("content-length")

            if content_length is not None:
                try:
                    body_length = int(content_length)
                except ValueError:
                    break

                if body_length < 0:
                    break

                next_position = body_start + body_length

                if next_position > len(data):
                    break

                body = data[body_start:next_position]

            elif first_line.startswith("HTTP/"):
                # Responses with these status codes have no body.
                parts = first_line.split()

                try:
                    status_code = int(parts[1])
                except (IndexError, ValueError):
                    break

                if (
                    100 <= status_code < 200
                    or status_code in (204, 304)
                ):
                    body = b""
                    next_position = body_start

                else:
                    # Without Content-Length, the response body
                    # ends when the TCP connection closes.
                    # This assumes the captured stream contains
                    # the complete response.
                    body = data[body_start:]
                    next_position = len(data)

            else:
                # Requests without Content-Length have no body.
                body = b""
                next_position = body_start

        messages.append({
            "start_line": first_line,
            "headers": headers,
            "body": body
        })

        if next_position <= position:
            break

        position = next_position

    return messages

def extract_chunked_body(data, position):
    """Decode HTTP chunked transfer encoding."""
    chunks = []

    while True:
        line_end = data.find(b"\r\n", position)

        if line_end == -1:
            return b"", None

        size_line = data[position:line_end].split(b";", 1)[0].strip()

        try:
            chunk_size = int(size_line, 16)
        except ValueError:
            return b"", None

        position = line_end + 2

        if chunk_size == 0:
            trailer_end = data.find(b"\r\n\r\n", position)

            if data[position:position + 2] == b"\r\n":
                return b"".join(chunks), position + 2

            if trailer_end == -1:
                return b"", None

            return b"".join(chunks), trailer_end + 4

        chunk_end = position + chunk_size

        if chunk_end + 2 > len(data):
            return b"", None

        chunks.append(data[position:chunk_end])
        position = chunk_end + 2


def reassemble_tcp_streams(packets):
    """
    Reassemble payloads by TCP connection and direction.

    This is a teaching-oriented implementation. It handles basic
    ordering but is not a complete TCP reassembly engine.
    """
    streams = defaultdict(list)

    for packet in packets:
        if IP not in packet or TCP not in packet or Raw not in packet:
            continue

        tcp = packet[TCP]
        ip = packet[IP]

        key = (
            ip.src,
            tcp.sport,
            ip.dst,
            tcp.dport
        )

        streams[key].append((tcp.seq, bytes(packet[Raw].load)))

    result = {}

    for key, segments in streams.items():
        segments.sort(key=lambda item: item[0])

        assembled = bytearray()
        expected_seq = None

        for seq, payload in segments:
            if not payload:
                continue

            if expected_seq is None:
                assembled.extend(payload)
                expected_seq = seq + len(payload)
                continue

            if seq < expected_seq:
                overlap = expected_seq - seq

                if overlap >= len(payload):
                    continue

                payload = payload[overlap:]
                seq = expected_seq

            if seq > expected_seq:
                # A gap means some TCP data was not captured.
                print(
                    f"[!] TCP gap in {key}: "
                    f"expected {expected_seq}, received {seq}"
                )
                continue

            assembled.extend(payload)
            expected_seq += len(payload)

        if assembled:
            result[key] = bytes(assembled)

    return result


def print_body(body, headers):
    """Display HTTP body as readable text when possible."""
    decoded = decode_body(body, headers)

    content_type = headers.get("content-type", "")
    match = re.search(r"charset=([^;\s]+)", content_type, re.I)
    charset = match.group(1).strip('"') if match else "utf-8"

    try:
        text = decoded.decode(charset, errors="replace")
    except LookupError:
        text = decoded.decode("utf-8", errors="replace")

    if text:
        print(text[:4000])
    else:
        print("[Empty body]")


def analyze_pcap(input_file):
    """Read a PCAP file and print HTTP messages."""
    packets = rdpcap(input_file)

    print(f"Loaded packets: {len(packets)}")

    streams = reassemble_tcp_streams(packets)

    if not streams:
        print("No TCP payloads found.")
        return

    for connection, data in streams.items():
        src, sport, dst, dport = connection

        print("\n" + "=" * 70)
        print(f"TCP stream: {src}:{sport} -> {dst}:{dport}")
        print("=" * 70)

        messages = extract_messages(data)

        if not messages:
            print("No complete HTTP messages detected.")
            print("First bytes of stream:")
            print(data[:300].decode("iso-8859-1", errors="replace"))
            continue

        for index, message in enumerate(messages, start=1):
            start_line = message["start_line"]
            headers = message["headers"]
            body = message["body"]

            print(f"\n--- HTTP message {index} ---")
            print(start_line)

            if start_line.startswith("HTTP/"):
                print("\nHTTP response")
            else:
                print("\nHTTP request")

                parts = start_line.split()

                if len(parts) >= 2:
                    url = urlsplit(parts[1])

                    print(f"Path: {url.path}")

                    if url.query:
                        print("GET parameters:")

                        for name, values in parse_qs(
                            url.query,
                            keep_blank_values=True
                        ).items():
                            print(f"  {name}: {values}")

            print("\nHeaders:")

            for name, value in headers.items():
                print(f"  {name}: {value}")

            if body:
                print("\nBody:")
                print_body(body, headers)

                content_type = headers.get("content-type", "")

                if "application/x-www-form-urlencoded" in content_type:
                    print("\nPOST form parameters:")

                    form = parse_qs(
                        body.decode("utf-8", errors="replace"),
                        keep_blank_values=True
                    )

                    for name, values in form.items():
                        print(f"  {name}: {values}")
            else:
                print("\nBody: empty or not captured")


def main():
    parser = argparse.ArgumentParser(
        description="Scapy HTTP traffic analyzer"
    )

    subparsers = parser.add_subparsers(
        dest="command",
        required=True
    )

    capture_parser = subparsers.add_parser(
        "capture",
        help="Capture network traffic"
    )

    capture_parser.add_argument(
        "--interface",
        default=DEFAULT_INTERFACE
    )

    capture_parser.add_argument(
        "--filter",
        default="tcp port 8008"
    )

    capture_parser.add_argument(
        "--timeout",
        type=int,
        default=30
    )

    capture_parser.add_argument(
        "--output",
        default="traffic.pcap"
    )

    analyze_parser = subparsers.add_parser(
        "analyze",
        help="Analyze a PCAP file"
    )

    analyze_parser.add_argument(
        "--input",
        required=True
    )

    args = parser.parse_args()

    if args.command == "capture":
        capture_traffic(
            args.interface,
            args.filter,
            args.timeout,
            args.output
        )

    elif args.command == "analyze":
        analyze_pcap(args.input)


if __name__ == "__main__":
    main()
