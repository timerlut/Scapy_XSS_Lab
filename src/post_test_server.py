
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs
from html import escape


class TestHandler(BaseHTTPRequestHandler):

    def send_html(self, content):
        body = content.encode("utf-8")

        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        html = """
        <!DOCTYPE html>
        <html lang="ru">
        <head>
            <meta charset="UTF-8">
            <title>POST test</title>
        </head>
        <body>
            <h1>Тестирование POST-запроса</h1>

            <form method="POST" action="/submit">
                <label>Имя:</label>
                <input type="text" name="name" value="Yana">
                <br><br>

                <label>Сообщение:</label>
                <input type="text" name="message"
                       value="Hello Scapy">
                <br><br>

                <button type="submit">Отправить</button>
            </form>
        </body>
        </html>
        """

        self.send_html(html)

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        post_data = self.rfile.read(content_length)

        decoded_data = post_data.decode("utf-8", errors="replace")
        parameters = parse_qs(decoded_data, keep_blank_values=True)

        print("\nПолучен POST-запрос:")
        print("Сырые данные:", decoded_data)
        print("Параметры:", parameters)

        name = parameters.get("name", [""])[0]
        message = parameters.get("message", [""])[0]

        html = f"""
        <!DOCTYPE html>
        <html lang="ru">
        <head>
            <meta charset="UTF-8">
            <title>POST result</title>
        </head>
        <body>
            <h1>Данные получены</h1>
            <p>Имя: {escape(name)}</p>
            <p>Сообщение: {escape(message)}</p>
        </body>
        </html>
        """

        self.send_html(html)


if __name__ == "__main__":
    server = HTTPServer(("127.0.0.1", 8009), TestHandler)

    print("POST test server started:")
    print("http://127.0.0.1:8009")

    server.serve_forever()
