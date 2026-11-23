from scapy.all import sniff

INTERFACE = r"\Device\NPF_Loopback"

print("Начинаем перехват HTTP-трафика...")
print("Открой http://127.0.0.1:8008 в браузере.")
print("Продолжительность захвата: 20 секунд.")

packets = sniff(
    iface=INTERFACE,
    filter="tcp port 8008",
    timeout=20,
    store=True
)

print(f"\nПерехвачено пакетов: {len(packets)}")

for packet in packets:
    print(packet.summary())

if packets:
    print("\nЗахват выполнен успешно!")
else:
    print("\nПакеты не обнаружены.")
