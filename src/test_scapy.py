from scapy.all import conf, get_if_list

print("Scapy успешно запущен!")
print(f"Версия Scapy: {conf.version}")

print("\nДоступные сетевые интерфейсы:")

for interface in get_if_list():
    print(interface)