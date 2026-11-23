@'

\# Scapy XSS Lab



Учебный проект по перехвату и анализу HTTP-трафика с использованием Python и Scapy, а также исследованию XSS-уязвимостей в тестовом веб-приложении Google Gruyere.



\## Цель проекта



\- Изучить возможности Scapy для захвата сетевых пакетов.

\- Научиться анализировать TCP- и HTTP-трафик.

\- Изучить HTTP-запросы, ответы, заголовки и GET-параметры.

\- Исследовать обработку пользовательского HTML.

\- Практически проверить различные варианты XSS-payload.



\## Используемые технологии



\- Python 3.9

\- Scapy 2.8.0

\- Npcap

\- Google Gruyere

\- Windows / PowerShell



\## Структура проекта



```text

Scapy\_XSS\_Lab/

├── src/

│   ├── scapy\_analyzer.py

│   ├── post\_test\_server.py

│   ├── test\_capture.py

│   └── test\_scapy.py

├── captures/

├── reports/

├── screenshots/

├── requirements.txt

├── .gitignore

└── README.md

