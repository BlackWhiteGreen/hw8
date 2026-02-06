import argparse
import socket
import random
import time
import gzip
from urllib.parse import urlparse
from scapy.layers.inet import IP, TCP
from scapy.sendrecv import sr1, send
from scapy.all import sniff, wrpcap, rdpcap


def resolve_hostname(hostname):
    """Разрешает доменное имя в IP-адрес."""
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror as e:
        print(f"Ошибка разрешения доменного имени '{hostname}': {e}")
        return None


def parse_url(url_arg):
    """Парсит URL и извлекает hostname, path и scheme."""
    if not url_arg.startswith('http://') and not url_arg.startswith('https://'):
        url_arg = 'http://' + url_arg

    try:
        parsed = urlparse(url_arg)
        hostname = parsed.hostname
        path = parsed.path if parsed.path else '/'
        scheme = parsed.scheme or 'http'
        return hostname, path, scheme
    except Exception as e:
        print(f"Ошибка парсинга URL: {e}")
        return None, None, None


def send_http_request(hostname, path, custom_request=None):
    """Отправляет HTTP-запрос через Scapy."""
    dest_ip = resolve_hostname(hostname)
    if not dest_ip:
        return None

    port = 80
    client_sport = random.randint(1025, 65500)

    # Формируем HTTP-запрос
    if custom_request:
        http_request_str = custom_request
    else:
        http_request_str = f'GET {path} HTTP/1.1\r\nHost: {hostname}\r\nConnection: close\r\n\r\n'

    # Устанавливаем TCP-соединение
    syn = IP(dst=dest_ip) / TCP(sport=client_sport, dport=port, flags='S')
    syn_ack = sr1(syn, timeout=5, verbose=False)

    if not syn_ack or not syn_ack.haslayer(TCP) or syn_ack[TCP].flags != 0x12:
        print(f"Не удалось установить соединение с {hostname}")
        return None

    # Отправляем ACK
    client_seq = syn_ack[TCP].ack
    client_ack = syn_ack[TCP].seq + 1
    ack_packet = IP(dst=dest_ip) / TCP(
        sport=client_sport,
        dport=port,
        seq=client_seq,
        ack=client_ack,
        flags='A'
    )
    send(ack_packet, verbose=False)

    time.sleep(0.1)

    # Отправляем HTTP-запрос
    http_request = IP(dst=dest_ip) / TCP(
        sport=client_sport,
        dport=port,
        seq=client_seq,
        ack=client_ack,
        flags='PA'
    ) / http_request_str

    send(http_request, verbose=False)

    return dest_ip, port, client_sport


def capture_traffic(hostname, timeout=30, output_file=None):
    """Перехватывает HTTP-трафик для указанного хоста."""
    dest_ip = resolve_hostname(hostname)
    if not dest_ip:
        return None

    print(f"Начало перехвата трафика для {hostname} ({dest_ip})...")

    print(f"Жду пакеты {timeout} секунд... (Зайдите на сайт в браузере!)")
    print(f"Фильтр: host {dest_ip} and tcp port 80")
    # sniff перехватывает пакеты
    # Фильтр: host {dest_ip} и tcp port 80 для захвата только http трафика
    packets = sniff(filter=f"host {dest_ip} and tcp port 80", timeout=timeout)

    print(f"Перехвачено пакетов: {len(packets)}")

    if output_file and packets:
        wrpcap(output_file, packets)
        print(f"Трафик сохранен в {output_file}")

    return packets


def analyze_packets(packets):
    """Базовый анализ перехваченных пакетов."""
    if not packets:
        print("Нет пакетов для анализа")
        return

    http_data = []
    for pkt in packets:
        if pkt.haslayer('Raw'):
            try:
                raw_bytes = pkt['Raw'].load

                # Блок жля распаковки gzip
                if b'\r\n\r\n' in raw_bytes:
                    headers, body = raw_bytes.split(b'\r\n\r\n', 1)

                    # Если тело начинается с символов характерных gzip, распаковываем
                    if body.startswith(b'\x1f\x8b'):
                        try:
                            decompressed_body = gzip.decompress(body)
                            # склеиваем заголовки + Распакованное тело
                            data = headers.decode('utf-8',
                                                  errors='ignore') + '\n\n[DECOMPRESSED BODY]\n' + decompressed_body.decode(
                                'utf-8', errors='ignore')
                        except Exception:
                            # При неудачной распаковке декодирование как есть
                            data = raw_bytes.decode('utf-8', errors='ignore')
                    else:
                        # Не сжато
                        data = raw_bytes.decode('utf-8', errors='ignore')

                # Если разделителя характерного gzip нет
                elif raw_bytes.startswith(b'\x1f\x8b'):
                    try:
                        data = gzip.decompress(raw_bytes).decode('utf-8', errors='ignore')
                    except Exception:
                        data = raw_bytes.decode('utf-8', errors='ignore')

                # В ином случае просто текст
                else:
                    data = raw_bytes.decode('utf-8', errors='ignore')
                # -----------------------------------------------------

                # Жобавляем в список, если похоже на HTTP
                if 'HTTP' in data or 'GET' in data or 'POST' in data:
                    http_data.append(data)
            except:
                pass

    print(f"Найдено HTTP-сообщений: {len(http_data)}")

    # Выводим первые несколько HTTP-сообщений
    for i, data in enumerate(http_data[:3], 1):
        print(f"HTTP-сообщение {i} (первые 300 символов)")
        print(data[:300])

    print("-" * 30)
    print("АНАЛИЗ НА XSS:")

    xss_payloads = ["<script>", "alert(", "javascript:", "onerror="]
    found_xss = False

    for i, data in enumerate(http_data, 1):
        # Простая проверка на наличие типичных тегов XSS
        for payload in xss_payloads:
            if payload in data:
                print(f"[!] НАЙДЕНО ПОДОЗРЕНИЕ НА XSS в сообщении #{i}")
                print(f"    Пейлоад: {payload}")
                # Показываем контекст (строку с пейлоадом)
                start_index = data.find(payload)
                # Берем чуть больше контекста
                snippet = data[start_index:start_index + 150].replace('\n', ' ')
                print(f"    Контекст: ...{snippet}...")
                found_xss = True

                # Проверка на это запрос или ответ?
                if "GET " in data[:50] or "POST " in data[:50]:
                    print("    Тип: Исходный ЗАПРОС (Атака)")
                elif "HTTP/1." in data[:50]:
                    print("    Тип: ОТВЕТ Сервера (Успешная инъекция?)")

    if not found_xss:
        print("Явных следов XSS (script/alert) в текстовом виде не найдено.")


def analyze_saved_traffic(pcap_file):
    """Анализирует сохраненный трафик из .pcap файла."""
    print(f"Анализ трафика из файла: {pcap_file}")
    packets = rdpcap(pcap_file)
    analyze_packets(packets)


def main():
    parser = argparse.ArgumentParser(description='Анализ XSS-уязвимостей')
    parser.add_argument('--send', metavar='URL', help='Отправить HTTP-запрос')
    parser.add_argument('--capture', metavar='HOSTNAME', help='Перехватить трафик')
    parser.add_argument('--analyze', metavar='PCAP_FILE', help='Проанализировать pcap')
    parser.add_argument('--timeout', type=int, default=30, help='Таймаут (сек)')
    parser.add_argument('--output', metavar='FILE', help='Файл для сохранения')
    parser.add_argument('--request', metavar='HTTP_REQUEST', help='Кастомный запрос')

    args = parser.parse_args()

    if not any([args.send, args.capture, args.analyze]):
        parser.print_help()
        return

    if args.send:
        hostname, path, scheme = parse_url(args.send)
        if hostname:
            print(f"Отправка на {hostname}{path}")
            send_http_request(hostname, path, args.request)

    if args.capture:
        packets = capture_traffic(args.capture, args.timeout, args.output)
        if packets:
            analyze_packets(packets)

    if args.analyze:
        analyze_saved_traffic(args.analyze)


if __name__ == '__main__':
    main()