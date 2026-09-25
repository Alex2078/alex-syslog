#!/usr/bin/env python3
"""
Syslog-сервер: слушает UDP/514 и TCP/514 одновременно.
UDP — одиночные датаграммы (M240 и большинство устройств).
TCP — потоковые сессии (Sindoh/KATUSHA M247, M348 и др.).

RFC 3164 / RFC 5424 / RFC 6587 (octet-counted + newline-delimited).
"""

import socket
import datetime
import sys
import os
import signal
import time
import select
import threading
import chardet

DEFAULT_LOG_FILE = 'syslog.log'
DEFAULT_HOST = '0.0.0.0'
DEFAULT_PORT = 514
BUFFER_SIZE = 65535

# ---------------------------------------------------------------------------
# Декодирование сообщений
# ---------------------------------------------------------------------------
def decode_message(data: bytes) -> str:
    if not data:
        return ""
    result = chardet.detect(data)
    encoding = result.get('encoding') if result.get('confidence', 0) > 0.5 else None
    encodings_to_try = []
    if encoding:
        encodings_to_try.append(encoding)
    encodings_to_try.extend(['utf-8', 'cp1251', 'koi8-r', 'iso-8859-5', 'cp866'])
    seen = set()
    encodings_to_try = [e for e in encodings_to_try if not (e in seen or seen.add(e))]
    for enc in encodings_to_try:
        try:
            return data.decode(enc, errors='strict')
        except (UnicodeDecodeError, LookupError):
            continue
    return data.decode('utf-8', errors='replace')

# ---------------------------------------------------------------------------
# Запись в лог
# ---------------------------------------------------------------------------
log_lock = threading.Lock()

def write_log(log_file: str, addr, message: str, proto: str):
    timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')
    # В строке сохраняем пометку протокола, чтобы потом было видно, откуда пришло
    log_entry = f"{timestamp} [syslog] from {addr[0]}:{addr[1]} {proto} - {message}\n"
    with log_lock:
        with open(log_file, 'a', encoding='utf-8') as f:
            f.write(log_entry)
    print(log_entry.strip())

# ---------------------------------------------------------------------------
# Разбор TCP-потока syslog (RFC 6587)
# ---------------------------------------------------------------------------
def split_tcp_syslog_messages(buffer: bytes):
    """
    Возвращает (список_сообщений, остаток_буфера).
    Поддерживает:
      - octet-counted framing: b'123 <14>...'
      - newline-delimited:      b'<14>...\n'
      - без явного разделителя: одно сообщение на соединение
    """
    messages = []
    while buffer:
        # octet-counted?
        if buffer[:1].isdigit():
            space_pos = buffer.find(b' ')
            if space_pos > 0:
                try:
                    length = int(buffer[:space_pos])
                except ValueError:
                    length = None
                if length is not None:
                    total = space_pos + 1 + length
                    if len(buffer) >= total:
                        messages.append(buffer[space_pos + 1:total])
                        buffer = buffer[total:]
                        continue
                    else:
                        break  # ждём ещё данных
        # newline-delimited
        nl = buffer.find(b'\n')
        if nl != -1:
            line = buffer[:nl]
            if line.strip():
                messages.append(line)
            buffer = buffer[nl + 1:]
            continue
        # ни то, ни другое — ждём ещё данных
        break
    return messages, buffer

# ---------------------------------------------------------------------------
# TCP-клиент (обрабатывается в отдельном потоке)
# ---------------------------------------------------------------------------
def handle_tcp_client(conn: socket.socket, addr, log_file: str):
    print(f"[listener] TCP соединение от {addr[0]}:{addr[1]}")
    conn.settimeout(30)  # если 30 сек тишины — закрываем
    buffer = b''
    try:
        while True:
            try:
                chunk = conn.recv(BUFFER_SIZE)
            except socket.timeout:
                # нет данных — проверим, может, устройство уже всё прислало
                if buffer:
                    # отдадим то, что осталось, как одно сообщение
                    msg = decode_message(buffer).strip()
                    if msg:
                        write_log(log_file, addr, msg, "TCP")
                break
            if not chunk:
                # соединение закрыто клиентом
                if buffer:
                    msg = decode_message(buffer).strip()
                    if msg:
                        write_log(log_file, addr, msg, "TCP")
                break
            buffer += chunk
            msgs, buffer = split_tcp_syslog_messages(buffer)
            for raw in msgs:
                msg = decode_message(raw).strip()
                if msg:
                    write_log(log_file, addr, msg, "TCP")
    except Exception as e:
        print(f"[listener] TCP ошибка от {addr}: {e}")
    finally:
        try:
            conn.close()
        except Exception:
            pass
        print(f"[listener] TCP соединение закрыто: {addr[0]}:{addr[1]}")

# ---------------------------------------------------------------------------
# Основной цикл
# ---------------------------------------------------------------------------
def run_listener(log_file=DEFAULT_LOG_FILE, host=DEFAULT_HOST, port=DEFAULT_PORT):
    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    udp_sock.bind((host, port))

    tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    tcp_sock.bind((host, port))
    tcp_sock.listen(50)

    print(f"[listener] Syslog слушает UDP/{port} и TCP/{port} на {host}")
    print(f"[listener] Запись в файл: {log_file}")

    def signal_handler(sig, frame):
        print("[listener] Завершение, закрываем сокеты...")
        try:
            udp_sock.close()
        except Exception:
            pass
        try:
            tcp_sock.close()
        except Exception:
            pass
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    while True:
        try:
            rlist, _, _ = select.select([udp_sock, tcp_sock], [], [], 1.0)
        except (OSError, ValueError):
            break

        for sock in rlist:
            if sock is udp_sock:
                try:
                    data, addr = udp_sock.recvfrom(BUFFER_SIZE)
                except socket.error:
                    continue
                if data:
                    msg = decode_message(data).strip()
                    if msg:
                        write_log(log_file, addr, msg, "UDP")

            elif sock is tcp_sock:
                try:
                    conn, addr = tcp_sock.accept()
                except socket.error:
                    continue
                t = threading.Thread(
                    target=handle_tcp_client,
                    args=(conn, addr, log_file),
                    daemon=True,
                )
                t.start()

# ---------------------------------------------------------------------------
if __name__ == '__main__':
    log_file = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_LOG_FILE
    host = sys.argv[2] if len(sys.argv) > 2 else DEFAULT_HOST
    port = int(sys.argv[3]) if len(sys.argv) > 3 else DEFAULT_PORT
    run_listener(log_file, host, port)