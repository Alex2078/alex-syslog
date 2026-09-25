# Syslog Server – real-time syslog viewer
# Copyright (C) 2026  Alex
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

import os
import time
import hashlib
from flask import Flask, render_template, request, jsonify, send_file
import re
import chardet
import datetime

from config import (
    SYSLOG_HOST, SYSLOG_PORT, SYSLOG_LOG_FILE,
    FLASK_HOST, FLASK_PORT, FLASK_DEBUG,
    APP_VERSION,
    SYSLOG_DISPLAY_HOST,
    STATS_LOG_FILE,
    ADMIN_PASSWORD_HASH
)

app = Flask(__name__)

LOG_FILE = SYSLOG_LOG_FILE
STATS_FILE = STATS_LOG_FILE
LAST_LINES = 100

# --- Создание файлов логов, если они отсутствуют ---
def ensure_log_files():
    for file_path in [LOG_FILE, STATS_FILE]:
        if not os.path.exists(file_path):
            try:
                os.makedirs(os.path.dirname(file_path), exist_ok=True)
                with open(file_path, 'w', encoding='utf-8') as f:
                    pass
                print(f"[app] Создан файл: {file_path}")
            except Exception as e:
                print(f"[app] Ошибка создания {file_path}: {e}")

ensure_log_files()

# --- Преобразование числовых приоритетов в текст ---
SEVERITY_NAMES = [
    "Emergency", "Alert", "Critical", "Error",
    "Warning", "Notice", "Info", "Debug"
]
PRIORITY_PATTERN = re.compile(r'<(\d+)>')

# RFC 3164: "Sep 24 16:02:14 M247e3004 printer: "
RFC3164_PREFIX_RE = re.compile(
    r'^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+'   # timestamp
    r'(\S+)\s+'                                              # hostname (group 1)
    r'(?:[A-Za-z0-9_\-\.]+:\s+)?'                            # tag
)

# RFC 5424: "1 2026-09-25T09:22:57Z ET788C77B5D026 settings 0 <setting> ..."
#   VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID ...
RFC5424_PREFIX_RE = re.compile(
    r'^\d{1,2}\s+'                        # VERSION (обычно 1)
    r'\d{4}-\d{2}-\d{2}T\S+\s+'            # TIMESTAMP ISO 8601
    r'(\S+)\s+'                            # HOSTNAME (group 1)
)

# Уже подставленный [Severity] в строке
SEVERITY_TOKEN_RE = re.compile(
    r'(\[(?:Emergency|Alert|Critical|Error|Warning|Notice|Info|Debug)\])'
    r'\s*(.*)$'
)


def priority_to_text(match):
    try:
        prio = int(match.group(1))
        severity = prio & 0x07
        return f"[{SEVERITY_NAMES[severity]}]"
    except Exception:
        return match.group(0)


def translate_priorities_in_line(line):
    return PRIORITY_PATTERN.sub(priority_to_text, line)


# --- Очистка строки от служебных меток ---
# Формат: "DATE TIME IP PROTO HOSTNAME [LEVEL|-] raw_body"
# raw_body — тело от устройства БЕЗ изменений, включая <PRI>.
def clean_log_line(line):
    # 1) Убираем служебную метку [syslog]
    line = re.sub(r'\[syslog\]\s+', '', line)

    # 2) Вычисляем важность по <N>, но само <N> в теле НЕ трогаем
    severity = '-'
    pm = PRIORITY_PATTERN.search(line)
    if pm:
        try:
            sev_idx = int(pm.group(1)) & 0x07
            severity = f"[{SEVERITY_NAMES[sev_idx]}]"
        except Exception:
            severity = '-'

    # 3) "from IP:port [UDP|TCP] - " → "IP PROTO "
    holder = {'proto': '-'}

    def repl_from(m):
        holder['proto'] = m.group(2) or '-'
        return f"{m.group(1)} {holder['proto']} "

    line = re.sub(
        r'from\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):\d+'
        r'(?:\s+(UDP|TCP))?\s+-\s+',
        repl_from, line, count=1
    )

    # 4) Отделяем служебный заголовок (DATE TIME IP PROTO) от тела syslog
    parts = re.match(
        r'^(\d{4}-\d{2}-\d{2}\s+\S+\s+\S+\s+\S+)\s+(.*)$',
        line, re.S
    )
    if not parts:
        return line
    head, syslog_body = parts.group(1), parts.group(2)

    # 5) Определяем hostname по «пробной» строке без <N>
    probe = PRIORITY_PATTERN.sub('', syslog_body, count=1).lstrip()
    hostname = '-'
    hm = RFC3164_PREFIX_RE.match(probe)
    if hm:
        hostname = hm.group(1)
    else:
        hm = RFC5424_PREFIX_RE.match(probe)
        if hm:
            hostname = hm.group(1)

    # 6) Собираем итоговую строку, тело syslog_body НЕ меняется
    return f"{head} {hostname} {severity} {syslog_body}"
    

# --- Функции для работы с лог-файлом ---
def detect_line_encoding(line_bytes):
    try:
        result = chardet.detect(line_bytes)
        if result['confidence'] > 0.5:
            return result['encoding'] if result['encoding'] else 'utf-8'
    except Exception:
        pass
    return 'utf-8'


def decode_line_with_detection(line_bytes):
    if not line_bytes:
        return ""
    encoding = detect_line_encoding(line_bytes)
    encodings_to_try = [
        encoding, 'utf-8', 'cp1251', 'koi8-r',
        'iso-8859-5', 'cp866', 'mac_cyrillic', 'latin-1'
    ]
    encodings_to_try = list(dict.fromkeys(encodings_to_try))
    for enc in encodings_to_try:
        try:
            return line_bytes.decode(enc, errors='strict')
        except (UnicodeDecodeError, LookupError):
            continue
    return line_bytes.decode('utf-8', errors='replace')


def get_last_n_lines_binary(file_path, n=100):
    try:
        with open(file_path, 'rb') as f:
            f.seek(0, 2)
            file_size = f.tell()
            buffer_size = 8192
            lines_found = []
            buffer = b''
            position = file_size
            while position > 0 and len(lines_found) < n:
                read_size = min(buffer_size, position)
                position -= read_size
                f.seek(position)
                chunk = f.read(read_size)
                buffer = chunk + buffer
                while b'\n' in buffer:
                    pos = buffer.rfind(b'\n')
                    if pos == len(buffer) - 1:
                        buffer = buffer[:-1]
                        continue
                    line = buffer[pos + 1:] if pos != -1 else buffer
                    buffer = buffer[:pos]
                    if line.strip():
                        lines_found.append(line)
                    if len(lines_found) >= n:
                        break
            if buffer.strip() and len(lines_found) < n:
                lines_found.append(buffer)
            return lines_found[::-1]
    except FileNotFoundError:
        return []
    except Exception as e:
        print(f"[app] Ошибка чтения файла: {e}")
        return []


def extract_ips_from_line(line):
    ip_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
    return ip_pattern.findall(line)


def get_log_lines(filter_ip=None):
    try:
        if not os.path.exists(LOG_FILE):
            with open(LOG_FILE, 'w', encoding='utf-8') as f:
                pass
            return []
        binary_lines = get_last_n_lines_binary(LOG_FILE, LAST_LINES)
        decoded_lines = []
        for line_bytes in binary_lines:
            line = decode_line_with_detection(line_bytes)
#           line = translate_priorities_in_line(line)
            line = clean_log_line(line)
            decoded_lines.append(line)
        if filter_ip:
            filtered = []
            for line in decoded_lines:
                ips = extract_ips_from_line(line)
                if any(filter_ip in ip for ip in ips):
                    filtered.append(line)
            decoded_lines = filtered
        return decoded_lines[::-1]
    except Exception as e:
        return [f"Ошибка чтения файла: {str(e)}"]


def tail_log_with_encoding(file_path, filter_ip=None):
    if not os.path.exists(file_path):
        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                pass
        except Exception as e:
            print(f"[app] Не удалось создать файл {file_path}: {e}")
            return

    last_size = 0
    try:
        with open(file_path, 'rb') as f:
            f.seek(0, 2)
            last_size = f.tell()
    except Exception:
        pass

    while True:
        try:
            current_size = os.path.getsize(file_path)
            if current_size > last_size:
                with open(file_path, 'rb') as f:
                    f.seek(last_size)
                    new_data = f.read()
                    last_size = f.tell()
                    lines = new_data.splitlines()
                    for line_bytes in lines:
                        if not line_bytes:
                            continue
                        line = decode_line_with_detection(line_bytes)
#                       line = translate_priorities_in_line(line)
                        line = clean_log_line(line)
                        if filter_ip:
                            ips = extract_ips_from_line(line)
                            if not any(filter_ip in ip for ip in ips):
                                continue
                        yield line
            elif current_size < last_size:
                last_size = 0
            time.sleep(0.5)
        except FileNotFoundError:
            time.sleep(1)
        except Exception as e:
            print(f"[app] Ошибка в tail_log_with_encoding: {e}")
            time.sleep(1)


# --- Маршруты Flask ---
@app.route('/')
def index():
    try:
        ip = request.remote_addr
        if request.headers.get('X-Forwarded-For'):
            ip = request.headers.get('X-Forwarded-For').split(',')[0].strip()
        user_agent = request.headers.get('User-Agent', 'Unknown')
        timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        with open(STATS_FILE, 'a', encoding='utf-8') as f:
            f.write(f"{ip}, {user_agent}, {timestamp}\n")
    except Exception as e:
        print(f"[app] Ошибка записи статистики: {e}")

    return render_template('index.html',
                         version=APP_VERSION,
                         host=SYSLOG_DISPLAY_HOST,
                         port=SYSLOG_PORT)


@app.route('/get_log')
def get_log():
    filter_ip = request.args.get('filter_ip', '').strip()
    lines = get_log_lines(filter_ip if filter_ip else None)
    return jsonify({'lines': lines})


@app.route('/get_updates')
def get_updates():
    filter_ip = request.args.get('filter_ip', '').strip()

    def generate():
        try:
            for line in tail_log_with_encoding(LOG_FILE, filter_ip if filter_ip else None):
                yield f"data: {line}\n\n"
        except GeneratorExit:
            return
        except Exception as e:
            print(f"[app] SSE error: {e}")
            yield f"data: Ошибка соединения\n\n"

    return generate(), {'Content-Type': 'text/event-stream'}


@app.route('/download')
def download_log():
    if not os.path.exists(LOG_FILE):
        return "Файл лога не найден", 404
    try:
        return send_file(
            LOG_FILE,
            as_attachment=True,
            download_name='syslog.log',
            mimetype='text/plain'
        )
    except Exception as e:
        return str(e), 500


@app.route('/stats')
def stats():
    if not os.path.exists(STATS_FILE):
        return "Файл статистики пока пуст", 404
    try:
        with open(STATS_FILE, 'r', encoding='utf-8') as f:
            content = f.read()
        return content, 200, {'Content-Type': 'text/plain; charset=utf-8'}
    except Exception as e:
        return f"Ошибка чтения статистики: {e}", 500


@app.route('/clear_log', methods=['POST'])
def clear_log():
    """Очистка файла логов по паролю администратора."""
    data = request.get_json(silent=True) or {}
    password = (data.get('password') or '').strip()

    if not password:
        return jsonify({'ok': False, 'error': 'Введите пароль'}), 400

    pwd_hash = hashlib.sha256(password.encode('utf-8')).hexdigest()
    if pwd_hash != ADMIN_PASSWORD_HASH:
        # Небольшая задержка против перебора
        time.sleep(1.0)
        return jsonify({'ok': False, 'error': 'Неправильный пароль'}), 403

    try:
        with open(LOG_FILE, 'w', encoding='utf-8') as f:
            pass  # просто обнуляем файл
        print(f"[app] Лог очищен по запросу с {request.remote_addr}")
        return jsonify({'ok': True})
    except Exception as e:
        return jsonify({'ok': False, 'error': f'Ошибка очистки: {e}'}), 500
        
        
if __name__ == '__main__':
    app.run(debug=FLASK_DEBUG, threaded=True, host=FLASK_HOST, port=FLASK_PORT)