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

# Параметры syslog-сервера
SYSLOG_HOST = os.getenv('SYSLOG_HOST', '0.0.0.0')
SYSLOG_PORT = int(os.getenv('SYSLOG_PORT', 514))
SYSLOG_LOG_FILE = os.getenv('SYSLOG_LOG_FILE', 'syslog.log')

# Файл для статистики подключений
STATS_LOG_FILE = os.getenv('STATS_LOG_FILE', 'stats.log')

# Отображаемое имя хоста для веб-интерфейса
SYSLOG_DISPLAY_HOST = os.getenv('SYSLOG_DISPLAY_HOST', 'alex-syslog')

# Параметры Flask-приложения
FLASK_HOST = os.getenv('FLASK_HOST', '0.0.0.0')
FLASK_PORT = int(os.getenv('FLASK_PORT', 5000))
FLASK_DEBUG = os.getenv('FLASK_DEBUG', 'False').lower() == 'true'

# Версия приложения
APP_VERSION = os.getenv('APP_VERSION', '1.42')

# --- Пароль администратора для очистки лога (SHA-256) ---
# Значение по умолчанию соответствует паролю "admin".
# Переопределить можно через переменную окружения ADMIN_PASSWORD_HASH.
#
# Чтобы поменять пароль, посчитайте новый хэш, например:
#   echo -n "новый_пароль" | sha256sum
# и подставьте его сюда (или в переменную окружения).
ADMIN_PASSWORD_HASH = os.getenv(
    'ADMIN_PASSWORD_HASH',
    '8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918'
)