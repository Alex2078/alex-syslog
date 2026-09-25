FROM python:3.10-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir --default-timeout=100 -r requirements.txt

COPY . .

EXPOSE 5000
EXPOSE 514/udp

CMD ["sh", "-c", "python syslog_listener.py /app/data/syslog.log 0.0.0.0 514 & exec gunicorn app:app --workers 1 --worker-class gevent --bind 0.0.0.0:5000 --timeout 0"]