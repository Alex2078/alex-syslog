# alex-syslog

* **Syslog server with a Python/Flask web interface**

A lightweight server for receiving, saving, and viewing syslog messages over UDP with a user-friendly web interface for real-time log monitoring.

## Opportunities

 Receiving syslog messages over UDP protocol (default port 514)
- A web interface for viewing logs in a browser
- Real-time log updates via Server-Sent Events (SSE)
- Message filtering by sender's IP address
- Downloading the full log file
- Asynchronous operation: the syslog listener is running in a separate process
- Flexible configuration via a file `config.py `

## Technologies

- **Python 3.x**
- **Flask** — web framework
- **Socket** — working with UDP
- **HTML/CSS/JS** — frontend of the web interface
## Project structure

```
alex-syslog/
├── app.py                  # Main Flask application (web interface)
├── syslog_listener.py      # Syslog listener (UDP + TCP server)
├── config.py               # Configuration file
├── requirements.txt        # Python dependencies
├── Dockerfile              # Image definition
├── docker-compose.yml      # Compose orchestration
├── nginx/
│   └── default.conf        # Nginx reverse proxy config
├── templates/
│   └── index.html          # Web interface template
├── static/
│   ├── script.js           # Frontend logic
│   ├── style.css           # Styling
│   └── favicon.svg         # Icon
├── data/                   # Runtime logs (git-ignored)
├── README.md               # Documentation
└── LICENSE                 # GPL v3 License
```


## Installation and launch

### Requirements

- Python 3.7 or higher
- pip (Python Package Manager)

### 1. Cloning a repository

```bash
git clone https://github.com/Alex2078/alex-syslog.git
cd alex-syslog
```

pip install flask

###3. Setup (optional)

Open config.py and change the parameters if necessary:

# Syslog server parameters
SYSLOG_HOST = '0.0.0.0' # Interface for receiving syslog
SYSLOG_PORT = 514 # UDP port for syslog
SYSLOG_LOG_FILE = 'syslog.log' # File for recording logs

# Web Interface Settings
FLASK_HOST = '0.0.0.0' # Interface for the web server
FLASK_PORT = 5000 # Web Interface port
FLASK_DEBUG = False # Flask Debugging mode

Important: Root rights are required to run on ports < 1024 (for example, standard syslog port 514).
Possible solutions:

    Run with sudo: sudo python3 app.py
Use an unprivileged port (for example, 1514) and redirect traffic through iptables
    Configure capabilities for Python: sudo setcap 'cap_net_bind_service=+ep' $(which python3.x)

###4. Launching the app

```bash
python3 app.py
```

### 5. After the launch:

    Syslog listener will start receiving messages on UDP 514
    , The web interface will be available at: http://localhost:5000

### 6. Using the web interface

Open in the browser: http://<your_server>:5000
View the latest log entries (automatic updates)
Use the Filter by IP field to filter messages.
Click Download Log to download the full syslog.log file.

### 7. License

The project is distributed under the GNU General Public License v3.0.

### 8. Docker Hub

Official image: [`powerlion/syslog-server`](https://hub.docker.com/r/powerlion/syslog-server)

### 8.1 Quick start

```bash
# Pull the image
docker pull powerlion/syslog-server:latest
```

## 8.2 Run with docker run
```bash
docker run -d \
  --name syslog-app \
  -p 5000:5000 \
  -p 514:514/udp \
  -v $(pwd)/syslog.log:/app/syslog.log \
  powerlion/syslog-server:latest
```

## 8.3 Or with docker-compose
```bash
wget https://raw.githubusercontent.com/Alex2078/alex-syslog/main/docker-compose.yml
docker-compose up -d
```bash

The project is distributed under the GNU General Public License v3.0.
