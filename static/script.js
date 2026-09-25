/*
Syslog Server – real-time syslog viewer
Copyright (C) 2026  Alex

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License along
with this program; if not, write to the Free Software Foundation, Inc.,
51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

let eventSource = null;
let currentFilter = '';
let autoScroll = true;
let lineCounter = 0;

// --- Парсинг строки лога на колонки ---
// Формат: "DATE TIME IP PROTO HOSTNAME [Level] message"
//   PROTO = UDP | TCP | -
//   HOSTNAME = что-то | -
function parseLogLine(line) {
    // Формат: "DATE TIME IP PROTO HOSTNAME [LEVEL|-] MESSAGE"
    const re = /^(\d{4}-\d{2}-\d{2})\s+(\d{2}:\d{2}:\d{2}\.\d+)\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+(\S+)\s+(\S+)\s+(\[[^\]]+\]|-)\s+(.*)$/;
    const m = line.match(re);
    if (m) {
        return {
            date: m[1],
            time: m[2].replace(/\.(\d{3})\d+$/, '.$1'),  // обрезка до миллисекунд
            ip: m[3],
            proto: m[4],
            hostname: m[5],
            level: m[6],
            message: m[7]
        };
    }
    return { date: '', time: '', ip: '', proto: '', hostname: '', level: '', message: line };
}

// --- Экранирование HTML ---
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// --- Ячейка с IP (кликабельная ссылка) ---
function formatIpCell(ip) {
    if (!ip) return '';
    return `<span class="ip-address" onclick="applyFilter('${ip}')" title="Фильтровать по ${ip}">${ip}</span>`;
}

// --- Ячейка с протоколом (цветной бейдж) ---
function formatProtoCell(proto) {
    if (!proto || proto === '-') return '';
    let cls = '';
    if (proto === 'TCP') cls = 'proto-tcp';
    else if (proto === 'UDP') cls = 'proto-udp';
    return `<span class="proto-badge ${cls}">${escapeHtml(proto)}</span>`;
}

// --- Ячейка с hostname ---
function formatHostnameCell(hostname) {
    if (!hostname || hostname === '-') return '<span class="hostname-empty">—</span>';
    return `<span class="hostname">${escapeHtml(hostname)}</span>`;
}

// --- Ячейка с уровнем (регистронезависимо) ---
function formatLevelCell(level) {
    let cls = '';
    const l = (level || '').toLowerCase();
    if (l === '[info]' || l === '[notice]')                    cls = 'log-level-info';
    else if (l === '[warn]' || l === '[warning]')              cls = 'log-level-warn';
    else if (l === '[error]' || l === '[err]')                 cls = 'log-level-error';
    else if (l === '[debug]')                                  cls = 'log-level-debug';
    else if (l === '[critical]' || l === '[alert]' || l === '[emergency]') cls = 'log-level-error';
    return `<span class="${cls}">${escapeHtml(level)}</span>`;
}

// --- Форматирование одной строки как <tr> ---
function formatLogLine(line) {
    const p = parseLogLine(line);
    if (p.date) {
        return `<tr class="log-entry" id="entry-${++lineCounter}">
            <td class="col-date">${escapeHtml(p.date)}</td>
            <td class="col-time">${escapeHtml(p.time)}</td>
            <td class="col-ip">${formatIpCell(p.ip)}</td>
            <td class="col-proto">${formatProtoCell(p.proto)}</td>
            <td class="col-hostname">${formatHostnameCell(p.hostname)}</td>
            <td class="col-level">${formatLevelCell(p.level)}</td>
            <td class="col-message">${escapeHtml(p.message)}</td>
        </tr>`;
    }
    return `<tr class="log-entry" id="entry-${++lineCounter}">
        <td colspan="7" class="col-message">${escapeHtml(line)}</td>
    </tr>`;
}

// --- Обновление таблицы ---
function updateLogDisplay(lines) {
    const tbody = document.getElementById('logEntries');
    const lineCount = document.getElementById('lineCount');
    if (!lines || lines.length === 0) {
        tbody.innerHTML = `<tr><td colspan="7" class="no-logs">Нет записей${currentFilter ? ' (фильтр: ' + currentFilter + ')' : ''}</td></tr>`;
        lineCount.textContent = '0';
        return;
    }
    let html = '';
    lines.forEach(line => { html += formatLogLine(line); });
    tbody.innerHTML = html;
    lineCount.textContent = lines.length;
    if (autoScroll) document.getElementById('logContainer').scrollTop = 0;
}

// --- Остальные функции ---
async function loadInitialLogs() {
    try {
        showLoading(true);
        const response = await fetch(`/get_log?filter_ip=${encodeURIComponent(currentFilter)}`);
        const data = await response.json();
        updateLogDisplay(data.lines);
        showLoading(false);
    } catch (error) {
        console.error('Ошибка загрузки логов:', error);
        showError('Ошибка загрузки логов');
        showLoading(false);
    }
}

function showLoading(show) {
    const tbody = document.getElementById('logEntries');
    if (show) {
        tbody.innerHTML = `<tr><td colspan="7" class="loading"><div class="loader"></div><div>Загрузка логов...</div></td></tr>`;
    }
}

function showError(message) {
    const tbody = document.getElementById('logEntries');
    tbody.innerHTML = `<tr><td colspan="7" class="no-logs">${message}</td></tr>`;
}

function applyFilter(ip) {
    if (!ip) return;
    currentFilter = ip;
    lineCounter = 0;
    document.getElementById('activeFilter').style.display = 'flex';
    document.getElementById('noFilter').style.display = 'none';
    document.getElementById('filteredIp').textContent = ip;
    if (eventSource) eventSource.close();
    loadInitialLogs();
    startSSEConnection();
}

function clearFilter() {
    currentFilter = '';
    lineCounter = 0;
    document.getElementById('activeFilter').style.display = 'none';
    document.getElementById('noFilter').style.display = 'block';
    if (eventSource) eventSource.close();
    loadInitialLogs();
    startSSEConnection();
}

function startSSEConnection() {
    if (eventSource) eventSource.close();
    eventSource = new EventSource(`/get_updates?filter_ip=${encodeURIComponent(currentFilter)}`);
    eventSource.onmessage = function(e) {
        const newLine = e.data.trim();
        if (!newLine) return;
        const tbody = document.getElementById('logEntries');
        if (tbody.innerHTML.includes('no-logs') || tbody.innerHTML.includes('loading')) {
            loadInitialLogs();
            return;
        }
        const tr = document.createElement('tr');
        tr.className = 'log-entry new';
        tr.innerHTML = formatLogLine(newLine);
        if (tbody.firstChild) tbody.insertBefore(tr, tbody.firstChild);
        else tbody.appendChild(tr);
        const lineCount = document.getElementById('lineCount');
        lineCount.textContent = parseInt(lineCount.textContent) + 1;
        const rows = tbody.querySelectorAll('tr.log-entry');
        if (rows.length > 100) rows[rows.length - 1].remove();
        if (autoScroll) document.getElementById('logContainer').scrollTop = 0;
        document.getElementById('updateStatus').textContent = 'Активен';
        document.getElementById('statusIcon').textContent = '';
    };
    eventSource.onerror = function() {
        document.getElementById('updateStatus').textContent = 'Ошибка соединения';
        document.getElementById('statusIcon').textContent = '(!)';
        setTimeout(() => {
            if (!eventSource || eventSource.readyState === EventSource.CLOSED) {
                document.getElementById('updateStatus').textContent = 'Переподключение...';
                document.getElementById('statusIcon').textContent = '...';
                startSSEConnection();
            }
        }, 3000);
    };
}

document.getElementById('logContainer').addEventListener('scroll', function() {
    autoScroll = (this.scrollTop === 0);
});

window.onload = function() {
    loadInitialLogs();
    startSSEConnection();
};

window.onbeforeunload = function() {
    if (eventSource) eventSource.close();
};

// Обновление часов в реальном времени
function updateClock() {
    const now = new Date();
    const options = {
        year: 'numeric', month: '2-digit', day: '2-digit',
        hour: '2-digit', minute: '2-digit', second: '2-digit',
        hour12: false, timeZone: 'Europe/Moscow'
    };
    document.getElementById('currentTime').textContent = now.toLocaleString('ru-RU', options);
}

// --- Модальное окно справки ---
function openHelp() { document.getElementById('helpModal').style.display = 'flex'; }
function closeHelp(event) {
    if (event && event.target !== event.currentTarget) return;
    document.getElementById('helpModal').style.display = 'none';
}
function copyCommand() {
    const codeElement = document.getElementById('helpCommand');
    const textToCopy = codeElement.getAttribute('data-command') || codeElement.textContent;
    if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(textToCopy)
            .then(() => showCopySuccess())
            .catch(() => fallbackCopy(textToCopy));
    } else fallbackCopy(textToCopy);
}
function fallbackCopy(text) {
    const textarea = document.createElement('textarea');
    textarea.value = text;
    textarea.style.position = 'fixed';
    textarea.style.opacity = '0';
    document.body.appendChild(textarea);
    textarea.select();
    try { document.execCommand('copy'); showCopySuccess(); }
    catch (err) { alert('Не удалось скопировать. Скопируйте текст вручную.'); }
    document.body.removeChild(textarea);
}
function showCopySuccess() {
    const btn = document.querySelector('.copy-button');
    const original = btn.textContent;
    btn.textContent = '✅ Скопировано!';
    setTimeout(() => { btn.textContent = original; }, 2000);
}

document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
        const helpModal = document.getElementById('helpModal');
        if (helpModal.style.display === 'flex') {
            helpModal.style.display = 'none';
        }
        const clearModal = document.getElementById('clearLogModal');
        if (clearModal.style.display === 'flex') {
            clearModal.style.display = 'none';
        }
    }
});

// --- Модальное окно очистки лога ---
function openClearLog() {
    const modal = document.getElementById('clearLogModal');
    const input = document.getElementById('clearLogPassword');
    const errEl = document.getElementById('clearLogError');
    input.value = '';
    errEl.textContent = '';
    modal.style.display = 'flex';
    setTimeout(() => input.focus(), 50);
}

function closeClearLog(event) {
    if (event && event.target !== event.currentTarget) return;
    document.getElementById('clearLogModal').style.display = 'none';
}

async function confirmClearLog() {
    const input = document.getElementById('clearLogPassword');
    const errEl = document.getElementById('clearLogError');
    const password = input.value || '';

    if (!password) {
        errEl.textContent = 'Введите пароль';
        return;
    }

    try {
        const resp = await fetch('/clear_log', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({password: password})
        });
        const data = await resp.json();

        if (data.ok) {
            document.getElementById('clearLogModal').style.display = 'none';
            // Очищаем таблицу и перезагружаем пустой лог
            lineCounter = 0;
            loadInitialLogs();
            document.getElementById('lineCount').textContent = '0';
        } else {
            errEl.textContent = data.error || 'Неправильный пароль';
            input.value = '';
            input.focus();
        }
    } catch (err) {
        errEl.textContent = 'Ошибка соединения с сервером';
    }
}

updateClock();
setInterval(updateClock, 1000);