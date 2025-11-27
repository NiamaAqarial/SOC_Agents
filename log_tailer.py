# log_tailer.py
# Monitors multiple log files (/var/log/auth.log, ufw.log, nginx/access.log).
# Detects patterns for SSH failed, port scans, web fuzz.
# Generates events with ID, ISO timestamp, kind, src_ip, dst, raw.
# Sends to Collector via POST.
# Includes web interface for monitoring (adapted from sensor.py).
# Run as root/sudo for log access.

import time
import subprocess
import re
import requests
import json
import threading
import uuid
from flask import Flask, render_template_string, jsonify
from datetime import datetime
from config import COLLECTOR_URL, AUTH_TOKEN, LOGS_TO_MONITOR, HEURISTICS, WHITELIST_IPS, SENSOR_PORT

app = Flask(__name__)

HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Security Sensor Dashboard</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        .container {
            max-width: 1400px;
            margin: 0 auto;
        }
        .header {
            background: white;
            padding: 30px;
            border-radius: 15px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.2);
            margin-bottom: 30px;
            text-align: center;
        }
        h1 {
            color: #667eea;
            font-size: 2.5em;
            margin-bottom: 10px;
        }
        .sensor-badge {
            background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
            color: white;
            padding: 8px 20px;
            border-radius: 20px;
            display: inline-block;
            font-weight: bold;
            margin-top: 10px;
        }
        .status-active {
            display: inline-block;
            width: 12px;
            height: 12px;
            border-radius: 50%;
            background: #4CAF50;
            animation: pulse 2s infinite;
            margin-right: 10px;
        }
        @keyframes pulse {
            0%, 100% { opacity: 1; transform: scale(1); }
            50% { opacity: 0.5; transform: scale(1.1); }
        }
        .stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .stat-card {
            background: white;
            padding: 25px;
            border-radius: 15px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
            text-align: center;
            transition: all 0.3s;
        }
        .stat-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 10px 25px rgba(0,0,0,0.15);
        }
        .stat-number {
            font-size: 2.5em;
            font-weight: bold;
            margin-bottom: 10px;
        }
        .stat-number.detected { color: #f5576c; }
        .stat-number.sent { color: #4CAF50; }
        .stat-number.failed { color: #ff9800; }
        .stat-number.uptime { color: #667eea; }
        .stat-label {
            color: #666;
            font-size: 0.9em;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        .monitoring-info {
            background: white;
            padding: 25px;
            border-radius: 15px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
            margin-bottom: 30px;
        }
        .monitoring-info h3 {
            color: #667eea;
            margin-bottom: 15px;
            font-size: 1.3em;
        }
        .info-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 15px;
        }
        .info-item {
            padding: 15px;
            background: #f8f9fa;
            border-radius: 8px;
            border-left: 3px solid #667eea;
        }
        .info-item strong {
            color: #333;
            display: block;
            margin-bottom: 5px;
        }
        .info-item span {
            color: #666;
            font-family: 'Courier New', monospace;
        }
        .events-container {
            background: white;
            padding: 30px;
            border-radius: 15px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.2);
        }
        .events-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
        }
        .events-header h2 {
            color: #333;
        }
        .refresh-btn {
            background: #667eea;
            color: white;
            border: none;
            padding: 10px 20px;
            border-radius: 8px;
            cursor: pointer;
            font-size: 1em;
            transition: all 0.3s;
        }
        .refresh-btn:hover {
            background: #5568d3;
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(102, 126, 234, 0.4);
        }
        .event-card {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 10px;
            margin-bottom: 15px;
            border-left: 4px solid #667eea;
            transition: all 0.3s;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .event-card:hover {
            transform: translateX(5px);
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
        }
        .event-type {
            display: inline-block;
            background: #667eea;
            color: white;
            padding: 5px 15px;
            border-radius: 20px;
            font-size: 0.85em;
            font-weight: bold;
            margin-bottom: 10px;
        }
        .event-details {
            display: flex;
            flex-direction: column;
            gap: 5px;
        }
        .event-detail {
            color: #555;
        }
        .event-detail strong {
            color: #333;
        }
        .event-status {
            padding: 8px 15px;
            border-radius: 20px;
            font-weight: bold;
            white-space: nowrap;
        }
        .status-sent { background: #4CAF50; color: white; }
        .status-failed { background: #f5576c; color: white; }
        .no-events {
            text-align: center;
            color: #999;
            padding: 40px;
            font-size: 1.1em;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Security Sensor Dashboard</h1>
            <div class="sensor-badge"><span class="status-active"></span>Active Monitoring</div>
        </div>
        
        <div class="stats">
            <div class="stat-card">
                <div class="stat-number detected" id="detected">0</div>
                <div class="stat-label">Events Detected</div>
            </div>
            <div class="stat-card">
                <div class="stat-number sent" id="sent">0</div>
                <div class="stat-label">Events Sent</div>
            </div>
            <div class="stat-card">
                <div class="stat-number failed" id="failed">0</div>
                <div class="stat-label">Failed Sends</div>
            </div>
            <div class="stat-card">
                <div class="stat-number uptime" id="uptime">0s</div>
                <div class="stat-label">Uptime</div>
            </div>
        </div>
        
        <div class="monitoring-info">
            <h3>📊 Monitoring Configuration</h3>
            <div class="info-grid">
                <div class="info-item">
                    <strong>Start Time:</strong>
                    <span id="start-time">--</span>
                </div>
                <div class="info-item">
                    <strong>Status:</strong>
                    <span id="status">--</span>
                </div>
                <div class="info-item">
                    <strong>Collector URL:</strong>
                    <span>http://127.0.0.1:6001/event</span>
                </div>
                <div class="info-item">
                    <strong>Logs Monitored:</strong>
                    <span>/var/log/auth.log, /var/log/ufw.log, /var/log/nginx/access.log</span>
                </div>
            </div>
        </div>
        
        <div class="events-container">
            <div class="events-header">
                <h2>Recent Detected Events</h2>
                <button class="refresh-btn" onclick="loadData()">🔄 Refresh</button>
            </div>
            <div id="events-list"></div>
        </div>
    </div>

    <script>
        function calculateUptime() {
            const start = new Date(document.getElementById('start-time').textContent);
            const now = new Date();
            const diff = Math.floor((now - start) / 1000);
            const hours = Math.floor(diff / 3600);
            const mins = Math.floor((diff % 3600) / 60);
            const secs = diff % 60;
            return `${hours}h ${mins}m ${secs}s`;
        }

        function loadData() {
            fetch('/api/sensor-data')
                .then(response => response.json())
                .then(data => {
                    // Update stats
                    document.getElementById('detected').textContent = data.stats.total_detected || 0;
                    document.getElementById('sent').textContent = data.stats.total_sent || 0;
                    document.getElementById('failed').textContent = data.stats.failed_sends || 0;
                    document.getElementById('start-time').textContent = data.stats.start_time || '--';
                    document.getElementById('status').textContent = data.stats.monitoring_status || '--';
                    document.getElementById('uptime').textContent = calculateUptime();

                    const eventsList = document.getElementById('events-list');
                    const events = data.events || [];

                    if (events.length === 0) {
                        eventsList.innerHTML = '<div class="no-events">No events detected yet. Waiting for log activity...</div>';
                        return;
                    }

                    // Display events (most recent first)
                    eventsList.innerHTML = events.slice().reverse().map(event => {
                        const status = event.sent_successfully;
                        const statusClass = status ? 'status-sent' : 'status-failed';
                        const statusText = status ? 'Sent' : 'Failed';
                        const statusIcon = status ? '✅' : '❌';

                        return `
                        <div class="event-card">
                            <div>
                                <span class="event-type">${event.kind || 'Unknown'}</span>
                                <div class="event-details">
                                    <div class="event-detail">
                                        <strong>🎯 Source IP:</strong> ${event.src_ip || 'N/A'}
                                    </div>
                                    <div class="event-detail">
                                        <strong>📍 Detected At:</strong> ${event.ts || 'N/A'}
                                    </div>
                                    <div class="event-detail">
                                        <strong>🔍 Event Kind:</strong> ${event.kind || 'N/A'}
                                    </div>
                                </div>
                            </div>
                            <div class="event-status ${statusClass}">
                                ${statusIcon} ${statusText}
                            </div>
                        </div>
                        `;
                    }).join('');
                })
                .catch(error => {
                    console.error('Error loading sensor data:', error);
                });
        }

        // Load data on page load
        loadData();
        
        // Auto-refresh every 3 seconds
        setInterval(loadData, 3000);
        
        // Update uptime every second
        setInterval(() => {
            document.getElementById('uptime').textContent = calculateUptime();
        }, 1000);
    </script>
</body>
</html>
"""

# Storage for detected events and stats
detected_events = []
sensor_stats = {
    "start_time": datetime.now().isoformat(),
    "total_detected": 0,
    "total_sent": 0,
    "failed_sends": 0,
    "monitoring_status": "active"
}

# HTML_TEMPLATE (same as in provided sensor.py, omitted for brevity; copy from sensor.py if needed)

def tail_log(file_path, kind, pattern):
    """Tail a log file and detect patterns."""
    try:
        process = subprocess.Popen(
            ['tail', '-f', file_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        print(f"[Log Tailer] Monitoring {file_path} for {kind}...")
        while True:
            line = process.stdout.readline().decode('utf-8').strip()
            if re.search(pattern, line):
                # Extract src_ip (adapt regex per log type)
                src_ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)  # Basic IP extract
                src_ip = src_ip_match.group(1) if src_ip_match else "unknown"
                if src_ip in WHITELIST_IPS:
                    continue  # Skip whitelisted

                event = {
                    "id": f"evt-{uuid.uuid4().hex[:8]}",
                    "ts": datetime.now().isoformat() + "Z",
                    "kind": kind,
                    "src_ip": src_ip,
                    "dst": "ubuntu-vm",  # Or extract if available
                    "raw": line
                }
                sensor_stats["total_detected"] += 1
                success = send_to_collector(event)
                event["sent_successfully"] = success
                detected_events.append(event)
                if len(detected_events) > 100:
                    detected_events.pop(0)
    except Exception as e:
        print(f"[Log Tailer] Error monitoring {file_path}: {e}")
        sensor_stats["monitoring_status"] = "error"

def send_to_collector(event):
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {AUTH_TOKEN}"
    }
    try:
        response = requests.post(COLLECTOR_URL, json=event, headers=headers, timeout=5)
        if response.status_code == 200:
            print(f"[Log Tailer] Event sent: {event}")
            sensor_stats["total_sent"] += 1
            return True
        else:
            sensor_stats["failed_sends"] += 1
            return False
    except Exception as e:
        print(f"[Log Tailer] Send error: {e}")
        sensor_stats["failed_sends"] += 1
        return False

@app.route('/')
def dashboard():
    return render_template_string(HTML_TEMPLATE)  # Use the HTML from sensor.py

@app.route('/api/sensor-data', methods=['GET'])
def get_sensor_data():
    return jsonify({"stats": sensor_stats, "events": detected_events})

def run_flask():
    print(f"[Log Tailer] Web interface at http://0.0.0.0:{SENSOR_PORT}")
    app.run(host='0.0.0.0', port=SENSOR_PORT, debug=False, use_reloader=False)

if __name__ == "__main__":
    flask_thread = threading.Thread(target=run_flask, daemon=True)
    flask_thread.start()
    time.sleep(2)

    # Start tailing each log in separate threads
    threads = []
    for log in LOGS_TO_MONITOR:
        if "auth.log" in log:
            t = threading.Thread(target=tail_log, args=(log, "ssh_failed", HEURISTICS["ssh_failed"]["pattern"]))
        elif "ufw.log" in log:
            t = threading.Thread(target=tail_log, args=(log, "port_scan", HEURISTICS["port_scan"]["pattern"]))
        elif "nginx/access.log" in log:
            t = threading.Thread(target=tail_log, args=(log, "web_fuzz", HEURISTICS["web_fuzz"]["pattern"]))
        else:
            continue
        t.daemon = True
        t.start()
        threads.append(t)

    # Keep main thread alive
    for t in threads:
        t.join()
