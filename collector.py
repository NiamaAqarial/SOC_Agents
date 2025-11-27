# collector.py
# Receives events from log_tailer via POST /event.
# Stores events, forwards to Analyzer.
# Includes web interface (adapted from provided collector.py).

from flask import Flask, request, jsonify, render_template_string
import requests
from datetime import datetime
from config import AUTH_TOKEN, ANALYZER_URL, COLLECTOR_PORT

app = Flask(__name__)

events_storage = []  # In-memory storage (use DB for production)

HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Security Collector Dashboard</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        .container {
            max-width: 1200px;
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
        }
        .stat-number {
            font-size: 2.5em;
            font-weight: bold;
            color: #667eea;
            margin-bottom: 10px;
        }
        .stat-label {
            color: #666;
            font-size: 0.9em;
            text-transform: uppercase;
            letter-spacing: 1px;
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
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 10px;
            margin-top: 10px;
        }
        .event-detail {
            color: #555;
        }
        .event-detail strong {
            color: #333;
        }
        .no-events {
            text-align: center;
            color: #999;
            padding: 40px;
            font-size: 1.1em;
        }
        .status {
            display: inline-block;
            width: 10px;
            height: 10px;
            border-radius: 50%;
            background: #4CAF50;
            animation: pulse 2s infinite;
            margin-right: 10px;
        }
        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.5; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Security Event Collector</h1>
            <p><span class="status"></span>Active and Monitoring</p>
        </div>
        
        <div class="stats">
            <div class="stat-card">
                <div class="stat-number" id="total-events">0</div>
                <div class="stat-label">Total Events</div>
            </div>
            <div class="stat-card">
                <div class="stat-number" id="ssh-failed">0</div>
                <div class="stat-label">SSH Failed Attempts</div>
            </div>
            <div class="stat-card">
                <div class="stat-number" id="port-scans">0</div>
                <div class="stat-label">Port Scans</div>
            </div>
            <div class="stat-card">
                <div class="stat-number" id="web-fuzz">0</div>
                <div class="stat-label">Web Fuzz Attempts</div>
            </div>
            <div class="stat-card">
                <div class="stat-number" id="forwarded">0</div>
                <div class="stat-label">Forwarded to Analyzer</div>
            </div>
        </div>
        
        <div class="events-container">
            <div class="events-header">
                <h2>Recent Events</h2>
                <button class="refresh-btn" onclick="loadEvents()">🔄 Refresh</button>
            </div>
            <div id="events-list"></div>
        </div>
    </div>

    <script>
        function loadEvents() {
            fetch('/api/events')
                .then(response => response.json())
                .then(data => {
                    const eventsList = document.getElementById('events-list');
                    const events = data.events;
                    
                    // Update stats
                    document.getElementById('total-events').textContent = events.length;
                    const sshFailed = events.filter(e => e.kind === 'ssh_failed').length;
                    document.getElementById('ssh-failed').textContent = sshFailed;
                    const portScans = events.filter(e => e.kind === 'port_scan').length;
                    document.getElementById('port-scans').textContent = portScans;
                    const webFuzz = events.filter(e => e.kind === 'web_fuzz').length;
                    document.getElementById('web-fuzz').textContent = webFuzz;
                    document.getElementById('forwarded').textContent = events.length;
                    
                    if (events.length === 0) {
                        eventsList.innerHTML = '<div class="no-events">No events collected yet. Waiting for sensor data...</div>';
                        return;
                    }
                    
                    // Display events (most recent first)
                    eventsList.innerHTML = events.slice().reverse().map(event => `
                        <div class="event-card">
                            <span class="event-type">${event.kind || 'Unknown'}</span>
                            <div class="event-details">
                                <div class="event-detail"><strong>Source IP:</strong> ${event.src_ip || 'N/A'}</div>
                                <div class="event-detail"><strong>Timestamp:</strong> ${event.ts || 'N/A'}</div>
                                ${event.dst ? `<div class="event-detail"><strong>Destination:</strong> ${event.dst}</div>` : ''}
                            </div>
                        </div>
                    `).join('');
                })
                .catch(error => {
                    console.error('Error loading events:', error);
                });
        }

        // Load events on page load
        loadEvents();
        
        // Auto-refresh every 5 seconds
        setInterval(loadEvents, 5000);
    </script>
</body>
</html>
"""

@app.route('/')
def dashboard():
    return render_template_string(HTML_TEMPLATE)

@app.route('/api/events', methods=['GET'])
def get_events():
    return jsonify({"events": events_storage})

@app.route('/event', methods=['POST'])
def receive_event():
    if request.headers.get('Authorization') != f"Bearer {AUTH_TOKEN}":
        return jsonify({"error": "Unauthorized"}), 401
    
    event = request.json
    if not event:
        return jsonify({"error": "Invalid event"}), 400
    
    events_storage.append(event)
    print(f"[Collector] Received event: {event}")
    
    # Forward to Analyzer
    headers = {"Content-Type": "application/json", "Authorization": f"Bearer {AUTH_TOKEN}"}
    try:
        response = requests.post(ANALYZER_URL, json=event, headers=headers, timeout=10)
        if response.status_code == 200:
            return jsonify({"status": "Collected and forwarded"}), 200
        else:
            return jsonify({"error": "Failed to forward"}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    print(f"[Collector] Starting on port {COLLECTOR_PORT}...")
    app.run(host='0.0.0.0', port=COLLECTOR_PORT)
