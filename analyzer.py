# analyzer.py
# Receives events from Collector via POST /analyze.
# Applies heuristics (e.g., count thresholds).
# Calls LM via lm_client.py.
# Fuses results (e.g., take LM if available, else heuristics).
# Forwards decision to Responder.
# Includes web interface (adapted from provided analyzer.py).
# Now runs on Ubuntu, calls LM on Windows host via config.LM_API_URL.

from flask import Flask, request, jsonify, render_template_string
import requests
from datetime import datetime
from config import AUTH_TOKEN, RESPONDER_URL, HEURISTICS, ANALYZER_PORT
from lm_client import query_lm

app = Flask(__name__)

analysis_history = []

HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>AI Security Analyzer Dashboard</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
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
            color: #f5576c;
            font-size: 2.5em;
            margin-bottom: 10px;
        }
        .ai-badge {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 8px 20px;
            border-radius: 20px;
            display: inline-block;
            font-weight: bold;
            margin-top: 10px;
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
            margin-bottom: 10px;
        }
        .stat-number.high { color: #f5576c; }
        .stat-number.medium { color: #ff9800; }
        .stat-number.low { color: #4CAF50; }
        .stat-label {
            color: #666;
            font-size: 0.9em;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        .analysis-container {
            background: white;
            padding: 30px;
            border-radius: 15px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.2);
        }
        .analysis-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
        }
        .analysis-header h2 {
            color: #333;
        }
        .refresh-btn {
            background: #f5576c;
            color: white;
            border: none;
            padding: 10px 20px;
            border-radius: 8px;
            cursor: pointer;
            font-size: 1em;
            transition: all 0.3s;
        }
        .refresh-btn:hover {
            background: #e04658;
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(245, 87, 108, 0.4);
        }
        .analysis-card {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 10px;
            margin-bottom: 15px;
            border-left: 4px solid #f5576c;
            transition: all 0.3s;
        }
        .analysis-card:hover {
            transform: translateX(5px);
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
        }
        .severity-badge {
            display: inline-block;
            color: white;
            padding: 5px 15px;
            border-radius: 20px;
            font-size: 0.85em;
            font-weight: bold;
            margin-right: 10px;
        }
        .severity-high { background: #f5576c; }
        .severity-medium { background: #ff9800; }
        .severity-low { background: #4CAF50; }
        .category-badge {
            display: inline-block;
            background: #667eea;
            color: white;
            padding: 5px 15px;
            border-radius: 20px;
            font-size: 0.85em;
            font-weight: bold;
        }
        .action-badge {
            display: inline-block;
            background: #333;
            color: white;
            padding: 5px 15px;
            border-radius: 20px;
            font-size: 0.85em;
            font-weight: bold;
            margin-left: 10px;
        }
        .event-info {
            margin-top: 15px;
        }
        .event-info h4 {
            color: #333;
            margin-bottom: 10px;
        }
        .event-detail {
            color: #555;
            margin: 5px 0;
        }
        .event-detail strong {
            color: #333;
        }
        .no-analysis {
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
            <h1>🤖 AI Security Analyzer</h1>
            <div class="ai-badge">Powered by Local LM Studio</div>
        </div>
        
        <div class="stats">
            <div class="stat-card">
                <div class="stat-number total" id="total-analysis">0</div>
                <div class="stat-label">Total Analyses</div>
            </div>
            <div class="stat-card">
                <div class="stat-number high" id="high-severity">0</div>
                <div class="stat-label">High Severity</div>
            </div>
            <div class="stat-card">
                <div class="stat-number medium" id="medium-severity">0</div>
                <div class="stat-label">Medium Severity</div>
            </div>
            <div class="stat-card">
                <div class="stat-number low" id="low-severity">0</div>
                <div class="stat-label">Low Severity</div>
            </div>
        </div>
        
        <div class="analysis-container">
            <div class="analysis-header">
                <h2>Recent Analyses</h2>
                <button class="refresh-btn" onclick="loadAnalysis()">🔄 Refresh</button>
            </div>
            <div id="analysis-list"></div>
        </div>
    </div>

    <script>
        function loadAnalysis() {
            fetch('/api/analysis')
                .then(response => response.json())
                .then(data => {
                    const analysisList = document.getElementById('analysis-list');
                    const analyses = data.analyses;
                    
                    // Update stats
                    document.getElementById('total-analysis').textContent = analyses.length;
                    const high = analyses.filter(a => a.analysis.severity === 'High').length;
                    document.getElementById('high-severity').textContent = high;
                    const medium = analyses.filter(a => a.analysis.severity === 'Medium').length;
                    document.getElementById('medium-severity').textContent = medium;
                    const low = analyses.filter(a => a.analysis.severity === 'Low').length;
                    document.getElementById('low-severity').textContent = low;
                    
                    if (analyses.length === 0) {
                        analysisList.innerHTML = '<div class="no-analysis">No analysis results yet. Waiting for events from collector...</div>';
                        return;
                    }
                    
                    // Display analyses (most recent first)
                    analysisList.innerHTML = analyses.slice().reverse().map(item => {
                        const severity = item.analysis.severity || 'Unknown';
                        const category = item.analysis.category || 'other';
                        const action = item.analysis.recommended_action || 'none';
                        
                        return `
                        <div class="analysis-card">
                            <div>
                                <span class="severity-badge severity-${severity.toLowerCase()}">${severity} Severity</span>
                                <span class="category-badge">${category.replace('_', ' ').toUpperCase()}</span>
                                <span class="action-badge">Action: ${action.replace('_', ' ').toUpperCase()}</span>
                            </div>
                            <div class="event-info">
                                <h4>📋 Event Details</h4>
                                <div class="event-detail"><strong>Kind:</strong> ${item.event.kind || 'N/A'}</div>
                                <div class="event-detail"><strong>Source IP:</strong> ${item.event.src_ip || 'N/A'}</div>
                                <div class="event-detail"><strong>Timestamp:</strong> ${item.event.ts || 'N/A'}</div>
                                ${item.timestamp ? `<div class="event-detail"><strong>Analyzed:</strong> ${item.timestamp}</div>` : ''}
                            </div>
                        </div>
                        `;
                    }).join('');
                })
                .catch(error => {
                    console.error('Error loading analysis:', error);
                });
        }

        // Load analysis on page load
        loadAnalysis();
        
        // Auto-refresh every 5 seconds
        setInterval(loadAnalysis, 5000);
    </script>
</body>
</html>
"""

def apply_heuristics(event):
    """Simple heuristic-based analysis (fallback)."""
    kind = event.get("kind")
    if kind not in HEURISTICS:
        return {"severity": "Low", "category": "other", "recommended_action": "ignore"}
    
    # Placeholder: In real, track counts per IP over time (use dict or Redis)
    # For demo, assume single event triggers low, but could add state.
    return {
        "severity": "Medium",  # Example
        "category": HEURISTICS[kind]["category"],
        "recommended_action": "create_ticket" if kind == "web_fuzz" else "block_ip"
    }

@app.route('/')
def dashboard():
    return render_template_string(HTML_TEMPLATE)

@app.route('/api/analysis', methods=['GET'])
def get_analysis():
    return jsonify({"analyses": analysis_history})

@app.route("/analyze", methods=["POST"])
def analyze_event():
    if request.headers.get("Authorization") != f"Bearer {AUTH_TOKEN}":
        return jsonify({"error": "Unauthorized"}), 401

    event = request.get_json()
    if not event:
        return jsonify({"error": "Invalid event"}), 400

    print(f"[Analyzer] Analyzing event: {event}")

    # Get LM analysis
    lm_analysis = query_lm(event)
    
    # Fallback to heuristics
    if not lm_analysis:
        lm_analysis = apply_heuristics(event)
        print(f"[Analyzer] Using heuristics: {lm_analysis}")
    else:
        print(f"[Analyzer] LM result: {lm_analysis}")

    # Create decision (fuse if needed; here, prefer LM)
    decision = {
        "event_id": event["id"],
        "severity": lm_analysis["severity"],
        "category": lm_analysis["category"],
        "recommended_action": lm_analysis["recommended_action"],
        "target": event.get("src_ip")  # For block_ip
    }

    # Store
    analysis_history.append({
        "event": event,
        "analysis": decision,
        "timestamp": datetime.now().isoformat()
    })

    # Forward to Responder
    payload = {"event": event, "analysis": decision}
    headers = {"Authorization": f"Bearer {AUTH_TOKEN}", "Content-Type": "application/json"}
    try:
        response = requests.post(RESPONDER_URL, json=payload, headers=headers, timeout=10)
        if response.status_code == 200:
            return jsonify({"status": "Analyzed and forwarded"}), 200
        else:
            return jsonify({"error": "Responder error"}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    print(f"[Analyzer] Starting on port {ANALYZER_PORT}...")
    app.run(host='0.0.0.0', port=ANALYZER_PORT)
