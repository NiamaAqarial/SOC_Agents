# responder.py - FIXED VERSION
# Enhanced version: Executes LM-provided commands, sends emails, better logging
# Receives event + analysis from Analyzer via POST /respond.
# Executes action based on LM-recommended commands.
# Writes detailed logs to ALERT_LOG_PATH.
# Sends email notifications for critical events.
# MUST RUN AS ROOT: sudo python3 responder.py

from flask import Flask, request, jsonify, render_template_string
import subprocess
import json
from datetime import datetime
import requests
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import os
from config import (AUTH_TOKEN, DRY_RUN, BLOCK_METHOD, ALERT_LOG_PATH, 
                    WEBHOOK_URL, WHITELIST_IPS, RESPONDER_PORT,
                    EMAIL_ENABLED, SMTP_SERVER, SMTP_PORT, SMTP_USER, 
                    SMTP_PASSWORD, ALERT_EMAIL, EMAIL_ALERT_SEVERITIES)

app = Flask(__name__)
response_history = []

# HTML_TEMPLATE remains the same (your existing HTML code)
HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Security Responder Dashboard</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #43e97b 0%, #38f9d7 100%);
            min-height: 100vh;
            padding: 20px;
        }
        .container { max-width: 1400px; margin: 0 auto; }
        .header {
            background: white;
            padding: 30px;
            border-radius: 15px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.2);
            margin-bottom: 30px;
            text-align: center;
        }
        h1 { color: #43e97b; font-size: 2.5em; margin-bottom: 10px; }
        .mode-indicator {
            display: inline-block;
            padding: 8px 20px;
            border-radius: 20px;
            font-weight: bold;
            margin-top: 10px;
        }
        .mode-dry { background: #ff9800; color: white; }
        .mode-live { background: #f5576c; color: white; }
        .email-indicator {
            display: inline-block;
            padding: 6px 15px;
            border-radius: 15px;
            font-size: 0.85em;
            font-weight: bold;
            margin-left: 10px;
        }
        .email-enabled { background: #4CAF50; color: white; }
        .email-disabled { background: #999; color: white; }
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
        .stat-number.blocked { color: #f5576c; }
        .stat-number.ticket { color: #ff9800; }
        .stat-number.ignored { color: #999; }
        .stat-number.total { color: #43e97b; }
        .stat-number.emailed { color: #2196F3; }
        .stat-label {
            color: #666;
            font-size: 0.9em;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        .response-container {
            background: white;
            padding: 30px;
            border-radius: 15px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.2);
        }
        .response-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
        }
        .response-header h2 { color: #333; }
        .refresh-btn {
            background: #43e97b;
            color: white;
            border: none;
            padding: 10px 20px;
            border-radius: 8px;
            cursor: pointer;
            font-size: 1em;
            transition: all 0.3s;
        }
        .refresh-btn:hover {
            background: #37c968;
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(67, 233, 123, 0.4);
        }
        .response-card {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 10px;
            margin-bottom: 15px;
            transition: all 0.3s;
        }
        .response-card.blocked { border-left: 4px solid #f5576c; }
        .response-card.ticket { border-left: 4px solid #ff9800; }
        .response-card.ignored { border-left: 4px solid #999; }
        .response-card:hover {
            transform: translateX(5px);
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
        }
        .action-badge {
            display: inline-block;
            color: white;
            padding: 8px 20px;
            border-radius: 20px;
            font-size: 0.9em;
            font-weight: bold;
            margin-bottom: 15px;
        }
        .action-blocked { background: #f5576c; }
        .action-ticket { background: #ff9800; }
        .action-ignored { background: #999; }
        .email-badge {
            display: inline-block;
            background: #2196F3;
            color: white;
            padding: 5px 12px;
            border-radius: 15px;
            font-size: 0.8em;
            margin-left: 10px;
        }
        .response-details {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
            margin-top: 15px;
        }
        .detail-section {
            background: white;
            padding: 15px;
            border-radius: 8px;
        }
        .detail-section h4 {
            color: #43e97b;
            margin-bottom: 10px;
            font-size: 0.95em;
        }
        .detail-item {
            color: #555;
            margin: 5px 0;
            font-size: 0.9em;
        }
        .detail-item strong { color: #333; }
        .command-box {
            background: #1e1e1e;
            color: #00ff00;
            padding: 10px;
            border-radius: 5px;
            font-family: 'Courier New', monospace;
            font-size: 0.85em;
            margin-top: 10px;
            overflow-x: auto;
        }
        .justification-box {
            background: #fff3cd;
            border-left: 3px solid #ff9800;
            padding: 10px;
            margin-top: 10px;
            font-style: italic;
            color: #856404;
        }
        .severity-indicator {
            display: inline-block;
            width: 12px;
            height: 12px;
            border-radius: 50%;
            margin-right: 8px;
        }
        .severity-high { background: #f5576c; }
        .severity-medium { background: #ff9800; }
        .severity-low { background: #4CAF50; }
        .no-responses {
            text-align: center;
            color: #999;
            padding: 40px;
            font-size: 1.1em;
        }
        .root-warning {
            background: #f5576c;
            color: white;
            padding: 15px;
            border-radius: 10px;
            margin-bottom: 20px;
            text-align: center;
            font-weight: bold;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🚨 Security Response System</h1>
            <div>
                <div class="mode-indicator" id="mode-indicator">Loading...</div>
                <div class="email-indicator" id="email-indicator">Loading...</div>
            </div>
        </div>
        
        <div class="stats">
            <div class="stat-card">
                <div class="stat-number total" id="total-responses">0</div>
                <div class="stat-label">Total Responses</div>
            </div>
            <div class="stat-card">
                <div class="stat-number blocked" id="blocked">0</div>
                <div class="stat-label">IPs Blocked</div>
            </div>
            <div class="stat-card">
                <div class="stat-number ticket" id="tickets">0</div>
                <div class="stat-label">Tickets Created</div>
            </div>
            <div class="stat-card">
                <div class="stat-number ignored" id="ignored">0</div>
                <div class="stat-label">Ignored</div>
            </div>
            <div class="stat-card">
                <div class="stat-number emailed" id="emailed">0</div>
                <div class="stat-label">Emails Sent</div>
            </div>
        </div>
        
        <div class="response-container">
            <div class="response-header">
                <h2>Recent Responses</h2>
                <button class="refresh-btn" onclick="loadResponses()">🔄 Refresh</button>
            </div>
            <div id="responses-list"></div>
        </div>
    </div>

    <script>
        function loadResponses() {
            fetch('/api/responses')
                .then(response => response.json())
                .then(data => {
                    const responsesList = document.getElementById('responses-list');
                    const responses = data.responses;
                    
                    // Update mode indicator
                    const modeIndicator = document.getElementById('mode-indicator');
                    if (data.dry_run) {
                        modeIndicator.textContent = '🧪 DRY RUN MODE - No actual blocking';
                        modeIndicator.className = 'mode-indicator mode-dry';
                    } else {
                        modeIndicator.textContent = '⚠️ LIVE MODE - Active blocking';
                        modeIndicator.className = 'mode-indicator mode-live';
                    }
                    
                    // Update email indicator
                    const emailIndicator = document.getElementById('email-indicator');
                    if (data.email_enabled) {
                        emailIndicator.textContent = '📧 Email Alerts ON';
                        emailIndicator.className = 'email-indicator email-enabled';
                    } else {
                        emailIndicator.textContent = '📧 Email Alerts OFF';
                        emailIndicator.className = 'email-indicator email-disabled';
                    }
                    
                    // Update stats
                    document.getElementById('total-responses').textContent = responses.length;
                    const blocked = responses.filter(r => r.action === 'block_ip').length;
                    document.getElementById('blocked').textContent = blocked;
                    const tickets = responses.filter(r => r.action === 'create_ticket').length;
                    document.getElementById('tickets').textContent = tickets;
                    const ignored = responses.filter(r => r.action === 'ignore').length;
                    document.getElementById('ignored').textContent = ignored;
                    const emailed = responses.filter(r => r.email_sent).length;
                    document.getElementById('emailed').textContent = emailed;
                    
                    if (responses.length === 0) {
                        responsesList.innerHTML = '<div class="no-responses">No responses yet. Waiting for analyses...</div>';
                        return;
                    }
                    
                    // Display responses (most recent first)
                    responsesList.innerHTML = responses.slice().reverse().map(item => {
                        const action = item.action || 'none';
                        let actionClass = 'ignored';
                        let actionLabel = 'Ignored';
                        let actionIcon = '❌';
                        if (action === 'block_ip') {
                            actionClass = 'blocked';
                            actionLabel = 'IP Blocked';
                            actionIcon = '🚫';
                        } else if (action === 'create_ticket') {
                            actionClass = 'ticket';
                            actionLabel = 'Ticket Created';
                            actionIcon = '🎫';
                        }
                        
                        const severity = item.analysis.severity || 'Unknown';
                        const category = item.analysis.category || 'other';
                        const justification = item.analysis.justification || 'No justification provided';
                        const command = item.executed_command || 'N/A';
                        const emailSent = item.email_sent ? '<span class="email-badge">📧 Email Sent</span>' : '';
                        
                        return `
                        <div class="response-card ${actionClass}">
                            <div class="action-badge action-${actionClass}">
                                ${actionIcon} ${actionLabel}
                            </div>
                            ${emailSent}
                            <div class="response-details">
                                <div class="detail-section">
                                    <h4>📊 THREAT ANALYSIS</h4>
                                    <div class="detail-item">
                                        <span class="severity-indicator severity-${severity.toLowerCase()}"></span>
                                        <strong>Severity:</strong> ${severity}
                                    </div>
                                    <div class="detail-item"><strong>Category:</strong> ${category.replace('_', ' ').toUpperCase()}</div>
                                    <div class="detail-item"><strong>Action:</strong> ${action.replace('_', ' ').toUpperCase()}</div>
                                    <div class="detail-item"><strong>Confidence:</strong> ${(item.analysis.confidence * 100).toFixed(0)}%</div>
                                    ${item.analysis.justification ? `
                                    <div class="justification-box">
                                        <strong>🤖 AI Justification:</strong><br>
                                        ${justification}
                                    </div>
                                    ` : ''}
                                </div>
                                <div class="detail-section">
                                    <h4>🎯 EVENT INFORMATION</h4>
                                    <div class="detail-item"><strong>Kind:</strong> ${item.event.kind || 'N/A'}</div>
                                    <div class="detail-item"><strong>Source IP:</strong> ${item.event.src_ip || 'N/A'}</div>
                                    <div class="detail-item"><strong>Event Time:</strong> ${item.event.ts || 'N/A'}</div>
                                    ${item.timestamp ? `<div class="detail-item"><strong>Response Time:</strong> ${item.timestamp}</div>` : ''}
                                    ${command !== 'N/A' ? `
                                    <div class="command-box">
                                        <strong>💻 Executed Command:</strong><br>
                                        ${command}
                                    </div>
                                    ` : ''}
                                </div>
                            </div>
                        </div>
                        `;
                    }).join('');
                })
                .catch(error => {
                    console.error('Error loading responses:', error);
                });
        }

        // Load responses on page load
        loadResponses();
        
        // Auto-refresh every 5 seconds
        setInterval(loadResponses, 5000);
    </script>
</body>
</html>
"""

def check_root_privileges():
    """Check if script is running with root privileges."""
    if os.geteuid() != 0:
        print("\n" + "="*80)
        print("❌ ERROR: Responder must run as root to execute firewall commands!")
        print("="*80)
        print("\nPlease run with sudo:")
        print(f"  sudo python3 {__file__}")
        print("\nOr if using virtual environment:")
        print(f"  sudo /path/to/venv/bin/python3 {__file__}")
        print("="*80 + "\n")
        return False
    return True

def log_alert(event, analysis, action_result):
    """Write detailed alert to log file with timestamp and full context."""
    timestamp = datetime.now().isoformat()
    log_entry = {
        "timestamp": timestamp,
        "event_id": event.get("id"),
        "event_kind": event.get("kind"),
        "source_ip": event.get("src_ip"),
        "severity": analysis.get("severity"),
        "category": analysis.get("category"),
        "recommended_action": analysis.get("recommended_action"),
        "justification": analysis.get("justification", "N/A"),
        "confidence": analysis.get("confidence", 0),
        "action_taken": action_result.get("action_taken"),
        "executed_command": action_result.get("command_executed"),
        "email_sent": action_result.get("email_sent", False),
        "dry_run": DRY_RUN,
        "raw_event": event.get("raw", "")
    }
    
    try:
        with open(ALERT_LOG_PATH, "a") as f:
            f.write(json.dumps(log_entry, indent=2))
            f.write("\n" + "="*80 + "\n")
        print(f"[Responder] Alert logged to {ALERT_LOG_PATH}")
    except Exception as e:
        print(f"[Responder] Failed to write log: {e}")

def send_email_alert(event, analysis, action_result):
    """Send email notification for critical events."""
    if not EMAIL_ENABLED:
        print(f"[Responder] Email disabled, skipping notification")
        return False
    
    severity = analysis.get("severity", "Unknown")
    if severity not in EMAIL_ALERT_SEVERITIES:
        print(f"[Responder] Severity '{severity}' not in alert list, skipping email")
        return False
    
    try:
        msg = MIMEMultipart('alternative')
        msg['Subject'] = f"[SOC Alert] {severity} - {analysis.get('category')} from {event.get('src_ip')}"
        msg['From'] = SMTP_USER
        msg['To'] = ALERT_EMAIL
        
        body = f"""
Security Event Alert - {severity} Severity
============================================

Event ID: {event.get('id')}
Timestamp: {event.get('ts')}
Response Time: {datetime.now().isoformat()}

THREAT DETAILS:
---------------
- Severity: {severity}
- Category: {analysis.get('category')}
- Source IP: {event.get('src_ip')}
- Event Type: {event.get('kind')}

AI ANALYSIS:
------------
- Recommended Action: {analysis.get('recommended_action')}
- Confidence: {analysis.get('confidence', 0)*100:.1f}%
- Justification: {analysis.get('justification', 'N/A')}

ACTION TAKEN:
-------------
- Action: {action_result.get('action_taken')}
- Command: {action_result.get('command_executed', 'N/A')}
- Success: {action_result.get('success', False)}
- Mode: {'DRY RUN (simulation only)' if DRY_RUN else 'LIVE (actual blocking)'}

RAW EVENT DATA:
---------------
{event.get('raw', 'N/A')}

---
This is an automated alert from your Mini-SOC Security Response System.
Powered by LM Studio + Python
        """
        
        msg.attach(MIMEText(body, 'plain'))
        
        print(f"[Responder] Sending email alert for {severity} severity event...")
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT, timeout=10) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASSWORD)
            server.send_message(msg)
        
        print(f"[Responder] ✅ Email alert sent to {ALERT_EMAIL}")
        return True
        
    except smtplib.SMTPAuthenticationError as e:
        print(f"[Responder] ❌ Email authentication failed: {e}")
        print(f"[Responder] Check SMTP_USER and SMTP_PASSWORD in config.py")
        print(f"[Responder] For Gmail, use an App Password (16 chars, no spaces)")
        return False
    except smtplib.SMTPException as e:
        print(f"[Responder] ❌ SMTP error: {e}")
        return False
    except Exception as e:
        print(f"[Responder] ❌ Failed to send email: {e}")
        return False

def validate_and_sanitize_command(command, ip):
    """
    Validate and sanitize the blocking command for security.
    Returns (is_valid, sanitized_command, error_message)
    """
    # Check IP is in whitelist
    if ip in WHITELIST_IPS:
        return (False, None, f"IP {ip} is whitelisted")
    
    # Validate IP format (basic check)
    import re
    if not re.match(r'^(\d{1,3}\.){3}\d{1,3}$', ip):
        return (False, None, f"Invalid IP format: {ip}")
    
    # Check command starts with allowed prefixes (without sudo)
    allowed_commands = ["ufw", "iptables"]
    
    # Remove 'sudo' prefix if present
    cmd_parts = command.strip().split()
    if cmd_parts[0] == "sudo":
        cmd_parts = cmd_parts[1:]
    
    if not cmd_parts or cmd_parts[0] not in allowed_commands:
        return (False, None, f"Invalid command prefix. Must start with: {allowed_commands}")
    
    # Reconstruct command (we're running as root, so no need for sudo)
    sanitized_cmd = " ".join(cmd_parts)
    
    # Ensure IP is in the command
    if ip not in sanitized_cmd:
        return (False, None, f"IP {ip} not found in command")
    
    # Additional security: block dangerous patterns
    dangerous_patterns = [';', '&&', '||', '`', '$', '>', '<', '|', '\n', '\r']
    for pattern in dangerous_patterns:
        if pattern in sanitized_cmd:
            return (False, None, f"Command contains dangerous character: {pattern}")
    
    return (True, sanitized_cmd, None)

def execute_block_command(command, ip):
    """Execute the LM-provided blocking command with strict validation."""
    # Validate command
    is_valid, sanitized_cmd, error_msg = validate_and_sanitize_command(command, ip)
    
    if not is_valid:
        print(f"[Responder] ❌ Command validation failed: {error_msg}")
        return {"success": False, "reason": error_msg}
    
    if DRY_RUN:
        print(f"[Responder] 🧪 DRY_RUN: Would execute: {sanitized_cmd}")
        return {"success": True, "command": sanitized_cmd, "simulated": True}
    
    try:
        print(f"[Responder] 🔒 Executing: {sanitized_cmd}")
        
        # Execute the command (we're running as root, so no sudo needed)
        result = subprocess.run(
            sanitized_cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=10
        )
        
        if result.returncode == 0:
            print(f"[Responder]  Successfully executed: {sanitized_cmd}")
            
            # Reload UFW to apply changes
            reload_cmd = "ufw reload"
            print(f"[Responder]  Executing: {reload_cmd}")
            result_reload = subprocess.run(
                reload_cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result_reload.returncode == 0:
                print(f"[Responder]  Successfully reloaded UFW")
                return {
                    "success": True,
                    "command": sanitized_cmd,
                    "output": result.stdout.strip() if result.stdout else "Command executed successfully",
                    "reload_output": result_reload.stdout.strip() if result_reload.stdout else "UFW reloaded successfully"
                }
            else:
                reload_error = result_reload.stderr.strip() if result_reload.stderr else "Unknown error"
                print(f"[Responder]  UFW reload failed: {reload_error}")
                return {
                    "success": False,
                    "reason": f"Blocking succeeded but reload failed: {reload_error}",
                    "command": sanitized_cmd
                }
        else:
            error_output = result.stderr.strip() if result.stderr else "Unknown error"
            print(f"[Responder]  Command failed: {error_output}")
            return {
                "success": False,
                "reason": error_output,
                "command": sanitized_cmd
            }
    
    
    except subprocess.TimeoutExpired:
        print(f"[Responder] ⏱️ Command timeout: {sanitized_cmd}")
        return {"success": False, "reason": "Command timeout (10s limit)"}
    except Exception as e:
        print(f"[Responder] ❌ Execution error: {e}")
        return {"success": False, "reason": str(e)}

@app.route('/')
def dashboard():
    return render_template_string(HTML_TEMPLATE)

@app.route('/api/responses', methods=['GET'])
def get_responses():
    return jsonify({
        "responses": response_history, 
        "dry_run": DRY_RUN,
        "email_enabled": EMAIL_ENABLED
    })

@app.route('/respond', methods=['POST'])
def respond_to_event():
    if request.headers.get('Authorization') != f"Bearer {AUTH_TOKEN}":
        return jsonify({"error": "Unauthorized"}), 401
    
    data = request.json
    if not data or 'event' not in data or 'analysis' not in data:
        return jsonify({"error": "Invalid data"}), 400
    
    event = data['event']
    analysis = data['analysis']
    action = analysis.get('recommended_action')
    
    print(f"[Responder] 📥 Responding to event {event.get('id')} with action: {action}")
    
    action_result = {
        "action_taken": action,
        "timestamp": datetime.now().isoformat(),
        "command_executed": None,
        "success": False,
        "email_sent": False
    }
    
    # Execute action based on LM recommendation
    if action == "block_ip":
        ip = analysis.get('target_ip') or event.get('src_ip')
        command = analysis.get('block_command')
        
        if command and ip:
            # Use LM-provided command
            result = execute_block_command(command, ip)
            action_result["command_executed"] = command
            action_result["success"] = result.get("success", False)
            action_result["details"] = result
        else:
            # Fallback to default command
            if BLOCK_METHOD == "ufw":
                command = f"ufw insert 1 deny from {ip}"
            else:
                command = f"iptables -I INPUT 1 -s {ip} -j DROP"
            
            result = execute_block_command(command, ip)
            action_result["command_executed"] = command
            action_result["success"] = result.get("success", False)
            action_result["details"] = result
    
    elif action == "create_ticket":
        print(f"[Responder] 🎫 Creating ticket for event {event.get('id')}")
        ticket_info = {
            "event_id": event.get("id"),
            "severity": analysis.get("severity"),
            "category": analysis.get("category"),
            "source_ip": event.get("src_ip"),
            "justification": analysis.get("justification")
        }
        print(f"[Responder] Ticket details: {json.dumps(ticket_info, indent=2)}")
        action_result["success"] = True
        action_result["ticket"] = ticket_info
    
    else:  # ignore
        print(f"[Responder] ❌ Ignoring event {event.get('id')}")
        action_result["success"] = True
    
    # Send email alert if enabled and severity matches
    email_sent = send_email_alert(event, analysis, action_result)
    action_result["email_sent"] = email_sent
    
    # Create response record
    response_record = {
        "event": event,
        "analysis": analysis,
        "action": action,
        "executed_command": action_result.get("command_executed"),
        "timestamp": action_result["timestamp"],
        "success": action_result["success"],
        "email_sent": email_sent
    }
    
    response_history.append(response_record)
    
    # Keep only last 100 responses in memory
    if len(response_history) > 100:
        response_history.pop(0)
    
    # Log to file
    log_alert(event, analysis, action_result)
    
    # Optional webhook
    if WEBHOOK_URL:
        try:
            requests.post(WEBHOOK_URL, json=response_record, timeout=5)
        except:
            pass
    
    return jsonify({
        "status": "action_taken",
        "action": action,
        "success": action_result["success"],
        "email_sent": email_sent
    }), 200

if __name__ == "__main__":
    print("\n" + "="*80)
    print("🚨 SECURITY RESPONSE SYSTEM STARTING")
    print("="*80)
    
    # Check root privileges
    if not check_root_privileges():
        exit(1)
    
    print(f"✅ Running as root (UID: {os.geteuid()})")
    print(f"📍 Port: {RESPONDER_PORT}")
    print(f"🧪 DRY_RUN: {DRY_RUN}")
    print(f"🔒 BLOCK_METHOD: {BLOCK_METHOD}")
    print(f"📧 EMAIL_ENABLED: {EMAIL_ENABLED}")
    if EMAIL_ENABLED:
        print(f"   📬 From: {SMTP_USER}")
        print(f"   📨 To: {ALERT_EMAIL}")
        print(f"   📊 Alert severities: {EMAIL_ALERT_SEVERITIES}")
    print(f"📝 Alert log: {ALERT_LOG_PATH}")
    print(f"🛡️ Whitelisted IPs: {len(WHITELIST_IPS)}")
    print("="*80 + "\n")
    
    app.run(host='0.0.0.0', port=RESPONDER_PORT)
