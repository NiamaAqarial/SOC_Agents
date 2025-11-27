# lm_client.py
# Enhanced version: LM now provides actual executable commands
# Wrapper for HTTP requests to LM Studio API.
# Ensures strict JSON output via system prompt with command generation.

import requests
import json
from config import LM_API_URL, LM_MODEL

def query_lm(event: dict) -> dict | None:
    """
    Sends the event to LM Studio and forces a strict JSON response.
    Now includes executable command generation for blocking.
    """
    prompt = f"""You are a JSON-only security analyst AI for a Security Operations Center (SOC).
Analyze the security event and respond with ONLY valid JSON, no explanations.

Event to analyze:
{json.dumps(event, indent=2)}

Your analysis must include:
1. Severity assessment (Low/Medium/High)
2. Attack category classification
3. Recommended action
4. If blocking is needed, provide the exact command to execute
5. Justification for your decision (for explainability)

Return EXACTLY this JSON structure:
{{
  "severity": "Low|Medium|High",
  "category": "brute_force|port_scan|web_fuzz|other",
  "recommended_action": "block_ip|create_ticket|ignore",
  "target_ip": "<IP address from event>",
  "block_command": "sudo ufw insert 1 deny from <IP>",
  "justification": "Brief explanation of why this action is recommended",
  "confidence": 0.0-1.0
}}

Rules:
- If recommended_action is "block_ip", block_command must contain valid ufw or iptables command
- For ssh_failed events with severity High, recommend block_ip
- For port_scan events, analyze frequency before blocking
- For web_fuzz, consider creating ticket first unless severity is High
- Justify your decision for explainability (required by Atelier 2)
"""

    payload = {
        "model": LM_MODEL,
        "messages": [
            {"role": "system", "content": "You are a security analyst AI. You MUST respond ONLY with valid JSON. No markdown, no explanations, just pure JSON."},
            {"role": "user", "content": prompt}
        ],
        "temperature": 0.1,
        "max_tokens": 200
    }

    headers = {"Content-Type": "application/json"}

    try:
        response = requests.post(LM_API_URL, json=payload, headers=headers, timeout=30)
        response.raise_for_status()
        content = response.json()["choices"][0]["message"]["content"].strip()
        
        # Remove markdown code blocks if present
        if content.startswith("```"):
            content = content.split("```")[1]
            if content.startswith("json"):
                content = content[4:]
            content = content.strip()
        
        parsed = json.loads(content)
        print(f"[LM Client] Successfully parsed LM response: {parsed}")
        return parsed
    except requests.RequestException as e:
        print(f"[LM Client] HTTP error: {e}")
        return None
    except (KeyError, json.JSONDecodeError) as e:
        print(f"[LM Client] Bad response / JSON parse error: {e}")
        print(f"[LM Client] Raw content: {content if 'content' in locals() else 'N/A'}")
        return None
