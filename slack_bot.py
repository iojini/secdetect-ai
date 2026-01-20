import os
from dotenv import load_dotenv
from slack_bolt import App
from slack_bolt.adapter.socket_mode import SocketModeHandler
from datetime import datetime
import anthropic
from detection_engine import DetectionEngine
from enrichment_engine import EnrichmentEngine

load_dotenv()

app = App(token=os.environ.get("SLACK_BOT_TOKEN"))
claude = anthropic.Anthropic(api_key=os.environ.get("ANTHROPIC_API_KEY"))
detection_engine = DetectionEngine()
enrichment_engine = EnrichmentEngine()

@app.message("hello")
def handle_hello(message, say):
    user = message['user']
    say(f"Hey <@{user}>! 👋 SecDetect Bot is online and ready!")

@app.message("status")
def handle_status(message, say):
    rules_count = len(detection_engine.rules)
    say({
        "blocks": [
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": "🛡️ *SecDetect AI Status*"}
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": "*Status:*\n✅ Online"},
                    {"type": "mrkdwn", "text": "*Version:*\n0.1.0"},
                    {"type": "mrkdwn", "text": f"*Detection Rules:*\n{rules_count} loaded"},
                    {"type": "mrkdwn", "text": "*AI:*\n🧠 Claude Active"}
                ]
            }
        ]
    })

@app.message("rules")
def handle_rules(message, say):
    rules = detection_engine.get_rules_summary()
    if not rules:
        say("⚠️ No detection rules loaded.")
        return
    
    blocks = [{"type": "section", "text": {"type": "mrkdwn", "text": "📋 *Loaded Detection Rules*"}}]
    
    for rule in rules:
        level_emoji = {"low": "🟢", "medium": "🟡", "high": "🟠", "critical": "🔴"}.get(rule['level'], "⚪")
        blocks.append({
            "type": "section",
            "text": {"type": "mrkdwn", "text": f"{level_emoji} *{rule['title']}*\n_{rule['description']}_"}
        })
    
    say({"blocks": blocks})

@app.message("detect")
def handle_detect(message, say):
    text = message['text'].replace("detect", "").strip()
    
    if not text:
        say("⚠️ Usage: `detect <event_type> <user> <hour>`\nExample: `detect login admin 3`")
        return
    
    # Parse simple format: "login admin 3"
    parts = text.split()
    if len(parts) < 3:
        say("⚠️ Usage: `detect <event_type> <user> <hour>`\nExample: `detect login admin 3`")
        return
    
    event_type, user, hour = parts[0], parts[1], int(parts[2])
    
    log_event = {
        'event_type': event_type,
        'user': user,
        'hour': hour,
        'source_ip': '192.168.1.100',
        'timestamp': datetime.now().isoformat()
    }
    
    say(f"🔍 Running detection on: `{event_type}` event for user `{user}` at hour `{hour}`...")
    
    matches = detection_engine.evaluate_log(log_event)
    
    if matches:
        for match in matches:
            level_emoji = {"low": "🟢", "medium": "🟡", "high": "🟠", "critical": "🔴"}.get(match['level'], "⚪")
            say({
                "blocks": [
                    {"type": "section", "text": {"type": "mrkdwn", "text": f"🚨 *ALERT TRIGGERED*"}},
                    {"type": "section", "fields": [
                        {"type": "mrkdwn", "text": f"*Rule:*\n{match['rule_title']}"},
                        {"type": "mrkdwn", "text": f"*Severity:*\n{level_emoji} {match['level'].upper()}"},
                        {"type": "mrkdwn", "text": f"*User:*\n{user}"},
                        {"type": "mrkdwn", "text": f"*Time:*\n{hour}:00"}
                    ]},
                    {"type": "section", "text": {"type": "mrkdwn", "text": f"*Description:*\n{match['description']}"}},
                    {"type": "context", "elements": [
                        {"type": "mrkdwn", "text": f"_MITRE ATT&CK: {', '.join(match['tags'])}_"}
                    ]}
                ]
            })
    else:
        say("✅ No detections triggered. Event appears normal.")

@app.message("analyze")
def handle_analyze(message, say):
    text = message['text'].replace("analyze", "").strip()
    
    if not text:
        say("⚠️ Please provide something to analyze. Example: `analyze 192.168.1.100`")
        return
    
    say(f"🔍 Analyzing: `{text}`...")
    
    response = claude.messages.create(
        model="claude-sonnet-4-20250514",
        max_tokens=1024,
        messages=[{
            "role": "user",
            "content": f"""You are a security analyst assistant. Analyze the following and provide:
1. What type of indicator this is (IP, domain, hash, etc.)
2. Potential security concerns
3. Recommended actions

Keep response concise (under 200 words). Use emoji for visual clarity.

Analyze: {text}"""
        }]
    )
    
    analysis = response.content[0].text
    
    say({
        "blocks": [
            {"type": "section", "text": {"type": "mrkdwn", "text": f"🛡️ *Security Analysis*\n\n{analysis}"}},
            {"type": "context", "elements": [
                {"type": "mrkdwn", "text": f"_Analyzed by Claude AI at {datetime.now().strftime('%H:%M:%S')}_"}
            ]}
        ]
    })

@app.message("enrich")
def handle_enrich(message, say):
    text = message['text'].replace("enrich", "").strip()
    
    if not text:
        say("⚠️ Usage: `enrich <user> <ip>`\nExample: `enrich admin 192.168.1.100`")
        return
    
    parts = text.split()
    user = parts[0] if len(parts) > 0 else "unknown"
    ip = parts[1] if len(parts) > 1 else "0.0.0.0"
    
    alert_data = {
        "event_type": "security_alert",
        "user": user,
        "source_ip": ip,
        "severity": "medium"
    }
    
    say(f"🔍 Enriching alert for user `{user}` from IP `{ip}`...")
    
    enriched = enrichment_engine.enrich_alert(alert_data)
    
    user_ctx = enriched['enrichments'].get('user_context', {})
    user_hist = enriched['enrichments'].get('user_history', {})
    ip_intel = enriched['enrichments'].get('ip_intel', {})
    
    risk_emoji = {"low": "🟢", "medium": "🟡", "high": "🟠", "critical": "🔴"}.get(enriched['risk_level'], "⚪")
    
    say({
        "blocks": [
            {"type": "section", "text": {"type": "mrkdwn", "text": "📊 *Alert Enrichment Report*"}},
            {"type": "section", "fields": [
                {"type": "mrkdwn", "text": f"*Risk Score:*\n{risk_emoji} {enriched['risk_score']}/100 ({enriched['risk_level'].upper()})"},
                {"type": "mrkdwn", "text": f"*User:*\n{user}"}
            ]},
            {"type": "divider"},
            {"type": "section", "text": {"type": "mrkdwn", "text": "👤 *User Context*"}},
            {"type": "section", "fields": [
                {"type": "mrkdwn", "text": f"*Department:*\n{user_ctx.get('department', 'Unknown')}"},
                {"type": "mrkdwn", "text": f"*Role:*\n{user_ctx.get('role', 'Unknown')}"},
                {"type": "mrkdwn", "text": f"*Device:*\n{user_ctx.get('device', 'Unknown')}"},
                {"type": "mrkdwn", "text": f"*Risk Level:*\n{user_ctx.get('risk_level', 'Unknown')}"}
            ]},
            {"type": "divider"},
            {"type": "section", "text": {"type": "mrkdwn", "text": "📜 *User History*"}},
            {"type": "section", "fields": [
                {"type": "mrkdwn", "text": f"*Previous Alerts:*\n{user_hist.get('previous_alerts', 0)}"},
                {"type": "mrkdwn", "text": f"*Repeat Offender:*\n{'⚠️ Yes' if user_hist.get('is_repeat_offender') else '✅ No'}"}
            ]},
            {"type": "divider"},
            {"type": "section", "text": {"type": "mrkdwn", "text": "🌐 *IP Intelligence*"}},
            {"type": "section", "fields": [
                {"type": "mrkdwn", "text": f"*IP Address:*\n{ip}"},
                {"type": "mrkdwn", "text": f"*Reputation:*\n{ip_intel.get('reputation', 'Unknown')}"},
                {"type": "mrkdwn", "text": f"*Category:*\n{ip_intel.get('category', 'Unknown')}"},
                {"type": "mrkdwn", "text": f"*Source:*\n{ip_intel.get('source', 'N/A')}"}
            ]},
            {"type": "context", "elements": [
                {"type": "mrkdwn", "text": f"_Enriched at {enriched['enrichment_timestamp']}_"}
            ]}
        ]
    })

@app.event("app_mention")
def handle_mention(event, say):
    say("👋 I'm SecDetect Bot! Try:\n• `hello` - Greeting\n• `status` - System status\n• `rules` - List detection rules\n• `detect login <user> <hour>` - Run detection\n• `analyze <IOC>` - AI analysis")

if __name__ == "__main__":
    print("⚡ SecDetect Bot is starting...")
    print(f"📋 Loaded {len(detection_engine.rules)} detection rules")
    handler = SocketModeHandler(app, os.environ.get("SLACK_APP_TOKEN"))
    handler.start()