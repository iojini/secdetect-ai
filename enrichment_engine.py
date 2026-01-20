import hashlib
from datetime import datetime, timedelta
import random

class EnrichmentEngine:
    def __init__(self):
        # Simulated threat intelligence database
        self.threat_intel = {
            "malicious_ips": {
                "45.33.32.156": {"reputation": "malicious", "category": "C2 Server", "source": "AlienVault"},
                "185.220.101.1": {"reputation": "malicious", "category": "Tor Exit Node", "source": "AbuseIPDB"},
                "91.121.87.18": {"reputation": "suspicious", "category": "Scanner", "source": "GreyNoise"},
            },
            "malicious_domains": {
                "evil-malware.ru": {"reputation": "malicious", "category": "Malware Distribution", "source": "VirusTotal"},
                "phishing-site.xyz": {"reputation": "malicious", "category": "Phishing", "source": "PhishTank"},
                "suspicious-domain.cn": {"reputation": "suspicious", "category": "Newly Registered", "source": "DomainTools"},
            }
        }
        
        # Simulated asset inventory
        self.asset_inventory = {
            "admin": {"department": "IT", "role": "System Administrator", "risk_level": "high", "device": "WORKSTATION-001"},
            "john.doe": {"department": "Finance", "role": "Analyst", "risk_level": "medium", "device": "LAPTOP-042"},
            "jane.smith": {"department": "Engineering", "role": "Developer", "risk_level": "medium", "device": "MACBOOK-103"},
            "service_account": {"department": "IT", "role": "Service Account", "risk_level": "critical", "device": "SERVER-DB01"},
        }
        
        # Simulated historical alerts
        self.alert_history = {
            "admin": [
                {"date": "2024-01-15", "alert": "Failed login attempts", "severity": "low"},
                {"date": "2024-01-18", "alert": "Privilege escalation attempt", "severity": "high"},
            ],
            "john.doe": [
                {"date": "2024-01-10", "alert": "Unusual data download", "severity": "medium"},
            ]
        }
    
    def enrich_alert(self, alert_data):
        """Main enrichment function - adds all available context to an alert"""
        enriched = {
            "original_alert": alert_data,
            "enrichments": {},
            "risk_score": 0,
            "enrichment_timestamp": datetime.now().isoformat()
        }
        
        # Enrich user information
        if 'user' in alert_data:
            enriched['enrichments']['user_context'] = self._get_user_context(alert_data['user'])
            enriched['enrichments']['user_history'] = self._get_user_history(alert_data['user'])
        
        # Enrich IP information
        if 'source_ip' in alert_data:
            enriched['enrichments']['ip_intel'] = self._get_ip_intel(alert_data['source_ip'])
        
        # Enrich domain information
        if 'domain' in alert_data:
            enriched['enrichments']['domain_intel'] = self._get_domain_intel(alert_data['domain'])
        
        # Calculate risk score
        enriched['risk_score'] = self._calculate_risk_score(enriched)
        enriched['risk_level'] = self._get_risk_level(enriched['risk_score'])
        
        return enriched
    
    def _get_user_context(self, username):
        """Get asset/user context from inventory"""
        if username in self.asset_inventory:
            return {
                "found": True,
                **self.asset_inventory[username]
            }
        return {
            "found": False,
            "department": "Unknown",
            "role": "Unknown",
            "risk_level": "unknown",
            "device": "Unknown"
        }
    
    def _get_user_history(self, username):
        """Get historical alerts for a user"""
        if username in self.alert_history:
            history = self.alert_history[username]
            return {
                "previous_alerts": len(history),
                "alerts": history[-3:],  # Last 3 alerts
                "is_repeat_offender": len(history) > 1
            }
        return {
            "previous_alerts": 0,
            "alerts": [],
            "is_repeat_offender": False
        }
    
    def _get_ip_intel(self, ip_address):
        """Look up IP in threat intelligence"""
        if ip_address in self.threat_intel["malicious_ips"]:
            intel = self.threat_intel["malicious_ips"][ip_address]
            return {
                "found": True,
                "reputation": intel["reputation"],
                "category": intel["category"],
                "source": intel["source"]
            }
        
        # Check if private IP
        if ip_address.startswith(("10.", "192.168.", "172.16.", "172.17.", "172.18.")):
            return {
                "found": False,
                "reputation": "internal",
                "category": "Private IP",
                "source": "RFC1918"
            }
        
        return {
            "found": False,
            "reputation": "unknown",
            "category": "Not in threat feeds",
            "source": "N/A"
        }
    
    def _get_domain_intel(self, domain):
        """Look up domain in threat intelligence"""
        if domain in self.threat_intel["malicious_domains"]:
            intel = self.threat_intel["malicious_domains"][domain]
            return {
                "found": True,
                "reputation": intel["reputation"],
                "category": intel["category"],
                "source": intel["source"]
            }
        return {
            "found": False,
            "reputation": "unknown",
            "category": "Not in threat feeds",
            "source": "N/A"
        }
    
    def _calculate_risk_score(self, enriched):
        """Calculate a risk score from 0-100 based on enrichments"""
        score = 0
        
        # Base score from original alert severity
        original = enriched.get('original_alert', {})
        severity = original.get('severity', 'medium')
        severity_scores = {"low": 10, "medium": 30, "high": 50, "critical": 70}
        score += severity_scores.get(severity, 30)
        
        enrichments = enriched.get('enrichments', {})
        
        # User context scoring
        user_ctx = enrichments.get('user_context', {})
        if user_ctx.get('risk_level') == 'critical':
            score += 20
        elif user_ctx.get('risk_level') == 'high':
            score += 15
        
        # User history scoring
        user_hist = enrichments.get('user_history', {})
        if user_hist.get('is_repeat_offender'):
            score += 15
        score += min(user_hist.get('previous_alerts', 0) * 5, 15)
        
        # IP intel scoring
        ip_intel = enrichments.get('ip_intel', {})
        if ip_intel.get('reputation') == 'malicious':
            score += 25
        elif ip_intel.get('reputation') == 'suspicious':
            score += 15
        
        # Domain intel scoring
        domain_intel = enrichments.get('domain_intel', {})
        if domain_intel.get('reputation') == 'malicious':
            score += 25
        elif domain_intel.get('reputation') == 'suspicious':
            score += 15
        
        return min(score, 100)
    
    def _get_risk_level(self, score):
        """Convert numeric score to risk level"""
        if score >= 80:
            return "critical"
        elif score >= 60:
            return "high"
        elif score >= 40:
            return "medium"
        else:
            return "low"


# Test the engine if run directly
if __name__ == "__main__":
    engine = EnrichmentEngine()
    
    print("🧪 Testing Enrichment Engine...\n")
    
    # Test alert
    test_alert = {
        "event_type": "login",
        "user": "admin",
        "source_ip": "192.168.1.100",
        "hour": 3,
        "severity": "medium"
    }
    
    print(f"Original Alert: {test_alert}\n")
    
    enriched = engine.enrich_alert(test_alert)
    
    print("📊 Enrichment Results:")
    print(f"  Risk Score: {enriched['risk_score']}/100")
    print(f"  Risk Level: {enriched['risk_level'].upper()}")
    print(f"\n👤 User Context:")
    user_ctx = enriched['enrichments'].get('user_context', {})
    print(f"  Department: {user_ctx.get('department')}")
    print(f"  Role: {user_ctx.get('role')}")
    print(f"  Device: {user_ctx.get('device')}")
    print(f"\n📜 User History:")
    user_hist = enriched['enrichments'].get('user_history', {})
    print(f"  Previous Alerts: {user_hist.get('previous_alerts')}")
    print(f"  Repeat Offender: {user_hist.get('is_repeat_offender')}")
    print(f"\n🌐 IP Intelligence:")
    ip_intel = enriched['enrichments'].get('ip_intel', {})
    print(f"  Reputation: {ip_intel.get('reputation')}")
    print(f"  Category: {ip_intel.get('category')}")