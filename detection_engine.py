import yaml
import os
from datetime import datetime
from pathlib import Path

class DetectionEngine:
    def __init__(self, rules_path="detections/rules"):
        self.rules_path = rules_path
        self.rules = []
        self.load_rules()
    
    def load_rules(self):
        """Load all YAML detection rules from the rules directory"""
        self.rules = []
        rules_dir = Path(self.rules_path)
        
        if not rules_dir.exists():
            print(f"⚠️ Rules directory not found: {self.rules_path}")
            return
        
        for rule_file in rules_dir.glob("*.yml"):
            try:
                with open(rule_file, 'r') as f:
                    rule = yaml.safe_load(f)
                    rule['_filename'] = rule_file.name
                    self.rules.append(rule)
                    print(f"✅ Loaded rule: {rule.get('title', 'Unknown')}")
            except Exception as e:
                print(f"❌ Error loading {rule_file}: {e}")
        
        print(f"📋 Total rules loaded: {len(self.rules)}")
    
    def evaluate_log(self, log_event):
        """Evaluate a log event against all loaded rules"""
        matches = []
        
        for rule in self.rules:
            if self._matches_rule(log_event, rule):
                matches.append({
                    'rule_title': rule.get('title'),
                    'rule_id': rule.get('id'),
                    'description': rule.get('description'),
                    'level': rule.get('level', 'unknown'),
                    'tags': rule.get('tags', []),
                    'falsepositives': rule.get('falsepositives', [])
                })
        
        return matches
    
    def _matches_rule(self, log_event, rule):
        """Check if a log event matches a specific rule"""
        detection = rule.get('detection', {})
        
        # Get selection criteria
        selection = detection.get('selection', {})
        
        # Check if basic selection matches
        for key, value in selection.items():
            if key not in log_event:
                return False
            if log_event[key] != value:
                return False
        
        # Check condition (simplified - handles our off-hours example)
        condition = detection.get('condition', '')
        
        if 'not filter_hours' in condition:
            filter_hours = detection.get('filter_hours', {})
            hour = log_event.get('hour', 12)
            
            min_hour = filter_hours.get('hour|gte', 0)
            max_hour = filter_hours.get('hour|lte', 23)
            
            # Match if OUTSIDE business hours
            if min_hour <= hour <= max_hour:
                return False
            return True
        
        return True
    
    def get_rules_summary(self):
        """Return a summary of loaded rules"""
        summary = []
        for rule in self.rules:
            summary.append({
                'title': rule.get('title'),
                'level': rule.get('level'),
                'description': rule.get('description')
            })
        return summary


# Test the engine if run directly
if __name__ == "__main__":
    engine = DetectionEngine()
    
    print("\n🧪 Testing detection engine...\n")
    
    # Test: Normal login (should NOT trigger)
    normal_login = {
        'event_type': 'login',
        'user': 'john.doe',
        'hour': 14,  # 2 PM - business hours
        'source_ip': '10.0.0.50'
    }
    
    # Test: Suspicious login (should trigger)
    suspicious_login = {
        'event_type': 'login',
        'user': 'admin',
        'hour': 3,  # 3 AM - outside business hours
        'source_ip': '192.168.1.100'
    }
    
    print("Testing normal login (2 PM):")
    matches = engine.evaluate_log(normal_login)
    print(f"  Matches: {len(matches)}\n")
    
    print("Testing suspicious login (3 AM):")
    matches = engine.evaluate_log(suspicious_login)
    print(f"  Matches: {len(matches)}")
    if matches:
        print(f"  🚨 Triggered: {matches[0]['rule_title']}")
        print(f"  Level: {matches[0]['level']}")