import pytest
from detection_engine import DetectionEngine
from enrichment_engine import EnrichmentEngine

class TestDetectionEngine:
    """Test suite for the Detection Engine"""
    
    @pytest.fixture
    def engine(self):
        """Create a fresh detection engine for each test"""
        return DetectionEngine()
    
    def test_rules_loaded(self, engine):
        """Test that detection rules are loaded successfully"""
        assert len(engine.rules) > 0, "No detection rules loaded"
        print(f"✅ Loaded {len(engine.rules)} detection rules")
    
    def test_rule_has_required_fields(self, engine):
        """Test that each rule has required fields"""
        required_fields = ['title', 'id', 'description', 'detection', 'level']
        
        for rule in engine.rules:
            for field in required_fields:
                assert field in rule, f"Rule missing required field: {field}"
        print("✅ All rules have required fields")
    
    def test_normal_login_no_alert(self, engine):
        """Test that normal business hours login does NOT trigger alert"""
        normal_login = {
            'event_type': 'login',
            'user': 'john.doe',
            'hour': 14,  # 2 PM - business hours
            'source_ip': '10.0.0.50'
        }
        
        matches = engine.evaluate_log(normal_login)
        assert len(matches) == 0, "Normal login should not trigger alerts"
        print("✅ Normal login (2 PM) - No false positive")
    
    def test_off_hours_login_triggers_alert(self, engine):
        """Test that off-hours login DOES trigger alert"""
        suspicious_login = {
            'event_type': 'login',
            'user': 'admin',
            'hour': 3,  # 3 AM - outside business hours
            'source_ip': '192.168.1.100'
        }
        
        matches = engine.evaluate_log(suspicious_login)
        assert len(matches) > 0, "Off-hours login should trigger alert"
        assert matches[0]['level'] == 'medium', "Alert level should be medium"
        print("✅ Off-hours login (3 AM) - Correctly detected")
    
    def test_early_morning_triggers_alert(self, engine):
        """Test that early morning (5 AM) triggers alert"""
        early_login = {
            'event_type': 'login',
            'user': 'developer',
            'hour': 5,  # 5 AM - before business hours
            'source_ip': '10.0.0.100'
        }
        
        matches = engine.evaluate_log(early_login)
        assert len(matches) > 0, "5 AM login should trigger alert"
        print("✅ Early morning login (5 AM) - Correctly detected")
    
    def test_late_night_triggers_alert(self, engine):
        """Test that late night (11 PM) triggers alert"""
        late_login = {
            'event_type': 'login',
            'user': 'analyst',
            'hour': 23,  # 11 PM - after business hours
            'source_ip': '10.0.0.200'
        }
        
        matches = engine.evaluate_log(late_login)
        assert len(matches) > 0, "11 PM login should trigger alert"
        print("✅ Late night login (11 PM) - Correctly detected")
    
    def test_boundary_6am_no_alert(self, engine):
        """Test that exactly 6 AM does NOT trigger (start of business)"""
        boundary_login = {
            'event_type': 'login',
            'user': 'early_bird',
            'hour': 6,  # 6 AM - start of business hours
            'source_ip': '10.0.0.75'
        }
        
        matches = engine.evaluate_log(boundary_login)
        assert len(matches) == 0, "6 AM login should not trigger alert"
        print("✅ Boundary test (6 AM) - No false positive")
    
    def test_boundary_10pm_no_alert(self, engine):
        """Test that exactly 10 PM does NOT trigger (end of business)"""
        boundary_login = {
            'event_type': 'login',
            'user': 'night_owl',
            'hour': 22,  # 10 PM - end of business hours
            'source_ip': '10.0.0.80'
        }
        
        matches = engine.evaluate_log(boundary_login)
        assert len(matches) == 0, "10 PM login should not trigger alert"
        print("✅ Boundary test (10 PM) - No false positive")


class TestEnrichmentEngine:
    """Test suite for the Enrichment Engine"""
    
    @pytest.fixture
    def engine(self):
        """Create a fresh enrichment engine for each test"""
        return EnrichmentEngine()
    
    def test_known_user_enrichment(self, engine):
        """Test enrichment for a known user"""
        alert = {
            'user': 'admin',
            'source_ip': '192.168.1.100',
            'severity': 'medium'
        }
        
        enriched = engine.enrich_alert(alert)
        
        user_ctx = enriched['enrichments']['user_context']
        assert user_ctx['found'] == True, "Known user should be found"
        assert user_ctx['department'] == 'IT', "Admin should be in IT"
        print("✅ Known user enrichment working")
    
    def test_unknown_user_enrichment(self, engine):
        """Test enrichment for an unknown user"""
        alert = {
            'user': 'unknown_user_12345',
            'source_ip': '192.168.1.100',
            'severity': 'medium'
        }
        
        enriched = engine.enrich_alert(alert)
        
        user_ctx = enriched['enrichments']['user_context']
        assert user_ctx['found'] == False, "Unknown user should not be found"
        print("✅ Unknown user handled gracefully")
    
    def test_malicious_ip_detection(self, engine):
        """Test that malicious IPs are identified"""
        alert = {
            'user': 'admin',
            'source_ip': '45.33.32.156',  # Known C2 server
            'severity': 'medium'
        }
        
        enriched = engine.enrich_alert(alert)
        
        ip_intel = enriched['enrichments']['ip_intel']
        assert ip_intel['reputation'] == 'malicious', "C2 IP should be malicious"
        assert ip_intel['category'] == 'C2 Server', "Should be categorized as C2"
        print("✅ Malicious IP correctly identified")
    
    def test_private_ip_detection(self, engine):
        """Test that private IPs are identified correctly"""
        alert = {
            'user': 'admin',
            'source_ip': '192.168.1.100',
            'severity': 'medium'
        }
        
        enriched = engine.enrich_alert(alert)
        
        ip_intel = enriched['enrichments']['ip_intel']
        assert ip_intel['reputation'] == 'internal', "Private IP should be internal"
        print("✅ Private IP correctly identified")
    
    def test_risk_score_calculation(self, engine):
        """Test that risk scores are calculated correctly"""
        # Low risk scenario
        low_risk = engine.enrich_alert({
            'user': 'john.doe',
            'source_ip': '10.0.0.50',
            'severity': 'low'
        })
        
        # High risk scenario
        high_risk = engine.enrich_alert({
            'user': 'admin',
            'source_ip': '45.33.32.156',  # Malicious IP
            'severity': 'high'
        })
        
        assert high_risk['risk_score'] > low_risk['risk_score'], \
            "High risk scenario should have higher score"
        print(f"✅ Risk scoring working (Low: {low_risk['risk_score']}, High: {high_risk['risk_score']})")
    
    def test_repeat_offender_detection(self, engine):
        """Test that repeat offenders are flagged"""
        alert = {
            'user': 'admin',  # Has previous alerts
            'source_ip': '192.168.1.100',
            'severity': 'medium'
        }
        
        enriched = engine.enrich_alert(alert)
        
        user_hist = enriched['enrichments']['user_history']
        assert user_hist['is_repeat_offender'] == True, "Admin should be repeat offender"
        assert user_hist['previous_alerts'] > 0, "Should have previous alerts"
        print("✅ Repeat offender detection working")


class TestIntegration:
    """Integration tests combining detection and enrichment"""
    
    def test_full_alert_pipeline(self):
        """Test complete alert pipeline: detect -> enrich"""
        detection_engine = DetectionEngine()
        enrichment_engine = EnrichmentEngine()
        
        # Simulate a suspicious event
        log_event = {
            'event_type': 'login',
            'user': 'admin',
            'hour': 3,
            'source_ip': '45.33.32.156',
            'severity': 'medium'
        }
        
        # Step 1: Detection
        matches = detection_engine.evaluate_log(log_event)
        assert len(matches) > 0, "Should detect suspicious login"
        
        # Step 2: Enrichment
        enriched = enrichment_engine.enrich_alert(log_event)
        assert enriched['risk_score'] >= 80, "Should be high/critical risk"
        
        print("✅ Full pipeline working: Detection → Enrichment")
        print(f"   Detected: {matches[0]['rule_title']}")
        print(f"   Risk Score: {enriched['risk_score']}/100 ({enriched['risk_level']})")


# Run with: pytest test_detections.py -v
if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])