"""
Sigma Rule Engine for KumoShield
Detects security events using Sigma rules with < 200ms latency
"""

import yaml
import re
import time
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from datetime import datetime
import logging

logger = logging.getLogger("kumoshield.sigma")

@dataclass
class SigmaRule:
    """Sigma detection rule"""
    id: str
    title: str
    description: str
    level: str  # low, medium, high, critical
    status: str  # experimental, testing, stable
    detection: Dict[str, Any]
    tags: List[str]
    author: Optional[str] = None
    references: List[str] = None
    
    def __post_init__(self):
        if self.references is None:
            self.references = []

@dataclass
class DetectionResult:
    """Result from detection engine"""
    rule_id: str
    rule_title: str
    matched: bool
    event_data: Dict[str, Any]
    timestamp: float
    latency_ms: float

class SigmaEngine:
    """
    Sigma rule detection engine
    
    Performance target: < 200ms detection latency
    """
    
    def __init__(self):
        self.rules: Dict[str, SigmaRule] = {}
        self.rule_count = 0
        self.detections = []
        
    def load_rule(self, rule_path: str) -> SigmaRule:
        """Load a Sigma rule from YAML file"""
        with open(rule_path, 'r') as f:
            rule_data = yaml.safe_load(f)
        
        rule = SigmaRule(
            id=rule_data.get('id', ''),
            title=rule_data['title'],
            description=rule_data.get('description', ''),
            level=rule_data.get('level', 'medium'),
            status=rule_data.get('status', 'experimental'),
            detection=rule_data['detection'],
            tags=rule_data.get('tags', []),
            author=rule_data.get('author'),
            references=rule_data.get('references', [])
        )
        
        self.rules[rule.id] = rule
        self.rule_count += 1
        logger.info(f"Loaded rule: {rule.title} ({rule.id})")
        
        return rule
    
    def load_rule_from_dict(self, rule_data: Dict[str, Any]) -> SigmaRule:
        """Load a Sigma rule from dictionary"""
        rule = SigmaRule(
            id=rule_data.get('id', f"rule-{len(self.rules)}"),
            title=rule_data['title'],
            description=rule_data.get('description', ''),
            level=rule_data.get('level', 'medium'),
            status=rule_data.get('status', 'experimental'),
            detection=rule_data['detection'],
            tags=rule_data.get('tags', []),
            author=rule_data.get('author'),
            references=rule_data.get('references', [])
        )
        
        self.rules[rule.id] = rule
        self.rule_count += 1
        
        return rule
    
    def detect(self, event: Dict[str, Any]) -> List[DetectionResult]:
        """
        Run detection on a security event
        Returns list of matched rules
        """
        start_time = time.perf_counter()
        results = []
        
        for rule_id, rule in self.rules.items():
            matched = self._match_rule(rule, event)
            
            if matched:
                latency_ms = (time.perf_counter() - start_time) * 1000
                
                result = DetectionResult(
                    rule_id=rule_id,
                    rule_title=rule.title,
                    matched=True,
                    event_data=event,
                    timestamp=time.time(),
                    latency_ms=latency_ms
                )
                
                results.append(result)
                self.detections.append(result)
                
                logger.warning(
                    f"[DETECTION] Rule '{rule.title}' matched "
                    f"(level: {rule.level}, latency: {latency_ms:.2f}ms)"
                )
        
        total_latency = (time.perf_counter() - start_time) * 1000
        
        # Check performance target
        if total_latency > 200:
            logger.warning(f"Detection latency {total_latency:.2f}ms exceeds 200ms target")
        
        return results
    
    def _match_rule(self, rule: SigmaRule, event: Dict[str, Any]) -> bool:
        """
        Match a single rule against an event
        Implements Sigma detection logic
        """
        detection = rule.detection
        condition = detection.get('condition', '')
        
        # Parse condition (simplified)
        # Real implementation would use proper Sigma parser
        
        # Example: condition: "selection"
        if condition == "selection":
            selection = detection.get('selection', {})
            return self._match_selection(selection, event)
        
        # Example: condition: "selection and not filter"
        if "and not" in condition:
            parts = condition.split(" and not ")
            selection_name = parts[0].strip()
            filter_name = parts[1].strip()
            
            selection = detection.get(selection_name, {})
            filter_cond = detection.get(filter_name, {})
            
            return (self._match_selection(selection, event) and 
                    not self._match_selection(filter_cond, event))
        
        # Example: condition: "selection1 or selection2"
        if " or " in condition:
            parts = condition.split(" or ")
            for part in parts:
                selection = detection.get(part.strip(), {})
                if self._match_selection(selection, event):
                    return True
            return False
        
        return False
    
    def _match_selection(self, selection: Dict[str, Any], event: Dict[str, Any]) -> bool:
        """Match a selection block against event"""
        for key, value in selection.items():
            event_value = event.get(key)
            
            # Exact match
            if isinstance(value, str):
                if value.startswith('*') and value.endswith('*'):
                    # Contains
                    pattern = value.strip('*')
                    if not (event_value and pattern in str(event_value)):
                        return False
                elif value.endswith('*'):
                    # Starts with
                    pattern = value.rstrip('*')
                    if not (event_value and str(event_value).startswith(pattern)):
                        return False
                elif value.startswith('*'):
                    # Ends with
                    pattern = value.lstrip('*')
                    if not (event_value and str(event_value).endswith(pattern)):
                        return False
                else:
                    # Exact match
                    if event_value != value:
                        return False
            
            # List match (OR)
            elif isinstance(value, list):
                if event_value not in value:
                    return False
            
            # Regex match
            elif isinstance(value, dict):
                if '|re' in value:
                    pattern = value['|re']
                    if not re.search(pattern, str(event_value)):
                        return False
        
        return True
    
    def get_stats(self) -> Dict[str, Any]:
        """Get detection engine statistics"""
        return {
            "rules_loaded": self.rule_count,
            "total_detections": len(self.detections),
            "detections_by_level": self._count_by_level(),
            "avg_latency_ms": self._calculate_avg_latency()
        }
    
    def _count_by_level(self) -> Dict[str, int]:
        """Count detections by severity level"""
        counts = {"low": 0, "medium": 0, "high": 0, "critical": 0}
        for detection in self.detections:
            rule = self.rules.get(detection.rule_id)
            if rule:
                counts[rule.level] = counts.get(rule.level, 0) + 1
        return counts
    
    def _calculate_avg_latency(self) -> float:
        """Calculate average detection latency"""
        if not self.detections:
            return 0.0
        
        total_latency = sum(d.latency_ms for d in self.detections)
        return total_latency / len(self.detections)


# Example Sigma rules
EXAMPLE_RULES = [
    {
        "title": "Suspicious Process Execution",
        "id": "rule-001",
        "description": "Detects suspicious process names like netcat",
        "level": "high",
        "status": "stable",
        "tags": ["attack.execution", "attack.t1059"],
        "detection": {
            "selection": {
                "process_name": ["nc", "ncat", "netcat", "bash -i"],
            },
            "condition": "selection"
        }
    },
    {
        "title": "Connection to Suspicious Port",
        "id": "rule-002",
        "description": "Detects connections to common backdoor ports",
        "level": "critical",
        "status": "stable",
        "tags": ["attack.command_and_control", "attack.t1071"],
        "detection": {
            "selection": {
                "dst_port": [4444, 31337, 1337, 8888],
            },
            "condition": "selection"
        }
    },
    {
        "title": "Access to Sensitive Files",
        "id": "rule-003",
        "description": "Detects access to /etc/shadow or /etc/passwd",
        "level": "high",
        "status": "stable",
        "tags": ["attack.credential_access", "attack.t1003"],
        "detection": {
            "selection": {
                "file_path": ["*/etc/shadow*", "*/etc/passwd*"],
            },
            "condition": "selection"
        }
    },
]


def test_sigma_engine():
    """Test Sigma engine performance"""
    engine = SigmaEngine()
    
    # Load example rules
    for rule_data in EXAMPLE_RULES:
        engine.load_rule_from_dict(rule_data)
    
    # Test events
    test_events = [
        {
            "process_name": "nc",
            "pid": 1234,
            "user": "root"
        },
        {
            "dst_port": 4444,
            "src_ip": "192.168.1.100",
            "dst_ip": "10.0.0.1"
        },
        {
            "file_path": "/etc/shadow",
            "operation": "read",
            "user": "attacker"
        },
        {
            "process_name": "python3",
            "pid": 5678,
            "user": "normal"
        }
    ]
    
    print("\n=== Sigma Engine Test ===")
    print(f"Loaded {engine.rule_count} rules\n")
    
    total_start = time.perf_counter()
    
    for i, event in enumerate(test_events, 1):
        print(f"Event {i}: {event}")
        results = engine.detect(event)
        
        if results:
            for result in results:
                print(f"  ✗ DETECTED: {result.rule_title} ({result.latency_ms:.2f}ms)")
        else:
            print(f"  ✓ Clean")
        print()
    
    total_time = (time.perf_counter() - total_start) * 1000
    
    stats = engine.get_stats()
    print("=== Statistics ===")
    print(f"Total detections: {stats['total_detections']}")
    print(f"Average latency: {stats['avg_latency_ms']:.2f}ms")
    print(f"Total processing time: {total_time:.2f}ms")
    print(f"Target: < 200ms per detection")
    print(f"Status: {'✓ PASS' if stats['avg_latency_ms'] < 200 else '✗ FAIL'}")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    test_sigma_engine()
