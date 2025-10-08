"""
Test suite for Sigma Detection Engine
Performance target: < 200ms detection latency
"""

import pytest
import time
from sigma_engine import SigmaEngine, DetectionResult

# ============================================================================
# Fixtures
# ============================================================================

@pytest.fixture
def engine():
    """Create a fresh Sigma engine for each test"""
    return SigmaEngine()

@pytest.fixture
def loaded_engine():
    """Create engine with pre-loaded rules"""
    engine = SigmaEngine()
    
    # Load test rules
    test_rules = [
        {
            "title": "Test Suspicious Process",
            "id": "test-001",
            "level": "high",
            "detection": {
                "selection": {
                    "process_name": ["nc", "netcat"]
                },
                "condition": "selection"
            }
        },
        {
            "title": "Test Suspicious Port",
            "id": "test-002",
            "level": "critical",
            "detection": {
                "selection": {
                    "dst_port": [4444, 31337]
                },
                "condition": "selection"
            }
        }
    ]
    
    for rule in test_rules:
        engine.load_rule_from_dict(rule)
    
    return engine

# ============================================================================
# Basic Functionality Tests
# ============================================================================

def test_engine_initialization(engine):
    """Test engine initializes correctly"""
    assert engine.rule_count == 0
    assert len(engine.rules) == 0
    assert len(engine.detections) == 0

def test_load_rule_from_dict(engine):
    """Test loading rule from dictionary"""
    rule_data = {
        "title": "Test Rule",
        "id": "test-001",
        "level": "medium",
        "detection": {
            "selection": {"key": "value"},
            "condition": "selection"
        }
    }
    
    rule = engine.load_rule_from_dict(rule_data)
    
    assert rule.title == "Test Rule"
    assert rule.id == "test-001"
    assert rule.level == "medium"
    assert engine.rule_count == 1

def test_load_multiple_rules(engine):
    """Test loading multiple rules"""
    for i in range(5):
        rule_data = {
            "title": f"Test Rule {i}",
            "id": f"test-{i:03d}",
            "level": "low",
            "detection": {
                "selection": {"key": f"value{i}"},
                "condition": "selection"
            }
        }
        engine.load_rule_from_dict(rule_data)
    
    assert engine.rule_count == 5

# ============================================================================
# Detection Tests
# ============================================================================

def test_simple_detection(loaded_engine):
    """Test simple event detection"""
    event = {
        "process_name": "nc",
        "pid": 1234
    }
    
    results = loaded_engine.detect(event)
    
    assert len(results) == 1
    assert results[0].matched is True
    assert results[0].rule_title == "Test Suspicious Process"

def test_no_match(loaded_engine):
    """Test event that doesn't match any rule"""
    event = {
        "process_name": "python3",
        "pid": 5678
    }
    
    results = loaded_engine.detect(event)
    
    assert len(results) == 0

def test_multiple_matches(loaded_engine):
    """Test event matching multiple rules"""
    # Add another rule
    loaded_engine.load_rule_from_dict({
        "title": "Test Process Name Pattern",
        "id": "test-003",
        "level": "medium",
        "detection": {
            "selection": {
                "process_name": ["nc", "bash"]
            },
            "condition": "selection"
        }
    })
    
    event = {
        "process_name": "nc",
        "pid": 1234
    }
    
    results = loaded_engine.detect(event)
    
    assert len(results) == 2

# ============================================================================
# Performance Tests
# ============================================================================

def test_detection_latency(loaded_engine):
    """Test detection latency < 200ms"""
    event = {
        "process_name": "nc",
        "dst_port": 4444
    }
    
    results = loaded_engine.detect(event)
    
    # Check that each detection was under 200ms
    for result in results:
        assert result.latency_ms < 200, f"Latency {result.latency_ms}ms exceeds 200ms target"

@pytest.mark.benchmark
def test_detection_performance(loaded_engine, benchmark):
    """Benchmark detection performance"""
    event = {
        "process_name": "nc",
        "pid": 1234
    }
    
    result = benchmark(loaded_engine.detect, event)
    assert len(result) >= 1

def test_bulk_detection_performance(loaded_engine):
    """Test performance with bulk events"""
    events = [
        {"process_name": "nc", "pid": i} for i in range(100)
    ]
    
    start_time = time.perf_counter()
    
    for event in events:
        loaded_engine.detect(event)
    
    elapsed = (time.perf_counter() - start_time) * 1000  # Convert to ms
    avg_latency = elapsed / len(events)
    
    assert avg_latency < 200, f"Average latency {avg_latency:.2f}ms exceeds 200ms target"

# ============================================================================
# Pattern Matching Tests
# ============================================================================

def test_exact_match(engine):
    """Test exact string matching"""
    engine.load_rule_from_dict({
        "title": "Exact Match Test",
        "id": "test-exact",
        "detection": {
            "selection": {"key": "exact_value"},
            "condition": "selection"
        }
    })
    
    # Should match
    assert len(engine.detect({"key": "exact_value"})) == 1
    
    # Should not match
    assert len(engine.detect({"key": "other_value"})) == 0

def test_wildcard_contains(engine):
    """Test wildcard contains matching"""
    engine.load_rule_from_dict({
        "title": "Contains Test",
        "id": "test-contains",
        "detection": {
            "selection": {"key": "*test*"},
            "condition": "selection"
        }
    })
    
    # Should match
    assert len(engine.detect({"key": "before_test_after"})) == 1
    assert len(engine.detect({"key": "test"})) == 1
    
    # Should not match
    assert len(engine.detect({"key": "no_match"})) == 0

def test_wildcard_starts_with(engine):
    """Test wildcard starts with matching"""
    engine.load_rule_from_dict({
        "title": "Starts With Test",
        "id": "test-starts",
        "detection": {
            "selection": {"key": "prefix*"},
            "condition": "selection"
        }
    })
    
    # Should match
    assert len(engine.detect({"key": "prefix_anything"})) == 1
    
    # Should not match
    assert len(engine.detect({"key": "no_prefix"})) == 0

def test_list_match(engine):
    """Test list matching (OR logic)"""
    engine.load_rule_from_dict({
        "title": "List Match Test",
        "id": "test-list",
        "detection": {
            "selection": {"key": ["value1", "value2", "value3"]},
            "condition": "selection"
        }
    })
    
    # Should match any
    assert len(engine.detect({"key": "value1"})) == 1
    assert len(engine.detect({"key": "value2"})) == 1
    assert len(engine.detect({"key": "value3"})) == 1
    
    # Should not match
    assert len(engine.detect({"key": "value4"})) == 0

# ============================================================================
# Condition Logic Tests
# ============================================================================

def test_and_not_condition(engine):
    """Test 'and not' condition logic"""
    engine.load_rule_from_dict({
        "title": "AND NOT Test",
        "id": "test-and-not",
        "detection": {
            "selection": {"process_name": "cmd.exe"},
            "filter": {"user": "SYSTEM"},
            "condition": "selection and not filter"
        }
    })
    
    # Should match (selection true, filter false)
    assert len(engine.detect({"process_name": "cmd.exe", "user": "admin"})) == 1
    
    # Should not match (both true)
    assert len(engine.detect({"process_name": "cmd.exe", "user": "SYSTEM"})) == 0
    
    # Should not match (selection false)
    assert len(engine.detect({"process_name": "other.exe", "user": "admin"})) == 0

def test_or_condition(engine):
    """Test OR condition logic"""
    engine.load_rule_from_dict({
        "title": "OR Test",
        "id": "test-or",
        "detection": {
            "selection1": {"key1": "value1"},
            "selection2": {"key2": "value2"},
            "condition": "selection1 or selection2"
        }
    })
    
    # Should match either
    assert len(engine.detect({"key1": "value1"})) == 1
    assert len(engine.detect({"key2": "value2"})) == 1
    assert len(engine.detect({"key1": "value1", "key2": "value2"})) == 1
    
    # Should not match
    assert len(engine.detect({"key3": "value3"})) == 0

# ============================================================================
# Statistics Tests
# ============================================================================

def test_statistics(loaded_engine):
    """Test engine statistics"""
    # Trigger some detections
    events = [
        {"process_name": "nc"},
        {"dst_port": 4444},
        {"process_name": "python"},
    ]
    
    for event in events:
        loaded_engine.detect(event)
    
    stats = loaded_engine.get_stats()
    
    assert stats["rules_loaded"] == 2
    assert stats["total_detections"] >= 2
    assert "avg_latency_ms" in stats

# ============================================================================
# Run Tests
# ============================================================================

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short", "--benchmark-only"])
