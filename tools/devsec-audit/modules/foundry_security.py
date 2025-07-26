#!/usr/bin/env python3
"""
Foundry Security Module
Scans for Foundry-related security issues including FFI usage and unsafe configurations
"""

import re
from pathlib import Path
from typing import Dict, List, Any, Optional
from core.scanner import BaseSecurityModule, Finding, Severity, ScanResult


class FoundrySecurityModule(BaseSecurityModule):
    def __init__(self, target_path, config: Dict[str, Any] = None):
        # Ensure target_path is a Path object
        if isinstance(target_path, str):
            target_path = Path(target_path)
        if config is None:
            config = {
                "severity_filter": ["critical", "high", "medium", "low", "info"],
                "whitelist": [],
                "exclude_paths": [],
                "exclude_files": []
            }
        super().__init__(target_path, config)
        self.module_name = "foundry"
    
    def scan(self) -> ScanResult:
        self.findings = []
        total_checks = 0
        
        total_checks += self._check_foundry_toml()
        total_checks += self._check_ffi_usage_in_tests()
        
        failed_checks = len(self.findings)
        score = self._calculate_module_score(total_checks, failed_checks)
        passed_checks = max(0, total_checks - failed_checks)
        
        return ScanResult(
            module_name=self.module_name,
            findings=self.findings,
            score=score,
            total_checks=total_checks,
            passed_checks=passed_checks,
            failed_checks=failed_checks
        )
    
    def _check_foundry_toml(self) -> int:
        """Check foundry.toml for dangerous FFI configuration"""
        foundry_toml = self.target_path / "foundry.toml"
        
        if not foundry_toml.exists():
            return 0
            
        try:
            content = foundry_toml.read_text()
            lines = content.split('\n')
            
            for line_num, line in enumerate(lines, 1):
                stripped = line.strip()
                
                # Check for FFI enabled
                if re.match(r'^\s*ffi\s*=\s*true\s*$', stripped, re.IGNORECASE):
                    self.add_finding(Finding(
                        id="FOUNDRY-001",
                        title="Foundry FFI Enabled",
                        description="Foreign Function Interface (FFI) is enabled, allowing arbitrary command execution",
                        severity=Severity.CRITICAL,
                        category="foundry",
                        file_path=str(foundry_toml),
                        line_number=line_num,
                        evidence=line,
                        recommendation="Disable FFI unless absolutely necessary: ffi = false"
                    ))
                
                # Check for other dangerous configurations
                if re.match(r'^\s*fs_permissions\s*=\s*\[.*".*"\.*\]', stripped, re.IGNORECASE):
                    self.add_finding(Finding(
                        id="FOUNDRY-002",
                        title="Foundry Filesystem Permissions",
                        description="Custom filesystem permissions configured for tests",
                        severity=Severity.HIGH,
                        category="foundry",
                        file_path=str(foundry_toml),
                        line_number=line_num,
                        evidence=line,
                        recommendation="Review filesystem permissions to ensure they're necessary and secure"
                    ))
                
                # Check for dangerous read/write permissions
                if 'read' in stripped.lower() and ('/' in stripped or '~' in stripped):
                    self.add_finding(Finding(
                        id="FOUNDRY-003",
                        title="Foundry Broad Read Permissions",
                        description="Broad filesystem read permissions detected",
                        severity=Severity.MEDIUM,
                        category="foundry",
                        file_path=str(foundry_toml),
                        line_number=line_num,
                        evidence=line,
                        recommendation="Limit read permissions to specific necessary directories"
                    ))
                
                if 'write' in stripped.lower() and ('/' in stripped or '~' in stripped):
                    self.add_finding(Finding(
                        id="FOUNDRY-004",
                        title="Foundry Broad Write Permissions",
                        description="Broad filesystem write permissions detected",
                        severity=Severity.HIGH,
                        category="foundry",
                        file_path=str(foundry_toml),
                        line_number=line_num,
                        evidence=line,
                        recommendation="Limit write permissions to specific necessary directories"
                    ))
            
            return 1
            
        except Exception:
            return 1
    
    def _check_ffi_usage_in_tests(self) -> int:
        """Check for FFI usage in Solidity test files"""
        # Look for .sol test files and deduplicate
        test_patterns = [
            "**/test/**/*.sol",
            "**/tests/**/*.sol", 
            "**/*Test.sol",
            "**/*.t.sol"
        ]
        
        # Use a set to deduplicate files that match multiple patterns
        test_files = set()
        for pattern in test_patterns:
            test_files.update(self.target_path.glob(pattern))
        
        # Analyze each unique file once
        for test_file in test_files:
            self._analyze_solidity_test_file(test_file)
        
        return max(len(test_files), 1)  # At least 1 check performed
    
    def _analyze_solidity_test_file(self, test_file: Path):
        """Analyze Solidity test file for FFI usage"""
        try:
            content = test_file.read_text()
            lines = content.split('\n')
            
            for line_num, line in enumerate(lines, 1):
                stripped = line.strip()
                
                # Check for FFI cheatcode usage (combine patterns to avoid duplicates)
                ffi_pattern = r'(vm\.ffi\s*\(|cheats\.ffi\s*\(|\.ffi\s*\([^)]*\))'
                
                if re.search(ffi_pattern, stripped, re.IGNORECASE):
                    self.add_finding(Finding(
                        id="FOUNDRY-005",
                        title="FFI Usage in Test",
                        description="Foreign Function Interface (FFI) used in test - can execute arbitrary commands",
                        severity=Severity.CRITICAL,
                        category="foundry",
                        file_path=str(test_file),
                        line_number=line_num,
                        evidence=line,
                        recommendation="Review FFI usage - ensure it's necessary and doesn't execute untrusted commands"
                    ))
                
                # Check for dangerous command patterns in FFI calls
                dangerous_commands = [
                    'curl', 'wget', 'bash', 'sh', 'rm', 'mv', 'cp',
                    'cat', 'echo', 'eval', 'exec', 'nc', 'netcat'
                ]
                
                for cmd in dangerous_commands:
                    if cmd in stripped and 'ffi' in stripped.lower():
                        self.add_finding(Finding(
                            id="FOUNDRY-006",
                            title="Dangerous Command in FFI",
                            description=f"Potentially dangerous command '{cmd}' found in FFI call",
                            severity=Severity.CRITICAL,
                            category="foundry",
                            file_path=str(test_file),
                            line_number=line_num,
                            evidence=line,
                            recommendation="Avoid using dangerous commands in FFI calls"
                        ))
                        
        except Exception:
            pass