#!/usr/bin/env python3
"""
Secrets Scanner Module
Scans for hardcoded secrets, API keys, passwords, and other sensitive information
in source code, configuration files, and environment files
"""

import re
import os
from pathlib import Path
from typing import List, Dict, Any, Optional, Pattern
from core.scanner import BaseSecurityModule, Finding, Severity, ScanResult


class SecretsScanner(BaseSecurityModule):
    def __init__(self, target_path: Path, config: Dict[str, Any]):
        super().__init__(target_path, config)
        self.module_name = "secrets"
        self.secret_patterns = self._load_secret_patterns()
        self.ignore_patterns = self._load_ignore_patterns()
        
    def scan(self) -> ScanResult:
        self.findings = []
        total_checks = 0
        
        total_checks += self._scan_files_for_secrets()
        total_checks += self._check_environment_files()
        total_checks += self._check_config_files()
        total_checks += self._check_history_files()
        
        failed_checks = len(self.findings)
        score = self._calculate_module_score(total_checks, failed_checks)
        
        return ScanResult(
            module_name=self.module_name,
            findings=self.findings,
            score=score,
            total_checks=total_checks,
            passed_checks=total_checks - failed_checks,
            failed_checks=failed_checks
        )
    
    def _load_secret_patterns(self) -> Dict[str, Dict]:
        return {
            "aws_access_key": {
                "pattern": r"AKIA[0-9A-Z]{16}",
                "description": "AWS Access Key ID",
                "severity": Severity.CRITICAL
            },
            "aws_secret_key": {
                "pattern": r"[A-Za-z0-9/\+=]{40}",
                "description": "AWS Secret Access Key",
                "severity": Severity.CRITICAL,
                "context": r"(aws_secret_access_key|secret.?key)"
            },
            "github_token": {
                "pattern": r"gh[pousr]_[A-Za-z0-9_]{36}",
                "description": "GitHub Token",
                "severity": Severity.HIGH
            },
            "github_classic_token": {
                "pattern": r"[0-9a-f]{32}",
                "description": "GitHub Classic Token",
                "severity": Severity.HIGH,
                "context": r"(github|gh).?(token|pat)"
            },
            "slack_token": {
                "pattern": r"xox[baprs]-([0-9a-zA-Z]{10,48})",
                "description": "Slack Token",
                "severity": Severity.HIGH
            },
            "discord_token": {
                "pattern": r"[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}",
                "description": "Discord Bot Token",
                "severity": Severity.HIGH
            },
            "jwt_token": {
                "pattern": r"eyJ[A-Za-z0-9_/+=\-]+\.eyJ[A-Za-z0-9_/+=\-]+\.[A-Za-z0-9_/+=\-]+",
                "description": "JWT Token",
                "severity": Severity.MEDIUM
            },
            "api_key_generic": {
                "pattern": r"[A-Za-z0-9]{32,}",
                "description": "Generic API Key",
                "severity": Severity.MEDIUM,
                "context": r"(api[_-]?key|apikey|key)"
            },
            "private_key": {
                "pattern": r"-----BEGIN[\s\w]*PRIVATE KEY-----",
                "description": "Private Key",
                "severity": Severity.CRITICAL
            },
            "password_assignment": {
                "pattern": r'password\s*[:=]\s*["\']?[^"\'\s\n]{6,}["\']?',
                "description": "Password Assignment",
                "severity": Severity.HIGH
            },
            "database_url": {
                "pattern": r"(mysql|postgresql|mongodb)://[^:\s]+:[^@\s]+@[^/\s]+",
                "description": "Database Connection String with Credentials",
                "severity": Severity.HIGH
            },
            "stripe_key": {
                "pattern": r"sk_live_[0-9a-zA-Z]{24}",
                "description": "Stripe Live Secret Key",
                "severity": Severity.CRITICAL
            },
            "mailgun_key": {
                "pattern": r"key-[0-9a-zA-Z]{32}",
                "description": "Mailgun API Key",
                "severity": Severity.MEDIUM
            },
            "twilio_sid": {
                "pattern": r"AC[0-9a-fA-F]{32}",
                "description": "Twilio Account SID",
                "severity": Severity.MEDIUM
            },
            "google_api_key": {
                "pattern": r"AIza[0-9A-Za-z\-_]{35}",
                "description": "Google API Key",
                "severity": Severity.HIGH
            }
        }
    
    def _load_ignore_patterns(self) -> List[Pattern]:
        ignore_regexes = [
            r"\.git/",
            r"node_modules/",
            r"__pycache__/",
            r"\.pyc$",
            r"\.jpg$|\.jpeg$|\.png$|\.gif$|\.svg$",
            r"\.pdf$|\.doc$|\.docx$",
            r"\.zip$|\.tar$|\.gz$",
            r"example",
            r"test.*key",
            r"dummy.*key",
            r"fake.*key",
            r"sample.*key"
        ]
        return [re.compile(pattern, re.IGNORECASE) for pattern in ignore_regexes]
    
    def _should_ignore_file(self, file_path: Path) -> bool:
        file_str = str(file_path)
        return any(pattern.search(file_str) for pattern in self.ignore_patterns)
    
    def _scan_files_for_secrets(self) -> int:
        checks = 0
        text_extensions = {
            '.py', '.js', '.ts', '.jsx', '.tsx', '.java', '.go', '.rs', '.rb', 
            '.php', '.cpp', '.c', '.h', '.cs', '.swift', '.kt', '.scala',
            '.json', '.yaml', '.yml', '.xml', '.ini', '.cfg', '.conf',
            '.env', '.txt', '.md', '.sh', '.bash', '.zsh', '.fish',
            '.sql', '.dockerfile', '.gitconfig', '.gitignore'
        }
        
        for file_path in self.target_path.rglob("*"):
            if file_path.is_file() and not self._should_ignore_file(file_path):
                if file_path.suffix.lower() in text_extensions or file_path.name.startswith('.'):
                    checks += 1
                    self._scan_file_content(file_path)
                    
        return checks
    
    def _scan_file_content(self, file_path: Path):
        try:
            # Try to read as text, skip binary files
            content = file_path.read_text(encoding='utf-8', errors='ignore')
            lines = content.split('\n')
            
            for line_num, line in enumerate(lines, 1):
                self._check_line_for_secrets(line, file_path, line_num)
                
        except Exception:
            # Skip files that can't be read
            pass
    
    def _check_line_for_secrets(self, line: str, file_path: Path, line_num: int):
        for secret_id, secret_info in self.secret_patterns.items():
            pattern = secret_info["pattern"]
            
            # Check if context is required
            if "context" in secret_info:
                context_pattern = secret_info["context"]
                if not re.search(context_pattern, line, re.IGNORECASE):
                    continue
            
            matches = re.finditer(pattern, line, re.IGNORECASE)
            for match in matches:
                matched_text = match.group(0)
                
                # Additional validation for certain patterns
                if self._is_likely_secret(secret_id, matched_text, line):
                    self.add_finding(Finding(
                        id=f"SECRET-{secret_id.upper()}",
                        title=f"Hardcoded {secret_info['description']}",
                        description=f"Found {secret_info['description']} in source code",
                        severity=secret_info["severity"],
                        category="secrets",
                        file_path=str(file_path),
                        line_number=line_num,
                        evidence=self._redact_secret(line),
                        recommendation="Remove hardcoded secrets and use environment variables or secret management systems"
                    ))
    
    def _is_likely_secret(self, secret_id: str, matched_text: str, line: str) -> bool:
        # Additional validation to reduce false positives
        
        # Check for obvious false positives
        false_positive_indicators = [
            "example", "test", "dummy", "fake", "sample", "placeholder",
            "your_key_here", "insert_key", "replace_with", "todo",
            "xxxxxxx", "000000", "111111", "123456"
        ]
        
        line_lower = line.lower()
        matched_lower = matched_text.lower()
        
        if any(fp in line_lower or fp in matched_lower for fp in false_positive_indicators):
            return False
        
        # Special validation for generic patterns
        if secret_id == "api_key_generic":
            # Must be longer than 20 chars and contain mixed case/numbers
            if len(matched_text) < 20:
                return False
            if not (any(c.islower() for c in matched_text) and 
                   any(c.isupper() for c in matched_text) and
                   any(c.isdigit() for c in matched_text)):
                return False
        
        # Special validation for AWS secret keys
        if secret_id == "aws_secret_key":
            # Must be exactly 40 characters
            if len(matched_text) != 40:
                return False
        
        return True
    
    def _redact_secret(self, line: str) -> str:
        """Redact the actual secret value while keeping context"""
        # Replace potential secrets with asterisks
        redacted = re.sub(r'[A-Za-z0-9/\+=]{10,}', lambda m: m.group(0)[:4] + '*' * (len(m.group(0)) - 4), line)
        return redacted[:100] + "..." if len(redacted) > 100 else redacted
    
    def _check_environment_files(self) -> int:
        env_files = [
            ".env", ".env.local", ".env.development", ".env.production",
            ".env.staging", ".env.test", ".environment"
        ]
        
        checks = 0
        for env_file in env_files:
            env_path = self.target_path / env_file
            if env_path.exists():
                checks += 1
                self._analyze_env_file(env_path)
                
        return checks
    
    def _analyze_env_file(self, env_path: Path):
        try:
            content = env_path.read_text()
            lines = content.split('\n')
            
            for line_num, line in enumerate(lines, 1):
                line = line.strip()
                if line and not line.startswith('#'):
                    if '=' in line:
                        key, value = line.split('=', 1)
                        self._check_env_variable(key.strip(), value.strip(), env_path, line_num)
                        
        except Exception as e:
            self.add_finding(Finding(
                id="SECRET-ENV-001",
                title="Environment File Read Error",
                description=f"Could not read environment file: {e}",
                severity=Severity.LOW,
                category="secrets",
                file_path=str(env_path)
            ))
    
    def _check_env_variable(self, key: str, value: str, env_path: Path, line_num: int):
        sensitive_keys = [
            "password", "secret", "key", "token", "api", "auth",
            "database_url", "db_password", "jwt_secret", "private_key"
        ]
        
        key_lower = key.lower()
        
        if any(sensitive in key_lower for sensitive in sensitive_keys):
            if value and value not in ["", '""', "''", "your_secret_here", "change_me"]:
                severity = Severity.HIGH
                
                # Check for particularly dangerous secrets
                if any(critical in key_lower for critical in ["production", "prod", "live"]):
                    severity = Severity.CRITICAL
                
                self.add_finding(Finding(
                    id="SECRET-ENV-002",
                    title="Sensitive Environment Variable",
                    description=f"Environment variable '{key}' contains sensitive information",
                    severity=severity,
                    category="secrets",
                    file_path=str(env_path),
                    line_number=line_num,
                    evidence=f"{key}={value[:10]}..." if len(value) > 10 else f"{key}=***",
                    recommendation="Consider using a secret management system or encrypted env files"
                ))
    
    def _check_config_files(self) -> int:
        config_patterns = [
            "config/*.yml", "config/*.yaml", "config/*.json",
            "*.config.js", "*.config.json", "application.properties",
            "database.yml", "secrets.yml"
        ]
        
        checks = 0
        for pattern in config_patterns:
            config_files = list(self.target_path.glob(f"**/{pattern}"))
            for config_file in config_files:
                if config_file.is_file():
                    checks += 1
                    self._scan_file_content(config_file)
                    
        return checks
    
    def _check_history_files(self) -> int:
        history_files = [
            Path.home() / ".bash_history",
            Path.home() / ".zsh_history", 
            Path.home() / ".history",
            Path.home() / ".mysql_history",
            Path.home() / ".psql_history"
        ]
        
        checks = 0
        for history_file in history_files:
            if history_file.exists():
                checks += 1
                self._analyze_history_file(history_file)
                
        return checks
    
    def _analyze_history_file(self, history_path: Path):
        try:
            content = history_path.read_text(errors='ignore')
            lines = content.split('\n')
            
            suspicious_commands = [
                r'mysql.*-p\w+',  # MySQL with inline password
                r'psql.*password=\w+',  # PostgreSQL with password
                r'curl.*Authorization.*Bearer',  # API calls with tokens
                r'export.*SECRET.*=',  # Exporting secrets
                r'export.*KEY.*=',  # Exporting keys
            ]
            
            for line_num, line in enumerate(lines[-100:], max(1, len(lines) - 99)):  # Check last 100 commands
                for pattern in suspicious_commands:
                    if re.search(pattern, line, re.IGNORECASE):
                        self.add_finding(Finding(
                            id="SECRET-HISTORY-001",
                            title="Credentials in Command History",
                            description="Command history contains credentials or sensitive information",
                            severity=Severity.MEDIUM,
                            category="secrets",
                            file_path=str(history_path),
                            line_number=line_num,
                            evidence=self._redact_secret(line),
                            recommendation="Clear command history and avoid using credentials in command line"
                        ))
                        break  # Only report once per line
                        
        except Exception:
            # History files might not be readable
            pass