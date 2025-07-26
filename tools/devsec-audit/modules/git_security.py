#!/usr/bin/env python3
"""
Git Security Module
Scans for Git-related security issues including dangerous configurations, hooks, and aliases
"""

import os
import re
import configparser
from pathlib import Path
from typing import List, Dict, Any, Optional
from core.scanner import BaseSecurityModule, Finding, Severity, ScanResult


class GitSecurityModule(BaseSecurityModule):
    def __init__(self, target_path: Path, config: Dict[str, Any]):
        super().__init__(target_path, config)
        self.module_name = "git"
        
    def scan(self) -> ScanResult:
        self.findings = []
        total_checks = 0
        
        total_checks += self._check_git_configs()
        total_checks += self._check_git_hooks()
        total_checks += self._check_git_aliases()
        total_checks += self._check_credentials_in_config()
        total_checks += self._check_dangerous_core_settings()
        total_checks += self._check_ssh_keys()
        
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
    
    def _check_git_configs(self) -> int:
        checks = 0
        git_configs = [
            self.target_path / ".git" / "config",  # Local repo config
            Path.home() / ".gitconfig",  # Global user config
            Path("/etc/gitconfig"),  # System config
        ]
        
        for config_path in git_configs:
            if config_path.exists():
                checks += 1
                self._analyze_git_config(config_path)
                
        return checks
    
    def _analyze_git_config(self, config_path: Path):
        try:
            config = configparser.ConfigParser()
            config.read(str(config_path))
            
            for section_name in config.sections():
                for key, value in config[section_name].items():
                    self._check_config_value(section_name, key, value, config_path)
                    
        except Exception as e:
            self.add_finding(Finding(
                id="GIT-001",
                title="Git Config Parse Error",
                description=f"Could not parse git config: {e}",
                severity=Severity.LOW,
                category="git",
                file_path=str(config_path)
            ))
    
    def _check_config_value(self, section: str, key: str, value: str, config_path: Path):
        if 'url' in key.lower() and any(cred in value for cred in ['://', '@', 'token', 'password']):
            if re.search(r'://.*[@:].*@', value) or 'token=' in value or 'password=' in value:
                self.add_finding(Finding(
                    id="GIT-002",
                    title="Credentials in Git URL",
                    description=f"Git URL contains embedded credentials: {key}",
                    severity=Severity.HIGH,
                    category="git",
                    file_path=str(config_path),
                    evidence=f"{section}.{key} = {value[:50]}...",
                    recommendation="Use SSH keys or credential helpers instead of embedding credentials in URLs"
                ))
    
    def _check_git_hooks(self) -> int:
        hooks_dir = self.target_path / ".git" / "hooks"
        if not hooks_dir.exists():
            return 0
            
        checks = 0
        hook_files = [f for f in hooks_dir.iterdir() if f.is_file() and not f.name.endswith('.sample')]
        
        for hook_file in hook_files:
            checks += 1
            if os.access(hook_file, os.X_OK):
                self._analyze_hook_file(hook_file)
                
        return checks
    
    def _analyze_hook_file(self, hook_file: Path):
        try:
            content = hook_file.read_text()
            
            dangerous_patterns = [
                (r'curl\s+.*\|\s*(bash|sh)', "Remote script execution via curl"),
                (r'wget\s+.*\|\s*(bash|sh)', "Remote script execution via wget"),
                (r'eval\s*\$\(.*\)', "Dynamic code evaluation"),
                (r'system\s*\(.*["\'].*["\'].*\)', "System command execution"),
                (r'exec\s*\(.*\)', "Code execution via exec"),
                (r'rm\s+-rf\s+/', "Dangerous file deletion"),
            ]
            
            for pattern, description in dangerous_patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    self.add_finding(Finding(
                        id="GIT-003",
                        title="Dangerous Git Hook",
                        description=f"Git hook contains dangerous pattern: {description}",
                        severity=Severity.CRITICAL,
                        category="git",
                        file_path=str(hook_file),
                        evidence=f"Pattern found: {pattern}",
                        recommendation="Review and sanitize git hook scripts"
                    ))
                    
        except Exception as e:
            self.add_finding(Finding(
                id="GIT-004",
                title="Hook Analysis Error",
                description=f"Could not analyze hook {hook_file.name}: {e}",
                severity=Severity.LOW,
                category="git"
            ))
    
    def _check_git_aliases(self) -> int:
        checks = 0
        git_configs = [
            self.target_path / ".git" / "config",
            Path.home() / ".gitconfig",
            Path("/etc/gitconfig"),
        ]
        
        for config_path in git_configs:
            if config_path.exists():
                checks += 1
                self._check_aliases_in_config(config_path)
                
        return checks
    
    def _check_aliases_in_config(self, config_path: Path):
        try:
            config = configparser.ConfigParser()
            config.read(str(config_path))
            
            if 'alias' in config:
                for alias_name, alias_value in config['alias'].items():
                    self._analyze_git_alias(alias_name, alias_value, config_path)
                    
        except Exception:
            pass
    
    def _analyze_git_alias(self, alias_name: str, alias_value: str, config_path: Path):
        dangerous_patterns = [
            (r'!\s*.*', "Shell command execution"),
            (r'.*\|\s*(bash|sh)', "Pipe to shell"),
            (r'eval\s*', "Dynamic evaluation"),
            (r'system\s*\(', "System call"),
            (r'rm\s+-rf', "Dangerous deletion"),
        ]
        
        for pattern, description in dangerous_patterns:
            if re.search(pattern, alias_value, re.IGNORECASE):
                self.add_finding(Finding(
                    id="GIT-005",
                    title="Dangerous Git Alias",
                    description=f"Git alias '{alias_name}' contains dangerous pattern: {description}",
                    severity=Severity.HIGH,
                    category="git",
                    file_path=str(config_path),
                    evidence=f"alias.{alias_name} = {alias_value}",
                    recommendation="Review and sanitize git aliases"
                ))
    
    def _check_credentials_in_config(self) -> int:
        checks = 0
        git_configs = [
            self.target_path / ".git" / "config",
            Path.home() / ".gitconfig",
        ]
        
        for config_path in git_configs:
            if config_path.exists():
                checks += 1
                try:
                    content = config_path.read_text()
                    
                    credential_patterns = [
                        (r'password\s*=\s*[^\s\n]+', "Plaintext password"),
                        (r'token\s*=\s*[^\s\n]+', "API token"),
                        (r'username\s*=\s*[^\s\n]+.*password', "Username/password combo"),
                    ]
                    
                    for pattern, description in credential_patterns:
                        if re.search(pattern, content, re.IGNORECASE):
                            self.add_finding(Finding(
                                id="GIT-006",
                                title="Credentials in Git Config",
                                description=f"Git config contains {description}",
                                severity=Severity.HIGH,
                                category="git",
                                file_path=str(config_path),
                                recommendation="Use git credential helpers or SSH keys"
                            ))
                            
                except Exception:
                    pass
                    
        return checks
    
    def _check_dangerous_core_settings(self) -> int:
        checks = 0
        git_configs = [
            self.target_path / ".git" / "config",
            Path.home() / ".gitconfig",
        ]
        
        for config_path in git_configs:
            if config_path.exists():
                checks += 1
                try:
                    config = configparser.ConfigParser()
                    config.read(str(config_path))
                    
                    if 'core' in config:
                        core_section = config['core']
                        
                        if 'editor' in core_section:
                            editor = core_section['editor']
                            if any(dangerous in editor for dangerous in ['|', ';', '&&', 'curl', 'wget']):
                                self.add_finding(Finding(
                                    id="GIT-007",
                                    title="Dangerous Git Editor",
                                    description="Git core.editor contains potentially dangerous commands",
                                    severity=Severity.MEDIUM,
                                    category="git",
                                    file_path=str(config_path),
                                    evidence=f"core.editor = {editor}",
                                    recommendation="Use a simple text editor path"
                                ))
                        
                        if 'pager' in core_section:
                            pager = core_section['pager']
                            if any(dangerous in pager for dangerous in ['|', ';', '&&', 'curl', 'wget', 'eval']):
                                self.add_finding(Finding(
                                    id="GIT-008",
                                    title="Dangerous Git Pager",
                                    description="Git core.pager contains potentially dangerous commands",
                                    severity=Severity.MEDIUM,
                                    category="git",
                                    file_path=str(config_path),
                                    evidence=f"core.pager = {pager}",
                                    recommendation="Use a simple pager like 'less' or 'more'"
                                ))
                                
                except Exception:
                    pass
                    
        return checks
    
    def _check_ssh_keys(self) -> int:
        ssh_dir = Path.home() / ".ssh"
        if not ssh_dir.exists():
            return 0
            
        checks = 1
        key_files = [f for f in ssh_dir.iterdir() if f.is_file() and not f.name.endswith('.pub')]
        
        for key_file in key_files:
            if key_file.name.startswith('id_'):
                stat_info = key_file.stat()
                
                if stat_info.st_mode & 0o077:
                    self.add_finding(Finding(
                        id="GIT-009",
                        title="SSH Key Permissions Too Permissive",
                        description=f"SSH private key has overly permissive permissions: {oct(stat_info.st_mode)[-3:]}",
                        severity=Severity.HIGH,
                        category="git",
                        file_path=str(key_file),
                        recommendation="Set permissions to 600: chmod 600 ~/.ssh/id_*"
                    ))
                
                try:
                    content = key_file.read_text()
                    if 'ENCRYPTED' not in content:
                        self.add_finding(Finding(
                            id="GIT-010",
                            title="Unencrypted SSH Key",
                            description="SSH private key is not encrypted with a passphrase",
                            severity=Severity.MEDIUM,
                            category="git",
                            file_path=str(key_file),
                            recommendation="Add a passphrase to your SSH key: ssh-keygen -p -f ~/.ssh/id_rsa"
                        ))
                except Exception:
                    pass
                    
        return checks