#!/usr/bin/env python3
"""
Exposed Files Scanner Module
Scans for sensitive files that should not be exposed (env files, config files, etc.)
and checks if they're properly excluded from version control
"""

import re
import os
import fnmatch
from pathlib import Path
from typing import List, Dict, Any, Optional, Set
from core.scanner import BaseSecurityModule, Finding, Severity, ScanResult


class SecretsScanner(BaseSecurityModule):
    def __init__(self, target_path: Path, config: Dict[str, Any]):
        super().__init__(target_path, config)
        self.module_name = "secrets"
        self.gitignore_patterns = self._load_gitignore_patterns()
        
    def scan(self) -> ScanResult:
        self.findings = []
        total_checks = 0
        
        total_checks += self._check_exposed_sensitive_files()
        total_checks += self._check_gitignore_coverage()
        total_checks += self._check_lockfiles()
        
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
    
    def _load_gitignore_patterns(self) -> Set[str]:
        """Load patterns from .gitignore files"""
        patterns = set()
        
        gitignore_locations = [
            self.target_path / ".gitignore",
            self.target_path / ".git" / "info" / "exclude"
        ]
        
        for gitignore_path in gitignore_locations:
            if gitignore_path.exists():
                try:
                    content = gitignore_path.read_text()
                    for line in content.split('\n'):
                        line = line.strip()
                        if line and not line.startswith('#'):
                            patterns.add(line)
                except Exception:
                    pass
        
        return patterns
    
    def _is_ignored_by_git(self, file_path: Path) -> bool:
        """Check if a file would be ignored by git"""
        relative_path = str(file_path.relative_to(self.target_path))
        
        for pattern in self.gitignore_patterns:
            # Handle negation patterns
            if pattern.startswith('!'):
                continue
                
            # Convert gitignore pattern to fnmatch pattern
            if pattern.endswith('/'):
                # Directory pattern
                if fnmatch.fnmatch(relative_path + '/', pattern) or fnmatch.fnmatch(relative_path, pattern[:-1]):
                    return True
            else:
                # File pattern
                if fnmatch.fnmatch(relative_path, pattern) or fnmatch.fnmatch(file_path.name, pattern):
                    return True
                # Also check if any parent directory matches
                parts = relative_path.split('/')
                for i in range(len(parts)):
                    partial_path = '/'.join(parts[:i+1])
                    if fnmatch.fnmatch(partial_path, pattern):
                        return True
        
        return False
    
    def _check_exposed_sensitive_files(self) -> int:
        """Check for sensitive files that are exposed in the repository"""
        checks = 0
        
        # Define sensitive file patterns
        sensitive_patterns = {
            # Environment files
            ".env": ("Environment file", Severity.CRITICAL),
            ".env.*": ("Environment file variant", Severity.CRITICAL),
            "*.env": ("Environment file", Severity.CRITICAL),
            
            # Configuration files with potential secrets
            "config.json": ("Configuration file", Severity.HIGH),
            "config.yaml": ("Configuration file", Severity.HIGH),
            "config.yml": ("Configuration file", Severity.HIGH),
            "secrets.json": ("Secrets file", Severity.CRITICAL),
            "secrets.yaml": ("Secrets file", Severity.CRITICAL),
            "credentials.json": ("Credentials file", Severity.CRITICAL),
            
            # Database files
            "*.db": ("Database file", Severity.HIGH),
            "*.sqlite": ("SQLite database", Severity.HIGH),
            "*.sqlite3": ("SQLite database", Severity.HIGH),
            
            # Key files
            "*.pem": ("Private key file", Severity.CRITICAL),
            "*.key": ("Key file", Severity.CRITICAL), 
            "*.p12": ("Certificate file", Severity.HIGH),
            "*.pfx": ("Certificate file", Severity.HIGH),
            "id_rsa": ("SSH private key", Severity.CRITICAL),
            "id_dsa": ("SSH private key", Severity.CRITICAL),
            "id_ed25519": ("SSH private key", Severity.CRITICAL),
            
            # Cloud provider files
            ".aws/credentials": ("AWS credentials", Severity.CRITICAL),
            ".azure/credentials": ("Azure credentials", Severity.CRITICAL),
            "gcloud/credentials.json": ("Google Cloud credentials", Severity.CRITICAL),
            
            # IDE and editor files with potential secrets
            ".vscode/settings.json": ("VS Code settings", Severity.MEDIUM),
            "*.swp": ("Vim swap file", Severity.LOW),
            "*.swo": ("Vim swap file", Severity.LOW),
            "*~": ("Backup file", Severity.LOW),
            
            # Logs that might contain secrets
            "*.log": ("Log file", Severity.MEDIUM),
            "nohup.out": ("Process output file", Severity.MEDIUM),
            
            # Backup files
            "*.bak": ("Backup file", Severity.MEDIUM),
            "*.backup": ("Backup file", Severity.MEDIUM),
            "*.orig": ("Original file backup", Severity.LOW),
            
            # Docker-related files
            ".dockercfg": ("Docker config", Severity.HIGH),
            ".docker/config.json": ("Docker config", Severity.HIGH),
            
            # Other sensitive files
            ".htpasswd": ("HTTP password file", Severity.HIGH),
            ".netrc": ("Network credentials", Severity.HIGH),
            "Thumbs.db": ("Windows thumbnail cache", Severity.LOW),
            ".DS_Store": ("macOS metadata", Severity.LOW),
        }
        
        # Scan for sensitive files and deduplicate
        found_files = {}  # path -> (description, severity)
        
        for pattern, (description, severity) in sensitive_patterns.items():
            matching_files = list(self.target_path.glob(f"**/{pattern}"))
            for file_path in matching_files:
                # Only keep the highest severity finding for each file
                if file_path not in found_files or severity.value == "critical":
                    found_files[file_path] = (description, severity)
        
        # Process each unique file once
        for file_path, (description, severity) in found_files.items():
            checks += 1
            
            # Check if file is properly ignored
            if not self._is_ignored_by_git(file_path):
                self.add_finding(Finding(
                    id="EXPOSED-001",
                    title=f"Exposed Sensitive File: {description}",
                    description=f"Sensitive file '{file_path.name}' is not excluded from version control",
                    severity=severity,
                    category="secrets",
                    file_path=str(file_path),
                    recommendation=f"Add '{file_path.name}' to .gitignore to prevent accidental commits"
                ))
        
        return max(checks, 1)
    
    def _check_gitignore_coverage(self) -> int:
        """Check if .gitignore exists and covers common sensitive patterns"""
        gitignore_path = self.target_path / ".gitignore"
        
        if not gitignore_path.exists():
            self.add_finding(Finding(
                id="GITIGNORE-001",
                title="Missing .gitignore File",
                description="No .gitignore found - sensitive files may be accidentally committed",
                severity=Severity.HIGH,
                category="secrets",
                file_path=str(self.target_path),
                recommendation="Create a .gitignore file to exclude sensitive files from version control"
            ))
            return 1
        
        # Check for common patterns that should be in .gitignore
        recommended_patterns = {
            ".env": "Environment files",
            "*.log": "Log files", 
            "node_modules/": "Node.js dependencies",
            "__pycache__/": "Python cache",
            "*.pyc": "Python compiled files",
            ".DS_Store": "macOS metadata",
            "Thumbs.db": "Windows thumbnails",
            "*.swp": "Vim swap files",
            ".vscode/": "VS Code settings (optional)",
            ".idea/": "IntelliJ settings (optional)",
        }
        
        try:
            gitignore_content = gitignore_path.read_text()
            
            for pattern, description in recommended_patterns.items():
                if pattern not in gitignore_content:
                    # Only warn for critical patterns
                    if pattern in [".env", "*.log"]:
                        self.add_finding(Finding(
                            id="GITIGNORE-002",
                            title="Missing Critical .gitignore Pattern",
                            description=f"Pattern '{pattern}' not found in .gitignore ({description})",
                            severity=Severity.MEDIUM,
                            category="secrets",
                            file_path=str(gitignore_path),
                            recommendation=f"Add '{pattern}' to .gitignore to exclude {description.lower()}"
                        ))
        
        except Exception:
            pass
        
        return 1
    
    def _check_lockfiles(self) -> int:
        """Check lock files for potential tampering indicators"""
        checks = 0
        
        lockfile_patterns = [
            "package-lock.json",
            "yarn.lock", 
            "composer.lock",
            "Pipfile.lock",
            "poetry.lock",
            "pnpm-lock.yaml",
            "Gemfile.lock"
        ]
        
        for pattern in lockfile_patterns:
            lockfiles = list(self.target_path.glob(f"**/{pattern}"))
            for lockfile in lockfiles:
                checks += 1
                self._analyze_lockfile(lockfile)
        
        return max(checks, 1)
    
    def _analyze_lockfile(self, lockfile: Path):
        """Analyze a lockfile for signs of tampering"""
        try:
            content = lockfile.read_text()
            lines = content.split('\n')
            
            # Check for suspicious patterns in lockfiles
            suspicious_patterns = [
                # Missing integrity checks
                (r'"resolved".*"integrity":\s*""', "Missing integrity check"),
                (r'"version".*"resolved".*(?!"integrity")', "Dependency without integrity"),
                
                # Suspicious domains/URLs
                (r'"resolved".*://(?!registry\.npmjs\.org|registry\.yarnpkg\.com)', "Non-standard registry"),
                (r'"resolved".*localhost', "Local registry reference"),
                (r'"resolved".*127\.0\.0\.1', "Local IP registry reference"),
                
                # Typosquatting indicators
                (r'"name":\s*"[^"]*[0-9]+[^"]*"', "Package name with unusual numbers"),
                (r'"name":\s*"[^"]*[-_][0-9]+[^"]*"', "Package name with suspicious numbering"),
                
                # Suspicious version patterns
                (r'"version":\s*"0\.0\.[0-9]+"', "Suspicious version 0.0.x"),
                (r'"version":\s*"999\.[0-9]+\.[0-9]+"', "Suspicious high version number"),
            ]
            
            for line_num, line in enumerate(lines, 1):
                for pattern, description in suspicious_patterns:
                    if re.search(pattern, line, re.IGNORECASE):
                        self.add_finding(Finding(
                            id="LOCKFILE-001",
                            title="Suspicious Lockfile Entry",
                            description=f"Potential lockfile tampering detected: {description}",
                            severity=Severity.HIGH,
                            category="secrets",
                            file_path=str(lockfile),
                            line_number=line_num,
                            evidence=line[:100] + "..." if len(line) > 100 else line,
                            recommendation="Review lockfile changes and verify package authenticity"
                        ))
                        break
            
            # Check for specific NPM package tampering patterns mentioned in NOTES.md
            if lockfile.name == "package-lock.json":
                self._check_npm_lockfile_specific(lockfile, content, lines)
                        
        except Exception:
            pass
    
    def _check_npm_lockfile_specific(self, lockfile: Path, content: str, lines: List[str]):
        """Check NPM lockfile for specific tampering patterns from NOTES.md"""
        
        # Look for dependency without integrity check (mentioned in NOTES.md line 124)
        if '"integrity":' not in content and '"resolved":' in content:
            self.add_finding(Finding(
                id="LOCKFILE-002",
                title="NPM Dependency Without Integrity Check",
                description="Dependencies found without integrity verification",
                severity=Severity.CRITICAL,
                category="secrets",
                file_path=str(lockfile),
                recommendation="Regenerate lockfile to ensure all dependencies have integrity checks"
            ))
        
        # Check for typosquatted packages (like blakejs vs bldkejs mentioned in NOTES.md)
        typosquat_indicators = [
            (r'"blakejs".*"bldkejs"', "Potential blakejs tyrosquat"),
            (r'"lodash".*"1odash"', "Potential lodash typosquat"),
            (r'"express".*"expres"', "Potential express typosquat"),
            (r'"react".*"raect"', "Potential react typosquat"),
        ]
        
        for pattern, description in typosquat_indicators:
            if re.search(pattern, content, re.IGNORECASE):
                self.add_finding(Finding(
                    id="LOCKFILE-003",
                    title="Potential Typosquatted Package",
                    description=f"Possible package typosquatting detected: {description}",
                    severity=Severity.CRITICAL,
                    category="secrets",
                    file_path=str(lockfile),
                    recommendation="Verify package names are correct and from trusted sources"
                ))