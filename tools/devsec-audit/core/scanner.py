#!/usr/bin/env python3
"""
DevSec Audit - Core Scanner Engine
Main scanning engine that orchestrates security checks across different modules
"""

import os
import sys
import json
import yaml
from pathlib import Path
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from enum import Enum


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class Finding:
    id: str
    title: str
    description: str
    severity: Severity
    category: str
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    recommendation: Optional[str] = None
    evidence: Optional[str] = None


@dataclass
class ScanResult:
    module_name: str
    findings: List[Finding]
    score: int
    total_checks: int
    passed_checks: int
    failed_checks: int


class SecurityScanner:
    def __init__(self, target_path: str, config_path: Optional[str] = None):
        self.target_path = Path(target_path).resolve()
        self.config = self._load_config(config_path)
        self.modules = {}
        self.results = []
        
    def _load_config(self, config_path: Optional[str]) -> Dict[str, Any]:
        default_config = {
            "modules": ["git", "docker", "vscode", "secrets"],
            "severity_filter": ["critical", "high", "medium", "low", "info"],
            "whitelist": [],
            "scoring": {
                "git": 20,
                "docker": 25,
                "vscode": 15,
                "secrets": 25,
                "filesystem": 15
            }
        }
        
        if config_path and Path(config_path).exists():
            with open(config_path, 'r') as f:
                user_config = yaml.safe_load(f)
                default_config.update(user_config)
                
        return default_config
    
    def register_module(self, name: str, module_class):
        self.modules[name] = module_class
        
    def scan(self, modules: Optional[List[str]] = None) -> List[ScanResult]:
        if not self.target_path.exists():
            raise FileNotFoundError(f"Target path does not exist: {self.target_path}")
            
        modules_to_scan = modules or self.config["modules"]
        self.results = []
        
        for module_name in modules_to_scan:
            if module_name in self.modules:
                print(f"[*] Scanning with {module_name} module...")
                module_instance = self.modules[module_name](
                    self.target_path, 
                    self.config
                )
                result = module_instance.scan()
                self.results.append(result)
                
        return self.results
    
    def calculate_overall_score(self) -> int:
        if not self.results:
            return 0
            
        total_weighted_score = 0
        total_weight = 0
        
        for result in self.results:
            weight = self.config["scoring"].get(result.module_name, 10)
            total_weighted_score += result.score * weight
            total_weight += weight
            
        return int(total_weighted_score / total_weight) if total_weight > 0 else 0
    
    def get_summary(self) -> Dict[str, Any]:
        total_findings = sum(len(r.findings) for r in self.results)
        
        severity_counts = {s.value: 0 for s in Severity}
        for result in self.results:
            for finding in result.findings:
                severity_counts[finding.severity.value] += 1
                
        return {
            "overall_score": self.calculate_overall_score(),
            "total_findings": total_findings,
            "severity_counts": severity_counts,
            "modules_scanned": len(self.results),
            "target_path": str(self.target_path)
        }


class BaseSecurityModule:
    def __init__(self, target_path: Path, config: Dict[str, Any]):
        self.target_path = target_path
        self.config = config
        self.findings = []
        
    def scan(self) -> ScanResult:
        raise NotImplementedError("Subclasses must implement scan method")
    
    def add_finding(self, finding: Finding):
        if self._should_report_finding(finding):
            self.findings.append(finding)
    
    def _should_report_finding(self, finding: Finding) -> bool:
        if finding.severity.value not in self.config["severity_filter"]:
            return False
            
        for whitelist_item in self.config.get("whitelist", []):
            if finding.id == whitelist_item.get("id"):
                return False
                
        return True
    
    def _calculate_module_score(self, total_checks: int, failed_checks: int) -> int:
        if total_checks == 0:
            return 100
        return max(0, int(100 - (failed_checks / total_checks * 100)))