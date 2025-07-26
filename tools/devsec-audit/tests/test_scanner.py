#!/usr/bin/env python3
"""
Unit tests for the DevSec Audit scanner core functionality
"""

import unittest
import tempfile
import shutil
from pathlib import Path
from unittest.mock import Mock, patch

import sys
sys.path.append(str(Path(__file__).parent.parent))

from core.scanner import SecurityScanner, BaseSecurityModule, Finding, Severity, ScanResult


class MockSecurityModule(BaseSecurityModule):
    def __init__(self, target_path: Path, config: dict):
        super().__init__(target_path, config)
        self.module_name = "mock"
    
    def scan(self) -> ScanResult:
        # Add a test finding
        self.add_finding(Finding(
            id="MOCK-001",
            title="Test Finding",
            description="This is a test finding",
            severity=Severity.HIGH,
            category="mock"
        ))
        
        return ScanResult(
            module_name=self.module_name,
            findings=self.findings,
            score=75,
            total_checks=4,
            passed_checks=3,
            failed_checks=1
        )


class TestSecurityScanner(unittest.TestCase):
    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp())
        self.scanner = SecurityScanner(str(self.temp_dir))
        
    def tearDown(self):
        shutil.rmtree(self.temp_dir)
    
    def test_scanner_initialization(self):
        self.assertEqual(self.scanner.target_path, self.temp_dir)
        self.assertIsInstance(self.scanner.config, dict)
        self.assertEqual(len(self.scanner.modules), 0)
        self.assertEqual(len(self.scanner.results), 0)
    
    def test_register_module(self):
        self.scanner.register_module("mock", MockSecurityModule)
        self.assertIn("mock", self.scanner.modules)
        self.assertEqual(self.scanner.modules["mock"], MockSecurityModule)
    
    def test_scan_with_mock_module(self):
        self.scanner.register_module("mock", MockSecurityModule)
        results = self.scanner.scan(["mock"])
        
        self.assertEqual(len(results), 1)
        result = results[0]
        self.assertEqual(result.module_name, "mock")
        self.assertEqual(result.score, 75)
        self.assertEqual(len(result.findings), 1)
        self.assertEqual(result.findings[0].id, "MOCK-001")
    
    def test_calculate_overall_score(self):
        self.scanner.register_module("mock", MockSecurityModule)
        self.scanner.scan(["mock"])
        
        overall_score = self.scanner.calculate_overall_score()
        self.assertEqual(overall_score, 75)  # Only one module with score 75
    
    def test_get_summary(self):
        self.scanner.register_module("mock", MockSecurityModule)
        self.scanner.scan(["mock"])
        
        summary = self.scanner.get_summary()
        self.assertIn("overall_score", summary)
        self.assertIn("total_findings", summary)
        self.assertIn("severity_counts", summary)
        self.assertEqual(summary["total_findings"], 1)
        self.assertEqual(summary["severity_counts"]["high"], 1)


class TestBaseSecurityModule(unittest.TestCase):
    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp())
        self.config = {"severity_filter": ["critical", "high", "medium", "low", "info"]}
        self.module = MockSecurityModule(self.temp_dir, self.config)
        
    def tearDown(self):
        shutil.rmtree(self.temp_dir)
    
    def test_add_finding(self):
        finding = Finding(
            id="TEST-001",
            title="Test Finding",
            description="Test description",
            severity=Severity.MEDIUM,
            category="test"
        )
        
        self.module.add_finding(finding)
        self.assertEqual(len(self.module.findings), 1)
        self.assertEqual(self.module.findings[0], finding)
    
    def test_severity_filter(self):
        # Set config to only show critical findings
        self.module.config["severity_filter"] = ["critical"]
        
        # Add a medium severity finding (should be filtered out)
        medium_finding = Finding(
            id="TEST-002",
            title="Medium Finding",
            description="Medium severity",
            severity=Severity.MEDIUM,
            category="test"
        )
        
        # Add a critical finding (should be included)
        critical_finding = Finding(
            id="TEST-003",
            title="Critical Finding", 
            description="Critical severity",
            severity=Severity.CRITICAL,
            category="test"
        )
        
        self.module.add_finding(medium_finding)
        self.module.add_finding(critical_finding)
        
        # Only critical finding should be added
        self.assertEqual(len(self.module.findings), 1)
        self.assertEqual(self.module.findings[0].severity, Severity.CRITICAL)


class TestFinding(unittest.TestCase):
    def test_finding_creation(self):
        finding = Finding(
            id="TEST-001",
            title="Test Finding",
            description="Test description",
            severity=Severity.HIGH,
            category="test",
            file_path="/test/path",
            line_number=42,
            recommendation="Fix this issue",
            evidence="Some evidence"
        )
        
        self.assertEqual(finding.id, "TEST-001")
        self.assertEqual(finding.title, "Test Finding")
        self.assertEqual(finding.severity, Severity.HIGH)
        self.assertEqual(finding.file_path, "/test/path")
        self.assertEqual(finding.line_number, 42)


class TestScanResult(unittest.TestCase):
    def test_scan_result_creation(self):
        findings = [
            Finding("TEST-001", "Test 1", "Description 1", Severity.HIGH, "test"),
            Finding("TEST-002", "Test 2", "Description 2", Severity.MEDIUM, "test")
        ]
        
        result = ScanResult(
            module_name="test_module",
            findings=findings,
            score=80,
            total_checks=10,
            passed_checks=8,
            failed_checks=2
        )
        
        self.assertEqual(result.module_name, "test_module")
        self.assertEqual(len(result.findings), 2)
        self.assertEqual(result.score, 80)
        self.assertEqual(result.total_checks, 10)


if __name__ == '__main__':
    unittest.main()