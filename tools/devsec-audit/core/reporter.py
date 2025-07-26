#!/usr/bin/env python3
"""
DevSec Audit Reporter
Generates security audit reports in multiple formats (JSON, HTML, text)
with color coding and severity-based formatting
"""

import json
import sys
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any, Optional
from jinja2 import Template
from colorama import init, Fore, Back, Style
from tabulate import tabulate

from core.scanner import ScanResult, Finding, Severity

init(autoreset=True)  # Initialize colorama


class SecurityReporter:
    def __init__(self):
        self.severity_colors = {
            Severity.CRITICAL: Fore.RED + Style.BRIGHT,
            Severity.HIGH: Fore.RED,
            Severity.MEDIUM: Fore.YELLOW,
            Severity.LOW: Fore.CYAN,
            Severity.INFO: Fore.BLUE
        }
        
        self.severity_emojis = {
            Severity.CRITICAL: "🔴",
            Severity.HIGH: "🟠", 
            Severity.MEDIUM: "🟡",
            Severity.LOW: "🟢",
            Severity.INFO: "🔵"
        }
    
    def generate_report(self, results: List[ScanResult], summary: Dict[str, Any], 
                       format_type: str = "text", output_path: Optional[str] = None) -> str:
        """Generate a security audit report in the specified format"""
        
        if format_type.lower() == "json":
            report_content = self._generate_json_report(results, summary)
        elif format_type.lower() == "html":
            report_content = self._generate_html_report(results, summary)
        else:  # Default to text
            report_content = self._generate_text_report(results, summary)
        
        if output_path:
            Path(output_path).write_text(report_content, encoding='utf-8')
            
        return report_content
    
    def _generate_text_report(self, results: List[ScanResult], summary: Dict[str, Any]) -> str:
        """Generate a colored text report similar to Lynis output"""
        report_lines = []
        
        # Header
        report_lines.extend([
            f"{Fore.CYAN}{Style.BRIGHT}=" * 60,
            f"{Fore.CYAN}{Style.BRIGHT}DevSec Audit - Security Assessment Report",
            f"{Fore.CYAN}{Style.BRIGHT}=" * 60,
            "",
            f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"Target: {summary['target_path']}",
            f"Modules Scanned: {summary['modules_scanned']}",
            "",
        ])
        
        # Overall Score
        score = summary['overall_score']
        score_color = self._get_score_color(score)
        report_lines.extend([
            f"{Fore.WHITE}{Style.BRIGHT}Overall Security Score: {score_color}{score}/100",
            "",
        ])
        
        # Summary Statistics
        severity_counts = summary['severity_counts']
        report_lines.extend([
            f"{Fore.WHITE}{Style.BRIGHT}Finding Summary:",
            f"  {self.severity_emojis[Severity.CRITICAL]} Critical: {self.severity_colors[Severity.CRITICAL]}{severity_counts['critical']}",
            f"  {self.severity_emojis[Severity.HIGH]} High:     {self.severity_colors[Severity.HIGH]}{severity_counts['high']}",
            f"  {self.severity_emojis[Severity.MEDIUM]} Medium:   {self.severity_colors[Severity.MEDIUM]}{severity_counts['medium']}",
            f"  {self.severity_emojis[Severity.LOW]} Low:      {self.severity_colors[Severity.LOW]}{severity_counts['low']}",
            f"  {self.severity_emojis[Severity.INFO]} Info:     {self.severity_colors[Severity.INFO]}{severity_counts['info']}",
            "",
        ])
        
        # Module Results
        for result in results:
            report_lines.extend(self._format_module_result(result))
        
        # Detailed Findings
        if any(result.findings for result in results):
            report_lines.extend([
                f"{Fore.WHITE}{Style.BRIGHT}=" * 60,
                f"{Fore.WHITE}{Style.BRIGHT}DETAILED FINDINGS",
                f"{Fore.WHITE}{Style.BRIGHT}=" * 60,
                "",
            ])
            
            # Group findings by severity
            all_findings = []
            for result in results:
                all_findings.extend(result.findings)
            
            findings_by_severity = {}
            for severity in Severity:
                findings_by_severity[severity] = [f for f in all_findings if f.severity == severity]
            
            for severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
                findings = findings_by_severity[severity]
                if findings:
                    report_lines.extend([
                        f"{self.severity_colors[severity]}{Style.BRIGHT}{severity.value.upper()} SEVERITY FINDINGS {self.severity_emojis[severity]}",
                        f"{self.severity_colors[severity]}{'-' * 40}",
                        "",
                    ])
                    
                    for finding in findings:
                        report_lines.extend(self._format_finding(finding))
        
        # Recommendations Summary
        report_lines.extend([
            f"{Fore.WHITE}{Style.BRIGHT}=" * 60,
            f"{Fore.WHITE}{Style.BRIGHT}RECOMMENDATIONS",
            f"{Fore.WHITE}{Style.BRIGHT}=" * 60,
            "",
        ])
        
        if score < 70:
            report_lines.append(f"{Fore.RED}⚠️  Your security score is below recommended levels!")
        elif score < 85:
            report_lines.append(f"{Fore.YELLOW}⚠️  Your security posture could be improved.")
        else:
            report_lines.append(f"{Fore.GREEN}✅ Your security posture looks good!")
        
        report_lines.extend([
            "",
            "Priority Actions:",
            f"1. Address all {self.severity_colors[Severity.CRITICAL]}CRITICAL{Style.RESET_ALL} findings immediately",
            f"2. Review and fix {self.severity_colors[Severity.HIGH]}HIGH{Style.RESET_ALL} severity issues",
            f"3. Plan remediation for {self.severity_colors[Severity.MEDIUM]}MEDIUM{Style.RESET_ALL} severity findings",
            "",
            f"{Fore.CYAN}For detailed remediation guidance, see individual finding recommendations above.",
            "",
        ])
        
        return "\n".join(report_lines)
    
    def _format_module_result(self, result: ScanResult) -> List[str]:
        """Format a single module result for text output"""
        lines = []
        
        score_color = self._get_score_color(result.score)
        status_icon = "✅" if result.score >= 80 else "⚠️" if result.score >= 60 else "❌"
        
        lines.extend([
            f"{Fore.WHITE}{Style.BRIGHT}Module: {result.module_name.upper()}",
            f"  Score: {score_color}{result.score}/100 {status_icon}",
            f"  Checks: {Fore.GREEN}{result.passed_checks}/{result.total_checks} passed{Style.RESET_ALL}",
            f"  Findings: {len(result.findings)}",
            "",
        ])
        
        return lines
    
    def _format_finding(self, finding: Finding) -> List[str]:
        """Format a single finding for text output"""
        lines = []
        severity_color = self.severity_colors[finding.severity]
        
        lines.extend([
            f"{severity_color}[{finding.id}] {finding.title}",
            f"  Description: {finding.description}",
        ])
        
        if finding.file_path:
            location = finding.file_path
            if finding.line_number:
                location += f":{finding.line_number}"
            lines.append(f"  Location: {location}")
        
        if finding.evidence:
            lines.append(f"  Evidence: {finding.evidence}")
        
        if finding.recommendation:
            lines.append(f"  {Fore.CYAN}Recommendation: {finding.recommendation}{Style.RESET_ALL}")
        
        lines.append("")
        return lines
    
    def _get_score_color(self, score: int) -> str:
        """Get color for a score based on its value"""
        if score >= 85:
            return Fore.GREEN + Style.BRIGHT
        elif score >= 70:
            return Fore.YELLOW + Style.BRIGHT
        elif score >= 50:
            return Fore.RED
        else:
            return Fore.RED + Style.BRIGHT
    
    def _generate_json_report(self, results: List[ScanResult], summary: Dict[str, Any]) -> str:
        """Generate a JSON report"""
        report_data = {
            "scan_info": {
                "timestamp": datetime.now().isoformat(),
                "target_path": summary['target_path'],
                "modules_scanned": summary['modules_scanned']
            },
            "summary": summary,
            "modules": []
        }
        
        for result in results:
            module_data = {
                "name": result.module_name,
                "score": result.score,
                "total_checks": result.total_checks,
                "passed_checks": result.passed_checks,
                "failed_checks": result.failed_checks,
                "findings": []
            }
            
            for finding in result.findings:
                finding_data = {
                    "id": finding.id,
                    "title": finding.title,
                    "description": finding.description,
                    "severity": finding.severity.value,
                    "category": finding.category,
                    "file_path": finding.file_path,
                    "line_number": finding.line_number,
                    "evidence": finding.evidence,
                    "recommendation": finding.recommendation
                }
                module_data["findings"].append(finding_data)
            
            report_data["modules"].append(module_data)
        
        return json.dumps(report_data, indent=2)
    
    def _generate_html_report(self, results: List[ScanResult], summary: Dict[str, Any]) -> str:
        """Generate an HTML report"""
        template_str = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DevSec Audit Security Report</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .header { text-align: center; margin-bottom: 30px; padding: 20px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; border-radius: 10px; }
        .score { font-size: 3em; font-weight: bold; margin: 10px 0; }
        .score.excellent { color: #28a745; }
        .score.good { color: #ffc107; }
        .score.poor { color: #dc3545; }
        .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 30px 0; }
        .summary-card { padding: 20px; border-radius: 8px; text-align: center; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
        .critical { background-color: #f8d7da; border-left: 4px solid #dc3545; }
        .high { background-color: #fff3cd; border-left: 4px solid #fd7e14; }
        .medium { background-color: #fff3cd; border-left: 4px solid #ffc107; }
        .low { background-color: #d1ecf1; border-left: 4px solid #17a2b8; }
        .info { background-color: #d1ecf1; border-left: 4px solid #007bff; }
        .module { margin: 30px 0; padding: 20px; border: 1px solid #ddd; border-radius: 8px; }
        .module-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px; }
        .module-score { font-size: 1.5em; font-weight: bold; }
        .finding { margin: 15px 0; padding: 15px; border-radius: 5px; border-left: 4px solid; }
        .finding h4 { margin: 0 0 10px 0; }
        .finding-meta { font-size: 0.9em; color: #666; margin: 5px 0; }
        .evidence { background: #f8f9fa; padding: 10px; border-radius: 4px; font-family: monospace; margin: 10px 0; }
        .recommendation { background: #e8f4fd; padding: 10px; border-radius: 4px; margin: 10px 0; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 DevSec Audit Security Report</h1>
            <p>Scan Date: {{ scan_date }}</p>
            <p>Target: {{ summary.target_path }}</p>
            <div class="score {{ score_class }}">{{ summary.overall_score }}/100</div>
        </div>
        
        <div class="summary">
            <div class="summary-card critical">
                <h3>🔴 Critical</h3>
                <div style="font-size: 2em;">{{ summary.severity_counts.critical }}</div>
            </div>
            <div class="summary-card high">
                <h3>🟠 High</h3>
                <div style="font-size: 2em;">{{ summary.severity_counts.high }}</div>
            </div>
            <div class="summary-card medium">
                <h3>🟡 Medium</h3>
                <div style="font-size: 2em;">{{ summary.severity_counts.medium }}</div>
            </div>
            <div class="summary-card low">
                <h3>🟢 Low</h3>
                <div style="font-size: 2em;">{{ summary.severity_counts.low }}</div>
            </div>
            <div class="summary-card info">
                <h3>🔵 Info</h3>
                <div style="font-size: 2em;">{{ summary.severity_counts.info }}</div>
            </div>
        </div>
        
        {% for result in results %}
        <div class="module">
            <div class="module-header">
                <h2>{{ result.module_name.upper() }} Module</h2>
                <div class="module-score {{ 'excellent' if result.score >= 85 else 'good' if result.score >= 70 else 'poor' }}">
                    {{ result.score }}/100
                </div>
            </div>
            <p>Checks: {{ result.passed_checks }}/{{ result.total_checks }} passed</p>
            
            {% for finding in result.findings %}
            <div class="finding {{ finding.severity.value }}">
                <h4>[{{ finding.id }}] {{ finding.title }}</h4>
                <p>{{ finding.description }}</p>
                {% if finding.file_path %}
                <div class="finding-meta">
                    📁 {{ finding.file_path }}{% if finding.line_number %}:{{ finding.line_number }}{% endif %}
                </div>
                {% endif %}
                {% if finding.evidence %}
                <div class="evidence">{{ finding.evidence }}</div>
                {% endif %}
                {% if finding.recommendation %}
                <div class="recommendation">
                    <strong>💡 Recommendation:</strong> {{ finding.recommendation }}
                </div>
                {% endif %}
            </div>
            {% endfor %}
        </div>
        {% endfor %}
    </div>
</body>
</html>
        '''
        
        template = Template(template_str)
        
        # Determine score class for styling
        score = summary['overall_score']
        score_class = 'excellent' if score >= 85 else 'good' if score >= 70 else 'poor'
        
        return template.render(
            scan_date=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            summary=summary,
            results=results,
            score_class=score_class
        )
    
    def print_summary(self, summary: Dict[str, Any]):
        """Print a quick summary to console"""
        score = summary['overall_score']
        score_color = self._get_score_color(score)
        
        print(f"\n{Fore.CYAN}{Style.BRIGHT}DevSec Audit Summary:")
        print(f"{Fore.CYAN}{'-' * 25}")
        print(f"Overall Score: {score_color}{score}/100{Style.RESET_ALL}")
        print(f"Total Findings: {summary['total_findings']}")
        print(f"Modules Scanned: {summary['modules_scanned']}")
        
        severity_counts = summary['severity_counts']
        if severity_counts['critical'] > 0:
            print(f"{Fore.RED}{Style.BRIGHT}⚠️  {severity_counts['critical']} Critical issues found!{Style.RESET_ALL}")
        if severity_counts['high'] > 0:
            print(f"{Fore.RED}⚠️  {severity_counts['high']} High severity issues found!{Style.RESET_ALL}")
        
        print()