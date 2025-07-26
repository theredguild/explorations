#!/usr/bin/env python3
"""
VS Code Security Module
Scans for VS Code related security issues including malicious extensions,
dangerous settings, automated tasks, and workspace configurations
"""

import json
import re
from pathlib import Path
from typing import List, Dict, Any, Optional
from core.scanner import BaseSecurityModule, Finding, Severity, ScanResult


class VSCodeSecurityModule(BaseSecurityModule):
    def __init__(self, target_path: Path, config: Dict[str, Any]):
        super().__init__(target_path, config)
        self.module_name = "vscode"
        
    def scan(self) -> ScanResult:
        self.findings = []
        total_checks = 0
        
        total_checks += self._check_vscode_settings()
        total_checks += self._check_vscode_tasks()
        total_checks += self._check_vscode_launch()
        total_checks += self._check_vscode_extensions()
        total_checks += self._check_workspace_trust()
        
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
    
    def _check_vscode_settings(self) -> int:
        settings_files = [
            self.target_path / ".vscode" / "settings.json",
            Path.home() / ".vscode" / "settings.json",
            Path.home() / "Library" / "Application Support" / "Code" / "User" / "settings.json",  # macOS
            Path.home() / ".config" / "Code" / "User" / "settings.json",  # Linux
        ]
        
        checks = 0
        for settings_file in settings_files:
            if settings_file.exists():
                checks += 1
                self._analyze_settings_file(settings_file)
                
        return checks
    
    def _analyze_settings_file(self, settings_path: Path):
        try:
            content = settings_path.read_text()
            settings = json.loads(content)
            
            self._check_dangerous_settings(settings, settings_path)
            self._check_terminal_settings(settings, settings_path)
            self._check_python_settings(settings, settings_path)
            self._check_auto_execution_settings(settings, settings_path)
            
        except json.JSONDecodeError as e:
            self.add_finding(Finding(
                id="VSCODE-001",
                title="VS Code Settings Parse Error",
                description=f"Could not parse VS Code settings.json: {e}",
                severity=Severity.LOW,
                category="vscode",
                file_path=str(settings_path)
            ))
        except Exception as e:
            self.add_finding(Finding(
                id="VSCODE-002",
                title="VS Code Settings Access Error",
                description=f"Could not read VS Code settings: {e}",
                severity=Severity.LOW,
                category="vscode",
                file_path=str(settings_path)
            ))
    
    def _check_dangerous_settings(self, settings: Dict, settings_path: Path):
        dangerous_settings = {
            "security.workspace.trust.enabled": ("false", "Workspace trust disabled"),
            "extensions.autoUpdate": ("true", "Auto-update extensions enabled"),
            "extensions.autoCheckUpdates": ("true", "Auto-check for extension updates"),
            "telemetry.telemetryLevel": ("all", "Full telemetry enabled"),
            "update.mode": ("start", "Auto-update VS Code enabled"),
        }
        
        for setting_key, (dangerous_value, description) in dangerous_settings.items():
            if setting_key in settings:
                if str(settings[setting_key]).lower() == dangerous_value.lower():
                    self.add_finding(Finding(
                        id="VSCODE-003",
                        title="Dangerous VS Code Setting",
                        description=f"{description}: {setting_key} = {settings[setting_key]}",
                        severity=Severity.MEDIUM,
                        category="vscode",
                        file_path=str(settings_path),
                        evidence=f'"{setting_key}": {json.dumps(settings[setting_key])}',
                        recommendation=f"Consider setting {setting_key} to a safer value"
                    ))
    
    def _check_terminal_settings(self, settings: Dict, settings_path: Path):
        terminal_settings = [
            "terminal.integrated.shell.windows",
            "terminal.integrated.shell.osx",
            "terminal.integrated.shell.linux",
            "terminal.integrated.defaultProfile.windows",
            "terminal.integrated.defaultProfile.osx",
            "terminal.integrated.defaultProfile.linux",
        ]
        
        for setting in terminal_settings:
            if setting in settings:
                shell_path = settings[setting]
                if isinstance(shell_path, str):
                    suspicious_patterns = [
                        r'.*\.exe$',  # Windows executables in wrong context
                        r'.*powershell.*',  # PowerShell usage
                        r'.*cmd.*',  # Command prompt usage
                        r'/tmp/.*',  # Temporary executables
                        r'.*\|\|.*',  # Command chaining
                        r'.*&&.*',  # Command chaining
                    ]
                    
                    for pattern in suspicious_patterns:
                        if re.search(pattern, shell_path, re.IGNORECASE):
                            self.add_finding(Finding(
                                id="VSCODE-004",
                                title="Suspicious Terminal Configuration",
                                description=f"Terminal shell setting contains suspicious pattern: {setting}",
                                severity=Severity.MEDIUM,
                                category="vscode",
                                file_path=str(settings_path),
                                evidence=f'"{setting}": "{shell_path}"',
                                recommendation="Use standard system shells"
                            ))
    
    def _check_python_settings(self, settings: Dict, settings_path: Path):
        python_settings = {
            "python.defaultInterpreterPath": "Custom Python interpreter path",
            "python.pythonPath": "Deprecated Python path setting",
        }
        
        for setting, description in python_settings.items():
            if setting in settings:
                python_path = settings[setting]
                if isinstance(python_path, str):
                    suspicious_locations = [
                        r'/tmp/',
                        r'\\temp\\',
                        r'\.\./',
                        r'http://',
                        r'https://',
                    ]
                    
                    for location in suspicious_locations:
                        if re.search(location, python_path, re.IGNORECASE):
                            self.add_finding(Finding(
                                id="VSCODE-005",
                                title="Suspicious Python Interpreter",
                                description=f"{description} points to suspicious location",
                                severity=Severity.HIGH,
                                category="vscode",
                                file_path=str(settings_path),
                                evidence=f'"{setting}": "{python_path}"',
                                recommendation="Use trusted Python interpreters from standard locations"
                            ))
    
    def _check_auto_execution_settings(self, settings: Dict, settings_path: Path):
        auto_exec_settings = {
            "python.terminal.activateEnvironment": "Auto-activate Python environment",
            "python.terminal.executeInFileDir": "Auto-execute in file directory",
            "code-runner.runInTerminal": "Auto-run code in terminal",
            "code-runner.saveFileBeforeRun": "Auto-save before running code",
        }
        
        for setting, description in auto_exec_settings.items():
            if setting in settings and settings[setting] is True:
                self.add_finding(Finding(
                    id="VSCODE-006",
                    title="Auto-Execution Setting Enabled",
                    description=f"{description} is enabled",
                    severity=Severity.LOW,
                    category="vscode",
                    file_path=str(settings_path),
                    evidence=f'"{setting}": true',
                    recommendation="Review auto-execution settings for security implications"
                ))
    
    def _check_vscode_tasks(self) -> int:
        tasks_file = self.target_path / ".vscode" / "tasks.json"
        
        if not tasks_file.exists():
            return 0
            
        try:
            content = tasks_file.read_text()
            tasks_data = json.loads(content)
            
            if "tasks" in tasks_data:
                for task in tasks_data["tasks"]:
                    self._analyze_task(task, tasks_file)
                    
            return 1
            
        except Exception as e:
            self.add_finding(Finding(
                id="VSCODE-007",
                title="VS Code Tasks Parse Error",
                description=f"Could not parse tasks.json: {e}",
                severity=Severity.LOW,
                category="vscode",
                file_path=str(tasks_file)
            ))
            return 1
    
    def _analyze_task(self, task: Dict, tasks_file: Path):
        task_label = task.get("label", "Unknown Task")
        command = task.get("command", "")
        args = task.get("args", [])
        
        dangerous_commands = [
            "curl", "wget", "powershell", "cmd", "bash", "sh", 
            "python", "node", "eval", "exec"
        ]
        
        full_command = f"{command} {' '.join(args)}" if args else command
        
        for dangerous_cmd in dangerous_commands:
            if dangerous_cmd in command.lower() or any(dangerous_cmd in str(arg).lower() for arg in args):
                severity = Severity.HIGH if dangerous_cmd in ["curl", "wget", "eval", "exec"] else Severity.MEDIUM
                
                self.add_finding(Finding(
                    id="VSCODE-008",
                    title="Dangerous VS Code Task",
                    description=f"Task '{task_label}' contains potentially dangerous command: {dangerous_cmd}",
                    severity=severity,
                    category="vscode",
                    file_path=str(tasks_file),
                    evidence=full_command[:100],
                    recommendation="Review task commands for security implications"
                ))
        
        if task.get("runOptions", {}).get("runOn") == "folderOpen":
            self.add_finding(Finding(
                id="VSCODE-009",
                title="Auto-Run Task on Folder Open",
                description=f"Task '{task_label}' is configured to run automatically when folder opens",
                severity=Severity.HIGH,
                category="vscode",
                file_path=str(tasks_file),
                recommendation="Avoid auto-running tasks on folder open"
            ))
    
    def _check_vscode_launch(self) -> int:
        launch_file = self.target_path / ".vscode" / "launch.json"
        
        if not launch_file.exists():
            return 0
            
        try:
            content = launch_file.read_text()
            launch_data = json.loads(content)
            
            if "configurations" in launch_data:
                for config in launch_data["configurations"]:
                    self._analyze_launch_config(config, launch_file)
                    
            return 1
            
        except Exception as e:
            self.add_finding(Finding(
                id="VSCODE-010",
                title="VS Code Launch Config Parse Error",
                description=f"Could not parse launch.json: {e}",
                severity=Severity.LOW,
                category="vscode",
                file_path=str(launch_file)
            ))
            return 1
    
    def _analyze_launch_config(self, config: Dict, launch_file: Path):
        config_name = config.get("name", "Unknown Config")
        program = config.get("program", "")
        python_path = config.get("pythonPath", "")
        console = config.get("console", "")
        
        if program and not program.startswith(("${workspaceFolder}", "${file}")):
            if any(suspicious in program for suspicious in ["/tmp/", "\\temp\\", "../"]):
                self.add_finding(Finding(
                    id="VSCODE-011",
                    title="Suspicious Launch Program Path",
                    description=f"Launch config '{config_name}' uses suspicious program path",
                    severity=Severity.MEDIUM,
                    category="vscode",
                    file_path=str(launch_file),
                    evidence=f"program: {program}",
                    recommendation="Use relative paths within the workspace"
                ))
        
        if python_path and any(suspicious in python_path for suspicious in ["/tmp/", "\\temp\\", "http"]):
            self.add_finding(Finding(
                id="VSCODE-012",
                title="Suspicious Python Path in Launch Config",
                description=f"Launch config '{config_name}' uses suspicious Python path",
                severity=Severity.HIGH,
                category="vscode",
                file_path=str(launch_file),
                evidence=f"pythonPath: {python_path}",
                recommendation="Use trusted Python interpreters"
            ))
        
        if console == "externalTerminal":
            self.add_finding(Finding(
                id="VSCODE-013",
                title="External Terminal Usage",
                description=f"Launch config '{config_name}' uses external terminal",
                severity=Severity.LOW,
                category="vscode",
                file_path=str(launch_file),
                recommendation="Consider using integrated terminal for better security"
            ))
    
    def _check_vscode_extensions(self) -> int:
        extensions_file = self.target_path / ".vscode" / "extensions.json"
        
        if not extensions_file.exists():
            return 0
            
        try:
            content = extensions_file.read_text()
            extensions_data = json.loads(content)
            
            recommendations = extensions_data.get("recommendations", [])
            unwanted_recommendations = extensions_data.get("unwantedRecommendations", [])
            
            self._check_extension_recommendations(recommendations, extensions_file)
            self._check_extension_security(recommendations, extensions_file)
            
            return 1
            
        except Exception as e:
            self.add_finding(Finding(
                id="VSCODE-014",
                title="VS Code Extensions Parse Error",
                description=f"Could not parse extensions.json: {e}",
                severity=Severity.LOW,
                category="vscode",
                file_path=str(extensions_file)
            ))
            return 1
    
    def _check_extension_recommendations(self, recommendations: List[str], extensions_file: Path):
        for extension in recommendations:
            if not self._is_trusted_publisher(extension):
                self.add_finding(Finding(
                    id="VSCODE-015",
                    title="Untrusted Extension Recommendation",
                    description=f"Recommended extension from potentially untrusted publisher: {extension}",
                    severity=Severity.MEDIUM,
                    category="vscode",
                    file_path=str(extensions_file),
                    evidence=extension,
                    recommendation="Verify publisher and extension security before installation"
                ))
    
    def _check_extension_security(self, recommendations: List[str], extensions_file: Path):
        high_risk_extensions = [
            "code-runner",  # Can execute arbitrary code
            "remote-ssh",   # Network access
            "remote-containers",  # Container access
        ]
        
        for extension in recommendations:
            extension_name = extension.split('.')[-1] if '.' in extension else extension
            
            if any(risky in extension_name.lower() for risky in high_risk_extensions):
                self.add_finding(Finding(
                    id="VSCODE-016",
                    title="High-Risk Extension Recommended",
                    description=f"High-risk extension recommended: {extension}",
                    severity=Severity.MEDIUM,
                    category="vscode",
                    file_path=str(extensions_file),
                    evidence=extension,
                    recommendation="Review security implications of this extension"
                ))
    
    def _is_trusted_publisher(self, extension: str) -> bool:
        trusted_publishers = [
            "ms-python", "ms-vscode", "microsoft", "redhat", "golang",
            "rust-lang", "ms-dotnettools", "ms-vscode-remote", "github"
        ]
        
        publisher = extension.split('.')[0] if '.' in extension else ""
        return publisher.lower() in trusted_publishers
    
    def _check_workspace_trust(self) -> int:
        workspace_files = list(self.target_path.glob("*.code-workspace"))
        
        checks = 0
        for workspace_file in workspace_files:
            checks += 1
            try:
                content = workspace_file.read_text()
                workspace_data = json.loads(content)
                
                settings = workspace_data.get("settings", {})
                if settings.get("security.workspace.trust.enabled") is False:
                    self.add_finding(Finding(
                        id="VSCODE-017",
                        title="Workspace Trust Disabled",
                        description="Workspace trust is disabled in workspace file",
                        severity=Severity.MEDIUM,
                        category="vscode",
                        file_path=str(workspace_file),
                        recommendation="Enable workspace trust for better security"
                    ))
                    
            except Exception:
                pass
                
        return checks