import os
import re
import configparser
from pathlib import Path
from typing import Dict, List, Any

from core.scanner import BaseSecurityModule, Finding, Severity, ScanResult


class GitSecurityModule(BaseSecurityModule):
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
        self.module_name = "git"
    
    def scan(self) -> ScanResult:
        self.findings = []
        total_checks = 0
        
        total_checks += self._check_git_config()
        total_checks += self._check_git_hooks()
        total_checks += self._check_git_aliases()
        total_checks += self._check_credentials_in_config()
        total_checks += self._check_dangerous_core_settings()
        total_checks += self._check_gitmodules()
        total_checks += self._check_git_includes()
        total_checks += self._check_ssh_keys()
        total_checks += self._check_gitattributes()
        total_checks += self._check_commit_identity_spoofing()
        total_checks += self._check_typosquatting_aliases()
        
        # Calculate pass/fail based on whether checks found issues
        failed_checks = min(len(self.findings), total_checks)  # Can't fail more checks than we ran
        passed_checks = total_checks - failed_checks
        score = self._calculate_module_score(total_checks, failed_checks)
        
        return ScanResult(
            module_name=self.module_name,
            findings=self.findings,
            score=score,
            total_checks=total_checks,
            passed_checks=passed_checks,
            failed_checks=failed_checks
        )
    
    def _check_git_config(self) -> int:
        """Check git configurations for security issues with enhanced parsing"""
        checks = 0
        git_configs = [
            self.target_path / ".git" / "config",
            self.target_path / ".gitconfig",  # Project-level gitconfig
            Path.home() / ".gitconfig",
            Path.home() / ".config" / "git" / "config",
            Path("/etc/gitconfig"),
        ]
        
        for config_path in git_configs:
            if config_path.exists():
                checks += 1
                # Use both configparser and manual parsing for comprehensive analysis
                self._analyze_git_config_configparser(config_path)
                self._analyze_git_config_manual(config_path)
                
        return checks
    
    def _analyze_git_config_configparser(self, config_path: Path):
        """Standard configparser analysis"""
        try:
            config = configparser.ConfigParser()
            config.read(str(config_path))
            
            for section_name in config.sections():
                section = config[section_name]
                for key, value in section.items():
                    self._check_config_value(section_name, key, value, config_path)
                    
        except Exception:
            # If configparser fails, manual parsing will catch issues
            pass
    
    def _analyze_git_config_manual(self, config_path: Path):
        """Manual parsing to catch cases configparser misses"""
        try:
            content = config_path.read_text()
            lines = content.split('\n')
            current_section = None
            
            for line_num, line in enumerate(lines, 1):
                stripped = line.strip()
                original_line = line
                
                # Skip comments and empty lines
                if not stripped or stripped.startswith('#') or stripped.startswith(';'):
                    continue
                
                # Section headers
                if stripped.startswith('[') and stripped.endswith(']'):
                    current_section = stripped[1:-1].strip()
                    continue
                
                # Key-value pairs
                if '=' in stripped and current_section:
                    try:
                        key, value = stripped.split('=', 1)
                        key = key.strip()
                        value = value.strip().strip('"\'')
                        
                        self._check_config_value_detailed(current_section, key, value, config_path, line_num, original_line)
                        
                    except ValueError:
                        continue
                        
        except Exception:
            pass
    
    def _check_config_value_detailed(self, section: str, key: str, value: str, config_path: Path, line_num: int, original_line: str):
        """Detailed analysis of git config values with comprehensive backdoor detection"""
        
        # Route to specialized checkers based on section type
        if section.startswith('alias'):
            self._check_git_alias_detailed(key, value, config_path, line_num, original_line)
        elif section == 'core':
            self._check_core_setting_detailed(key, value, config_path, line_num, original_line)
        elif section.startswith('url '):
            self._check_url_rewrite(section, key, value, config_path, line_num, original_line)
        elif section.startswith('credential'):
            self._check_credential_helper(section, key, value, config_path, line_num, original_line)
        elif section.startswith('diff ') or section.startswith('merge '):
            self._check_diff_merge_tool(section, key, value, config_path, line_num, original_line)
        elif section.startswith('filter '):
            self._check_filter_setting(section, key, value, config_path, line_num, original_line)
        elif section == 'transfer':
            self._check_transfer_setting(key, value, config_path, line_num, original_line)
        elif section.startswith('protocol '):
            self._check_protocol_setting(section, key, value, config_path, line_num, original_line)
        elif section.startswith('remote '):
            self._check_remote_config(section, key, value, config_path, line_num, original_line)
        elif section.startswith('submodule '):
            self._check_submodule_setting(section, key, value, config_path, line_num, original_line)
        elif section.startswith('include') or section.startswith('includeIf'):
            self._check_include_setting(section, key, value, config_path, line_num, original_line)
        elif section == 'gpg':
            self._check_gpg_setting(section, key, value, config_path, line_num, original_line)
        
        # Generic credential checks
        if 'url' in key.lower() and any(cred in value for cred in ['://', '@', 'token', 'password']):
            if re.search(r'://.*[@:].*@', value) or 'token=' in value or 'password=' in value:
                self.add_finding(Finding(
                    id="GIT-002",
                    title="Credentials in Git URL",
                    description=f"Git URL contains embedded credentials: {key}",
                    severity=Severity.HIGH,
                    category="git",
                    file_path=str(config_path),
                    line_number=line_num,
                    evidence=original_line,
                    recommendation="Use SSH keys or credential helpers instead of embedding credentials in URLs"
                ))
    
    def _check_core_setting_detailed(self, key: str, value: str, config_path: Path, line_num: int, original_line: str):
        """Check core git settings for dangerous configurations"""
        
        dangerous_patterns = ['|', ';', '&&', '$', 'curl', 'wget', 'bash', 'sh', 'eval', 'nc', 'python', 'perl']
        
        if key == 'editor':
            if any(pattern in value for pattern in dangerous_patterns):
                self.add_finding(Finding(
                    id="GIT-017",
                    title="Malicious Git Editor",
                    description="Git core.editor contains dangerous shell commands",
                    severity=Severity.CRITICAL,
                    category="git",
                    file_path=str(config_path),
                    line_number=line_num,
                    evidence=original_line,
                    recommendation="Use a simple text editor path"
                ))
        
        elif key == 'pager':
            if any(pattern in value for pattern in dangerous_patterns):
                self.add_finding(Finding(
                    id="GIT-018",
                    title="Malicious Git Pager",
                    description="Git core.pager contains dangerous shell commands",
                    severity=Severity.CRITICAL,
                    category="git",
                    file_path=str(config_path),
                    line_number=line_num,
                    evidence=original_line,
                    recommendation="Use a simple pager like 'less'"
                ))
        
        elif key == 'sshcommand':
            if any(pattern in value for pattern in dangerous_patterns):
                self.add_finding(Finding(
                    id="GIT-019",
                    title="Malicious Git SSH Command",
                    description="Git core.sshCommand contains dangerous shell commands",
                    severity=Severity.CRITICAL,
                    category="git",
                    file_path=str(config_path),
                    line_number=line_num,
                    evidence=original_line,
                    recommendation="Use standard SSH configuration"
                ))
        
        elif key == 'gitproxy':
            self.add_finding(Finding(
                id="GIT-020",
                title="Git Proxy Configuration",
                description="Git uses custom proxy which could intercept traffic",
                severity=Severity.HIGH,
                category="git",
                file_path=str(config_path),
                line_number=line_num,
                evidence=original_line,
                recommendation="Verify proxy configuration is trusted"
            ))
        
        elif key == 'askpass':
            if any(pattern in value for pattern in dangerous_patterns):
                self.add_finding(Finding(
                    id="GIT-021",
                    title="Malicious Git Askpass Program",
                    description="Git core.askpass points to potentially malicious program",  
                    severity=Severity.HIGH,
                    category="git",
                    file_path=str(config_path),
                    line_number=line_num,
                    evidence=original_line,
                    recommendation="Use trusted credential helper programs"
                ))
        
        elif key == 'hookspath':
            self.add_finding(Finding(
                id="GIT-022",
                title="Custom Git Hooks Directory",
                description=f"Git uses custom hooks directory: {value}",
                severity=Severity.MEDIUM,
                category="git",
                file_path=str(config_path),
                line_number=line_num,
                evidence=original_line,
                recommendation="Review custom hooks directory for malicious scripts"
            ))
    
    def _check_git_alias_detailed(self, alias_name: str, alias_value: str, config_path: Path, line_num: int, original_line: str):
        """Check git aliases for shell command execution"""
        
        # Aliases starting with ! execute shell commands
        if alias_value.startswith('!'):
            shell_command = alias_value[1:].strip()
            
            dangerous_patterns = [
                ('curl.*\\|.*bash', 'Remote script execution via curl'),
                ('wget.*\\|.*sh', 'Remote script execution via wget'),
                ('rm\\s+-rf\\s*/', 'Dangerous file deletion'),
                ('chmod\\s+777', 'Dangerous permission change'),
                ('eval\\s*\\$', 'Dynamic code evaluation'),
                ('\\$\\(.*\\)', 'Command substitution'),
                ('`.*`', 'Command substitution'),
                ('nc\\s+.*\\|', 'Netcat piping'),
                ('bash\\s+-c', 'Bash command execution'),
                ('sh\\s+-c', 'Shell command execution'),
                ('python.*-c', 'Python code execution'),
                ('perl.*-e', 'Perl code execution'),
                ('echo.*>.*bashrc', 'Shell profile modification'),
                ('crontab', 'Cron modification'),
                ('systemctl', 'Service manipulation'),
            ]
            
            severity = Severity.CRITICAL
            for pattern, description in dangerous_patterns:
                if re.search(pattern, shell_command, re.IGNORECASE):
                    self.add_finding(Finding(
                        id="GIT-023",
                        title="Malicious Git Alias with Shell Execution",
                        description=f"Git alias '{alias_name}' contains {description}",
                        severity=severity,
                        category="git",
                        file_path=str(config_path),
                        line_number=line_num,
                        evidence=original_line,
                        recommendation="Remove dangerous shell commands from git aliases"
                    ))
                    return
            
            # Any shell execution is at least medium risk
            self.add_finding(Finding(
                id="GIT-024",
                title="Git Alias with Shell Execution",
                description=f"Git alias '{alias_name}' executes shell commands",
                severity=Severity.MEDIUM,
                category="git",
                file_path=str(config_path),
                line_number=line_num,
                evidence=original_line,
                recommendation="Review shell commands in git aliases for security implications"
            ))
    
    def _check_url_rewrite(self, section: str, key: str, value: str, config_path: Path, line_num: int, original_line: str):
        """Check URL rewrites that could redirect to malicious repositories"""
        
        if key == 'insteadof':
            # Check if rewriting to suspicious domains
            suspicious_domains = [
                'localhost', '127.0.0.1', '192.168.', '10.', '172.',
                '.onion', 'bit.ly', 'tinyurl.com', 'goo.gl',
                'pastebin.com', 'hastebin.com'
            ]
            
            original_url = section.replace('url "', '').replace('"', '')
            
            if any(domain in original_url.lower() for domain in suspicious_domains):
                self.add_finding(Finding(
                    id="GIT-025",
                    title="Suspicious URL Rewrite",
                    description=f"Git rewrites URLs to suspicious domain: {value} -> {original_url}",
                    severity=Severity.HIGH,
                    category="git", 
                    file_path=str(config_path),
                    line_number=line_num,
                    evidence=original_line,
                    recommendation="Verify URL rewrite destination is trusted"
                ))
    
    def _check_credential_helper(self, section: str, key: str, value: str, config_path: Path, line_num: int, original_line: str):
        """Check credential helpers for malicious programs"""
        
        if key == 'helper':
            if value and value != 'store' and value != 'cache' and value != 'osxkeychain':
                # Custom credential helper - could steal credentials
                dangerous_patterns = [
                    '/tmp/', 'curl', 'wget', 'nc', 'bash', 'sh', 'python', 'perl', '.py', '.sh', '.exe'
                ]
                
                if any(pattern in value for pattern in dangerous_patterns):
                    self.add_finding(Finding(
                        id="GIT-026",
                        title="Malicious Credential Helper",
                        description="Git uses suspicious credential helper that could steal credentials",
                        severity=Severity.CRITICAL,
                        category="git",
                        file_path=str(config_path),
                        line_number=line_num,
                        evidence=original_line,
                        recommendation="Use trusted credential helpers only"
                    ))
    
    def _check_diff_merge_tool(self, section: str, key: str, value: str, config_path: Path, line_num: int, original_line: str):
        """Check diff and merge tools for command injection"""
        
        if key in ['cmd', 'path']:
            dangerous_patterns = ['|', ';', '&&', '$', 'curl', 'wget', 'bash', 'sh', 'eval']
            
            if any(pattern in value for pattern in dangerous_patterns):
                tool_type = 'diff' if section.startswith('diff') else 'merge'
                self.add_finding(Finding(
                    id="GIT-027",
                    title=f"Malicious Git {tool_type.title()} Tool",
                    description=f"Git {tool_type} tool contains dangerous shell patterns",
                    severity=Severity.HIGH,
                    category="git",
                    file_path=str(config_path),
                    line_number=line_num,
                    evidence=original_line,
                    recommendation=f"Use trusted {tool_type} tools without shell metacharacters"
                ))
    
    def _check_filter_setting(self, section: str, key: str, value: str, config_path: Path, line_num: int, original_line: str):
        """Check filter settings that execute on checkout/checkin"""
        
        if key in ['clean', 'smudge']:
            # Filters execute on every checkout/checkin - very dangerous
            self.add_finding(Finding(
                id="GIT-028", 
                title="Git Filter Command",
                description=f"Git filter executes command on {key}: {value}",
                severity=Severity.CRITICAL,
                category="git",
                file_path=str(config_path),
                line_number=line_num,
                evidence=original_line,
                recommendation="Review filter commands as they execute on every checkout/checkin"
            ))
    
    def _check_transfer_setting(self, key: str, value: str, config_path: Path, line_num: int, original_line: str):
        """Check transfer settings for security issues"""
        
        if key == 'fsckobjects' and value.lower() == 'false':
            self.add_finding(Finding(
                id="GIT-029",
                title="Git FSCK Disabled",
                description="Git object integrity checking is disabled",
                severity=Severity.MEDIUM,
                category="git",
                file_path=str(config_path),
                line_number=line_num,
                evidence=original_line,
                recommendation="Enable fsckObjects for better security"
            ))
    
    def _check_protocol_setting(self, section: str, key: str, value: str, config_path: Path, line_num: int, original_line: str):
        """Check protocol settings for insecure configurations"""
        
        protocol = section.replace('protocol "', '').replace('"', '')
        
        if key == 'allow' and value.lower() == 'always':
            if protocol in ['file', 'ext']:
                self.add_finding(Finding(
                    id="GIT-030",
                    title="Dangerous Git Protocol Enabled",
                    description=f"Git allows dangerous protocol: {protocol}",
                    severity=Severity.HIGH,
                    category="git",
                    file_path=str(config_path),
                    line_number=line_num,
                    evidence=original_line,
                    recommendation="Disable dangerous protocols or restrict to trusted repositories"
                ))
    
    def _check_remote_config(self, section: str, key: str, value: str, config_path: Path, line_num: int, original_line: str):
        """Check remote configurations for suspicious settings"""
        
        if key == 'url':
            # Check for malicious remote URLs
            suspicious_patterns = [
                r'github\.com/.*/$(pwned|backdoor|malicious|evil|hack)',
                r'(pwned|backdoor|malicious|evil|hack)',
                r'\.onion', 
                r'192\.168\.',
                r'10\.',
                r'172\.(1[6-9]|2[0-9]|3[01])\.',
                r'localhost',
                r'127\.0\.0\.1',
                r'bit\.ly',
                r'tinyurl\.com'
            ]
            
            for pattern in suspicious_patterns:
                if re.search(pattern, value, re.IGNORECASE):
                    severity = Severity.CRITICAL if any(word in value.lower() for word in ['pwned', 'backdoor', 'malicious', 'evil']) else Severity.HIGH
                    
                    self.add_finding(Finding(
                        id="GIT-031",
                        title="Suspicious Remote URL",
                        description=f"Git remote has suspicious URL: {value}",
                        severity=severity,
                        category="git",
                        file_path=str(config_path),
                        line_number=line_num,
                        evidence=original_line,
                        recommendation="Verify remote repository source is trusted"
                    ))
                    break
    
    def _check_submodule_setting(self, section: str, key: str, value: str, config_path: Path, line_num: int, original_line: str):
        """Check submodule settings for security issues"""
        
        if key == 'url':
            self._check_submodule_url(value, config_path, section)
        elif key == 'update':
            # Check for dangerous update commands
            if '!' in value or any(dangerous in value for dangerous in ['curl', 'wget', 'bash', 'sh']):
                self.add_finding(Finding(
                    id="GIT-032",
                    title="Dangerous Submodule Update Command",
                    description=f"Submodule uses dangerous update command: {value}",
                    severity=Severity.CRITICAL,
                    category="git",
                    file_path=str(config_path),
                    line_number=line_num,
                    evidence=original_line,
                    recommendation="Use standard submodule update methods"
                ))
    
    def _check_include_setting(self, section: str, key: str, value: str, config_path: Path, line_num: int, original_line: str):
        """Check include/includeIf settings for malicious includes"""
        
        if key == 'path':
            # Check for suspicious include paths
            suspicious_indicators = [
                'script', '.sh', '.py', '.exe', '/tmp/', 'temp',
                'backdoor', 'pwned', 'evil', 'hack', 'malicious'
            ]
            
            if any(indicator in value.lower() for indicator in suspicious_indicators):
                self.add_finding(Finding(
                    id="GIT-033",
                    title="Suspicious Git Include Path",
                    description=f"Git config includes suspicious file: {value}",
                    severity=Severity.HIGH,
                    category="git",
                    file_path=str(config_path),
                    line_number=line_num,
                    evidence=original_line,
                    recommendation="Review included configuration file for malicious content"
                ))
            
            # If the included file exists, try to analyze it too
            if not value.startswith('/'):
                full_path = self.target_path / value
            else:
                full_path = Path(value)
                
            if full_path.exists():
                try:
                    content = full_path.read_text()
                    if any(dangerous in content for dangerous in ['curl', 'wget', 'bash', 'sh', 'eval', 'exec']):
                        self.add_finding(Finding(
                            id="GIT-034",
                            title="Malicious Content in Included Git Config",
                            description=f"Included git config contains dangerous commands: {value}",
                            severity=Severity.CRITICAL, 
                            category="git",
                            file_path=str(full_path),
                            recommendation="Remove malicious included configuration"
                        ))
                except Exception:
                    pass
    
    def _check_gpg_setting(self, section: str, key: str, value: str, config_path: Path, line_num: int, original_line: str):
        """Check GPG settings for security issues"""
        
        if key == 'program':
            # GPG program should be a trusted executable
            dangerous_patterns = ['|', ';', '&&', '$', 'curl', 'wget', 'bash', 'sh', 'eval']
            
            if any(pattern in value for pattern in dangerous_patterns):
                self.add_finding(Finding(
                    id="GIT-035",
                    title="Malicious GPG Program",
                    description="Git GPG program contains dangerous shell patterns",
                    severity=Severity.HIGH,
                    category="git",
                    file_path=str(config_path),
                    line_number=line_num,
                    evidence=original_line,
                    recommendation="Use trusted GPG executable path"
                ))
    
    def _check_config_value(self, section: str, key: str, value: str, config_path: Path):
        """Legacy method for basic config checks"""
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
                            if any(dangerous in editor for dangerous in ['|', ';', '&&', 'curl', 'wget', 'echo']):
                                self.add_finding(Finding(
                                    id="GIT-007",
                                    title="Dangerous Git Editor",
                                    description="Git core.editor contains potentially dangerous commands",
                                    severity=Severity.HIGH,
                                    category="git",
                                    file_path=str(config_path),
                                    evidence=f"core.editor = {editor}",
                                    recommendation="Use a simple text editor path"
                                ))
                        
                        if 'pager' in core_section:
                            pager = core_section['pager']
                            if any(dangerous in pager for dangerous in ['|', ';', '&&', 'curl', 'wget', 'eval', 'echo']):
                                self.add_finding(Finding(
                                    id="GIT-008",
                                    title="Dangerous Git Pager",
                                    description="Git core.pager contains potentially dangerous commands",
                                    severity=Severity.HIGH,
                                    category="git",
                                    file_path=str(config_path),
                                    evidence=f"core.pager = {pager}",
                                    recommendation="Use a simple pager like 'less' or 'more'"
                                ))
                        
                        if 'sshcommand' in core_section:
                            ssh_cmd = core_section['sshcommand']
                            if any(dangerous in ssh_cmd for dangerous in ['touch', 'rm', 'echo', 'curl', 'wget', ';', '&&', '|']):
                                self.add_finding(Finding(
                                    id="GIT-011",
                                    title="Dangerous Git SSH Command",
                                    description="Git core.sshCommand contains potentially dangerous commands",
                                    severity=Severity.CRITICAL,
                                    category="git", 
                                    file_path=str(config_path),
                                    evidence=f"core.sshCommand = {ssh_cmd}",
                                    recommendation="Use standard SSH configuration"
                                ))
                        
                        if 'hookspath' in core_section:
                            hooks_path = core_section['hookspath']
                            custom_hooks_dir = self.target_path / hooks_path
                            if custom_hooks_dir.exists():
                                self.add_finding(Finding(
                                    id="GIT-012", 
                                    title="Custom Git Hooks Directory",
                                    description=f"Git uses custom hooks directory: {hooks_path}",
                                    severity=Severity.MEDIUM,
                                    category="git",
                                    file_path=str(config_path),
                                    evidence=f"core.hooksPath = {hooks_path}",
                                    recommendation="Review custom hooks for malicious content"
                                ))
                                # Check the custom hooks directory
                                self._check_custom_hooks_directory(custom_hooks_dir)
                                
                except Exception:
                    pass
                    
        return checks
    
    def _check_custom_hooks_directory(self, hooks_dir: Path):
        """Check custom hooks directory for malicious scripts"""
        if not hooks_dir.exists():
            return
            
        for hook_file in hooks_dir.iterdir():
            if hook_file.is_file() and os.access(hook_file, os.X_OK):
                self._analyze_hook_file(hook_file)
    
    def _check_gitmodules(self) -> int:
        """Check .gitmodules for malicious submodule URLs"""
        gitmodules_path = self.target_path / ".gitmodules"
        
        if not gitmodules_path.exists():
            return 0
            
        try:
            config = configparser.ConfigParser()
            config.read(str(gitmodules_path))
            
            for section_name in config.sections():
                if section_name.startswith('submodule '):
                    if 'url' in config[section_name]:
                        url = config[section_name]['url']
                        self._check_submodule_url(url, gitmodules_path, section_name)
                        
            return 1
            
        except Exception as e:
            self.add_finding(Finding(
                id="GIT-013",
                title="Gitmodules Parse Error",
                description=f"Could not parse .gitmodules: {e}",
                severity=Severity.LOW,
                category="git",
                file_path=str(gitmodules_path)
            ))
            return 1
    
    def _check_submodule_url(self, url: str, gitmodules_path: Path, section_name: str):
        """Check if submodule URL is suspicious"""
        suspicious_patterns = [
            r'github\.com/.*/$(pwned|backdoor|malicious|evil|hack)',
            r'(pwned|backdoor|malicious|evil|hack)',
            r'\.onion',
            r'192\.168\.',
            r'10\.',
            r'172\.(1[6-9]|2[0-9]|3[01])\.',
            r'localhost',
            r'127\.0\.0\.1'
        ]
        
        for pattern in suspicious_patterns:
            if re.search(pattern, url, re.IGNORECASE):
                severity = Severity.CRITICAL if any(word in url.lower() for word in ['pwned', 'backdoor', 'malicious', 'evil']) else Severity.HIGH
                
                self.add_finding(Finding(
                    id="GIT-014",
                    title="Suspicious Submodule URL",
                    description=f"Submodule has suspicious URL: {section_name}",
                    severity=severity,
                    category="git",
                    file_path=str(gitmodules_path),
                    evidence=f"url = {url}",
                    recommendation="Verify submodule source is trusted"
                ))
                break
    
    def _check_git_includes(self) -> int:
        """Check for git include/includeIf configurations that might load malicious configs"""
        checks = 0
        git_configs = [
            self.target_path / ".git" / "config",
            self.target_path / ".gitconfig",
        ]
        
        for config_path in git_configs:
            if config_path.exists():
                checks += 1
                try:
                    config = configparser.ConfigParser()  
                    config.read(str(config_path))
                    
                    # Check for include sections
                    for section_name in config.sections():
                        if section_name.startswith('include') or section_name.startswith('includeIf'):
                            if 'path' in config[section_name]:
                                include_path = config[section_name]['path']
                                self._check_include_path(include_path, config_path, section_name)
                                
                except Exception:
                    pass
                    
        return checks
    
    def _check_include_path(self, include_path: str, config_path: Path, section_name: str):
        """Check if included git config path is suspicious"""
        # Resolve relative paths
        if not include_path.startswith('/'):
            full_path = self.target_path / include_path
        else:
            full_path = Path(include_path)
            
        # Check for suspicious include paths
        suspicious_indicators = [
            'script', '.sh', '.py', '.exe', '/tmp/', 'temp', 
            'backdoor', 'pwned', 'evil', 'hack', 'malicious'
        ]
        
        if any(indicator in include_path.lower() for indicator in suspicious_indicators):
            self.add_finding(Finding(
                id="GIT-015",
                title="Suspicious Git Include Path", 
                description=f"Git config includes suspicious file: {section_name}",
                severity=Severity.HIGH,
                category="git",
                file_path=str(config_path),
                evidence=f"{section_name} path = {include_path}",
                recommendation="Review included configuration file for malicious content"
            ))
        
        # If the included file exists, try to analyze it too
        if full_path.exists():
            try:
                content = full_path.read_text()
                if any(dangerous in content for dangerous in ['curl', 'wget', 'bash', 'sh', 'eval', 'exec']):
                    self.add_finding(Finding(
                        id="GIT-016",
                        title="Malicious Content in Included Git Config",
                        description=f"Included git config contains dangerous commands: {include_path}",
                        severity=Severity.CRITICAL,
                        category="git", 
                        file_path=str(full_path),
                        recommendation="Remove malicious included configuration"
                    ))
            except Exception:
                pass
    
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
    
    def _check_gitattributes(self) -> int:
        """Check .gitattributes for malicious merge drivers"""
        gitattributes_path = self.target_path / ".gitattributes"
        
        if not gitattributes_path.exists():
            return 0
            
        try:
            content = gitattributes_path.read_text()
            lines = content.split('\n')
            
            for line_num, line in enumerate(lines, 1):
                stripped = line.strip()
                if not stripped or stripped.startswith('#'):
                    continue
                
                # Check for merge driver assignments
                if 'merge=' in stripped:
                    self.add_finding(Finding(
                        id="GIT-036",
                        title="Custom Merge Driver Detected",
                        description=f"Custom merge driver found: {stripped}",
                        severity=Severity.HIGH,
                        category="git",
                        file_path=str(gitattributes_path),
                        line_number=line_num,
                        evidence=line,
                        recommendation="Review custom merge drivers for malicious code execution"
                    ))
            
            return 1
            
        except Exception:
            return 1
    
    def _check_commit_identity_spoofing(self) -> int:
        """Check for potential commit identity spoofing indicators"""
        checks = 0
        git_configs = [
            self.target_path / ".git" / "config",
            self.target_path / ".gitconfig",
        ]
        
        for config_path in git_configs:
            if config_path.exists():
                checks += 1
                try:
                    config = configparser.ConfigParser()
                    config.read(str(config_path))
                    
                    if 'user' in config:
                        user_section = config['user']
                        
                        # Check for suspicious user configurations
                        suspicious_names = [
                            'admin', 'administrator', 'root', 'system', 'service',
                            'bot', 'automated', 'ci', 'github-actions', 'dependabot'
                        ]
                        
                        if 'name' in user_section:
                            name = user_section['name'].lower()
                            if any(suspicious in name for suspicious in suspicious_names):
                                self.add_finding(Finding(
                                    id="GIT-037",
                                    title="Suspicious Git User Identity",
                                    description=f"Potentially spoofed git user name: {user_section['name']}",
                                    severity=Severity.MEDIUM,
                                    category="git",
                                    file_path=str(config_path),
                                    evidence=f"user.name = {user_section['name']}",
                                    recommendation="Verify this is the correct user identity and enable GPG signing"
                                ))
                        
                        # Check if GPG signing is disabled (potential for spoofing)
                        if 'signingkey' not in user_section:
                            self.add_finding(Finding(
                                id="GIT-038",
                                title="GPG Signing Not Configured",
                                description="Git commits are not GPG signed, allowing potential identity spoofing",
                                severity=Severity.LOW,
                                category="git",
                                file_path=str(config_path),
                                recommendation="Configure GPG signing to prevent commit identity spoofing"
                            ))
                                
                except Exception:
                    pass
                    
        return checks
    
    def _check_typosquatting_aliases(self) -> int:
        """Check for typosquatting aliases that could execute malicious commands"""
        checks = 0
        git_configs = [
            self.target_path / ".git" / "config",
            self.target_path / ".gitconfig",
        ]
        
        # Common git command typos that attackers might alias
        typosquat_patterns = [
            'puhs', 'pushs', 'phus', 'pish', 'psuh',  # push typos
            'comit', 'committ', 'comitt', 'comiit',   # commit typos
            'checkot', 'chekout', 'checkout',         # checkout typos  
            'cloen', 'clne', 'clon',                  # clone typos
            'fecth', 'featch', 'fetxh',               # fetch typos
            'merg', 'merge', 'mrege',                 # merge typos
            'reabse', 'rebas', 'rabase',              # rebase typos
            'stash', 'stsh', 'sash',                  # stash typos
        ]
        
        for config_path in git_configs:
            if config_path.exists():
                checks += 1
                try:
                    config = configparser.ConfigParser()
                    config.read(str(config_path))
                    
                    if 'alias' in config:
                        for alias_name, alias_value in config['alias'].items():
                            # Check if alias name matches common typos
                            if alias_name.lower() in typosquat_patterns:
                                severity = Severity.CRITICAL if alias_value.startswith('!') else Severity.HIGH
                                
                                self.add_finding(Finding(
                                    id="GIT-039",
                                    title="Potential Typosquatting Git Alias",
                                    description=f"Git alias '{alias_name}' matches common command typo",
                                    severity=severity,
                                    category="git",
                                    file_path=str(config_path),
                                    evidence=f"alias.{alias_name} = {alias_value}",
                                    recommendation="Remove typosquatting aliases to prevent accidental malicious execution"
                                ))
                                
                except Exception:
                    pass
                    
        return checks