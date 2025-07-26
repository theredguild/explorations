#!/usr/bin/env python3
"""
Docker Security Module
Scans for Docker-related security issues including Dockerfile configurations,
container privileges, and dangerous volume mounts
"""

import re
import json
from pathlib import Path
from typing import List, Dict, Any, Optional
from core.scanner import BaseSecurityModule, Finding, Severity, ScanResult


class DockerSecurityModule(BaseSecurityModule):
    def __init__(self, target_path: Path, config: Dict[str, Any]):
        super().__init__(target_path, config)
        self.module_name = "docker"
        
    def scan(self) -> ScanResult:
        self.findings = []
        total_checks = 0
        
        total_checks += self._check_dockerfiles()
        total_checks += self._check_docker_compose()
        total_checks += self._check_devcontainer()
        total_checks += self._check_docker_ignore()
        
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
    
    def _check_dockerfiles(self) -> int:
        dockerfile_patterns = ["Dockerfile", "Dockerfile.*", "*.dockerfile"]
        dockerfiles = []
        
        for pattern in dockerfile_patterns:
            dockerfiles.extend(self.target_path.glob(f"**/{pattern}"))
            
        if not dockerfiles:
            return 0
            
        checks = 0
        for dockerfile in dockerfiles:
            if dockerfile.is_file():
                checks += 1
                self._analyze_dockerfile(dockerfile)
                
        return checks
    
    def _analyze_dockerfile(self, dockerfile_path: Path):
        try:
            content = dockerfile_path.read_text()
            lines = content.split('\n')
            
            self._check_base_image(content, dockerfile_path)
            self._check_user_privileges(content, dockerfile_path)
            self._check_secrets_in_dockerfile(content, dockerfile_path)
            self._check_dangerous_commands(lines, dockerfile_path)
            self._check_exposed_ports(content, dockerfile_path)
            
        except Exception as e:
            self.add_finding(Finding(
                id="DOCKER-001",
                title="Dockerfile Parse Error",
                description=f"Could not parse Dockerfile: {e}",
                severity=Severity.LOW,
                category="docker",
                file_path=str(dockerfile_path)
            ))
    
    def _check_base_image(self, content: str, dockerfile_path: Path):
        from_matches = re.findall(r'^FROM\s+(.+)', content, re.MULTILINE | re.IGNORECASE)
        
        for from_line in from_matches:
            image = from_line.strip()
            
            if ':latest' in image or not ':' in image:
                self.add_finding(Finding(
                    id="DOCKER-002",
                    title="Unpinned Base Image",
                    description="Dockerfile uses unpinned or 'latest' tag for base image",
                    severity=Severity.MEDIUM,
                    category="docker",
                    file_path=str(dockerfile_path),
                    evidence=f"FROM {image}",
                    recommendation="Use specific version tags for base images (e.g., ubuntu:20.04)"
                ))
            
            suspicious_registries = ['dockerhub.io', 'docker.io']
            if not any(trusted in image for trusted in ['gcr.io', 'quay.io', 'registry.redhat.io']):
                if not image.startswith(('ubuntu', 'debian', 'alpine', 'centos', 'fedora', 'node', 'python')):
                    self.add_finding(Finding(
                        id="DOCKER-003",
                        title="Untrusted Base Image",
                        description="Dockerfile uses potentially untrusted base image",
                        severity=Severity.LOW,
                        category="docker",
                        file_path=str(dockerfile_path),
                        evidence=f"FROM {image}",
                        recommendation="Use official images from trusted registries"
                    ))
    
    def _check_user_privileges(self, content: str, dockerfile_path: Path):
        if not re.search(r'^USER\s+(?!root)', content, re.MULTILINE | re.IGNORECASE):
            self.add_finding(Finding(
                id="DOCKER-004",
                title="Container Running as Root",
                description="Dockerfile does not specify a non-root user",
                severity=Severity.HIGH,
                category="docker",
                file_path=str(dockerfile_path),
                recommendation="Add 'USER' instruction to run container as non-root user"
            ))
    
    def _check_secrets_in_dockerfile(self, content: str, dockerfile_path: Path):
        secret_patterns = [
            (r'API_KEY\s*=\s*["\']?[\w-]{10,}', "API Key"),
            (r'SECRET_KEY\s*=\s*["\']?[\w-]{10,}', "Secret Key"),
            (r'PASSWORD\s*=\s*["\']?[\w-]{5,}', "Password"),
            (r'TOKEN\s*=\s*["\']?[\w-]{10,}', "Token"),
            (r'AWS_SECRET_ACCESS_KEY\s*=', "AWS Secret"),
            (r'GITHUB_TOKEN\s*=', "GitHub Token"),
        ]
        
        for pattern, secret_type in secret_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                self.add_finding(Finding(
                    id="DOCKER-005",
                    title="Hardcoded Secret in Dockerfile",
                    description=f"Dockerfile contains hardcoded {secret_type}",
                    severity=Severity.CRITICAL,
                    category="docker",
                    file_path=str(dockerfile_path),
                    recommendation="Use Docker secrets or environment variables at runtime"
                ))
    
    def _check_dangerous_commands(self, lines: List[str], dockerfile_path: Path):
        dangerous_patterns = [
            (r'curl\s+.*\|\s*bash', "Piping curl to bash"),
            (r'wget\s+.*\|\s*sh', "Piping wget to shell"),
            (r'chmod\s+777', "Overly permissive permissions"),
            (r'--privileged', "Privileged mode"),
            (r'--cap-add\s+SYS_ADMIN', "Dangerous capability"),
        ]
        
        for i, line in enumerate(lines, 1):
            for pattern, description in dangerous_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    self.add_finding(Finding(
                        id="DOCKER-006",
                        title="Dangerous Command in Dockerfile",
                        description=f"Dockerfile contains dangerous pattern: {description}",
                        severity=Severity.HIGH,
                        category="docker",
                        file_path=str(dockerfile_path),
                        line_number=i,
                        evidence=line.strip(),
                        recommendation="Avoid dangerous commands and excessive privileges"
                    ))
    
    def _check_exposed_ports(self, content: str, dockerfile_path: Path):
        expose_matches = re.findall(r'^EXPOSE\s+(.+)', content, re.MULTILINE | re.IGNORECASE)
        
        dangerous_ports = {
            '22': 'SSH',
            '3389': 'RDP',
            '5432': 'PostgreSQL',
            '3306': 'MySQL',
            '27017': 'MongoDB',
            '6379': 'Redis',
        }
        
        for expose_line in expose_matches:
            ports = expose_line.strip().split()
            for port in ports:
                port_num = port.split('/')[0]  # Remove protocol if present
                if port_num in dangerous_ports:
                    self.add_finding(Finding(
                        id="DOCKER-007",
                        title="Dangerous Port Exposed",
                        description=f"Dockerfile exposes potentially dangerous port: {port} ({dangerous_ports[port_num]})",
                        severity=Severity.MEDIUM,
                        category="docker",
                        file_path=str(dockerfile_path),
                        evidence=f"EXPOSE {port}",
                        recommendation="Only expose necessary ports and use proper authentication"
                    ))
    
    def _check_docker_compose(self) -> int:
        compose_files = list(self.target_path.glob("**/docker-compose*.yml")) + \
                      list(self.target_path.glob("**/docker-compose*.yaml"))
        
        if not compose_files:
            return 0
            
        checks = 0
        for compose_file in compose_files:
            checks += 1
            self._analyze_docker_compose(compose_file)
            
        return checks
    
    def _analyze_docker_compose(self, compose_path: Path):
        try:
            import yaml
            content = compose_path.read_text()
            compose_data = yaml.safe_load(content)
            
            if 'services' in compose_data:
                for service_name, service_config in compose_data['services'].items():
                    self._check_compose_service(service_name, service_config, compose_path)
                    
        except Exception as e:
            self.add_finding(Finding(
                id="DOCKER-008",
                title="Docker Compose Parse Error",
                description=f"Could not parse docker-compose file: {e}",
                severity=Severity.LOW,
                category="docker",
                file_path=str(compose_path)
            ))
    
    def _check_compose_service(self, service_name: str, service_config: Dict, compose_path: Path):
        if service_config.get('privileged'):
            self.add_finding(Finding(
                id="DOCKER-009",
                title="Privileged Container in Compose",
                description=f"Service '{service_name}' runs in privileged mode",
                severity=Severity.CRITICAL,
                category="docker",
                file_path=str(compose_path),
                recommendation="Remove privileged mode unless absolutely necessary"
            ))
        
        volumes = service_config.get('volumes', [])
        dangerous_mounts = [
            '/', '/etc', '/var/run/docker.sock', '/proc', '/sys', '/dev'
        ]
        
        for volume in volumes:
            if isinstance(volume, str):
                volume_parts = volume.split(':')
                if len(volume_parts) >= 2:
                    host_path = volume_parts[0]
                    if host_path in dangerous_mounts:
                        self.add_finding(Finding(
                            id="DOCKER-010",
                            title="Dangerous Volume Mount",
                            description=f"Service '{service_name}' mounts dangerous host path: {host_path}",
                            severity=Severity.HIGH,
                            category="docker",
                            file_path=str(compose_path),
                            evidence=volume,
                            recommendation="Avoid mounting sensitive host directories"
                        ))
        
        cap_add = service_config.get('cap_add', [])
        dangerous_caps = ['SYS_ADMIN', 'NET_ADMIN', 'SYS_PTRACE', 'SYS_MODULE']
        
        for cap in cap_add:
            if cap in dangerous_caps:
                self.add_finding(Finding(
                    id="DOCKER-011",
                    title="Dangerous Capability Added",
                    description=f"Service '{service_name}' adds dangerous capability: {cap}",
                    severity=Severity.HIGH,
                    category="docker",
                    file_path=str(compose_path),
                    recommendation="Only add necessary capabilities"
                ))
    
    def _check_devcontainer(self) -> int:
        devcontainer_files = [
            self.target_path / ".devcontainer" / "devcontainer.json",
            self.target_path / ".devcontainer.json"
        ]
        
        checks = 0
        for devcontainer_file in devcontainer_files:
            if devcontainer_file.exists():
                checks += 1
                self._analyze_devcontainer(devcontainer_file)
                
        return checks
    
    def _analyze_devcontainer(self, devcontainer_path: Path):
        try:
            content = devcontainer_path.read_text()
            devcontainer_data = json.loads(content)
            
            if devcontainer_data.get('privileged'):
                self.add_finding(Finding(
                    id="DOCKER-012",
                    title="Privileged DevContainer",
                    description="DevContainer runs in privileged mode",
                    severity=Severity.HIGH,
                    category="docker",
                    file_path=str(devcontainer_path),
                    recommendation="Remove privileged mode unless absolutely necessary"
                ))
            
            mounts = devcontainer_data.get('mounts', [])
            for mount in mounts:
                if isinstance(mount, str) and mount.startswith('source=/'):
                    source = mount.split(',')[0].replace('source=', '')
                    if source in ['/', '/etc', '/var/run/docker.sock']:
                        self.add_finding(Finding(
                            id="DOCKER-013",
                            title="Dangerous DevContainer Mount",
                            description=f"DevContainer mounts dangerous host path: {source}",
                            severity=Severity.HIGH,
                            category="docker",
                            file_path=str(devcontainer_path),
                            evidence=mount,
                            recommendation="Avoid mounting sensitive host directories"
                        ))
            
            post_create_command = devcontainer_data.get('postCreateCommand')
            if post_create_command:
                dangerous_commands = ['curl', 'wget', 'sudo', 'chmod 777']
                if any(cmd in str(post_create_command) for cmd in dangerous_commands):
                    self.add_finding(Finding(
                        id="DOCKER-014",
                        title="Dangerous DevContainer Post-Create Command",
                        description="DevContainer postCreateCommand contains potentially dangerous operations",
                        severity=Severity.MEDIUM,
                        category="docker",
                        file_path=str(devcontainer_path),
                        evidence=str(post_create_command)[:100],
                        recommendation="Review and sanitize post-create commands"
                    ))
                    
        except Exception as e:
            self.add_finding(Finding(
                id="DOCKER-015",
                title="DevContainer Parse Error",
                description=f"Could not parse devcontainer.json: {e}",
                severity=Severity.LOW,
                category="docker",
                file_path=str(devcontainer_path)
            ))
    
    def _check_docker_ignore(self) -> int:
        dockerignore_path = self.target_path / ".dockerignore"
        
        if not dockerignore_path.exists():
            self.add_finding(Finding(
                id="DOCKER-016",
                title="Missing .dockerignore",
                description="No .dockerignore file found",
                severity=Severity.LOW,
                category="docker",
                recommendation="Create .dockerignore to exclude sensitive files from build context"
            ))
            return 1
        
        try:
            content = dockerignore_path.read_text()
            sensitive_patterns = ['.env', '*.key', '*.pem', '.git', 'node_modules', '*.log']
            
            missing_patterns = []
            for pattern in sensitive_patterns:
                if pattern not in content:
                    missing_patterns.append(pattern)
            
            if missing_patterns:
                self.add_finding(Finding(
                    id="DOCKER-017",
                    title="Incomplete .dockerignore",
                    description=f"Missing patterns in .dockerignore: {', '.join(missing_patterns)}",
                    severity=Severity.LOW,
                    category="docker",
                    file_path=str(dockerignore_path),
                    recommendation="Add common sensitive file patterns to .dockerignore"
                ))
                
        except Exception:
            pass
            
        return 1