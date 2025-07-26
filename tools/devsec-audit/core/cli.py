#!/usr/bin/env python3
"""
DevSec Audit CLI
Command-line interface for the DevSec security auditor
"""

import sys
import click
from pathlib import Path
from typing import Optional, List

from core.scanner import SecurityScanner
from core.reporter import SecurityReporter
from modules.git_security import GitSecurityModule
from modules.docker_security import DockerSecurityModule  
from modules.vscode_security import VSCodeSecurityModule
from modules.secrets_scanner import SecretsScanner


@click.command()
@click.option('--target', '-t', 
              type=click.Path(exists=True, path_type=Path),
              default=Path.cwd(),
              help='Target directory to scan (default: current directory)')
@click.option('--modules', '-m',
              help='Comma-separated list of modules to run (git,docker,vscode,secrets)')
@click.option('--format', '-f',
              type=click.Choice(['text', 'json', 'html'], case_sensitive=False),
              default='text',
              help='Output format')
@click.option('--output', '-o',
              type=click.Path(path_type=Path),
              help='Output file path (default: stdout for text, devsec-report.{ext} for others)')
@click.option('--config', '-c',
              type=click.Path(exists=True, path_type=Path),
              help='Configuration file path')
@click.option('--severity', '-s',
              help='Minimum severity level to report (critical,high,medium,low,info)')
@click.option('--quick', '-q',
              is_flag=True,
              help='Quick scan - run essential checks only')
@click.option('--verbose', '-v',
              is_flag=True,
              help='Verbose output')
@click.option('--no-color',
              is_flag=True,
              help='Disable colored output')
@click.version_option(version='1.0.0', prog_name='devsec-audit')
def main(target: Path, modules: Optional[str], format: str, output: Optional[Path],
         config: Optional[Path], severity: Optional[str], quick: bool, 
         verbose: bool, no_color: bool):
    """
    DevSec Audit - Security auditor for development environments
    
    Scans development projects for security issues including:
    - Git configuration vulnerabilities
    - Docker security misconfigurations  
    - VS Code security settings
    - Hardcoded secrets and credentials
    
    Examples:
      devsec-audit --target /path/to/project
      devsec-audit --modules git,docker --format html --output report.html
      devsec-audit --quick --severity high
    """
    
    # Disable colors if requested
    if no_color:
        import colorama
        colorama.init(strip=True, convert=False)
    
    try:
        # Initialize scanner
        scanner = SecurityScanner(
            target_path=str(target.resolve()),
            config_path=str(config) if config else None
        )
        
        # Register available modules
        scanner.register_module('git', GitSecurityModule)
        scanner.register_module('docker', DockerSecurityModule)
        scanner.register_module('vscode', VSCodeSecurityModule)
        scanner.register_module('secrets', SecretsScanner)
        
        # Parse modules to scan
        modules_to_scan = None
        if modules:
            modules_to_scan = [m.strip() for m in modules.split(',')]
            # Validate module names
            valid_modules = {'git', 'docker', 'vscode', 'secrets'}
            invalid_modules = set(modules_to_scan) - valid_modules
            if invalid_modules:
                click.echo(f"Error: Invalid modules: {', '.join(invalid_modules)}", err=True)
                click.echo(f"Valid modules: {', '.join(valid_modules)}", err=True)
                sys.exit(1)
        elif quick:
            # Quick scan - essential modules only
            modules_to_scan = ['secrets', 'git']
        
        # Apply severity filter if specified
        if severity:
            severity_levels = ['critical', 'high', 'medium', 'low', 'info']
            if severity.lower() not in severity_levels:
                click.echo(f"Error: Invalid severity level: {severity}", err=True)
                click.echo(f"Valid levels: {', '.join(severity_levels)}", err=True)
                sys.exit(1)
            
            # Update scanner config to filter by severity
            if scanner.config is None:
                scanner.config = {}
            
            # Include specified severity and all higher severities
            min_index = severity_levels.index(severity.lower())
            scanner.config['severity_filter'] = severity_levels[:min_index + 1]
        
        if verbose:
            click.echo(f"🔍 Starting DevSec audit of: {target}")
            click.echo(f"📋 Modules: {modules_to_scan or scanner.config['modules']}")
            if quick:
                click.echo("⚡ Running in quick scan mode")
        
        # Run the scan
        results = scanner.scan(modules_to_scan)
        
        if not results:
            click.echo("❌ No scan results generated. Check if target directory is valid.", err=True)
            sys.exit(1)
        
        # Generate summary
        summary = scanner.get_summary()
        
        # Initialize reporter
        reporter = SecurityReporter()
        
        # Print summary to console (always shown)
        if format.lower() == 'text':
            reporter.print_summary(summary)
        
        # Determine output path
        if not output and format.lower() != 'text':
            extensions = {'json': 'json', 'html': 'html'}
            output = Path(f"devsec-report.{extensions[format.lower()]}")
        
        # Generate and output report
        report_content = reporter.generate_report(
            results, 
            summary, 
            format_type=format,
            output_path=str(output) if output else None
        )
        
        if format.lower() == 'text':
            if output:
                output.write_text(report_content, encoding='utf-8')
                click.echo(f"📄 Report saved to: {output}")
            else:
                click.echo(report_content)
        else:
            click.echo(f"📄 {format.upper()} report saved to: {output}")
        
        # Exit with error code if critical or high severity issues found
        severity_counts = summary['severity_counts']
        if severity_counts['critical'] > 0:
            if verbose:
                click.echo("❌ Critical security issues found!", err=True)
            sys.exit(2)  # Critical issues
        elif severity_counts['high'] > 0:
            if verbose:
                click.echo("⚠️  High severity security issues found!", err=True)
            sys.exit(1)  # High severity issues
        else:
            if verbose:
                click.echo("✅ Scan completed successfully!")
            sys.exit(0)  # Success
            
    except KeyboardInterrupt:
        click.echo("\n🛑 Scan interrupted by user", err=True)
        sys.exit(130)
    except Exception as e:
        click.echo(f"❌ Scan failed: {e}", err=True)
        if verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


@click.group()
def cli():
    """DevSec Audit CLI tools"""
    pass


@cli.command()
@click.option('--target', '-t',
              type=click.Path(exists=True, path_type=Path),
              default=Path.cwd(),
              help='Target directory')
def info(target: Path):
    """Show information about the target directory and available scans"""
    
    click.echo(f"🔍 DevSec Audit - Target Analysis")
    click.echo(f"{'=' * 40}")
    click.echo(f"Target: {target.resolve()}")
    click.echo(f"Exists: {'✅' if target.exists() else '❌'}")
    click.echo(f"Is Directory: {'✅' if target.is_dir() else '❌'}")
    click.echo()
    
    # Check what can be scanned
    checks = {
        'Git Repository': (target / '.git').exists(),
        'Docker Files': bool(list(target.glob('**/Dockerfile*')) or list(target.glob('**/docker-compose*.yml'))),
        'VS Code Config': (target / '.vscode').exists(),
        'DevContainer': ((target / '.devcontainer').exists() or (target / '.devcontainer.json').exists()),
        'Environment Files': bool(list(target.glob('**/.env*'))),
        'Python Files': bool(list(target.glob('**/*.py'))),
        'JavaScript Files': bool(list(target.glob('**/*.js')) or list(target.glob('**/*.ts'))),
        'Config Files': bool(list(target.glob('**/config.*')) or list(target.glob('**/*.config.*')))
    }
    
    click.echo("📋 Scannable Components:")
    for component, available in checks.items():
        status = "✅" if available else "❌"
        click.echo(f"  {status} {component}")
    
    click.echo()
    recommended_modules = []
    if checks['Git Repository']:
        recommended_modules.append('git')
    if checks['Docker Files'] or checks['DevContainer']:
        recommended_modules.append('docker')
    if checks['VS Code Config']:
        recommended_modules.append('vscode')
    if any([checks['Environment Files'], checks['Python Files'], checks['JavaScript Files']]):
        recommended_modules.append('secrets')
    
    if recommended_modules:
        click.echo(f"💡 Recommended modules: {', '.join(recommended_modules)}")
        click.echo(f"   Run: devsec-audit --target {target} --modules {','.join(recommended_modules)}")
    else:
        click.echo("⚠️  No specific security modules recommended for this directory")


@cli.command()
def modules():
    """List available security modules"""
    
    modules_info = {
        'git': {
            'name': 'Git Security',
            'description': 'Scans Git configurations, hooks, aliases, and SSH keys',
            'checks': ['Config files', 'Git hooks', 'Dangerous aliases', 'SSH key permissions', 'Credentials in URLs']
        },
        'docker': {
            'name': 'Docker Security', 
            'description': 'Analyzes Docker and container configurations',
            'checks': ['Dockerfile best practices', 'Privileged containers', 'Volume mounts', 'DevContainer configs']
        },
        'vscode': {
            'name': 'VS Code Security',
            'description': 'Reviews VS Code settings and extensions',
            'checks': ['Dangerous settings', 'Auto-execution', 'Extension security', 'Workspace trust']
        },
        'secrets': {
            'name': 'Secrets Scanner',
            'description': 'Detects hardcoded secrets and credentials',
            'checks': ['API keys', 'Passwords', 'Tokens', 'Database credentials', 'Private keys']
        }
    }
    
    click.echo("🔧 Available Security Modules:")
    click.echo("=" * 50)
    
    for module_id, info in modules_info.items():
        click.echo(f"\n📦 {info['name']} ({module_id})")
        click.echo(f"   {info['description']}")
        click.echo("   Checks:")
        for check in info['checks']:
            click.echo(f"     • {check}")


if __name__ == '__main__':
    main()