#!/usr/bin/env python3
"""
Skill Security Audit - Main Scanning Engine

A comprehensive security scanner for Claude Code skills to detect
supply chain attack vectors, malicious code patterns, and potential backdoors.

Usage:
    python scan_skill.py <skill_path> [options]

Options:
    --format {console,json,html}    Output format (default: console)
    --output FILE                   Save report to file
    --verbose                       Show detailed progress
    --severity {critical,high,medium,low}  Minimum severity to report
"""

import argparse
import json
import os
import sys
import yaml
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

# Import scanners - add parent directory to path
sys.path.insert(0, str(Path(__file__).parent))
from scripts.scanners import PythonScanner, BashScanner, SkillMetadataScanner

# Version information
__version__ = "1.0.0"
__author__ = "liuyang21cn"


class ScanConfig:
    """Configuration for security scan."""

    def __init__(self):
        self.skill_path: Path = Path()
        self.output_format: str = "console"
        self.output_file: Optional[Path] = None
        self.verbose: bool = False
        self.min_severity: str = "low"
        self.include_info: bool = False
        self.max_file_size: int = 10 * 1024 * 1024  # 10MB
        self.excluded_dirs: Set[str] = {
            '.git', '.svn', 'node_modules', '__pycache__', '.pytest_cache',
            'venv', 'env', '.env', 'dist', 'build', '.tox', '.idea', '.vscode'
        }


class RuleLoader:
    """Loads and manages security rules from YAML files."""

    def __init__(self, rules_dir: Path):
        self.rules_dir = rules_dir
        self.rules: List[Dict] = []
        self._load_all_rules()

    def _load_all_rules(self) -> None:
        """Load all rule files from the rules directory."""
        if not self.rules_dir.exists():
            print(f"Warning: Rules directory not found: {self.rules_dir}")
            return

        for rule_file in self.rules_dir.glob("*.yml"):
            try:
                with open(rule_file, 'r', encoding='utf-8') as f:
                    data = yaml.safe_load(f)
                    if data and 'rules' in data:
                        for rule in data['rules']:
                            rule['_source_file'] = rule_file.name
                        self.rules.extend(data['rules'])
            except Exception as e:
                print(f"Warning: Failed to load rules from {rule_file}: {e}")

        print(f"Loaded {len(self.rules)} security rules")

    def get_rules_for_language(self, language: str) -> List[Dict]:
        """Get all rules applicable to a specific language."""
        matching_rules = []
        for rule in self.rules:
            languages = rule.get('languages', [])
            if language.lower() in [lang.lower() for lang in languages]:
                matching_rules.append(rule)
        return matching_rules


class SecurityScanner:
    """Main security scanner orchestrator."""

    def __init__(self, config: ScanConfig):
        self.config = config
        self.findings: List[Dict] = []
        self.scanned_files: int = 0
        self.total_files: int = 0

        # Load rules
        script_dir = Path(__file__).parent
        rules_dir = script_dir.parent / 'rules'
        self.rule_loader = RuleLoader(rules_dir)

        # Initialize scanners
        self.python_scanner = PythonScanner(self.rule_loader.rules)
        self.bash_scanner = BashScanner(self.rule_loader.rules)
        self.metadata_scanner = SkillMetadataScanner()

    def scan(self) -> List[Dict]:
        """Run the complete security scan."""
        skill_path = self.config.skill_path

        if not skill_path.exists():
            print(f"Error: Skill path does not exist: {skill_path}")
            return []

        print(f"\n[SCAN] Starting security scan of: {skill_path}")
        print("=" * 70)

        # Enumerate all files
        all_files = self._enumerate_files(skill_path)
        self.total_files = len(all_files)
        print(f"[FILE] Found {self.total_files} files to scan\n")

        # Scan each file
        for file_path in all_files:
            self.scanned_files += 1
            if self.config.verbose:
                print(f"  [{self.scanned_files}/{self.total_files}] Scanning: {file_path.name}")

            try:
                self._scan_file(file_path)
            except Exception as e:
                if self.config.verbose:
                    print(f"    [WARN]  Error scanning {file_path}: {e}")

        # Print summary
        print(f"\n[OK] Scan complete!")
        print(f"   Files scanned: {self.scanned_files}")
        print(f"   Total findings: {len(self.findings)}")

        # Group findings by severity
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        for finding in self.findings:
            sev = finding.get('severity', 'low')
            if sev in severity_counts:
                severity_counts[sev] += 1

        print(f"   Critical: {severity_counts['critical']} | "
              f"High: {severity_counts['high']} | "
              f"Medium: {severity_counts['medium']} | "
              f"Low: {severity_counts['low']}")

        return self.findings

    def _enumerate_files(self, skill_path: Path) -> List[Path]:
        """Enumerate all files to be scanned."""
        all_files = []

        if skill_path.is_file():
            return [skill_path]

        for root, dirs, files in os.walk(skill_path):
            # Remove excluded directories
            dirs[:] = [d for d in dirs if d not in self.config.excluded_dirs]

            for filename in files:
                file_path = Path(root) / filename

                # Skip files that are too large
                try:
                    if file_path.stat().st_size > self.config.max_file_size:
                        if self.config.verbose:
                            print(f"  Skipping large file: {file_path}")
                        continue
                except OSError:
                    continue

                all_files.append(file_path)

        return all_files

    def _scan_file(self, file_path: Path) -> None:
        """Scan a single file based on its type."""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except (IOError, OSError) as e:
            if self.config.verbose:
                print(f"  Could not read {file_path}: {e}")
            return

        filename = file_path.name.lower()
        suffix = file_path.suffix.lower()

        # Route to appropriate scanner
        if filename == 'skill.md':
            findings = self.metadata_scanner.scan_skill_md(file_path, content)
            self._add_findings(findings)

        elif suffix == '.py' or filename.endswith('.pyw'):
            findings = self.python_scanner.scan_file(file_path, content)
            self._add_findings(findings)

        elif suffix in ['.sh', '.bash'] or filename.endswith('.zsh'):
            # Check if it's actually a shell script
            if content.startswith('#!/bin/bash') or content.startswith('#!/bin/sh') or \
               content.startswith('#!/usr/bin/env bash') or content.startswith('#!/usr/bin/env sh'):
                findings = self.bash_scanner.scan_file(file_path, content)
                self._add_findings(findings)

        # Also check if it's a shell script without extension
        elif content.startswith('#!/bin/bash') or content.startswith('#!/bin/sh'):
            findings = self.bash_scanner.scan_file(file_path, content)
            self._add_findings(findings)

        # Scan all text files for generic security issues
        self._scan_generic_security_issues(file_path, content)

    def _scan_generic_security_issues(self, file_path: Path, content: str) -> None:
        """Scan for security issues applicable to all text files."""
        lines = content.split('\n')

        # Check for hardcoded secrets
        secret_patterns = [
            (r'\b[A-Za-z0-9_]*password\s*=\s*[\'"][^\'"]{4,}[\'"]', 'hardcoded-password'),
            (r'\b[A-Za-z0-9_]*secret\s*=\s*[\'"][^\'"]{8,}[\'"]', 'hardcoded-secret'),
            (r'\b[A-Za-z0-9_]*api_key\s*=\s*[\'"][^\'"]{10,}[\'"]', 'hardcoded-api-key'),
            (r'\b[A-Za-z0-9_]*token\s*=\s*[\'"][^\'"]{10,}[\'"]', 'hardcoded-token'),
            (r'\b[A-Za-z0-9_]*private_key\s*=\s*[\'"][^\'"]{20,}[\'"]', 'hardcoded-private-key'),
            (r'\baws_access_key_id\s*=\s*[\'"][A-Z0-9]{20}[\'"]', 'aws-access-key'),
            (r'\baws_secret_access_key\s*=\s*[\'"][A-Za-z0-9/+=]{40}[\'"]', 'aws-secret-key'),
        ]

        for i, line in enumerate(lines, 1):
            for pattern, issue_type in secret_patterns:
                for match in re.finditer(pattern, line, re.IGNORECASE):
                    match_str = match.group()
                    # Skip placeholders
                    if any(placeholder in match_str.lower() for placeholder in
                           ['example', 'placeholder', 'your_', 'xxx', '***', 'changeme',
                            'test', 'demo', 'sample', 'fake']):
                        continue

                    self._add_generic_finding(
                        f'generic-{issue_type}',
                        f'Possible hardcoded {issue_type.replace("-", " ")}',
                        'high',
                        file_path,
                        i,
                        match_str[:50] + '...' if len(match_str) > 50 else match_str,
                        "Use environment variables or secure credential storage"
                    )

        # Check for suspicious URLs
        url_pattern = r'https?://[^\s<>"\'`\)\]\}]+'
        for i, line in enumerate(lines, 1):
            urls = re.findall(url_pattern, line)
            for url in urls:
                # Check for suspicious patterns in URLs
                suspicious_patterns = [
                    (r'/exec', 'remote-exec'),
                    (r'/run', 'remote-run'),
                    (r'/cmd', 'remote-cmd'),
                    (r'/shell', 'remote-shell'),
                    (r'/download', 'suspicious-download'),
                    (r'/install', 'suspicious-install'),
                ]

                for pattern, issue_type in suspicious_patterns:
                    if re.search(pattern, url, re.IGNORECASE):
                        self._add_generic_finding(
                            f'generic-url-{issue_type}',
                            f'Suspicious URL pattern detected: {issue_type}',
                            'medium',
                            file_path,
                            i,
                            url[:80],
                            "Review this URL carefully before accessing"
                        )
                        break

    def _add_generic_finding(self, rule_id: str, title: str, severity: str,
                             filepath: Path, line: int, code_snippet: str,
                             recommendation: str) -> None:
        """Add a generic finding (not from a specific scanner)."""
        finding = {
            'id': f"GENE-{len(self.findings)+1:04d}",
            'rule_id': rule_id,
            'title': title,
            'description': title,
            'severity': severity,
            'file': str(filepath),
            'line': line,
            'code_snippet': code_snippet,
            'recommendation': recommendation,
            'confidence': 'high'
        }
        self.findings.append(finding)

    def _add_findings(self, findings: list) -> None:
        """Add findings from a scanner."""
        for finding in findings:
            self.findings.append(finding.to_dict())


class SecurityReport:
    """Generates security audit reports."""

    SEVERITY_ORDER = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}

    def __init__(self, findings: List[Dict], skill_path: Path, scan_duration: float = 0):
        self.findings = findings
        self.skill_path = skill_path
        self.scan_duration = scan_duration
        self.scan_time = datetime.now()

    def generate(self, format: str = 'console') -> str:
        """Generate report in specified format."""
        if format == 'console':
            return self._generate_console()
        elif format == 'json':
            return self._generate_json()
        elif format == 'html':
            return self._generate_html()
        else:
            raise ValueError(f"Unknown format: {format}")

    def calculate_risk_score(self) -> Tuple[int, str, str]:
        """Calculate overall risk score."""
        weights = {'critical': 100, 'high': 50, 'medium': 20, 'low': 5}

        total_score = 0
        for finding in self.findings:
            severity = finding.get('severity', 'low')
            total_score += weights.get(severity, 5)

        normalized = min(total_score, 100)

        if normalized >= 70:
            return normalized, 'critical', '[CRIT]'
        elif normalized >= 50:
            return normalized, 'high', '[HIGH]'
        elif normalized >= 25:
            return normalized, 'medium', '[MED]'
        else:
            return normalized, 'low', '[LOW]'

    def _generate_console(self) -> str:
        """Generate console-formatted report."""
        score, level, emoji = self.calculate_risk_score()

        # Count findings by severity
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        for finding in self.findings:
            sev = finding.get('severity', 'low')
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        report = f"""
╔══════════════════════════════════════════════════════════════════╗
║                    Skill Security Audit Report                   ║
╚══════════════════════════════════════════════════════════════════╝

Skill: {self.skill_path}
Scan Date: {self.scan_time.strftime('%Y-%m-%d %H:%M:%S')}
Scan Duration: {self.scan_duration:.2f} seconds

═══════════════════════════════════════════════════════════════════
                        RISK ASSESSMENT
═══════════════════════════════════════════════════════════════════

Overall Risk Level: {emoji} {level.upper()}
Risk Score: {score}/100

Total Findings: {len(self.findings)}
  [CRIT] Critical: {severity_counts['critical']}
  [HIGH] High: {severity_counts['high']}
  [MED] Medium: {severity_counts['medium']}
  [LOW] Low: {severity_counts['low']}
"""

        # Add critical findings section
        critical_findings = [f for f in self.findings if f.get('severity') == 'critical']
        if critical_findings:
            report += "\n═══════════════════════════════════════════════════════════════════\n"
            report += "                    [CRIT] CRITICAL FINDINGS\n"
            report += "═══════════════════════════════════════════════════════════════════\n"
            for finding in critical_findings[:10]:  # Show top 10
                report += self._format_finding_console(finding)

        # Add high findings section
        high_findings = [f for f in self.findings if f.get('severity') == 'high']
        if high_findings:
            report += "\n═══════════════════════════════════════════════════════════════════\n"
            report += "                    [HIGH] HIGH RISK FINDINGS\n"
            report += "═══════════════════════════════════════════════════════════════════\n"
            for finding in high_findings[:10]:
                report += self._format_finding_console(finding)

        # Add recommendations
        report += "\n═══════════════════════════════════════════════════════════════════\n"
        report += "                      RECOMMENDATIONS\n"
        report += "═══════════════════════════════════════════════════════════════════\n"

        if critical_findings:
            report += """
[ALERT] IMMEDIATE ACTIONS REQUIRED:
1. DELETE this skill immediately - it contains critical vulnerabilities
2. Scan your system for signs of compromise
3. Rotate any potentially exposed credentials
4. Report this skill to your security team
"""
        elif score >= 50:
            report += """
[WARN]  HIGH RISK - PROCEED WITH CAUTION:
1. Perform manual code review before using this skill
2. Run in isolated sandbox environment first
3. Monitor network activity during skill execution
4. Consider finding alternative, safer skills
"""
        elif score >= 25:
            report += """
[LIGHT] MEDIUM RISK - REVIEW RECOMMENDED:
1. Review findings before using this skill
2. Ensure findings don't impact your use case
3. Monitor for any unusual behavior
"""
        else:
            report += """
[OK] LOW RISK - RELATIVELY SAFE:
This skill appears relatively safe for use.
Follow standard security practices:
- Keep software updated
- Monitor for unusual activity
- Use principle of least privilege
"""

        report += """
═══════════════════════════════════════════════════════════════════

Report Generated By: Skill Security Audit Tool v""" + __version__ + """
For more information: https://github.com/liuyang21cn/skill-security-audit
"""

        return report

    def _format_finding_console(self, finding: Dict) -> str:
        """Format a single finding for console output."""
        lines = []
        lines.append(f"\n  [{finding.get('id', 'UNKNOWN')}] {finding.get('title', 'Unknown Issue')}")
        lines.append(f"  {'-' * 60}")
        lines.append(f"  File: {finding.get('file', 'unknown')}")
        lines.append(f"  Line: {finding.get('line', 0)}")
        lines.append(f"  Risk: {finding.get('description', 'No description')}")

        code_snippet = finding.get('code_snippet', '')
        if code_snippet:
            lines.append(f"\n  Detected Code:")
            for snippet_line in code_snippet.split('\n')[:3]:  # Show max 3 lines
                lines.append(f"    {snippet_line[:70]}")

        recommendation = finding.get('recommendation', '')
        if recommendation:
            lines.append(f"\n  Fix: {recommendation}")

        lines.append("")
        return "\n".join(lines)

    def _generate_json(self) -> str:
        """Generate JSON format report."""
        score, level, emoji = self.calculate_risk_score()

        # Group findings by severity
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        for finding in self.findings:
            sev = finding.get('severity', 'low')
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        report_data = {
            'scan_info': {
                'tool': 'Skill Security Audit',
                'version': __version__,
                'scan_date': self.scan_time.isoformat(),
                'scan_duration_seconds': round(self.scan_duration, 2),
                'skill_path': str(self.skill_path),
            },
            'risk_assessment': {
                'score': score,
                'level': level,
                'emoji': emoji,
            },
            'summary': {
                'total_findings': len(self.findings),
                'severity_counts': severity_counts,
            },
            'findings': self.findings,
        }

        return json.dumps(report_data, indent=2)

    def _generate_html(self) -> str:
        """Generate HTML format report."""
        score, level, emoji = self.calculate_risk_score()

        # Group findings by severity
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        for finding in self.findings:
            sev = finding.get('severity', 'low')
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        # HTML template
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Skill Security Audit Report</title>
    <style>
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            line-height: 1.6;
            color: #333;
            background: #f5f5f5;
            padding: 20px;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            overflow: hidden;
        }}
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }}
        .header h1 {{
            font-size: 2em;
            margin-bottom: 10px;
        }}
        .header p {{
            opacity: 0.9;
        }}
        .risk-card {{
            display: flex;
            align-items: center;
            padding: 30px;
            border-bottom: 1px solid #eee;
        }}
        .risk-score {{
            font-size: 4em;
            font-weight: bold;
            margin-right: 30px;
        }}
        .risk-score.critical {{ color: #e74c3c; }}
        .risk-score.high {{ color: #e67e22; }}
        .risk-score.medium {{ color: #f1c40f; }}
        .risk-score.low {{ color: #27ae60; }}
        .risk-info h2 {{
            font-size: 1.5em;
            margin-bottom: 5px;
        }}
        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 15px;
            padding: 20px;
            background: #f8f9fa;
        }}
        .summary-card {{
            background: white;
            padding: 20px;
            border-radius: 6px;
            text-align: center;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }}
        .summary-card .count {{
            font-size: 2em;
            font-weight: bold;
            margin-bottom: 5px;
        }}
        .summary-card.critical .count {{ color: #e74c3c; }}
        .summary-card.high .count {{ color: #e67e22; }}
        .summary-card.medium .count {{ color: #f1c40f; }}
        .summary-card.low .count {{ color: #27ae60; }}
        .findings-section {{
            padding: 30px;
        }}
        .findings-section h2 {{
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 2px solid #eee;
        }}
        .finding {{
            background: #f8f9fa;
            border-left: 4px solid;
            padding: 15px;
            margin-bottom: 15px;
            border-radius: 0 4px 4px 0;
        }}
        .finding.critical {{ border-left-color: #e74c3c; }}
        .finding.high {{ border-left-color: #e67e22; }}
        .finding.medium {{ border-left-color: #f1c40f; }}
        .finding.low {{ border-left-color: #27ae60; }}
        .finding-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
        }}
        .finding-title {{
            font-weight: bold;
            font-size: 1.1em;
        }}
        .finding-severity {{
            padding: 2px 8px;
            border-radius: 3px;
            font-size: 0.8em;
            font-weight: bold;
            text-transform: uppercase;
        }}
        .finding-severity.critical {{ background: #e74c3c; color: white; }}
        .finding-severity.high {{ background: #e67e22; color: white; }}
        .finding-severity.medium {{ background: #f1c40f; color: black; }}
        .finding-severity.low {{ background: #27ae60; color: white; }}
        .finding-meta {{
            font-size: 0.9em;
            color: #666;
            margin-bottom: 10px;
        }}
        .finding-code {{
            background: #2d2d2d;
            color: #f8f8f2;
            padding: 10px;
            border-radius: 4px;
            font-family: 'Consolas', 'Monaco', monospace;
            font-size: 0.9em;
            overflow-x: auto;
            margin: 10px 0;
        }}
        .finding-recommendation {{
            background: #e8f4f8;
            border-left: 3px solid #3498db;
            padding: 10px;
            margin-top: 10px;
            border-radius: 0 4px 4px 0;
        }}
        .footer {{
            text-align: center;
            padding: 20px;
            background: #f8f9fa;
            color: #666;
            font-size: 0.9em;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 Skill Security Audit Report</h1>
            <p>Comprehensive security analysis of Claude Code skill</p>
        </div>

        <div class="risk-card">
            <div class="risk-score {level}">{score}</div>
            <div class="risk-info">
                <h2>Risk Score: {score}/100</h2>
                <p>Risk Level: <strong>{emoji} {level.upper()}</strong></p>
                <p>Skill: <code>{self.skill_path}</code></p>
                <p>Scan Date: {self.scan_time.strftime('%Y-%m-%d %H:%M:%S')}</p>
            </div>
        </div>

        <div class="summary-grid">
            <div class="summary-card critical">
                <div class="count">{severity_counts['critical']}</div>
                <div class="label">Critical</div>
            </div>
            <div class="summary-card high">
                <div class="count">{severity_counts['high']}</div>
                <div class="label">High</div>
            </div>
            <div class="summary-card medium">
                <div class="count">{severity_counts['medium']}</div>
                <div class="label">Medium</div>
            </div>
            <div class="summary-card low">
                <div class="count">{severity_counts['low']}</div>
                <div class="label">Low</div>
            </div>
        </div>

        <div class="findings-section">
            <h2>[SCAN] Detailed Findings</h2>
"""

        # Add findings
        # Sort by severity
        sorted_findings = sorted(
            self.findings,
            key=lambda x: self.SEVERITY_ORDER.get(x.get('severity', 'low'), 999)
        )

        for finding in sorted_findings:
            severity = finding.get('severity', 'low')
            title = finding.get('title', 'Unknown Issue')
            finding_id = finding.get('id', 'UNKNOWN')
            filepath = finding.get('file', 'unknown')
            line = finding.get('line', 0)
            description = finding.get('description', '')
            code_snippet = finding.get('code_snippet', '')
            recommendation = finding.get('recommendation', '')

            html += f"""
            <div class="finding {severity}">
                <div class="finding-header">
                    <div class="finding-title">[{finding_id}] {title}</div>
                    <div class="finding-severity {severity}">{severity.upper()}</div>
                </div>
                <div class="finding-meta">
                    <strong>File:</strong> <code>{filepath}</code> |
                    <strong>Line:</strong> {line}
                </div>
                <div class="finding-description">{description}</div>
"""

            if code_snippet:
                escaped_code = code_snippet.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
                html += f"""
                <div class="finding-code">{escaped_code}</div>
"""

            if recommendation:
                html += f"""
                <div class="finding-recommendation">
                    <strong>[TIP] Recommendation:</strong> {recommendation}
                </div>
"""

            html += """
            </div>
"""

        html += f"""
        </div>

        <div class="footer">
            <p>Generated by Skill Security Audit Tool v{__version__}</p>
            <p>For more information: https://github.com/liuyang21cn/skill-security-audit</p>
        </div>
    </div>
</body>
</html>
"""

        return html


def parse_arguments() -> ScanConfig:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description='Security audit tool for Claude Code skills',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic scan with console output
  python scan_skill.py ~/.claude/skills/suspicious-skill

  # JSON output to file
  python scan_skill.py ./new-skill --format json --output report.json

  # Show only high and critical findings
  python scan_skill.py ./skill --severity high

  # Verbose output with detailed progress
  python scan_skill.py ./skill --verbose
        """
    )

    parser.add_argument(
        'skill_path',
        type=str,
        help='Path to the skill directory or file to scan'
    )

    parser.add_argument(
        '--format', '-f',
        choices=['console', 'json', 'html'],
        default='console',
        help='Output format (default: console)'
    )

    parser.add_argument(
        '--output', '-o',
        type=str,
        help='Save report to file instead of stdout'
    )

    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Show detailed progress information'
    )

    parser.add_argument(
        '--severity', '-s',
        choices=['critical', 'high', 'medium', 'low'],
        default='low',
        help='Minimum severity level to report (default: low)'
    )

    args = parser.parse_args()

    # Create config
    config = ScanConfig()
    config.skill_path = Path(args.skill_path).resolve()
    config.output_format = args.format
    config.output_file = Path(args.output) if args.output else None
    config.verbose = args.verbose
    config.min_severity = args.severity

    return config


def main() -> int:
    """Main entry point."""
    # Parse arguments
    config = parse_arguments()

    # Validate skill path
    if not config.skill_path.exists():
        print(f"Error: Skill path does not exist: {config.skill_path}", file=sys.stderr)
        return 1

    # Start timer
    start_time = __import__('time').time()

    try:
        # Initialize scanner
        scanner = SecurityScanner(config)

        # Run scan
        findings = scanner.scan()

        # Calculate duration
        duration = __import__('time').time() - start_time

        # Filter by minimum severity
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
        min_level = severity_order.get(config.min_severity, 3)
        filtered_findings = [
            f for f in findings
            if severity_order.get(f.get('severity', 'low'), 3) <= min_level
        ]

        # Generate report
        report_generator = SecurityReport(filtered_findings, config.skill_path, duration)
        report = report_generator.generate(config.output_format)

        # Output report
        if config.output_file:
            with open(config.output_file, 'w', encoding='utf-8') as f:
                f.write(report)
            print(f"\n[OK] Report saved to: {config.output_file}")
        else:
            print(report)

        # Return exit code based on findings
        critical_count = len([f for f in filtered_findings if f.get('severity') == 'critical'])
        high_count = len([f for f in filtered_findings if f.get('severity') == 'high'])

        if critical_count > 0:
            return 2  # Critical findings
        elif high_count > 0:
            return 1  # High findings
        else:
            return 0  # Clean or low/medium findings only

    except KeyboardInterrupt:
        print("\n\n[WARN]  Scan interrupted by user", file=sys.stderr)
        return 130
    except Exception as e:
        print(f"\n[ERROR] Error during scan: {e}", file=sys.stderr)
        if config.verbose:
            import traceback
            traceback.print_exc()
        return 1


if __name__ == '__main__':
    sys.exit(main())
