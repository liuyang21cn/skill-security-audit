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

Example:
    python scan_skill.py ~/.claude/skills/suspicious-skill --format json --output report.json
"""

import argparse
import ast
import json
import os
import re
import subprocess
import sys
import yaml
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Any

# Version information
__version__ = "1.0.0"
__author__ = "liuyang21cn"


@dataclass
class Finding:
    """Represents a security finding."""
    id: str
    rule_id: str
    title: str
    description: str
    severity: str  # critical, high, medium, low, info
    file: str
    line: int
    column: int = 0
    code_snippet: str = ""
    recommendation: str = ""
    confidence: str = "high"  # high, medium, low

    def to_dict(self) -> Dict:
        """Convert finding to dictionary."""
        return {
            'id': self.id,
            'rule_id': self.rule_id,
            'title': self.title,
            'description': self.description,
            'severity': self.severity,
            'file': self.file,
            'line': self.line,
            'column': self.column,
            'code_snippet': self.code_snippet,
            'recommendation': self.recommendation,
            'confidence': self.confidence,
        }


@dataclass
class ScanConfig:
    """Configuration for security scan."""
    skill_path: Path
    output_format: str = "console"
    output_file: Optional[Path] = None
    verbose: bool = False
    min_severity: str = "low"
    include_info: bool = False
    max_file_size: int = 10 * 1024 * 1024  # 10MB
    excluded_dirs: Set[str] = field(default_factory=lambda: {
        '.git', '.svn', 'node_modules', '__pycache__', '.pytest_cache',
        'venv', 'env', '.env', 'dist', 'build', '.tox'
    })


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

        if self.verbose:
            print(f"Loaded {len(self.rules)} rules from {self.rules_dir}")

    def get_rules_for_language(self, language: str) -> List[Dict]:
        """Get all rules applicable to a specific language."""
        matching_rules = []
        for rule in self.rules:
            languages = rule.get('languages', [])
            if language.lower() in [lang.lower() for lang in languages]:
                matching_rules.append(rule)
        return matching_rules

    def get_rule_by_id(self, rule_id: str) -> Optional[Dict]:
        """Get a specific rule by its ID."""
        for rule in self.rules:
            if rule.get('id') == rule_id:
                return rule
        return None


class PythonScanner:
    """Security scanner for Python code."""

    def __init__(self, rules: List[Dict]):
        self.rules = rules
        self.findings: List[Finding] = []
        self.finding_counter = 0

    def scan_file(self, filepath: Path, source_code: str) -> List[Finding]:
        """Scan a Python file for security issues."""
        self.findings = []

        # AST-based analysis
        try:
            tree = ast.parse(source_code)
            self._analyze_ast(tree, filepath, source_code)
        except SyntaxError as e:
            # Log syntax error but continue with regex analysis
            pass

        # Regex-based pattern matching
        self._regex_scan(source_code, filepath)

        return self.findings

    def _analyze_ast(self, tree: ast.AST, filepath: Path, source_code: str) -> None:
        """Analyze AST for security issues."""
        for node in ast.walk(tree):
            # Check for dangerous function calls
            if isinstance(node, ast.Call):
                self._check_dangerous_call(node, filepath, source_code)

            # Check for dangerous imports
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name in ['pickle', 'marshal']:
                        self._add_finding(
                            'python-unsafe-deserialization',
                            f"Unsafe deserialization module: {alias.name}",
                            'critical',
                            filepath,
                            getattr(node, 'lineno', 0),
                            f"import {alias.name}",
                            "Use JSON for safe serialization"
                        )

            elif isinstance(node, ast.ImportFrom):
                if node.module in ['pickle', 'marshal']:
                    self._add_finding(
                        'python-unsafe-deserialization',
                        f"Unsafe deserialization import from {node.module}",
                        'critical',
                        filepath,
                        getattr(node, 'lineno', 0),
                        f"from {node.module} import ...",
                        "Use JSON for safe serialization"
                    )

    def _check_dangerous_call(self, node: ast.Call, filepath: Path, source_code: str) -> None:
        """Check for dangerous function calls."""
        func_name = None

        if isinstance(node.func, ast.Name):
            func_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name):
                func_name = f"{node.func.value.id}.{node.func.attr}"
            else:
                func_name = node.func.attr

        if not func_name:
            return

        # Map dangerous functions to rule IDs
        dangerous_functions = {
            'eval': ('python-eval-usage', 'critical', 'eval() executes arbitrary code'),
            'exec': ('python-exec-usage', 'critical', 'exec() executes arbitrary code'),
            'compile': ('python-compile-usage', 'high', 'compile() can execute arbitrary code'),
            '__import__': ('python-dynamic-import', 'medium', 'Dynamic imports can load arbitrary code'),
        }

        # Check subprocess calls
        if func_name in ['subprocess.call', 'subprocess.run', 'subprocess.Popen']:
            # Check for shell=True
            for keyword in node.keywords:
                if keyword.arg == 'shell':
                    if isinstance(keyword.value, ast.Constant) and keyword.value.value == True:
                        self._add_finding(
                            'python-subprocess-shell',
                            "subprocess with shell=True enables command injection",
                            'high',
                            filepath,
                            getattr(node, 'lineno', 0),
                            f"subprocess.{func_name.split('.')[1]}(..., shell=True)",
                            "Use shell=False and pass command as list"
                        )
                    break

        # Check os.system
        if func_name == 'os.system':
            self._add_finding(
                'python-os-system',
                "os.system() is vulnerable to command injection",
                'high',
                filepath,
                getattr(node, 'lineno', 0),
                "os.system(...)",
                "Use subprocess with shell=False"
            )

        # Check pickle
        if func_name in ['pickle.load', 'pickle.loads']:
            self._add_finding(
                'python-pickle-loads',
                "pickle deserialization can execute arbitrary code",
                'critical',
                filepath,
                getattr(node, 'lineno', 0),
                f"{func_name}(...)",
                "Use JSON for safe serialization"
            )

        # Check yaml.load
        if func_name == 'yaml.load':
            self._add_finding(
                'python-yaml-unsafe',
                "yaml.load() without safe Loader is unsafe",
                'critical',
                filepath,
                getattr(node, 'lineno', 0),
                "yaml.load(...)",
                "Use yaml.safe_load() instead"
            )

        # Check getattr with dynamic names
        if func_name == 'getattr':
            self._add_finding(
                'python-getattr-dangerous',
                "getattr() with dynamic names can bypass access controls",
                'medium',
                filepath,
                getattr(node, 'lineno', 0),
                "getattr(...)",
                "Validate attribute names before access"
            )

        # Check standard dangerous functions
        if func_name in dangerous_functions:
            rule_id, severity, message = dangerous_functions[func_name]
            self._add_finding(
                rule_id,
                message,
                severity,
                filepath,
                getattr(node, 'lineno', 0),
                f"{func_name}(...)",
                dangerous_functions[func_name][2] if len(dangerous_functions[func_name]) > 2 else "Avoid using this function"
            )

    def _regex_scan(self, source_code: str, filepath: Path) -> None:
        """Use regex patterns to find additional security issues."""
        lines = source_code.split('\n')

        # Pattern: Hardcoded secrets
        secret_patterns = [
            (r'(password|passwd|pwd|secret|key|token)\s*=\s*[\'"][^\'"]{8,}[\'"]',
             'python-hardcoded-secret',
             'Possible hardcoded credential detected',
             'low'),
            (r'(api_key|apikey|api-secret|access_token|auth_token)\s*=\s*[\'"][^\'"]+[\'"]',
             'python-hardcoded-api-key',
             'Possible hardcoded API key detected',
             'low'),
            (r'[\'"]https?://[^\s:@\'"]+:[^\s:@\'"]+@[^\s@\'"]+[\'"]',
             'python-hardcoded-url-credentials',
             'URL with embedded credentials detected',
             'medium'),
        ]

        for pattern, rule_id, message, severity in secret_patterns:
            for i, line in enumerate(lines, 1):
                for match in re.finditer(pattern, line, re.IGNORECASE):
                    # Skip if it looks like a placeholder
                    match_str = match.group()
                    if any(placeholder in match_str.lower() for placeholder in
                           ['example', 'placeholder', 'your_', 'xxx', '***', 'changeme']):
                        continue

                    self._add_finding(
                        rule_id,
                        message,
                        severity,
                        filepath,
                        i,
                        match_str[:50] + '...' if len(match_str) > 50 else match_str,
                        "Use environment variables or secure credential storage"
                    )

        # Pattern: HTTP without TLS
        for i, line in enumerate(lines, 1):
            if re.search(r'http://[^\s\'"]+', line):
                # Skip localhost and common non-sensitive patterns
                if re.search(r'localhost|127\.0\.0\.1|0\.0\.0\.0|example\.com', line):
                    continue
                self._add_finding(
                    'python-http-without-tls',
                    'HTTP URL detected without TLS encryption',
                    'low',
                    filepath,
                    i,
                    line.strip()[:80],
                    "Use HTTPS instead of HTTP for secure communications"
                )

        # Pattern: SQL string formatting
        sql_patterns = [
            (r'["\']SELECT\s+.*\s+FROM\s+.*\+', 'python-sql-string-concat'),
            (r'["\']INSERT\s+INTO\s+.*\+', 'python-sql-string-concat'),
            (r'["\']UPDATE\s+.*SET\s+.*\+', 'python-sql-string-concat'),
            (r'["\']DELETE\s+FROM\s+.*\+', 'python-sql-string-concat'),
            (r'\.format\s*\([^)]*SELECT|INSERT|UPDATE|DELETE', 'python-sql-format'),
            (r'f["\'][^"\']*SELECT\s+[^"\']*\{[^}]+\}', 'python-sql-fstring'),
        ]

        for pattern, rule_id in sql_patterns:
            for i, line in enumerate(lines, 1):
                if re.search(pattern, line, re.IGNORECASE):
                    self._add_finding(
                        rule_id,
                        'Possible SQL injection via string formatting',
                        'medium',
                        filepath,
                        i,
                        line.strip()[:80],
                        "Use parameterized queries with proper escaping"
                    )
                    break  # Only report once per line

    def _add_finding(self, rule_id: str, title: str, severity: str,
                     filepath: Path, line: int, code_snippet: str,
                     recommendation: str) -> None:
        """Add a new finding."""
        self.finding_counter += 1
        finding = Finding(
            id=f"PYTH-{self.finding_counter:04d}",
            rule_id=rule_id,
            title=title,
            description=title,  # Can be expanded
            severity=severity,
            file=str(filepath),
            line=line,
            code_snippet=code_snippet,
            recommendation=recommendation,
            confidence="high"
        )
        self.findings.append(finding)


class BashScanner:
    """Security scanner for Bash shell scripts."""

    def __init__(self, rules: List[Dict]):
        self.rules = rules
        self.findings: List[Finding] = []
        self.finding_counter = 0

    def scan_file(self, filepath: Path, source_code: str) -> List[Finding]:
        """Scan a Bash script for security issues."""
        self.findings = []

        # Apply regex-based rules
        self._apply_regex_rules(source_code, filepath)

        # Additional Bash-specific analysis
        self._analyze_bash_specific(source_code, filepath)

        return self.findings

    def _apply_regex_rules(self, source_code: str, filepath: Path) -> None:
        """Apply regex-based rules from YAML definitions."""
        lines = source_code.split('\n')

        for rule in self.rules:
            pattern = rule.get('pattern', '')
            if not pattern:
                continue

            try:
                compiled_pattern = re.compile(pattern, re.IGNORECASE)
            except re.error:
                continue

            for i, line in enumerate(lines, 1):
                for match in compiled_pattern.finditer(line):
                    self._add_finding(
                        rule.get('id', 'UNKNOWN'),
                        rule.get('name', 'Unknown Issue'),
                        rule.get('severity', 'low'),
                        filepath,
                        i,
                        match.group()[:80],
                        rule.get('recommendation', 'Review and fix the issue')
                    )

    def _analyze_bash_specific(self, source_code: str, filepath: Path) -> None:
        """Perform Bash-specific security analysis."""
        lines = source_code.split('\n')

        # Check for unsafe variable usage
        for i, line in enumerate(lines, 1):
            # Unquoted variable expansion in dangerous contexts
            dangerous_commands = ['rm', 'mv', 'cp', 'cat', 'echo', 'printf']
            for cmd in dangerous_commands:
                if re.search(rf'\b{cmd}\s+.*\$\w+', line):
                    # Check if quoted
                    if not re.search(rf'"[^"]*\$\w+[^"]*"', line) and "'$" not in line:
                        self._add_finding(
                            'bash-unquoted-variable',
                            f'Unquoted variable in {cmd} command',
                            'medium',
                            filepath,
                            i,
                            line.strip()[:80],
                            f'Quote variable expansions: "${{var}}" instead of $var'
                        )

        # Check for common script vulnerabilities
        for i, line in enumerate(lines, 1):
            # Check for $* or $@ without quotes
            if re.search(r'\$\*|\$@', line) and '"$@"' not in line:
                self._add_finding(
                    'bash-unquoted-special-vars',
                    'Unquoted $* or $@ causes word splitting',
                    'medium',
                    filepath,
                    i,
                    line.strip()[:80],
                    'Use "$@" instead of $@ or $*'
                )

    def _add_finding(self, rule_id: str, title: str, severity: str,
                     filepath: Path, line: int, code_snippet: str,
                     recommendation: str) -> None:
        """Add a new finding."""
        self.finding_counter += 1
        finding = Finding(
            id=f"BASH-{self.finding_counter:04d}",
            rule_id=rule_id,
            title=title,
            description=title,
            severity=severity,
            file=str(filepath),
            line=line,
            code_snippet=code_snippet,
            recommendation=recommendation,
            confidence="high"
        )
        self.findings.append(finding)


class SkillMetadataScanner:
    """Scanner for SKILL.md metadata and content."""

    def __init__(self):
        self.findings: List[Finding] = []
        self.finding_counter = 0

    def scan_skill_md(self, filepath: Path, content: str) -> List[Finding]:
        """Scan SKILL.md for security issues."""
        self.findings = []

        # Check frontmatter
        self._check_frontmatter(content, filepath)

        # Check for suspicious commands in skill instructions
        self._check_suspicious_commands(content, filepath)

        # Check for hidden/obfuscated content
        self._check_obfuscated_content(content, filepath)

        # Check for suspicious URLs/domains
        self._check_suspicious_urls(content, filepath)

        return self.findings

    def _check_frontmatter(self, content: str, filepath: Path) -> None:
        """Check YAML frontmatter for issues."""
        # Extract frontmatter
        frontmatter_match = re.match(r'^---\s*\n(.*?)\n---\s*\n', content, re.DOTALL)
        if not frontmatter_match:
            self._add_finding(
                'skill-no-frontmatter',
                'SKILL.md missing YAML frontmatter',
                'medium',
                filepath,
                1,
                '---',
                'All skills should have proper YAML frontmatter with name and description'
            )
            return

        frontmatter_content = frontmatter_match.group(1)

        # Try to parse as YAML
        try:
            frontmatter = yaml.safe_load(frontmatter_content)
            if not isinstance(frontmatter, dict):
                frontmatter = {}
        except yaml.YAMLError:
            frontmatter = {}

        # Check required fields
        if 'name' not in frontmatter:
            self._add_finding(
                'skill-missing-name',
                'SKILL.md frontmatter missing "name" field',
                'medium',
                filepath,
                1,
                frontmatter_content[:50],
                'All skills must have a name in the frontmatter'
            )

        if 'description' not in frontmatter:
            self._add_finding(
                'skill-missing-description',
                'SKILL.md frontmatter missing "description" field',
                'low',
                filepath,
                1,
                frontmatter_content[:50],
                'Consider adding a description for the skill'
            )

        # Check for suspicious name patterns
        if 'name' in frontmatter:
            name = str(frontmatter['name']).lower()
            suspicious_patterns = ['test', 'demo', 'temp', 'backup', 'copy', 'old', 'new']
            if any(pattern in name for pattern in suspicious_patterns):
                self._add_finding(
                    'skill-suspicious-name',
                    f'Skill name contains suspicious pattern: {name}',
                    'low',
                    filepath,
                    1,
                    f"name: {name}",
                    'Verify this is not a test or temporary skill'
                )

    def _check_suspicious_commands(self, content: str, filepath: Path) -> None:
        """Check for suspicious commands in skill content."""
        lines = content.split('\n')

        suspicious_commands = [
            (r'\bcurl\s+.*\|\s*(bash|sh)\b', 'curl-pipe-execution', 'critical'),
            (r'\bwget\s+.*-O?\s*-?\s*\|\s*(bash|sh)\b', 'wget-pipe-execution', 'critical'),
            (r'\beval\s*\$', 'eval-variable', 'high'),
            (r'\b(?:rm\s+-rf|del\s+/f)\s+/', 'dangerous-delete', 'high'),
            (r'\b(?:mkfs|dd\s+if=|format\s+)\b', 'disk-operations', 'high'),
            (r'\b(ping|traceroute|nslookup|dig)\s+', 'network-recon', 'low'),
        ]

        for i, line in enumerate(lines, 1):
            for pattern, issue_type, severity in suspicious_commands:
                if re.search(pattern, line, re.IGNORECASE):
                    # Skip if it's in a code block marked as an example
                    if 'example' in line.lower() or 'safe' in line.lower():
                        continue

                    self._add_finding(
                        f'skill-suspicious-{issue_type}',
                        f'Suspicious command pattern detected: {issue_type}',
                        severity,
                        filepath,
                        i,
                        line.strip()[:80],
                        'Review this command carefully before execution'
                    )

    def _check_obfuscated_content(self, content: str, filepath: Path) -> None:
        """Check for obfuscated or hidden content."""
        # Check for excessive base64 content
        base64_pattern = r'[A-Za-z0-9+/]{100,}={0,2}'
        base64_matches = re.findall(base64_pattern, content)
        total_base64 = sum(len(m) for m in base64_matches)

        if total_base64 > 1000:  # More than 1KB of base64
            self._add_finding(
                'skill-obfuscated-base64',
                f'Large amount of base64-encoded content detected ({total_base64} bytes)',
                'medium',
                filepath,
                1,
                base64_matches[0][:80] + '...' if base64_matches else '',
                'Base64 may hide malicious code - decode and review carefully'
            )

        # Check for hex-encoded content
        hex_pattern = r'\\x[0-9a-fA-F]{2}'
        hex_matches = re.findall(hex_pattern, content)
        if len(hex_matches) > 50:  # More than 50 hex escapes
            self._add_finding(
                'skill-obfuscated-hex',
                f'Hex-encoded content detected ({len(hex_matches)} escape sequences)',
                'low',
                filepath,
                1,
                ''.join(hex_matches[:20]) + '...',
                'Hex encoding may be used to obfuscate strings'
            )

        # Check for Unicode escapes
        unicode_pattern = r'\\u[0-9a-fA-F]{4}'
        unicode_matches = re.findall(unicode_pattern, content)
        if len(unicode_matches) > 20:
            self._add_finding(
                'skill-obfuscated-unicode',
                f'Unicode escape sequences detected ({len(unicode_matches)} escapes)',
                'low',
                filepath,
                1,
                ''.join(unicode_matches[:20]),
                'Unicode escapes may be used to hide strings'
            )

    def _check_suspicious_urls(self, content: str, filepath: Path) -> None:
        """Check for suspicious URLs and domains."""
        # Extract URLs
        url_pattern = r'https?://[^\s<>"\'`\)\]\}]+'
        urls = re.findall(url_pattern, content)

        suspicious_domains = [
            'pastebin.com', 'paste.ee', 'ghostbin.co',  # Paste sites often used for malware
            'transfer.sh', 'tmp.link', '0x0.st',       # Temporary file hosts
            'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', # URL shorteners
            'ngrok.io', 'serveo.net', 'localtunnel.me', # Tunneling services
            'duckdns.org', 'no-ip.com', 'dyndns.org',   # Dynamic DNS often used for C2
        ]

        for url in urls:
            # Check for suspicious TLDs
            suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.top', '.xyz', '.buzz']
            if any(url.lower().endswith(tld) for tld in suspicious_tlds):
                self._add_finding(
                    'skill-suspicious-tld',
                    f'URL with suspicious TLD: {url[:60]}',
                    'medium',
                    filepath,
                    1,
                    url[:80],
                    'Suspicious TLDs are often used for malicious domains'
                )

            # Check for suspicious domains
            domain = re.sub(r'^https?://', '', url).split('/')[0].lower()
            for susp_domain in suspicious_domains:
                if susp_domain in domain:
                    self._add_finding(
                        'skill-suspicious-domain',
                        f'URL points to potentially suspicious domain: {susp_domain}',
                        'medium',
                        filepath,
                        1,
                        url[:80],
                        f'{susp_domain} is often used for distributing malware or hiding malicious activity'
                    )
                    break

            # Check for IP addresses
            ip_pattern = r'https?://(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
            ip_match = re.search(ip_pattern, url)
            if ip_match:
                self._add_finding(
                    'skill-ip-url',
                    f'URL uses IP address instead of domain name: {ip_match.group(1)}',
                    'low',
                    filepath,
                    1,
                    url[:80],
                    'IP addresses in URLs may indicate malicious infrastructure'
                )

    def _add_finding(self, rule_id: str, title: str, severity: str,
                     filepath: Path, line: int, code_snippet: str,
                     recommendation: str) -> None:
        """Add a new finding."""
        self.finding_counter += 1
        finding = Finding(
            id=f"META-{self.finding_counter:04d}",
            rule_id=rule_id,
            title=title,
            description=title,
            severity=severity,
            file=str(filepath),
            line=line,
            code_snippet=code_snippet,
            recommendation=recommendation,
            confidence="high"
        )
        self.findings.append(finding)
