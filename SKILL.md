---
name: skill-security-audit
description: Use when installing or reviewing third-party Claude Code skills to detect supply chain security risks, malicious code patterns, and potential backdoors before execution
---

# Skill Security Audit

**Core Principle:** Every third-party skill is a potential supply chain attack vector. Never execute a skill without automated security verification.

## When to Use

- **Before installing** any skill from untrusted sources
- **Before executing** a skill downloaded from the internet
- **When reviewing** skills for organizational security compliance
- **After discovering** suspicious behavior in a running skill
- **During periodic** security audits of installed skills

**STOP and do NOT use this skill when:**
- You fully trust the skill source AND it has been previously audited
- You are in a fully isolated sandbox environment
- The skill is from an official, cryptographically signed source

## The Iron Law

**NO SKILL EXECUTES WITHOUT SECURITY AUDIT**

Every skill, regardless of source, must pass automated security checks before installation or execution.

## The Security Audit Process

### Step 1: File Structure Enumeration
```
- Scan all files in skill directory
- Identify file types and purposes
- Flag unexpected or hidden files
```

### Step 2: SKILL.md Analysis
- Parse frontmatter for suspicious metadata
- Scan for hidden backdoor commands
- Check for overly broad permission requests

### Step 3: Code Security Scanning
- **Python**: Check for eval, exec, subprocess, pickle, etc.
- **Bash**: Check for pipe execution, download-and-run patterns
- **JavaScript**: Check for eval, Function constructor, child_process
- **General**: Check for hardcoded secrets, suspicious URLs

### Step 4: Dependency Analysis
- Parse dependency files (requirements.txt, package.json, etc.)
- Check for known CVE vulnerabilities
- Verify package signatures and sources

### Step 5: Report Generation
- Calculate overall risk score
- Categorize findings by severity
- Provide actionable recommendations

## Risk Rating

| Level | Score | Icon | Action Required |
|-------|-------|------|-----------------|
| Critical | 70-100 | 🔴 | **DELETE IMMEDIATELY** - Do not use |
| High | 50-69 | 🟠 | **MANUAL REVIEW** - Use with extreme caution |
| Medium | 25-49 | 🟡 | **CAUTION** - Review findings before use |
| Low | 0-24 | 🟢 | **APPROVED** - Relatively safe to use |

## Quick Reference: Dangerous Patterns

### Python 🐍
| Pattern | Risk | Safer Alternative |
|---------|------|-------------------|
| `eval(user_input)` | 🔴 Critical | `ast.literal_eval()` |
| `exec(code)` | 🔴 Critical | None - avoid completely |
| `pickle.loads(data)` | 🔴 Critical | `json.loads()` |
| `subprocess.*(shell=True)` | 🟠 High | `subprocess.*(shell=False)` |
| `__import__(dynamic)` | 🟡 Medium | Static imports only |

### Bash 🐚
| Pattern | Risk | Safer Alternative |
|---------|------|-------------------|
| `curl \| bash` | 🔴 Critical | Download, verify, then execute |
| `eval "$var"` | 🟠 High | Use arrays or case statements |
| `source <(curl ...)` | 🔴 Critical | No safe alternative |

### JavaScript/Node.js 📦
| Pattern | Risk | Safer Alternative |
|---------|------|-------------------|
| `eval(userCode)` | 🔴 Critical | `JSON.parse()` for data |
| `new Function(code)()` | 🔴 Critical | None - avoid completely |
| `child_process.exec()` | 🟠 High | `child_process.spawn()` with args array |

## Common Mistakes to Avoid

### ❌ Mistake: Trusting Official Sources Blindly
**Wrong:** "This skill is from GitHub, so it's safe."
**Right:** Even official repositories can be compromised. Always audit.

### ❌ Mistake: Only Checking SKILL.md
**Wrong:** Reading only the documentation, not the code.
**Right:** Malicious code often hides in supporting scripts.

### ❌ Mistake: Ignoring Medium/Low Warnings
**Wrong:** "It's only medium risk, let's use it."
**Right:** Multiple medium issues can combine into critical vulnerabilities.

### ❌ Mistake: Not Checking Dependencies
**Wrong:** Assuming dependencies are safe.
**Right:** Supply chain attacks often target dependencies.

## Red Flags - STOP and Investigate

🚨 **STOP** if you see any of these:

1. **Hidden/Obfuscated Code**: Base64-encoded strings, excessive escaping, or minified code without source maps
2. **Network Calls to Unknown Domains**: Any request to non-standard domains
3. **Permission Escalation**: Requests for admin/root access without justification
4. **Download-and-Execute Patterns**: Scripts that download and immediately execute code
5. **Credential Access**: Attempts to read environment variables, config files, or credential stores
6. **Anti-Analysis Techniques**: Code that detects debuggers or sandboxes
7. **Unusual File Locations**: Files in system directories or unusual paths

## Real-World Impact

Recent supply chain attacks that this skill helps prevent:

| Incident | Year | Impact | Detection Method |
|----------|------|--------|------------------|
| Codecov Bash Uploader | 2021 | Thousands of CI/CD secrets stolen | Bash pipe execution check |
| ua-parser-js NPM | 2021 | Crypto miners, password stealers | Post-install script analysis |
| PyTorch Dependency | 2022 | Dependency confusion attack | Package name verification |
| XZ Utils Backdoor | 2024 | SSH backdoor in widely-used library | Binary analysis, obfuscation detection |

## References

### Security Standards
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CWE Top 25](https://cwe.mitre.org/top25/)
- [SLSA Framework](https://slsa.dev/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)

### Supply Chain Security
- [Sigstore](https://www.sigstore.dev/) - Software signing and transparency
- [in-toto](https://in-toto.io/) - Software supply chain security framework
- [TUF](https://theupdateframework.io/) - The Update Framework
- [Snyk](https://snyk.io/) - Developer security platform
- [Dependabot](https://github.com/dependabot) - Automated dependency updates

### Related Tools
- [Bandit](https://bandit.readthedocs.io/) - Python security linter
- [Semgrep](https://semgrep.dev/) - Lightweight static analysis
- [Trivy](https://trivy.dev/) - Vulnerability scanner
- [npm audit](https://docs.npmjs.com/cli/v8/commands/npm-audit) - Node.js security audit
- [pip-audit](https://github.com/pypa/pip-audit) - Python dependency auditor

---

**Version:** 1.0.0
**Last Updated:** 2024-01-15
**Maintainer:** liuyang21cn
**License:** MIT
