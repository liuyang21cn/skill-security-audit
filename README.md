# Skill Security Audit

**[English](#english) | [中文](#中文)**

---

<a name="english"></a>
## English

A comprehensive security scanner for Claude Code skills to detect supply chain attack vectors, malicious code patterns, and potential backdoors.

> **⚠️ Disclaimer / 声明:** This skill is currently **experimental** and provided as a proof-of-concept. While it implements various security checks, it may not catch all vulnerabilities or may produce false positives. **Contributions, optimizations, and improvements are highly welcome!** Please feel free to open issues or submit pull requests.
> <br><br>**本技能目前为实验性质**，作为概念验证提供。虽然它实现了各种安全检查，但可能无法捕获所有漏洞或可能产生误报。**非常欢迎贡献、优化和完善！** 请随时提出问题或提交拉取请求。

![License](https://img.shields.io/badge/License-MIT-blue.svg)
![Python](https://img.shields.io/badge/Python-3.8%2B-green.svg)
![Security](https://img.shields.io/badge/Security-Audited-orange.svg)

### Overview

Every third-party skill is a potential supply chain attack vector. This tool provides automated security auditing before skill execution, protecting users from malicious or compromised third-party skills.

### Quick Start

```bash
# Clone the repository
git clone https://github.com/liuyang21cn/skill-security-audit.git
cd skill-security-audit

# Install dependencies
pip install -r requirements.txt

# Run security scan
python scan_skill.py ~/.claude/skills/suspicious-skill
```

### Usage Examples

```bash
# Basic scan with console output
python scan_skill.py ./skill-to-check

# JSON output to file
python scan_skill.py ./skill --format json --output report.json

# HTML report
python scan_skill.py ./skill --format html --output report.html

# Show only high and critical findings
python scan_skill.py ./skill --severity high

# Verbose output with detailed progress
python scan_skill.py ./skill --verbose
```

### Risk Levels

| Level | Score | Icon | Action Required |
|-------|-------|------|-----------------|
| Critical | 70-100 | 🔴 | **DELETE IMMEDIATELY** - Do not use |
| High | 50-69 | 🟠 | **MANUAL REVIEW** - Use with extreme caution |
| Medium | 25-49 | 🟡 | **CAUTION** - Review findings before use |
| Low | 0-24 | 🟢 | **APPROVED** - Relatively safe to use |

### Detection Capabilities

**Python:**
- `eval()`, `exec()`, `compile()` - Code execution
- `pickle.loads()` - Insecure deserialization
- `yaml.unsafe_load()` - YAML code execution
- `subprocess.*(shell=True)` - Command injection
- `os.system()` - Command injection

**Bash/Shell:**
- `curl | bash` - Remote code execution
- `eval "$var"` - Dynamic code execution
- `source <(curl ...)` - Remote script sourcing
- `bash -i >& /dev/tcp/` - Reverse shell

**JavaScript/Node.js:**
- `eval()`, `new Function()` - Code execution
- `child_process.exec()` - Command execution
- `vm.runInContext()` - VM escape risk

### CI/CD Integration

GitHub Actions example:

```yaml
name: Skill Security Audit
on:
  push:
    paths: ['skills/**']
  pull_request:
    paths: ['skills/**']

jobs:
  security-audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.10'
      - name: Install dependencies
        run: pip install pyyaml
      - name: Run security audit
        run: |
          for skill in skills/*/; do
            echo "Auditing $skill..."
            python scan_skill.py --format json "$skill" || true
          done
      - name: Check for critical findings
        run: |
          if find skills -name "*.json" -exec grep -l '"severity": "critical"' {} \; | grep -q .; then
            echo "::error::Critical security issues found!"
            exit 1
          fi
          echo "✅ No critical issues found"
```

### Project Structure

```
skill-security-audit/
├── SKILL.md                      # Claude Code skill definition
├── README.md                     # Project documentation (this file)
├── LICENSE                       # MIT License
├── scan_skill.py                 # Main scanning engine
├── requirements.txt              # Python dependencies
├── rules/                        # Security detection rules
│   ├── python_dangerous_patterns.yml
│   ├── bash_dangerous_patterns.yml
│   └── js_dangerous_patterns.yml
├── scripts/                      # Scanner implementations
│   ├── __init__.py
│   └── scanners.py
└── examples/                     # Example malicious patterns (for testing)
```

### Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-rule`)
3. Commit your changes (`git commit -am 'Add new security rule'`)
4. Push to the branch (`git push origin feature/new-rule`)
5. Create a Pull Request

### License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

### Acknowledgments

- Inspired by [Bandit](https://bandit.readthedocs.io/) - Python security linter
- [Semgrep](https://semgrep.dev/) - Static analysis tool
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)

### Contact

- GitHub: [@liuyang21cn](https://github.com/liuyang21cn)
- Email: yang.liu.fly@gmail.com

---

**Protect your Claude Code environment - Always audit before installing!** 🔒

---

<a name="中文"></a>
## 中文

用于检测 Claude Code 技能的供应链攻击向量、恶意代码模式和潜在后门的综合安全扫描器。

### 概述

每个第三方技能都是潜在的供应链攻击向量。本工具在技能执行前提供自动化安全审计，保护用户免受恶意或被入侵的第三方技能的威胁。

### 快速开始

```bash
# 克隆仓库
git clone https://github.com/liuyang21cn/skill-security-audit.git
cd skill-security-audit

# 安装依赖
pip install -r requirements.txt

# 运行安全扫描
python scan_skill.py ~/.claude/skills/suspicious-skill
```

### 使用示例

```bash
# 基本扫描（控制台输出）
python scan_skill.py ./skill-to-check

# JSON 输出到文件
python scan_skill.py ./skill --format json --output report.json

# HTML 报告
python scan_skill.py ./skill --format html --output report.html

# 仅显示高危和严重发现
python scan_skill.py ./skill --severity high

# 详细输出（显示进度详情）
python scan_skill.py ./skill --verbose
```

### 风险等级

| 等级 | 分数 | 图标 | 所需操作 |
|-------|-------|------|-----------------|
| 严重 | 70-100 | 🔴 | **立即删除** - 禁止使用 |
| 高危 | 50-69 | 🟠 | **人工审查** - 极其谨慎使用 |
| 中危 | 25-49 | 🟡 | **谨慎** - 使用前审查发现 |
| 低危 | 0-24 | 🟢 | **批准** - 相对安全可使用 |

### 检测能力

**Python:**
- `eval()`, `exec()`, `compile()` - 代码执行
- `pickle.loads()` - 不安全反序列化
- `yaml.unsafe_load()` - YAML 代码执行
- `subprocess.*(shell=True)` - 命令注入
- `os.system()` - 命令注入

**Bash/Shell:**
- `curl | bash` - 远程代码执行
- `eval "$var"` - 动态代码执行
- `source <(curl ...)` - 远程脚本源
- `bash -i >& /dev/tcp/` - 反弹 Shell

**JavaScript/Node.js:**
- `eval()`, `new Function()` - 代码执行
- `child_process.exec()` - 命令执行
- `vm.runInContext()` - VM 逃逸风险

### CI/CD 集成

GitHub Actions 示例:

```yaml
name: 技能安全审计
on:
  push:
    paths: ['skills/**']
  pull_request:
    paths: ['skills/**']

jobs:
  security-audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: 设置 Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.10'
      - name: 安装依赖
        run: pip install pyyaml
      - name: 运行安全审计
        run: |
          for skill in skills/*/; do
            echo "审计 $skill..."
            python scan_skill.py --format json "$skill" || true
          done
      - name: 检查严重发现
        run: |
          if find skills -name "*.json" -exec grep -l '"severity": "critical"' {} \; | grep -q .; then
            echo "::error::发现严重安全问题!"
            exit 1
          fi
          echo "✅ 未发现严重问题"
```

### 项目结构

```
skill-security-audit/
├── SKILL.md                      # Claude Code 技能定义
├── README.md                     # 项目文档 (本文件)
├── LICENSE                       # MIT 许可证
├── scan_skill.py                 # 主扫描引擎
├── requirements.txt              # Python 依赖
├── rules/                        # 安全检测规则
│   ├── python_dangerous_patterns.yml
│   ├── bash_dangerous_patterns.yml
│   └── js_dangerous_patterns.yml
├── scripts/                      # 扫描器实现
│   ├── __init__.py
│   └── scanners.py
└── examples/                     # 示例恶意模式 (用于测试)
```

### 如何贡献

1. Fork 仓库
2. 创建功能分支 (`git checkout -b feature/new-rule`)
3. 提交更改 (`git commit -am '添加新安全规则'`)
4. 推送到分支 (`git push origin feature/new-rule`)
5. 创建 Pull Request

### 许可证

本项目采用 MIT 许可证 - 详见 [LICENSE](LICENSE) 文件。

### 致谢

- 灵感来自 [Bandit](https://bandit.readthedocs.io/) - Python 安全检测器
- [Semgrep](https://semgrep.dev/) - 静态分析工具
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)

### 联系方式

- GitHub: [@liuyang21cn](https://github.com/liuyang21cn)
- 邮箱: yang.liu.fly@gmail.com

---

**保护您的 Claude Code 环境 - 安装前务必审计！** 🔒