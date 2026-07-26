# 安全守护者技能库

> AI Agent Skills for Security —— 代码安全审计、密钥泄露检测、依赖漏洞扫描、认证授权审查

## 定位

为软件开发者提供一套可安装的 AI Agent 安全技能，让 Claude Code 成为你的安全审查搭档。

## 核心理念

> 安全是每个开发者的责任，不是安全团队的专利。用 AI 在开发阶段拦截漏洞，成本最低。

- **左移安全**——在 PR 阶段发现安全问题，不等生产环境出事故
- **自动化优先**——能自动检查的绝不让开发者手动排查
- **可操作输出**——每个发现附带修复建议和代码示例

## 技能清单

| 环节 | 技能 | 描述 | 来源 |
|------|------|------|------|
| 🔍 代码审计 | `security-audit` | OWASP Top 10 代码安全审计，发现注入/XSS/SSRF 等漏洞 | 原创 |
| 🔑 密钥检测 | `secret-scanner` | 检测代码中泄露的 API Key、Token、密码、证书 | 原创 |
| 📦 依赖扫描 | `dependency-audit` | npm/pip/cargo 依赖漏洞扫描与修复方案 | 原创 |
| 🔐 认证审查 | `auth-review` | 认证/授权流程审查，Session/JWT/OAuth 安全检查 | 原创 |

## 快速开始

```bash
# 安装全部技能
npx skills add skills-repo/security-guardian@security-audit -g -y
npx skills add skills-repo/security-guardian@secret-scanner -g -y
npx skills add skills-repo/security-guardian@dependency-audit -g -y
npx skills add skills-repo/security-guardian@auth-review -g -y
```

## 推荐工作流

```
代码审计 → 密钥检测 → 依赖扫描 → 认证审查
security-  secret-    dependency-  auth-
audit      scanner    audit        review
```

## 许可

MIT