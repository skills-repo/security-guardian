# 安全守护者技能库

> AI Agent Skills for Security —— 代码安全审计、密钥泄露检测、依赖漏洞扫描、认证授权审查

## 定位

为软件开发者提供一套可安装的 AI Agent 安全技能，让 Claude Code 成为你的安全审查搭档。

## 核心理念

> 安全是每个开发者的责任，不是安全团队的专利。用 AI 在开发阶段拦截漏洞，成本最低。

- **左移安全**——在 PR 阶段发现安全问题，不等生产环境出事故
- **自动化优先**——能自动检查的绝不让开发者手动排查
- **可操作输出**——每个发现附带修复建议和代码示例

## 安装

### 方式一：整库安装（推荐）

一次性安装全部 5 个技能：

```bash
npx skills add skills-repo/security-guardian -g -y
```

### 方式二：按需安装单个技能

只安装你需要的某一个技能：

```bash
npx skills add skills-repo/security-guardian@security-audit -g -y
npx skills add skills-repo/security-guardian@secret-scanner -g -y
npx skills add skills-repo/security-guardian@dependency-audit -g -y
npx skills add skills-repo/security-guardian@auth-review -g -y
npx skills add skills-repo/security-guardian@privacy-compliance -g -y
```

> 参数说明：`-g` 全局安装，`-y` 跳过确认。按你的 skills 工具习惯选择是否带这两个 flag。

## 技能清单

| 环节 | 技能 | 描述 | 来源 |
|------|------|------|------|
| 🔍 代码审计 | `security-audit` | 代码安全审计：发现可被利用的漏洞，含攻击场景和修复方案 | [衍生](https://skills.sh/cloudflare/security-audit-skill/security-audit) |
| 🔑 密钥检测 | `secret-scanner` | 密钥与凭证扫描：检测泄露的 API Key、Token、密码 | [衍生](https://skills.sh/ghostsecurity/skills/ghost-scan-secrets) |
| 📦 依赖扫描 | `dependency-audit` | 加密代码常量时间审计：检测时序侧信道漏洞 | [衍生](https://skills.sh/trailofbits/skills/constant-time-testing) |
| 🔐 认证审查 | `auth-review` | Firebase 认证与授权：用户管理、登录、安全规则 | [衍生](https://skills.sh/firebase/agent-skills/firebase-auth-basics) |
| 🛡️ 隐私合规 | `privacy-compliance` | 隐私合规与数据保护：GDPR/CCPA/PIPL 适用性、PII 盘点、DPIA、同意与跨境 | [衍生](https://skills.sh/phuryn/pm-skills/privacy-policy) |

## 推荐工作流

```
代码审计 → 密钥检测 → 依赖扫描 → 认证审查
security-  secret-    dependency-  auth-
audit      scanner    audit        review
```

## 许可

MIT
