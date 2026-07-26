---
name: security-audit
description: 基于 OWASP Top 10 的代码审计，发现 SQL 注入/XSS/SSRF/权限绕过等漏洞
source:
  type: original
  repo: skills-repo/security-guardian
  path: skills/security-audit/SKILL.md
  version: 1.0.0
  updated: 2026-07-26
metadata:
  category: 代码审计
  platform: Web
  difficulty: 专家
---

# 代码安全审计

> 基于 OWASP Top 10 和 CWE Top 25，深度审查代码中的安全漏洞。

## 能力

- **注入检测**：SQL 注入、命令注入、LDAP 注入、模板注入
- **XSS 识别**：反射型、存储型、DOM 型 XSS 及 CSP 绕过
- **SSRF 发现**：识别用户可控的 URL/HTTP 请求目标
- **权限审查**：越权、未授权访问、不安全的直接对象引用
- **加密检查**：弱加密算法、硬编码密钥、不安全的随机数
- **反序列化**：不安全的反序列化入口

## 使用方式

在 Claude Code 中使用 `/security-audit` 调用。

```
/security-audit 审计这个 PR 的安全风险
/security-audit 全面审查用户认证模块
```

## 工作流

1. 指定审计范围（文件、模块、PR diff）
2. AI 逐文件分析，标记可疑代码模式
3. 对每个发现标注：风险等级、CWE 编号、攻击向量
4. 给出修复代码和防御方案
5. 输出审计报告摘要

## 输出格式

```markdown
## 安全审计报告

| # | 漏洞类型 | 风险等级 | 文件:行号 | 状态 |
|---|---------|---------|----------|------|
| 1 | SQL 注入 | 严重 | api/users.ts:42 | 需修复 |
| 2 | 缺少 CSRF 保护 | 中 | form.tsx:15 | 建议修复 |

### 详细说明

#### #1 SQL 注入 — api/users.ts:42
**问题**：用户输入直接拼接到 SQL 查询
**攻击向量**：`GET /users?name='; DROP TABLE users; --`
**修复**：使用参数化查询
```

## 适用场景

- PR 安全审查
- 新功能上线前的安全检查
- 合规审计准备（SOC2、ISO27001）
- 接受外部安全报告后的验证

## 限制

- 不替代专业渗透测试
- 不覆盖运行时的 0day 攻击
- 框架安全特性的误报需要人工确认