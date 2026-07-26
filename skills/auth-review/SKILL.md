---
name: auth-review
description: 认证授权流程安全审查，检查 Session 管理、JWT 配置、OAuth 实现和权限模型
source:
  type: original
  repo: skills-repo/security-guardian
  path: skills/auth-review/SKILL.md
  version: 1.0.0
  updated: 2026-07-26
metadata:
  category: 认证审查
  platform: Web
  difficulty: 专家
---

# 认证授权审查

> 审查认证与授权实现，找出 Session/Token 管理、OAuth 流程、权限控制的安全缺陷。

## 能力

- **Session 安全**：Cookie 属性检查（HttpOnly/Secure/SameSite）、Session 固定攻击
- **JWT 审查**：算法混淆、密钥强度、过期策略、刷新逻辑
- **OAuth/OIDC**：redirect_uri 校验、state 参数、code 交换安全性
- **权限模型**：RBAC/ABAC 实现审查、越权检查、最小权限原则
- **多因素认证**：MFA 旁路检测、恢复流程安全性
- **密码策略**：哈希算法、盐值、重置流程

## 使用方式

在 Claude Code 中使用 `/auth-review` 调用。

```
/auth-review 审查登录和注册模块的认证实现
/auth-review 检查 API 的权限校验是否完备
```

## 工作流

1. 指定审查的认证/授权模块
2. AI 分析 Session/JWT/Token 管理代码
3. 检查 OWASP 认证类漏洞清单（ASVS V2/V3）
4. 逐条标注风险和建议修复
5. 输出 ASVS 对齐的审查报告

## 输出格式

```markdown
## 认证授权审查报告

| 类别 | 检查项 | 结果 | 风险 |
|------|--------|------|------|
| Session | Cookie HttpOnly | ✅ | - |
| JWT | 签名算法 RS256→HS256 混淆 | ❌ | 严重 |
| OAuth | state 参数未校验 | ❌ | 高 |

### 修复建议

#### JWT 算法混淆
**问题**：服务端未固定签名算法，攻击者可切换为 HS256 用公钥签名
**修复**：在 JWT 验证时显式指定 `algorithms: ['RS256']`
```

## 适用场景

- 自建认证系统的安全审查
- OAuth/OIDC 集成实现验证
- 权限系统重构前的安全基线
- 合规检查（ASVS、PCI DSS）

## 限制

- 不审查第三方认证服务（Auth0/Clerk）的实现
- 密码学层面的强度分析（如量子安全）需要专业工具
- 社交工程/钓鱼攻击不在审查范围内