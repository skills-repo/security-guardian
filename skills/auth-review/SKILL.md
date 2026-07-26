---
name: auth-review
description: Firebase 认证与授权基础：用户管理、登录流程、安全规则、多因素认证
source:
  type: derived
  repo: skills-repo/security-guardian
  path: skills/auth-review/SKILL.md
  version: 1.0.0
  updated: 2026-07-26
  url: https://skills.sh/firebase/agent-skills/firebase-auth-basics
metadata:
  category: 认证
  platform: Web
  difficulty: 入门
---

# 认证与授权基础

> 以 Firebase Auth 为参考的认证授权实践：用户管理、登录流程、安全规则、Session 管理。

## 能力

- **用户管理**：注册、登录、密码重置、邮箱验证、用户资料
- **登录方式**：邮箱/密码、Google/Apple/GitHub OAuth、匿名登录、手机号
- **安全规则**：Firestore Security Rules、基于角色的访问控制（RBAC）
- **Session 管理**：Token 刷新、自动登录、登出、多设备管理
- **多因素认证**：MFA 设置、SMS/TOTP 验证

## 使用方式

```
/auth-review 为我的应用设计认证流程
/auth-review 审查这个 Firestore 安全规则是否合理
/auth-review 添加 Google 登录到现有认证系统
```

## 工作流

1. 确认认证需求（登录方式、安全级别、用户量级）
2. 选择认证提供商组合
3. 实现注册/登录/密码重置流程
4. 配置安全规则和数据访问控制
5. 测试边界情况（Token 过期、网络中断、多设备）

## 适用场景

- 新应用认证系统搭建
- 已有系统添加第三方登录
- 安全规则审查
- Session 管理和安全策略

## 限制

- 以 Firebase Auth 为主要参考，非平台无关
- 不涉及企业级 SSO/SAML
- 不涉及自建认证服务器