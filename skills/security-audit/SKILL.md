---
name: security-audit
description: 代码安全审计：发现可被利用的漏洞，含攻击场景和修复方案
source:
  type: derived
  repo: skills-repo/security-guardian
  path: skills/security-audit/SKILL.md
  version: 1.0.0
  updated: 2026-07-26
  url: https://skills.sh/cloudflare/security-audit-skill/security-audit
metadata:
  category: 审计
  platform: 通用
  difficulty: 进阶
---

# 代码安全审计

> 发现可被利用的真实漏洞，不是理论担忧。每个发现都有具体攻击场景：攻击者是谁、做什么、得到什么。

## 能力

- **漏洞发现**：SQL 注入、XSS、SSRF、权限绕过、不安全的反序列化
- **攻击场景构建**：每个发现的威胁模型和利用路径
- **动态验证**：尽可能用实际请求验证漏洞存在
- **分阶段审计**：架构分析 → 并行审计 → 交叉验证 → 报告生成
- **历史感知**：复用之前审计结果，跳过已知发现，聚焦新攻击面

## 使用方式

```
/security-audit 审计这个代码库的安全漏洞
/security-audit 重点检查这个 API 端点的认证和授权
```

## 工作流

1. 建立审计目标路径和输出目录
2. 阶段一：分析架构（入口点、数据流、信任边界）
3. 阶段二：并行审计（注入、认证、授权、加密、业务逻辑）
4. 阶段三：交叉验证发现，动态确认可被利用
5. 阶段四：输出 REPORT.md + findings.json

## 适用场景

- 上线前安全审计
- PR 安全审查
- 加密实现审计
- 第三方依赖风险评估

## 限制

- 单次审计通常只能发现约 50% 的漏洞，建议多次运行
- 需要实际运行环境才能动态验证
- 不替代专业渗透测试