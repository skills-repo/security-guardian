---
name: secret-scanner
description: 密钥与凭证扫描：检测泄露的 API Key、Token、密码、敏感配置
source:
  type: derived
  repo: skills-repo/security-guardian
  path: skills/secret-scanner/SKILL.md
  version: 1.0.0
  updated: 2026-07-26
  url: https://skills.sh/ghostsecurity/skills/ghost-scan-secrets
metadata:
  category: 检测
  platform: 通用
  difficulty: 入门
---

# 密钥与凭证扫描

> 扫描代码库中的泄露密钥：API Key、Token、密码、证书、私钥、.env 文件。生成严重性分级和修复指导。

## 能力

- **多类型检测**：AWS/GC/Azure 云密钥、GitHub Token、JWT 密钥、数据库密码
- **深度扫描**：不仅检查当前文件，还扫描 Git 历史和已删除文件
- **严重性分级**：按密钥类型和暴露程度分级（严重/高/中/低）
- **修复指导**：每个发现附带具体修复步骤（轮换、撤销、移除）
- **持续监控**：可集成到 CI/CD 中阻止新密钥进入仓库

## 使用方式

```
/secret-scanner 扫描整个仓库
/secret-scanner 检查这个 PR 有没有泄露密钥
```

## 工作流

1. 确定扫描范围（全仓/指定目录/指定文件）
2. 运行 poltergeist 引擎扫描
3. 对每个候选密钥分析确认（真阳性 vs 假阳性）
4. 生成严重性分级和修复建议
5. 输出扫描报告

## 适用场景

- 代码推送到公开仓库前的检查
- CI/CD 流水线中的自动扫描
- 历史代码中的密钥泄露排查
- 合规审计中的凭证管理检查

## 限制

- 扫描结果可能有假阳性，需要人工确认
- 不检测已加密的密钥
- 不负责密钥轮换的具体执行