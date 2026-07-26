---
name: secret-scanner
description: 检测代码中泄露的 API Key、Token、证书和密码，防止敏感信息进入仓库
metadata:
  category: 密钥检测
  platform: 通用
  difficulty: 入门
---

# 密钥泄露扫描

> 全面扫描代码和 Git 历史中的 API Key、Token、私钥、数据库密码等敏感信息。

## 能力

- **高熵检测**：识别高熵字符串（Base64/Hex 编码的密钥）
- **模式匹配**：覆盖 AWS/GCP/Azure/OpenAI/GitHub Token 等 50+ 常见密钥格式
- **历史扫描**：检查 Git 提交历史中曾经提交的密钥
- **误报过滤**：排除测试数据、示例密钥、文档中的占位符
- **修复指南**：密钥轮换步骤 + `.gitignore` 配置 + pre-commit hook 设置

## 使用方式

在 Claude Code 中使用 `/secret-scanner` 调用。

```
/secret-scanner 扫描当前项目是否有泄露的密钥
/secret-scanner 检查 git 历史中是否曾提交过敏感信息
```

## 工作流

1. 扫描代码文件、配置文件、环境变量模板
2. 可选：扫描 Git 提交历史
3. AI 对每个告警判断是真实密钥还是误报
4. 对真实密钥：给出轮换步骤和清理方案
5. 建议 pre-commit hook 防止未来泄露

## 适用场景

- 开源前的最后安全检查
- 新成员加入团队时的仓库审计
- CI 中的自动密钥扫描
- 事故后的根因排查

## 限制

- 自定义格式的密钥可能被漏检
- 已在远端泄露的密钥轮换后才能消除风险
- 二进制文件（.p12/.jks）检测能力有限