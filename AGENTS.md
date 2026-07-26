# AGENTS.md

## 仓库性质

这是一个 **AI Agent 技能库**，不是软件项目。所有内容为 Markdown 格式的技能定义文件。

## 目录约定

```
security-guardian/
├── README.md              # 项目介绍和使用指南
├── AGENTS.md              # AI 助手使用指引（本文件）
└── skills/                # 技能目录
    ├── <skill-name>/      # 单个技能目录
    │   └── SKILL.md       # 技能定义文件
    └── ...
```

## SKILL.md 格式

每个技能文件遵循以下结构：

```markdown
---
name: <skill-name>
description: <一句话描述>
metadata:
  category: <代码审计|密钥检测|依赖扫描|认证审查>
  platform: <Web|API|通用>
  difficulty: <入门|进阶|专家>
---

# <技能名称>

> <一句话简介>

## 能力

- 能力点列表

## 使用方式

在 Claude Code 中使用 `/skill-name` 调用。

## 工作流

1. 步骤化的执行流程

## 适用场景

- 场景列表

## 限制

- 不擅长的领域
```

## 工作约定

- 所有技能内容使用中文编写
- 遵循 OWASP Top 10、CWE Top 25 等行业标准
- 每个发现必须附带：风险等级、利用条件、修复方案
- 不输出纯理论文章，聚焦可操作的检测和修复

## 技能添加流程

1. 在 `skills/` 下创建以技能名命名的目录
2. 编写 `SKILL.md`
3. 确保 `metadata` 字段完整
4. 更新 `README.md` 中的技能清单表

## 不做什么

- 不创建渗透测试/漏洞利用技能（仅防御性安全）
- 不创建面向特定商业产品的安全技能
- 不输出未经验证的修复方案