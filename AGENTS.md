# AGENTS.md

## 仓库性质

这是一个 **AI Agent 技能库**，不是软件项目。内容采用 **superpower 架构**，分为五层：

```
security-guardian/
├── SKILL.md              # 根路由层（L1）：只做能力索引与路由，不堆砌细节
├── README.md             # 项目介绍与使用指南（含整库 / 单技能双安装命令）
├── AGENTS.md             # AI 助手使用指引（本文件）
├── LICENSE               # MIT
├── .gitignore
├── references/           # 方法论 playbook（L2，按需加载）
│   ├── threat-modeling.md
│   ├── code-audit-playbook.md
│   ├── secrets-management.md
│   ├── dependency-supply-chain.md
│   ├── authn-authz.md
│   └── web-hardening.md
├── skills/               # 细粒度子技能（L3），每个含 SKILL.md
│   ├── <skill-name>/
│   │   └── SKILL.md
│   └── ...
├── scripts/              # 确定性、可重复执行的脚本（L4）
│   ├── secret_scan.py
│   ├── csp_audit.py
│   └── dep_audit.py
└── assets/               # 可复用模板与配置（L5）
    ├── threat-model-template.md
    ├── vulnerability-report-template.md
    ├── security-review-checklist.md
    ├── secret-scan-ci.yml
    └── security-headers.conf
```

## 分层约定

- **L1 `SKILL.md`**：顶层路由，用「能力索引表 + grep 关键词」把任务导向 `references/` 或 `skills/`。只在顶层写价值主张与何时使用，细节留给 references。
- **L2 `references/`**：深层方法论 playbook，渐进式加载。新增方法论时加文件并在根 SKILL.md 路由表登记。
- **L3 `skills/`**：细粒度子技能，目录名即技能名，每个含 `SKILL.md`（必须带 `source` 字段）。
- **L4 `scripts/`**：确定性任务优先写成脚本（纯标准库、零依赖、可离线），CI 可直接调用。
- **L5 `assets/`**：可直接套用的模板 / 配置文件，避免每次重写。

## 子技能 frontmatter 规范

每个 `skills/<name>/SKILL.md` 遵循：

```markdown
---
name: <skill-name>
description: <一句话描述>
source:
  type: derived | original
  repo: skills-repo/security-guardian
  path: skills/<skill-name>/SKILL.md
  version: 1.0.0
  updated: <YYYY-MM-DD>
  url: <来源链接，derived 必填>
metadata:
  category: <审计|检测|加密|认证>
  platform: <Web|API|通用>
  difficulty: <入门|进阶|专家>
---
```

## 工作约定

- 所有技能内容使用中文编写
- 遵循 OWASP Top 10、CWE Top 25 等行业标准
- 每个发现必须附带：风险等级、利用条件、修复方案
- 不输出纯理论文章，聚焦可操作的检测和修复
- 新增 `original` 内容前须先用 skill-radar 检索 skills.sh + GitHub（见 skills-repo-admin 规范），且单库 original 占比 ≤ 25%

## 技能添加流程

1. 在 `skills/` 下创建以技能名命名的目录，编写 `SKILL.md`（带 `source` 字段）
2. 如涉及新方法论，在 `references/` 增文并在根 `SKILL.md` 路由表登记
3. 如可用脚本确定性完成，放入 `scripts/`（保持零依赖、可离线）
4. 更新 `README.md` 的技能清单表
5. 运行 `audit_architecture.py --repo security-guardian --strict` 确认等级达标

## 不做什么

- 不创建渗透测试/漏洞利用技能（仅防御性安全）
- 不创建面向特定商业产品的安全技能
- 不输出未经验证的修复方案
- 不删除或重命名已发布的子技能目录（只增不减）
