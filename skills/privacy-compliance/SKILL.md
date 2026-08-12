---
name: privacy-compliance
description: 隐私合规与数据保护：GDPR/CCPA/PIPL 适用性判断、PII 盘点、DPIA、同意与隐私设计、跨境传输与数据主体权利
source:
  type: derived
  repo: skills-repo/security-guardian
  path: skills/privacy-compliance/SKILL.md
  version: 1.0.0
  updated: 2026-08-12
  url: https://skills.sh/phuryn/pm-skills/privacy-policy
metadata:
  category: 合规
  platform: 通用
  difficulty: 入门
---

# 隐私合规与数据保护

> 在功能设计 / 上线前判断「要遵守哪部隐私法、盘子里的 PII 是什么、需要走哪些合规动作」。给出可勾选的清单与决策树，而非法律意见。

## 能力

- **框架适用性判断**：根据「处理者所在地 / 用户所在地 / 数据类型」判定 GDPR、CCPA/CPRA、PIPL（中国个人信息保护法）中哪些适用。
- **PII 盘点（数据映射）**：梳理收集了哪些个人数据、存在哪、流向哪、保留多久。
- **DPIA 引导**：对高风险处理（大规模敏感数据、画像、跨境）做数据保护影响评估的步骤清单。
- **同意与隐私设计**：同意获取、隐私政策、默认隐私（privacy by design）的可勾选检查项。
- **跨境与权利**：跨境传输机制（SCC / 标准合同 / 充分性认定）、数据主体权利（访问/删除/携带）响应要点。
- **泄露通知**：发生数据泄露时的内部升级与外部通知时间线。

## 使用方式

```
/privacy-compliance 这个功能要收集用户手机号，要不要走 GDPR？
/privacy-compliance 帮我把这个新服务的 PII 盘点做出来
/privacy-compliance 我们的数据要传到美国，合规上要做什么？
```

## 工作流

1. 判定适用框架（见 `references/privacy-compliance-playbook.md` 的「框架适用性决策树」）。
2. 做 PII 盘点：列出字段、存储位置、用途、保留期、第三方共享。
3. 若属高风险处理 → 跑 DPIA 清单。
4. 检查同意获取与隐私政策是否齐备（隐私设计清单）。
5. 涉及跨境 → 确认传输机制；涉及敏感数据 → 确认合法性基础。
6. 输出「合规待办清单 + 风险点」，标注哪些必须由法务最终确认。

## 适用场景

- 新功能 / 新服务上线前的隐私影响自查
- 收集个人信息（邮箱、手机号、位置、生物识别等）前的合规性把关
- 数据出境 / 多地区用户产品的合规梳理
- 应对客户问卷、供应商尽调中的隐私合规部分

## 与其他技能协作

- 需要代码层拦截凭证泄露 → `skills/secret-scanner`
- 需要数据科学场景下的隐私治理 → `skills-repo/data-scientist`
- 本技能只做合规梳理与清单，**不构成法律意见**；落地文本与跨境合同以法务/律师为准。

## 限制

- 不输出法律意见，仅提供可操作的合规清单与决策树。
- 各国/地区细则更新频繁，关键判定（尤其是跨境与敏感数据）须由法务复核。
- 不替代专业的 DPO（数据保护官）或律所意见。
