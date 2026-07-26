---
name: dependency-audit
description: npm/pip/cargo 等依赖漏洞扫描，识别已知 CVE 并提供修复方案
source:
  type: original
  repo: skills-repo/security-guardian
  path: skills/dependency-audit/SKILL.md
  version: 1.0.0
  updated: 2026-07-26
metadata:
  category: 依赖扫描
  platform: 通用
  difficulty: 入门
---

# 依赖漏洞审计

> 扫描项目依赖，发现已知 CVE 漏洞，给出可执行的升级/替换方案。

## 能力

- **多生态支持**：npm、pip、cargo、go mod、maven、gradle
- **CVE 匹配**：关联依赖版本与 NVD/GitHub Advisory 数据库
- **风险分级**：CVSS 评分 → 紧急/高/中/低四级
- **修复方案**：直接升级、最小升级、替代包三种路径
- **兼容性检查**：升级后是否破坏 API、需要代码变更

## 使用方式

在 Claude Code 中使用 `/dependency-audit` 调用。

```
/dependency-audit 扫描项目依赖漏洞
/dependency-audit 修复所有 high 及以上的依赖漏洞
```

## 工作流

1. 运行依赖扫描（`npm audit`、`pip-audit`、`cargo audit` 等）
2. AI 解析输出，匹配 CVE 详情
3. 按风险等级排序，标注影响范围
4. 对每个漏洞给出修复方案（升级版本 + 可能的代码变更）
5. 输出修复命令和回归测试建议

## 适用场景

- CI 流水线中的依赖安全检查
- 新项目初始化时的依赖版本审计
- 定期安全维护窗口
- 第三方组件选型前的安全评估

## 限制

- 依赖 npm audit/pip-audit 等工具的准确性
- 零日漏洞不在 CVE 数据库范围内
- 间接依赖的修复可能引入传递性兼容问题