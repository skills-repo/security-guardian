---
name: dependency-audit
description: 加密代码常量时间审计：检测时序侧信道漏洞，适用于加密实现审查
source:
  type: derived
  repo: skills-repo/security-guardian
  path: skills/dependency-audit/SKILL.md
  version: 1.0.0
  updated: 2026-07-26
  url: https://skills.sh/trailofbits/skills/constant-time-testing
metadata:
  category: 加密
  platform: 通用
  difficulty: 专家
---

# 常量时间安全审计

> 检测加密代码中的时序侧信道漏洞。执行时间的差异可能泄露密钥——这影响任何加密实现。

## 能力

- **时序漏洞检测**：条件跳转、数组访问、整数除法、位移操作中的时序差异
- **四种违规模式**：基于密钥的条件分支、查表索引、可变位数除法、非固定移位
- **攻击场景分析**：RSA/ECDH 私钥提取、网络可观测的时序差异
- **修复模式**：常量时间比较、位掩码替代分支、预计算表

## 使用方式

```
/dependency-audit 审计这个加密函数的常量时间安全
/dependency-audit 检查这个密码学库有没有时序侧信道
```

## 工作流

1. 识别加密操作（密钥生成、签名、解密、比较）
2. 检查四种常见违规模式
3. 对每个可疑位置分析数据流和密钥依赖
4. 评估利用可行性（攻击者可观察性、查询次数）
5. 提供常量时间修复方案

## 适用场景

- 密码学库代码审查
- 认证模块安全审计
- JWT/Token 验证逻辑检查
- 后量子加密实现的时序安全性

## 限制

- 需要加密学基础知识
- 不覆盖功耗分析等非时序侧信道
- 微架构级时序差异需要实际测量验证