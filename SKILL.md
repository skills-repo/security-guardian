---
name: security-guardian
description: >-
  代码安全审计、密钥泄露检测、依赖供应链审计、认证授权审查、Web 加固与隐私合规（GDPR/CCPA/PIPL 数据保护）的 AI Agent 技能库。
  帮助开发者在 PR / 开发阶段拦截漏洞：发现可被利用的真实漏洞并给出攻击场景与修复方案。
  内置密钥扫描、CSP/安全头审计、依赖供应链审计三套零依赖脚本。
  触发词："安全审计、代码审计、漏洞、密钥扫描、secret、依赖审计、供应链、认证授权、JWT、登录安全、安全头、CSP、HSTS、威胁建模、左移安全、隐私合规、GDPR、CCPA、PIPL、数据保护、PII、跨境传输"。
agent_created: true
metadata:
  version: 1.0.0
  category: 安全与合规
  difficulty: 专家
  architecture: superpower
---

# 安全守护者

> 把 AI 助手变成一名能独立扛下「左移安全」链路的安全审查搭档：从威胁建模、代码审计、密钥检测、依赖审计到 Web 加固，每个发现都附带风险等级、利用条件与修复方案。

本技能采用 **superpower 架构**：`SKILL.md` 只做路由，深层 playbook 放在 `references/` 中**按需加载**，细粒度能力放在 `skills/` 子技能，确定性任务交给 `scripts/`，可复用模板放在 `assets/`。

## 何时使用

在以下任一情况触发本技能：

- 上线前 / PR 阶段需要做**代码安全审计**，找出可被利用的漏洞（注入、越权、SSRF、反序列化等）。
- 需要**扫描代码库或 Git 历史**中的泄露密钥、令牌、凭证、`.env` 文件。
- 想**审计依赖与供应链**：固定版本、typosquatting、lockfile 完整性、第三方 Action pin SHA。
- 需要审查**认证 / 授权**设计（登录流程、Session vs JWT、RBAC、对象级权限防 IDOR）。
- 想**加固 Web 层**：配置 CSP / HSTS / CORS / Cookie 属性等安全响应头。
- 新功能上线前做**威胁建模**（四问法 + STRIDE + 风险评级）。
- 收集个人信息（邮箱/手机号/位置/生物识别等）前做**隐私合规自查**：判断适用 GDPR/CCPA/PIPL、盘点 PII、确认同意与跨境机制。

## 能力索引（超级技能路由）

本技能采用渐进式加载（progressive disclosure）。`SKILL.md` 仅作路由，**按需**读取下列 `references/` 中的完整 playbook，避免一次性占满上下文。

| 任务 | 读取 / 调用 | 关键词（grep 线索） |
|------|------------|---------------------|
| 威胁建模：四问法、STRIDE、风险 2D 评级、接受/修复决策 | `references/threat-modeling.md` | 威胁建模、威胁模型、STRIDE、风险评估、threat model |
| 代码审计 playbook：四阶段、漏洞类别检测、误报过滤 | `references/code-audit-playbook.md` | 代码审计、漏洞、注入、XSS、SSRF、越权、反序列化 |
| 密钥管理：泄露处置顺序、历史清理、误报抑制 | `references/secrets-management.md` | 密钥、凭证、泄露、轮换、secret、revoke |
| 依赖供应链：可达性分级、投毒、lockfile、SBOM | `references/dependency-supply-chain.md` | 依赖、供应链、依赖审计、lockfile、SBOM、typosquat |
| 认证授权：选型树、JWT 校验、RBAC/ABAC、IDOR 防护 | `references/authn-authz.md` | 认证、授权、登录、JWT、Session、RBAC、权限 |
| Web 加固：安全头优先级、HSTS 阶梯、CSP 路径、CORS 误区 | `references/web-hardening.md` | 安全头、CSP、HSTS、CORS、加固、headers |
| 代码安全审计：发现可被利用漏洞，含攻击场景与修复 | `skills/security-audit/SKILL.md` | 安全审计、漏洞审计、security audit、代码审查 |
| 密钥与凭证扫描：检测泄露的 API Key、Token、密码 | `skills/secret-scanner/SKILL.md` | 密钥扫描、凭证扫描、secret scan、泄露检测 |
| 常量时间审计：检测加密代码的时序侧信道漏洞 | `skills/dependency-audit/SKILL.md` | 常量时间、时序侧信道、constant time、加密审计 |
| 认证授权基础：用户管理、登录流程、安全规则、会话 | `skills/auth-review/SKILL.md` | 认证审查、登录流程、Firebase、安全规则、会话 |
| 隐私合规与数据保护：GDPR/CCPA/PIPL 适用性、PII 盘点、DPIA、同意与跨境 | `skills/privacy-compliance/SKILL.md` + `references/privacy-compliance-playbook.md` | 隐私合规、GDPR、CCPA、PIPL、数据保护、PII、跨境传输、DPIA、同意 |

> 路由规则：先做**方法论决策**读 `references/`；要落地具体动作直接调 `skills/`；能用脚本确定性完成的（密钥扫描、CSP 审计、依赖审计）优先跑 `scripts/`。

## 内置脚本（确定性、可重复执行）

放在 `scripts/`，优先用脚本处理重复/确定性任务，而非每次重写代码：

- `scripts/secret_scan.py <paths> [--strict] [--json] [--baseline f.json]` — 扫描密钥/令牌泄露（正则 + 香农熵 + 占位符过滤），CI 中可阻断新泄露。
- `scripts/csp_audit.py --policy "..." | --headers-file f.txt [--report-only] [--strict] [--json]` — 审计 CSP/安全头、CORS、信息泄露头。
- `scripts/dep_audit.py <path> [--strict] [--json]` — 审计 npm/Python/Go/Action 的依赖供应链（版本固定、typosquat、pin SHA）。

运行示例：

```bash
python3 scripts/secret_scan.py . --strict
python3 scripts/csp_audit.py --headers-file headers.txt --strict
python3 scripts/dep_audit.py . --strict
```

## 模板资源

`assets/` 提供可直接套用的配置与模板：

- `assets/threat-model-template.md` — 四问法 + STRIDE + 风险矩阵记录表
- `assets/vulnerability-report-template.md` — 单漏洞发现报告（含 CWE/OWASP/利用场景/修复 diff）
- `assets/security-review-checklist.md` — PR/上线前统一打钩清单（覆盖 A–F 六类）
- `assets/secret-scan-ci.yml` — 在 CI 中阻断新密钥泄露的 GitHub Actions 示例
- `assets/security-headers.conf` — Nginx 安全响应头配置示例（CSP/HSTS/CORS）

## 核心原则（始终遵循）

1. **左移安全**：在 PR / 开发阶段拦截漏洞，不等生产环境出事故；能自动检查的绝不让开发者手动排查。
2. **可操作输出**：每个发现必须含「风险等级 + 利用条件 + 修复方案」，拒绝纯理论文章。
3. **渐进式加载**：先读路由表与对应 `references/`，再动手；不凭记忆猜命令与 API、不臆造缓解措施。
4. **证据优先**：能用实际请求/脚本验证的漏洞优先验证，尚未验证的项必须明确标注「未验证」。
5. **明确边界**：仅做防御性安全；不提供攻击利用脚本，不输出未经验证的修复方案，替代不了专业渗透测试。

## 与其他技能协作

- 需要全栈工程视角（含安全落地）→ `skills-repo/ai-fullstack-engineer`
- 需要 DevOps / 流水线把扫描接入 CI → `skills-repo/devops-engineer`
- 需要数据科学场景下的隐私 / 数据合规 → `skills-repo/data-scientist`
