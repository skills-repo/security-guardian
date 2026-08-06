# 安全审查清单（合并版）

> 用途：PR 审查 / 上线前自查的统一打钩表。配套 playbook 见 `references/` 各篇。
> 规则：每条必须「已查 / 不适用」二选一；命中风险项须附带处理记录。

## A. 认证与授权（references/authn-authz.md）

- [ ] 默认用 Session 而非 JWT，除非有无状态刚需
- [ ] JWT 已校验：签名算法非 `none`、密钥非硬编码、已校验过期与受众
- [ ] 对象级授权已校验（防 IDOR：ID 来自可信上下文而非用户输入）
- [ ] 权限模型明确（RBAC/ABAC/ReBAC 其一），无行级 `if user.is_admin` 散落
- [ ] 密码用 Argon2id/bcrypt/scrypt，无明文/弱哈希/自创算法
- [ ] 登录失败有速率限制与锁定，无账号枚举泄露

## B. 代码审计（references/code-audit-playbook.md）

- [ ] 注入类：SQL/NoSQL/命令/模板均已参数化或使用安全 API
- [ ] 反序列化使用白名单，无 `pickle.loads` 不可信数据
- [ ] SSRF：出站请求做了协议/主机/重定向限制
- [ ] 路径穿越：文件路径未被用户输入直接拼接
- [ ] 敏感信息未进入日志 / 错误响应 / 源码注释
- [ ] PR 为增量审查，覆盖新增/修改的每个入口

## C. 密钥管理（references/secrets-management.md）

- [ ] 无硬编码密钥；所有密钥来自环境变量 / 密钥管理
- [ ] 已运行 `python3 scripts/secret_scan.py . --strict` 且零命中
- [ ] 新增密钥已规划轮换机制
- [ ] `.env` / 凭据文件已加入 `.gitignore`

## D. 依赖与供应链（references/dependency-supply-chain.md）

- [ ] 已运行 `python3 scripts/dep_audit.py . --strict` 且零阻断
- [ ] 依赖版本已固定（lockfile 提交、无 `*`，无 http/git 源）
- [ ] 无 typosquatting 近似包名
- [ ] GitHub Actions 第三方 Action 已 pin SHA
- [ ] 有信心/计划生成 SBOM

## E. Web 加固（references/web-hardening.md）

- [ ] 已运行 `python3 scripts/csp_audit.py --headers-file <headers>.txt --strict`
- [ ] 设置 `Content-Security-Policy`（先 Report-Only 观察再强制）
- [ ] 设置 `Strict-Transport-Security`（确认无法回退后再上 max-age）
- [ ] `frame-ancestors` / `base-uri` / `form-action` 已显式约束
- [ ] Cookie 设 `Secure; HttpOnly; SameSite=Lax`（敏感操作 `Strict`）
- [ ] CORS 未对带凭证请求开放 `*`

## F. 威胁建模（references/threat-modeling.md）

- [ ] 新功能上线前完成「四问法」并归档（见 `assets/threat-model-template.md`）
- [ ] 高风险的威胁已修复或书面接受
