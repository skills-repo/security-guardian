# 代码安全审计 Playbook

> 目标是找到**能被真实利用的漏洞**，不是产出一份 200 条的扫描器报告。
> 一条附带完整攻击路径的发现，价值高于 50 条"建议加强输入校验"。
>
> 本篇写子技能 `skills/security-audit/` 装不下的部分：审计怎么排顺序、
> 怎么判假阳性、怎么在有限时间里覆盖最高价值的面。

## 1. 审计的四个阶段（顺序不能换）

```
① 摸清攻击面   → 列全部入口点，不看代码细节
② 定位高价值路径 → 从"资产"倒推，而不是从文件列表顺推
③ 逐类深挖     → 按漏洞类别并行，每类走完整数据流
④ 验证与定级   → 能构造 PoC 才算发现，构造不出降级为"可疑"
```

**最常见的错误是跳过 ①② 直接进 ③**——从 `src/` 第一个文件开始读，
读到一半上下文耗尽，覆盖的全是低价值代码。

### 阶段 ① 攻击面清单（先做，30 分钟内完成）

```bash
# HTTP 路由入口
grep -rnE "@(Get|Post|Put|Delete|Patch)Mapping|app\.(get|post|put|delete)\(|router\.(get|post)" --include=*.{js,ts,java,py,go} .
# 反序列化 / 动态执行
grep -rnE "eval\(|new Function|pickle\.loads|yaml\.load\(|Marshal|ObjectInputStream|exec\(|system\(" .
# 文件与路径操作
grep -rnE "readFile|open\(|os\.path\.join|new File\(|sendFile|download" .
# 外发请求（SSRF 面）
grep -rnE "fetch\(|axios\.|requests\.(get|post)|http\.Get|HttpClient" .
# 原始 SQL
grep -rnE "SELECT .*\+|execute\(.*%|query\(.*\$\{|rawQuery|createQuery\(" .
```

产出一张表：**入口 / 是否需认证 / 接受什么输入 / 能到达什么数据**。
这张表决定后面的读代码顺序。

### 阶段 ② 从资产倒推

问三个问题，答案决定优先级：

1. 这个系统里**最贵的东西**是什么？（资金流水、用户 PII、管理员权限、密钥）
2. 从**未认证的外部**出发，最短几跳能碰到它？
3. 这条路径上每一跳的**校验是谁做的**？

> 只有一处做校验的路径 = 单点防御 = 优先审计对象。

## 2. 漏洞类别检测速查

每类给出：**怎么找 → 怎么确认可利用 → 常见假阳性**。

### 注入类（SQL / NoSQL / 命令 / 模板）

| 步骤 | 做法 |
|------|------|
| 找 | 拼接符号进入查询/命令：`+`、模板串 `${}`、`%s`、f-string |
| 确认 | 追数据流：入参 → 是否经过参数化/转义 → 是否进入执行 |
| 假阳性 | ORM 的参数化写法看起来像拼接；常量拼接（表名来自枚举）不算 |

**真阳性判据**：能让攻击者控制**语法结构**，而不只是控制值。
`WHERE id = ${id}` 是漏洞；`WHERE id = ?` 绑定 `${id}` 不是。

命令注入特别注意：`exec("cmd " + arg)` 是漏洞，`execFile("cmd", [arg])` 不是。
Node 的 `child_process.exec` 走 shell，`execFile`/`spawn` 默认不走。

### 越权 / IDOR（最高频、扫描器最查不出）

```
凡是接口参数里出现资源 ID，就必须回答：
  服务端在哪一行确认了「当前用户拥有这个 ID」？
答不上来 = 漏洞。
```

三种常见伪装成"有鉴权"的假象：

1. **只校验登录，没校验归属**——`@RequireAuth` 只保证是某个用户
2. **前端隐藏入口**——按钮不显示但接口能直接调
3. **在错误的层做校验**——列表接口过滤了，详情接口没过滤

批量检查手法：把所有带 `:id` / `{id}` 的路由列出来，逐个 grep 处理函数里
有没有出现当前用户标识（`ctx.user`、`principal`、`session.uid`）。

### SSRF

| 找 | 用户可控 URL 进入服务端出网请求 |
| 确认 | 能否指向 `169.254.169.254`（云元数据）、`127.0.0.1`、内网段 |
| 假阳性 | URL 来自固定配置或严格白名单枚举 |

**绕过点**：只校验字符串前缀会被 `http://evil.com@169.254.169.254`、
`http://[::1]`、DNS rebinding、302 跳转绕过。正确做法是解析后校验解析出的 IP，
且**每次实际连接前**再校验（防 rebinding）。

### 反序列化与动态执行

高危但不常见。命中即高危，无需犹豫：
`pickle.loads`、`yaml.load`（无 `SafeLoader`）、Java `ObjectInputStream`、
`eval` / `new Function` 接收外部数据。

### 认证与 Session

见 `references/authn-authz.md`。审计时最快的三个检查点：

- JWT 是否校验 `alg`（防 `none` 与 HS/RS 混淆）、`exp`、`aud`、`iss`
- 登出/改密后旧 token 是否失效（无状态 JWT 通常不失效——这是设计缺陷）
- 密码存储是否用 bcrypt/argon2/scrypt（不是 MD5/SHA + salt）

### 敏感信息泄露

- 生产环境错误回显（栈、SQL、路径）
- 日志打印了 token / 密码 / 身份证 / 手机号
- API 返回了前端用不到的字段（`SELECT *` 直出）
- 源码里硬编码密钥 → 用 `scripts/secret_scan.py` 扫

## 3. 假阳性判定：三问过滤器

扫描器和 LLM 都会产生大量噪声。每条候选发现过这三关，过不了就降级：

```
Q1 可达性：外部输入真的能到这里吗？
   （被上游中间件拦掉 / 只有内部定时任务调用 / 是死代码 → 降级）
Q2 可控性：攻击者能控制的部分足以改变行为吗？
   （只能控制值不能控制结构 / 长度被限制到无法构造 → 降级）
Q3 影响面：利用成功后能拿到什么？
   （只能读到已经公开的数据 / 只能 DoS 自己的账号 → 降级）
```

三关全过 → **Finding**（要修）；过 1–2 关 → **Observation**（记录，不阻塞发布）；
全不过 → 丢弃，不要写进报告凑数。

## 4. 单次审计的时间分配（以 1 天为例）

| 阶段 | 占比 | 产出 |
|------|------|------|
| 攻击面清单 | 10% | 入口表 |
| 高价值路径识别 | 15% | 3–5 条重点路径 |
| 深挖 | 45% | 候选发现列表 |
| 验证与假阳性过滤 | 20% | 确认的 Finding |
| 报告与修复建议 | 10% | 报告 |

**深挖不要超过一半时间**。没有验证过的发现交付出去，
会消耗开发团队的信任——第二次他们就不看你的报告了。

## 5. 增量审计（PR 场景）

全量审计一次只能覆盖约一半漏洞，因此 PR 级增量审计是更高性价比的常态化手段。

```bash
# 只看本次改动，且带上下文
git diff origin/main...HEAD --unified=10

# 优先关注这些文件类型的改动
git diff --name-only origin/main...HEAD | grep -E "auth|permission|role|admin|payment|upload|download|query|sql|crypto|token"
```

PR 审计只问四个问题：

1. 这次改动**新增了输入源**吗？（新参数、新字段、新上传）
2. 这次改动**放宽了校验**吗？（删了 if、改了正则、加了 `||` 兜底）
3. 这次改动**动了权限判断**吗？
4. 这次改动**引入了新依赖**吗？（→ 跑 `scripts/dep_audit.py`）

四个都是"否" → 安全上放行。

## 6. 常见坑

| 坑 | 后果 | 规避 |
|----|------|------|
| 一次性读完整个代码库 | 上下文耗尽在低价值文件上 | 先做攻击面清单再读代码 |
| 把扫描器输出直接当报告 | 大量假阳性，团队失去信任 | 三问过滤器，只交付验证过的 |
| 只看后端，不看前端与配置 | 漏掉 CSP/CORS/Cookie 配置类问题 | 配置文件与 Nginx/网关规则一起审 |
| 发现即报，不给修复代码 | 开发不知道怎么改，问题挂着 | 每条 Finding 给可粘贴的修复片段 |
| 忽略"组合利用" | 两个中危串起来是高危 | 报告结尾单列"链式利用"一节 |
| 审计报告写完就结束 | 修完没人复验，问题回归 | 每条 Finding 附验收测试用例 |
| 只审代码不审 CI/CD | pipeline 的密钥与权限是真实攻击面 | 把 workflow 文件纳入审计范围 |

## 7. 检查清单

- [ ] 攻击面清单已列全（HTTP / 定时任务 / 消息队列 / CLI / webhook / 文件导入）
- [ ] 每个带资源 ID 的接口都确认了对象级鉴权
- [ ] 注入类：确认攻击者能否控制**语法结构**而非仅值
- [ ] 所有出网请求确认了 SSRF 防护（解析后校验 IP，非前缀匹配）
- [ ] 错误处理在生产环境不回显内部信息
- [ ] 已跑 `scripts/secret_scan.py`，硬编码凭据为零
- [ ] 已跑 `scripts/dep_audit.py`，供应链风险已确认
- [ ] 每条 Finding 过了三问过滤器，且有攻击场景描述
- [ ] 每条 Finding 有修复代码片段 + 验收测试
- [ ] 报告含"链式利用"与"接受的风险"两节

## 8. 衔接

- 建模阶段 → `references/threat-modeling.md`
- 认证授权细节 → `references/authn-authz.md`
- 响应头 / CSP / CORS → `references/web-hardening.md`
- 定级与披露 → `references/vuln-triage.md` + `scripts/cvss_score.py`
- 报告格式 → `assets/vulnerability-report-template.md`
- PR 审查清单 → `assets/security-review-checklist.md`
