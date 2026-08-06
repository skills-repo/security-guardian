# 依赖与供应链安全 Playbook

> `npm audit` 报了 87 个漏洞，其中 80 个你根本修不了也不需要修。
> 这篇讲的是**怎么分辨那 7 个**，以及比 CVE 更危险的一类风险：投毒与构建链。
>
> 参考：`patricio0312rev/skills@dependency-vulnerability-triage`、
> `aj-geddes/useful-ai-prompts@dependency-management`（437 安装）。

## 1. 依赖漏洞分诊：可达性优先于 CVSS

CVE 的 CVSS 分数描述的是**该漏洞在最坏情况下**的严重程度，与你的项目无关。
真正决定优先级的是可达性。

```
                     这个漏洞函数，我的代码调用了吗？
                       ├── 没调用 ──────────────► P3：跟随常规升级，不加急
                       └── 调用了
                             └── 攻击者能控制传进去的数据吗？
                                   ├── 不能（参数是常量/内部生成）──► P2：本迭代修
                                   └── 能
                                         └── 这条路径要认证吗？
                                               ├── 要 ──► P1：本周修
                                               └── 不要 ──► P0：今天修
```

**关键提问顺序**：`是否可达 → 是否可控 → 是否需认证`。
跳过这三问直接按 CVSS 排期，会把大量精力花在 devDependencies 的理论漏洞上。

### 快速判可达性

```bash
# npm：看依赖路径，判断是直接依赖还是深层传递依赖
npm ls <package>
# 传递依赖且只有一条路径 → 通常是某个直接依赖的内部实现，多半不可达

# Python
pip show <package> && pipdeptree -r -p <package>

# Go（Go 的漏洞库自带可达性分析，是目前做得最好的）
govulncheck ./...
```

> **`govulncheck` 值得单独一提**：它做符号级可达性分析，只报告你**实际调用到**的
> 漏洞函数。其他生态的工具大多只做版本号比对，噪声高一个数量级。

### 三类"不用修"的情况（要写进记录，不是默默忽略）

| 情况 | 判断依据 | 记录方式 |
|------|---------|---------|
| devDependencies 的漏洞 | 不进生产产物，且 CI 环境可信 | 标注 "dev-only, not shipped" |
| 漏洞函数未被调用 | `govulncheck` / 手工确认调用链 | 标注 "not reachable" + 依据 |
| 需要的前提在本项目不成立 | 如"需攻击者可写配置文件" | 标注具体前提与为何不成立 |

**不要用 `npm audit --force`**。它会做 breaking change 级别的版本跳跃，
经常把可用的项目改坏，而且掩盖了真正需要人判断的部分。

## 2. 比 CVE 更危险：供应链投毒

CVE 是"已知的旧问题"，投毒是"未知的新攻击"。近年真实事故几乎都来自后者。

### 五种攻击手法与对应信号

| 手法 | 说明 | 可检测的信号 |
|------|------|------------|
| **Typosquatting** | 抢注形近包名（`crossenv` vs `cross-env`） | 包名与流行包的编辑距离 ≤2 |
| **依赖混淆** | 在公共 registry 抢注你的内部包名 | 内部包名未在公共源占位；未配置 scope 隔离 |
| **维护者账号被盗** | 合法包突然发布恶意版本 | 版本发布间隔异常、新版本新增安装脚本 |
| **恶意安装脚本** | `postinstall` 执行外发请求 | package.json 存在 `preinstall`/`postinstall` |
| **协议依赖** | 直接依赖 git URL / tarball URL | 依赖项以 `git+`、`http://`、`file:` 开头 |

`scripts/dep_audit.py` 检测的正是这些**结构性信号**，不联网、不查 CVE 库，
与 `npm audit` 互补：一个查"已知漏洞"，一个查"可疑结构"。

### 安装脚本是最高危信号

```bash
# 全局关闭安装脚本（推荐在 CI 中默认开启）
npm ci --ignore-scripts
# 需要脚本的包（如 esbuild、sharp）单独放行
```

一个包如果只是提供工具函数却带 `postinstall`，值得人工看一眼那个脚本在干什么。

## 3. 锁文件：供应链的第一道防线

| 检查项 | 为什么 |
|--------|--------|
| 锁文件已提交进仓库 | 没有锁文件 = 每次构建装到的可能是不同代码 |
| CI 用 `npm ci` 而非 `npm install` | `install` 会改锁文件，`ci` 严格按锁文件装，不一致就失败 |
| 锁文件中每项有 `integrity` 哈希 | 防止 registry 侧内容被替换 |
| 锁文件中的 registry 地址统一 | 混入私有/第三方源是投毒的常见入口 |
| 版本范围不用 `*` / `latest` | 任意一次构建都可能引入未审查的新版本 |

```bash
# 检查锁文件是否与 package.json 一致（不一致会失败，适合做 CI 门禁）
npm ci --dry-run
# 检查是否混入了非官方 registry
grep -oE '"resolved": "https?://[^/]+' package-lock.json | sort -u
```

`scripts/dep_audit.py` 会把上面这些检查一次跑完，并对 `requirements.txt`、
`go.mod`、`pyproject.toml` 做等价检查。

## 4. 版本策略：固定 vs 浮动

| 依赖类型 | 建议 | 理由 |
|---------|------|------|
| 应用（最终产物） | **锁文件固定全部版本** | 可复现构建优先于自动获得补丁 |
| 库（被别人依赖） | `package.json` 用 caret，**不提交锁文件到发布物** | 避免给下游造成版本冲突 |
| Docker 基础镜像 | 固定到 digest（`@sha256:...`） | tag 会被覆盖，digest 不会 |
| GitHub Actions | 固定到 commit SHA，不用 `@v4` | tag 可被移动，是真实发生过的攻击 |
| 系统包（apt/apk） | 固定主版本 + 定期重建 | 完全固定会拿不到安全补丁 |

**固定版本的代价是必须有自动升级机制**。Dependabot / Renovate 不是可选项——
固定 + 无自动升级 = 半年后一堆高危漏洞。

配置要点：

```
- 安全更新：自动创建 PR，允许自动合并（补丁级）
- 常规更新：按周批量，人工审阅
- 主版本升级：单独 PR，永不自动合并
```

## 5. SBOM：什么时候真的需要

SBOM（软件物料清单）常被过度推销。判断标准：

- **需要**：对外交付软件、有合规要求（如需响应客户的成分询问）、金融/医疗等受监管行业
- **不需要**：纯内部系统、个人项目——锁文件已经是事实上的 SBOM

真要做，用 CycloneDX 或 SPDX 格式，在 CI 里生成并随制品一起归档：

```bash
npx @cyclonedx/cyclonedx-npm --output-file sbom.json
syft dir:. -o spdx-json > sbom.spdx.json      # 多语言/容器镜像
```

**SBOM 的价值在下一次 0day 爆发时体现**：能在几分钟内回答"我们哪些系统用了这个包"。
没有 SBOM 就得一个仓库一个仓库地 grep。

## 6. 常见坑

| 坑 | 后果 | 规避 |
|----|------|------|
| 按 `npm audit` 的数字排期 | 精力全花在不可达的 dev 依赖上 | 先做可达性分诊 |
| `npm audit fix --force` | 引入 breaking change，项目跑不起来 | 手工升级 + 跑测试 |
| 只看直接依赖 | 传递依赖占依赖总数的 90%+ | 用 `npm ls` / `pipdeptree` 看全树 |
| 锁文件冲突时直接删掉重装 | 静默引入一批未审查的新版本 | 用 `npm install --package-lock-only` 重建后 review diff |
| CI 里用 `npm install` | 锁文件形同虚设 | 一律 `npm ci` |
| Actions 用 `@v4` 浮动 tag | tag 可被 owner 移动到恶意 commit | 固定 SHA + Dependabot 更新 |
| 内部包只在私有源存在 | 依赖混淆攻击面 | 在公共源占位同名包，或配置 scope 强制私有源 |
| 忽略 `postinstall` 脚本 | 安装即执行任意代码 | CI 用 `--ignore-scripts`，白名单放行 |
| 只在 CI 扫，不定期全量扫 | 长期不动的仓库无人发现新 CVE | 定时任务每周全量扫一次 |

## 7. 检查清单

- [ ] 锁文件已提交，CI 使用 `npm ci` / `pip install -r` + hash 校验
- [ ] 所有依赖有 integrity 哈希，registry 来源统一
- [ ] 无 `git+` / `http://` / 本地路径形式的生产依赖
- [ ] 已跑 `scripts/dep_audit.py`，结构性风险信号为零或已逐条说明
- [ ] 已跑生态原生工具（`npm audit` / `pip-audit` / `govulncheck`）并完成可达性分诊
- [ ] 每个"不修"的漏洞有书面理由（dev-only / 不可达 / 前提不成立）
- [ ] Dependabot 或 Renovate 已启用，安全补丁可自动合并
- [ ] GitHub Actions 全部固定到 commit SHA
- [ ] Docker 基础镜像固定到 digest
- [ ] 内部包名已在公共 registry 占位或配置了 scope 隔离
- [ ] （如有合规要求）CI 产出 SBOM 并随制品归档

## 8. 衔接

- 结构性风险扫描 → `scripts/dep_audit.py`
- 漏洞定级统一口径 → `scripts/cvss_score.py` + `references/vuln-triage.md`
- 加密库的时序侧信道审计 → `skills/dependency-audit/SKILL.md`
- CI 门禁集成 → `assets/secret-scan-ci.yml`（同一 workflow 可加依赖检查步骤）
- 容器与 CI 的加固 → `skills-repo/devops-engineer`
