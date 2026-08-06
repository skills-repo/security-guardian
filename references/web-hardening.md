# Web 加固 Playbook：响应头、CSP、CORS、Cookie

> 这一层的特点是**改配置就能挡住一整类攻击**，性价比极高，却最常被忽略——
> 因为它不属于任何一个功能需求，没人会提这个卡片。
>
> 配合 `scripts/csp_audit.py`（离线分析 CSP 策略串）与 `assets/security-headers.conf`。

## 1. 安全响应头：按性价比排序

不要一次全上，按下表顺序推进。前四个几乎零风险，后面的需要评估。

| 优先级 | 头 | 推荐值 | 挡住什么 | 上线风险 |
|-------|-----|--------|---------|---------|
| ★★★ | `Strict-Transport-Security` | `max-age=31536000; includeSubDomains` | 降级到 HTTP、SSL 剥离 | 低（但**不可逆**，见下） |
| ★★★ | `X-Content-Type-Options` | `nosniff` | MIME 嗅探导致的 XSS | 极低 |
| ★★★ | `Referrer-Policy` | `strict-origin-when-cross-origin` | URL 中的敏感信息外泄 | 极低 |
| ★★★ | `X-Frame-Options` / CSP `frame-ancestors` | `DENY` 或 `SAMEORIGIN` | 点击劫持 | 低（若有正常嵌入需求需放行） |
| ★★☆ | `Content-Security-Policy` | 见下节 | XSS、数据外带 | **高**，必须先用 Report-Only |
| ★★☆ | `Permissions-Policy` | `camera=(), microphone=(), geolocation=()` | 第三方脚本滥用设备权限 | 低 |
| ★☆☆ | `Cross-Origin-Opener-Policy` | `same-origin` | 跨窗口攻击 | 中（会断掉某些 OAuth 弹窗） |
| ★☆☆ | `Cross-Origin-Resource-Policy` | `same-site` | 跨站资源读取 | 中（会断掉跨域静态资源） |

**要删掉的头**：`Server`、`X-Powered-By`、`X-AspNet-Version` —— 版本号信息对攻击者有价值，对用户没有。

### HSTS 的不可逆性（真实踩坑点）

`max-age=31536000` 意味着浏览器**一年内**都会强制对该域名走 HTTPS。
如果你的某个子域还没上 HTTPS，而你加了 `includeSubDomains`，那个子域会立刻不可访问，
且**你改回来也没用**——用户浏览器已经记住了。

安全的上线路径：

```
max-age=300              # 5 分钟，观察一天
  ↓ 无异常
max-age=86400            # 1 天，观察一周
  ↓ 无异常，且确认所有子域已支持 HTTPS
max-age=31536000; includeSubDomains
  ↓ 稳定运行数月后（可选）
+ preload  ← 提交到 preload 列表后，移除需要数月，谨慎
```

## 2. CSP：从 Report-Only 开始，别想一步到位

CSP 是本篇里唯一可能**直接把站点搞挂**的头。正确路径只有一条：

```
① Content-Security-Policy-Report-Only  ← 只上报不阻断，收集违规
② 分析上报，把合法来源加进策略          ← 通常需要 1–2 周
③ 违规量归零后，切成 Content-Security-Policy
④ 持续收上报，新增第三方脚本时先看是否触发
```

### 策略强度分级

```
# 第一档：能拦住绝大多数注入，改造成本可接受
default-src 'self';
script-src 'self';
object-src 'none';
base-uri 'self';
frame-ancestors 'none';

# 第二档：需要内联脚本时，用 nonce 而不是 'unsafe-inline'
script-src 'self' 'nonce-{每次请求随机生成}' 'strict-dynamic';

# 第三档：加上数据外带防护
connect-src 'self' https://api.example.com;
form-action 'self';
```

### 四个让 CSP 形同虚设的写法

| 写法 | 为什么等于没写 |
|------|--------------|
| `script-src 'unsafe-inline'` | 内联脚本正是 XSS 的主要载体，允许它 = 放弃 XSS 防护 |
| `script-src 'unsafe-eval'` | 允许 `eval`，注入点大幅增加 |
| `script-src *` 或 `https:` | 任意域名可加载脚本，攻击者托管一个即可 |
| 只写 `default-src` 不写 `object-src 'none'` | `<object>`/`<embed>` 可绕过（部分浏览器 fallback 行为不一致） |

**还有两个必写但常被忘的指令**：

- `base-uri 'self'` —— 不写的话，注入一个 `<base href="//evil.com">` 就能劫持所有相对路径脚本
- `form-action 'self'` —— 不写的话，注入的表单可把用户输入 POST 到外部域名

`scripts/csp_audit.py` 会把上述所有问题一次性检出，并给出严重度分级。

## 3. CORS：最常见的三个错误配置

CORS 的本质是**放宽同源策略**，每加一条都是在扩大攻击面。

```
❌ 致命：Access-Control-Allow-Origin: *  +  Allow-Credentials: true
   浏览器规范上不允许这个组合，但很多服务端实现是「反射 Origin」来变相实现，
   效果等同于「任何网站都能带着用户 Cookie 读你的 API」。

❌ 危险：反射请求头里的 Origin 且不校验
   Access-Control-Allow-Origin: $http_origin
   这就是上面那条的实际形态，扫描器经常漏报。

❌ 常见：白名单用 endsWith 匹配
   origin.endsWith("example.com")  →  "evilexample.com" 通过
   正确：精确匹配完整 origin 字符串，或用严格的子域正则并锚定
```

正确形态：

```
Access-Control-Allow-Origin: https://app.example.com   ← 精确单值，或从白名单查表后回填
Access-Control-Allow-Credentials: true                  ← 仅在确实需要带凭据时
Access-Control-Max-Age: 600                             ← 减少预检请求
Vary: Origin                                            ← 必须！否则 CDN 会把某个 origin 的响应缓存给所有人
```

> **`Vary: Origin` 漏写是缓存投毒的经典成因**：CDN 缓存了对 A 站的 CORS 响应，
> 然后把它返回给 B 站的请求。

## 4. Cookie 属性：四个都要设

```
Set-Cookie: sid=<value>; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=3600
```

| 属性 | 作用 | 不设的后果 |
|------|------|-----------|
| `HttpOnly` | JS 读不到 | XSS 可直接偷走会话 |
| `Secure` | 只走 HTTPS | 明文网络中被嗅探 |
| `SameSite` | 限制跨站发送 | CSRF |
| `Path` / 域 | 限制作用范围 | 子域泄露、过宽的共享 |

**SameSite 怎么选**：

- `Strict` —— 最安全，但从外部链接跳进来时会处于未登录态（体验差）
- `Lax` —— **默认选它**。顶层导航的 GET 会带上，POST 不会带
- `None` —— 必须同时加 `Secure`。只有在确实需要跨站带 Cookie（如嵌入式场景）时用

> SameSite 不能完全替代 CSRF Token。对于状态变更接口，
> **双保险**：`SameSite=Lax` + CSRF Token（或校验 `Origin`/`Sec-Fetch-Site` 头）。

## 5. 其他容易漏的加固点

| 项 | 做法 |
|----|------|
| 目录列表 | 关闭（nginx `autoindex off`） |
| 错误页 | 生产环境自定义，不回显栈与框架版本 |
| 文件上传 | 校验类型用 magic bytes 而非扩展名；存储在非 Web 根目录；下载时强制 `Content-Disposition: attachment` |
| 重定向 | 开放重定向：`?next=` 参数必须走白名单或只允许相对路径 |
| 限流 | 至少对登录、注册、密码重置、搜索、上传五类端点限流 |
| 请求体大小 | 设上限（nginx `client_max_body_size`），防内存耗尽 |
| TLS | 只启用 TLS 1.2+，禁用弱套件；证书自动续期并有到期告警 |

## 6. 常见坑

| 坑 | 后果 | 规避 |
|----|------|------|
| 直接上线严格 CSP | 站点大面积白屏 | 必须先 Report-Only 跑两周 |
| HSTS 一步到位加 preload | 子域不可访问且短期内无法回退 | 按 300s → 1d → 1y 阶梯推进 |
| CORS 反射 Origin 图省事 | 等价于完全开放 | 白名单精确匹配 |
| 忘记 `Vary: Origin` | CDN 缓存投毒 | 有 CORS 就必有 `Vary` |
| 只在应用层设头，CDN 覆盖掉了 | 线上实际生效的与代码里写的不一致 | 用 `curl -I` 验证**线上实际响应** |
| 用 `X-XSS-Protection` 当防护 | 该头已废弃，部分实现本身引入漏洞 | 显式设为 `0` 或干脆不设，靠 CSP |
| 上传只校验扩展名 | `evil.php.jpg`、双扩展名绕过 | 校验 magic bytes + 重命名存储 |

## 7. 检查清单

```bash
# 上线后必做：验证线上实际生效的头（不是看代码）
curl -sI https://your-domain.com | grep -iE "strict-transport|content-security|x-frame|x-content-type|referrer|permissions"
# 检查是否泄露了版本信息
curl -sI https://your-domain.com | grep -iE "^server:|x-powered-by"
# 离线分析 CSP 策略强度
python3 scripts/csp_audit.py --policy "$(curl -sI https://your-domain.com | grep -i content-security-policy | cut -d: -f2-)"
```

- [ ] HSTS 已启用，且按阶梯推进过（不是一上来就 1 年 + preload）
- [ ] `X-Content-Type-Options: nosniff` 已设
- [ ] `Referrer-Policy` 已设为 `strict-origin-when-cross-origin` 或更严
- [ ] 点击劫持防护已设（`frame-ancestors` 优先于 `X-Frame-Options`）
- [ ] CSP 已上线且不含 `unsafe-inline` / `unsafe-eval` / 通配符
- [ ] CSP 含 `object-src 'none'`、`base-uri 'self'`、`form-action 'self'`
- [ ] `scripts/csp_audit.py` 对线上策略零 error
- [ ] CORS 白名单精确匹配，未反射 Origin，且带 `Vary: Origin`
- [ ] Cookie 四属性齐全，状态变更接口另有 CSRF 防护
- [ ] `Server` / `X-Powered-By` 已移除
- [ ] 开放重定向参数走白名单
- [ ] 登录/注册/重置/上传等端点有限流
- [ ] TLS 仅 1.2+，证书有到期告警

## 8. 衔接

- Cookie 与会话安全的完整设计 → `references/authn-authz.md`
- XSS 的代码层面检测 → `references/code-audit-playbook.md`
- 可直接套用的配置 → `assets/security-headers.conf`（已通过 `csp_audit.py` 零 error）
- 网关/CDN 层的实施 → `skills-repo/devops-engineer`
