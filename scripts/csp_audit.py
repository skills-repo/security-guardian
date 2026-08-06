#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Content-Security-Policy 与安全响应头离线审查器。

不联网、不发请求。输入是策略字符串或一份已抓取的响应头文件，
输出是分级的弱点清单与可直接替换的建议策略。

用法:
    python3 csp_audit.py --policy "<CSP 策略串>"
    python3 csp_audit.py --headers-file <文件>     # 抓好的响应头（curl -I 的输出）
    python3 csp_audit.py --headers-file - < headers.txt

示例:
    python3 csp_audit.py --policy "default-src 'self'; script-src 'self' 'unsafe-inline'"
    curl -sI https://example.com > /tmp/h.txt && python3 csp_audit.py --headers-file /tmp/h.txt --strict
    python3 csp_audit.py --headers-file assets/security-headers.conf --strict --json
"""

import argparse
import json
import re
import sys

FETCH_DIRECTIVES = {
    "default-src", "script-src", "style-src", "img-src", "connect-src", "font-src",
    "object-src", "media-src", "frame-src", "child-src", "worker-src", "manifest-src",
    "prefetch-src", "script-src-elem", "script-src-attr", "style-src-elem", "style-src-attr",
}
KNOWN_DIRECTIVES = FETCH_DIRECTIVES | {
    "base-uri", "form-action", "frame-ancestors", "sandbox", "report-uri", "report-to",
    "upgrade-insecure-requests", "block-all-mixed-content", "require-trusted-types-for",
    "trusted-types", "navigate-to", "plugin-types",
}

# 必须存在的指令：不写就有明确的绕过手法
REQUIRED = {
    "default-src": "缺少兜底，未显式声明的资源类型不受任何限制",
    "object-src": "不设为 'none' 时，<object>/<embed> 可加载插件内容绕过 script-src",
    "base-uri": "不限制的话，注入 <base href=\"//evil.com\"> 可劫持全部相对路径脚本",
    "frame-ancestors": "缺少点击劫持防护（比 X-Frame-Options 更完整，支持多来源）",
    "form-action": "注入的表单可把用户输入 POST 到攻击者域名",
}

# 其他安全响应头基线
HEADER_RULES = [
    ("strict-transport-security", "error",
     lambda v: "max-age" in v.lower() and _hsts_age(v) >= 15552000,
     "应设 max-age ≥ 15552000（180 天）；上线走 300s → 1d → 1y 阶梯，勿一步到位加 preload"),
    ("x-content-type-options", "error",
     lambda v: v.strip().lower() == "nosniff",
     "应为 nosniff，防止 MIME 嗅探导致的 XSS"),
    ("referrer-policy", "warn",
     lambda v: v.strip().lower() in {
         "no-referrer", "same-origin", "strict-origin", "strict-origin-when-cross-origin"},
     "推荐 strict-origin-when-cross-origin，避免 URL 中的敏感信息随 Referer 外泄"),
    ("permissions-policy", "warn", lambda v: bool(v.strip()),
     "建议显式关闭不用的设备权限，如 camera=(), microphone=(), geolocation=()"),
]
# 不应出现的头
LEAK_HEADERS = {
    "server": "泄露服务器软件与版本，建议移除或改为通用值",
    "x-powered-by": "泄露技术栈与版本，应移除",
    "x-aspnet-version": "泄露框架版本，应移除",
    "x-aspnetmvc-version": "泄露框架版本，应移除",
}

RECOMMENDED_POLICY = (
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self'; "
    "img-src 'self' data:; "
    "connect-src 'self'; "
    "object-src 'none'; "
    "base-uri 'self'; "
    "form-action 'self'; "
    "frame-ancestors 'none'; "
    "upgrade-insecure-requests"
)


def _hsts_age(value):
    m = re.search(r"max-age\s*=\s*(\d+)", value, re.I)
    return int(m.group(1)) if m else -1


def parse_policy(policy):
    """把 CSP 字符串解析为 {directive: [sources]}。"""
    out = {}
    for part in policy.split(";"):
        part = part.strip()
        if not part:
            continue
        tokens = part.split()
        name = tokens[0].lower()
        out[name] = [t for t in tokens[1:]]
    return out


def audit_policy(policy, report_only=False):
    findings = []

    def add(sev, code, msg, fix=""):
        findings.append({"severity": sev, "code": code, "message": msg, "fix": fix})

    if not policy.strip():
        add("error", "csp-missing", "未设置 Content-Security-Policy",
            "先用 Content-Security-Policy-Report-Only 收集两周违规，再切为强制模式")
        return findings

    directives = parse_policy(policy)

    for name in directives:
        if name not in KNOWN_DIRECTIVES:
            add("warn", "unknown-directive", "未知或已废弃的指令: %s" % name,
                "确认拼写；plugin-types / navigate-to 等已被弃用")

    # 逐个 fetch 指令检查危险源
    for name, sources in directives.items():
        if name not in FETCH_DIRECTIVES and name not in ("base-uri", "form-action", "frame-ancestors"):
            continue
        lowered = [s.lower() for s in sources]
        is_script_like = name in ("script-src", "script-src-elem", "default-src")

        if "'unsafe-inline'" in lowered:
            has_nonce = any(s.startswith("'nonce-") for s in lowered)
            has_hash = any(s.startswith(("'sha256-", "'sha384-", "'sha512-")) for s in lowered)
            if has_nonce or has_hash:
                add("warn", "unsafe-inline-with-nonce",
                    "%s 同时含 'unsafe-inline' 与 nonce/hash" % name,
                    "支持 CSP2+ 的浏览器会忽略 'unsafe-inline'，保留它仅为兼容老浏览器；"
                    "若无需兼容则删除")
            else:
                add("error" if is_script_like else "warn", "unsafe-inline",
                    "%s 允许 'unsafe-inline'，内联脚本/样式正是 XSS 的主要载体" % name,
                    "改用 'nonce-<每次请求随机>' + 'strict-dynamic'")

        if "'unsafe-eval'" in lowered:
            add("error" if is_script_like else "warn", "unsafe-eval",
                "%s 允许 'unsafe-eval'，可执行字符串代码，注入面显著扩大" % name,
                "移除对 eval/new Function 的依赖；模板引擎改用预编译模式")

        if "'unsafe-hashes'" in lowered:
            add("warn", "unsafe-hashes",
                "%s 含 'unsafe-hashes'，允许内联事件处理器" % name,
                "改为外置事件绑定")

        for s in lowered:
            if s == "*":
                add("error", "wildcard-any",
                    "%s 使用通配符 *，等于不限制来源" % name, "改为具体域名白名单")
            elif s in ("http:", "https:", "data:", "blob:", "filesystem:") and is_script_like:
                add("error", "broad-scheme",
                    "%s 允许整个 %s 协议作为脚本源，攻击者托管一个文件即可绕过" % (name, s),
                    "改为具体域名")
            elif s == "data:" and name in ("object-src", "frame-src", "child-src"):
                add("error", "data-scheme-object",
                    "%s 允许 data: ，可用于构造可执行内容" % name, "移除 data:")
            elif s.startswith("http://") :
                add("error", "insecure-scheme",
                    "%s 含明文 http:// 来源: %s" % (name, s), "改用 https://")
            elif s.startswith("*.") or ("*" in s and s != "*"):
                add("warn", "wildcard-subdomain",
                    "%s 使用通配子域: %s，任一子域被拿下即失守" % (name, s),
                    "尽量收敛到具体主机名")
            elif s == "'self'" and name == "frame-ancestors":
                pass

    # 必需指令缺失（default-src 存在时，缺失的 fetch 指令会被兜底，但 base-uri/form-action 不会）
    for req, why in REQUIRED.items():
        if req in directives:
            continue
        if req == "object-src" and "default-src" in directives:
            dsrc = [s.lower() for s in directives["default-src"]]
            if dsrc == ["'none'"]:
                continue
        add("error" if req in ("base-uri", "object-src") else "warn",
            "missing-%s" % req, "缺少 %s —— %s" % (req, why),
            "补充 %s %s" % (req, "'none'" if req in ("object-src", "frame-ancestors") else "'self'"))

    if "object-src" in directives:
        if [s.lower() for s in directives["object-src"]] != ["'none'"]:
            add("warn", "object-src-not-none",
                "object-src 建议直接设为 'none'，除非确有插件需求", "object-src 'none'")

    if report_only:
        add("warn", "report-only",
            "当前为 Report-Only 模式，仅上报不阻断",
            "违规量归零后切换为 Content-Security-Policy 强制模式")

    if not any(d in directives for d in ("report-uri", "report-to")):
        add("warn", "no-reporting",
            "未配置 report-uri / report-to，无法收集违规上报",
            "配置上报端点，才能在加严策略前评估影响面")

    return findings


def parse_headers_file(text):
    """解析 curl -I 输出或 nginx add_header 配置，抽出响应头。"""
    headers = {}
    # curl -I 风格: Name: value
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(("HTTP/", "#", "//")):
            continue
        # nginx: add_header X-Foo "bar" always;
        m = re.match(r"""(?:more_set_headers\s+|add_header\s+)["']?([A-Za-z0-9\-]+)["']?\s+["']?(.*?)["']?\s*(?:always)?\s*;""", line)
        if m:
            headers[m.group(1).lower()] = m.group(2).strip().strip('"').strip("'")
            continue
        m = re.match(r"^([A-Za-z0-9\-]+)\s*:\s*(.*)$", line)
        if m:
            headers[m.group(1).lower()] = m.group(2).strip()
    return headers


def audit_headers(headers):
    findings = []

    def add(sev, code, msg, fix=""):
        findings.append({"severity": sev, "code": code, "message": msg, "fix": fix})

    for name, sev, ok, advice in HEADER_RULES:
        val = headers.get(name)
        if val is None:
            add(sev, "missing-header", "缺少响应头 %s" % name, advice)
        elif not ok(val):
            add(sev, "weak-header", "响应头 %s 取值不达标: %s" % (name, val), advice)

    if "x-frame-options" not in headers and "content-security-policy" not in headers:
        add("error", "missing-clickjacking",
            "既无 X-Frame-Options 也无 CSP frame-ancestors，无点击劫持防护",
            "优先用 CSP frame-ancestors 'none'，X-Frame-Options 作为老浏览器兜底")

    for name, why in LEAK_HEADERS.items():
        if name in headers and headers[name].strip():
            add("warn", "info-leak-header", "响应头 %s 暴露实现细节: %s" % (name, headers[name]), why)

    if "x-xss-protection" in headers:
        v = headers["x-xss-protection"].strip()
        if v not in ("0", ""):
            add("warn", "deprecated-xss-header",
                "X-Xss-Protection: %s 已废弃，部分实现自身引入漏洞" % v,
                "设为 0 或移除，改由 CSP 提供防护")

    acao = headers.get("access-control-allow-origin", "").strip()
    acac = headers.get("access-control-allow-credentials", "").strip().lower()
    if acao == "*" and acac == "true":
        add("error", "cors-wildcard-credentials",
            "CORS 同时使用 Allow-Origin: * 与 Allow-Credentials: true",
            "任何站点都能带用户凭据读取本接口；改为精确 origin 白名单")
    if acao and acao != "*" and "vary" in headers:
        if "origin" not in headers["vary"].lower():
            add("error", "cors-missing-vary",
                "设置了动态 Access-Control-Allow-Origin 但 Vary 未包含 Origin",
                "会导致 CDN 把某个 origin 的响应缓存给其他站点（缓存投毒）")
    elif acao and acao != "*" and "vary" not in headers:
        add("error", "cors-missing-vary",
            "设置了 Access-Control-Allow-Origin 但完全没有 Vary 头",
            "有 CORS 就必须有 Vary: Origin，否则 CDN 缓存投毒")

    return findings


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="CSP 与安全响应头离线审查（不联网、不发请求）",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__.split("用法:", 1)[-1],
    )
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--policy", metavar="CSP", help="直接给出 CSP 策略字符串")
    g.add_argument("--headers-file", metavar="FILE",
                   help="响应头文件（curl -I 输出 / nginx add_header 配置），- 表示读 stdin")
    ap.add_argument("--report-only", action="store_true", help="所给策略来自 Report-Only 头")
    ap.add_argument("--strict", action="store_true", help="存在 error 时退出码为 1")
    ap.add_argument("--json", action="store_true", dest="as_json", help="以 JSON 输出")
    args = ap.parse_args(argv)

    findings = []
    policy = ""
    if args.policy:
        policy = args.policy
        findings += audit_policy(policy, args.report_only)
    else:
        if args.headers_file == "-":
            text = sys.stdin.read()
        else:
            try:
                with open(args.headers_file, "r", encoding="utf-8", errors="replace") as fh:
                    text = fh.read()
            except OSError as e:
                print("无法读取文件: %s" % e, file=sys.stderr)
                return 2
        headers = parse_headers_file(text)
        if not headers:
            print("未从文件中解析出任何响应头", file=sys.stderr)
            return 2
        ro = "content-security-policy-report-only" in headers
        policy = headers.get("content-security-policy",
                             headers.get("content-security-policy-report-only", ""))
        findings += audit_policy(policy, args.report_only or ro)
        findings += audit_headers(headers)

    errors = [f for f in findings if f["severity"] == "error"]
    warns = [f for f in findings if f["severity"] == "warn"]

    if args.as_json:
        print(json.dumps({
            "error_count": len(errors), "warn_count": len(warns),
            "findings": findings, "recommended_policy": RECOMMENDED_POLICY,
        }, indent=2, ensure_ascii=False))
    else:
        print("\nCSP / 安全响应头审查   error %d   warn %d" % (len(errors), len(warns)))
        print("-" * 78)
        if not findings:
            print("未发现问题。")
        for f in sorted(findings, key=lambda x: x["severity"] != "error"):
            print("[%s] %s" % ("ERROR" if f["severity"] == "error" else "WARN ", f["message"]))
            if f["fix"]:
                print("        → %s" % f["fix"])
        if errors:
            print("\n参考基线策略:")
            print("  %s" % RECOMMENDED_POLICY)
            print("\n加严前务必先跑 Report-Only 两周，详见 references/web-hardening.md")

    if args.strict and errors:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
