#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""密钥与凭据泄露扫描器。

正则命中 + Shannon 熵阈值 + 占位符词表三重过滤，压制假阳性。
纯标准库、不联网、不修改被扫描的文件。

用法:
    python3 secret_scan.py <路径...> [选项]

示例:
    python3 secret_scan.py .                          # 扫当前目录
    python3 secret_scan.py src/ config/ --strict      # 有 error 即退出码 1
    python3 secret_scan.py . --json                   # 机器可读输出
    python3 secret_scan.py . --write-baseline .secretbaseline
    python3 secret_scan.py . --baseline .secretbaseline --strict   # 只报新增
    python3 secret_scan.py $(git diff --name-only origin/main...HEAD) --strict
"""

import argparse
import hashlib
import json
import math
import os
import re
import sys

# ---------------------------------------------------------------- 规则定义

# (规则名, 正则, 严重度, 是否需要通过熵检查)
# 严重度: error = 高置信度真实凭据; warn = 需人工确认
RULES = [
    ("aws-access-key-id", r"\b(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}\b", "error", False),
    ("aws-secret-access-key", r"(?i)aws.{0,20}?(?:secret|private).{0,20}?['\"]([A-Za-z0-9/+=]{40})['\"]", "error", True),
    ("github-token", r"\b(?:ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{20,}\b", "error", False),
    ("gitlab-token", r"\bglpat-[A-Za-z0-9\-_]{20,}\b", "error", False),
    ("slack-token", r"\bxox[baprs]-[A-Za-z0-9\-]{10,}\b", "error", False),
    ("stripe-key", r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{20,}\b", "error", False),
    ("google-api-key", r"\bAIza[0-9A-Za-z\-_]{35}\b", "error", False),
    ("openai-key", r"\bsk-(?:proj-)?[A-Za-z0-9\-_]{32,}\b", "error", False),
    ("anthropic-key", r"\bsk-ant-[A-Za-z0-9\-_]{24,}\b", "error", False),
    ("npm-token", r"\bnpm_[A-Za-z0-9]{36}\b", "error", False),
    ("private-key-block", r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----", "error", False),
    ("jwt-token", r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b", "warn", False),
    ("slack-webhook", r"https://hooks\.slack\.com/services/T[A-Za-z0-9]+/B[A-Za-z0-9]+/[A-Za-z0-9]+", "error", False),
    ("db-connection-uri", r"(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://[^\s:@/'\"]+:([^\s:@/'\"]{6,})@", "error", True),
    ("generic-secret-assign",
     r"(?i)\b(?:api[_\-]?key|apikey|secret[_\-]?key|access[_\-]?token|auth[_\-]?token|client[_\-]?secret|"
     r"private[_\-]?key|passwd|password|pwd|credential)\b\s*[:=]\s*['\"]([^'\"\s]{8,})['\"]",
     "warn", True),
    ("bearer-hardcoded", r"(?i)['\"]?(?:authorization|bearer)['\"]?\s*[:=]\s*['\"]Bearer\s+([A-Za-z0-9\-._~+/]{20,})['\"]", "warn", True),
]

COMPILED = [(name, re.compile(pat), sev, ent) for name, pat, sev, ent in RULES]

# 占位符 / 示例值词表 —— 命中即判为假阳性
PLACEHOLDER_TOKENS = {
    "changeme", "change_me", "your", "yours", "example", "sample", "dummy", "placeholder",
    "test", "testing", "fake", "mock", "xxx", "xxxx", "todo", "fixme", "none", "null",
    "undefined", "secret", "password", "passwd", "mypassword", "123456", "abc123",
    "redacted", "hidden", "insert", "replace", "notreal", "dontuse", "foo", "bar", "baz",
    "localhost", "admin", "root", "user", "username", "default", "empty", "value",
}
PLACEHOLDER_RE = re.compile(
    r"(?i)(your[_\-]?|my[_\-]?|the[_\-]?|some[_\-]?)?"
    r"(api|secret|access|auth|private|client)?[_\-]?(key|token|secret|password|here|goes)"
)
# 模板变量语法：${VAR} {{ var }} <VAR> %s $VAR os.environ[...]
TEMPLATE_RE = re.compile(r"(\$\{[^}]*\}|\{\{[^}]*\}\}|<[A-Za-z_ ]{2,}>|%\(?[sd]\)?|\$[A-Z_]{3,}|process\.env|os\.environ|getenv)")

# 目录 / 文件排除
SKIP_DIRS = {
    ".git", "node_modules", "vendor", "dist", "build", "out", "target", "coverage",
    ".venv", "venv", "env", "__pycache__", ".mypy_cache", ".pytest_cache", ".tox",
    ".next", ".nuxt", ".svelte-kit", ".terraform", ".gradle", ".idea", ".vscode",
    "site-packages", "bower_components", ".cache",
}
# 降级为 warn 而非跳过 —— 测试目录里放真实密钥的事故很常见
SOFT_DIRS_RE = re.compile(r"(?:^|/)(?:tests?|__tests__|fixtures?|mocks?|examples?|docs?|samples?)(?:/|$)")
SOFT_FILE_RE = re.compile(r"(?:\.(?:spec|test)\.[a-z]+|_test\.[a-z]+|test_[^/]*\.py)$")

# 锁文件里的 integrity hash 会大量触发高熵，单独跳过
SKIP_FILES = {
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock", "Cargo.lock",
    "composer.lock", "Gemfile.lock", "go.sum", "bun.lockb", "npm-shrinkwrap.json",
}
BINARY_EXT = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".webp", ".bmp", ".svg", ".pdf", ".zip",
    ".gz", ".tar", ".bz2", ".xz", ".7z", ".rar", ".exe", ".dll", ".so", ".dylib", ".bin",
    ".class", ".jar", ".war", ".pyc", ".pyo", ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".mp3", ".mp4", ".avi", ".mov", ".wav", ".ogg", ".webm", ".db", ".sqlite", ".lock",
}
MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_LINE_LEN = 4000
DEFAULT_ENTROPY_MIN = 3.2
ENTROPY_MIN = DEFAULT_ENTROPY_MIN


def shannon_entropy(s):
    """计算字符串的 Shannon 熵（bits/char）。真实随机凭据通常 > 3.5。"""
    if not s:
        return 0.0
    counts = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = float(len(s))
    return -sum((c / n) * math.log(c / n, 2) for c in counts.values())


def looks_like_placeholder(value):
    """判断候选值是否为占位符 / 示例值。"""
    v = value.strip()
    if not v:
        return True
    low = v.lower()
    if low in PLACEHOLDER_TOKENS:
        return True
    if TEMPLATE_RE.search(v):
        return True
    # 全部由同一字符组成，或纯数字递增等
    if len(set(low)) <= 2:
        return True
    # 拆词后每个片段都是占位词
    parts = [p for p in re.split(r"[_\-.\s]+", low) if p]
    if parts and all(p in PLACEHOLDER_TOKENS for p in parts):
        return True
    # your-api-key-here / my_secret_token 这类
    stripped = re.sub(r"[_\-.\s]", "", low)
    if PLACEHOLDER_RE.fullmatch(stripped):
        return True
    if low.startswith(("your", "example", "sample", "dummy", "placeholder", "insert", "replace")):
        return True
    return False


def iter_files(paths):
    """展开输入路径为待扫描文件列表。"""
    for p in paths:
        if os.path.isfile(p):
            yield p
        elif os.path.isdir(p):
            for root, dirs, files in os.walk(p):
                dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
                for f in sorted(files):
                    yield os.path.join(root, f)


def should_scan(path):
    base = os.path.basename(path)
    if base in SKIP_FILES:
        return False
    ext = os.path.splitext(base)[1].lower()
    if ext in BINARY_EXT:
        return False
    try:
        if os.path.getsize(path) > MAX_FILE_BYTES:
            return False
    except OSError:
        return False
    return True


def is_soft_context(path):
    """测试 / 示例 / 文档路径：降级为 warn，不完全跳过。"""
    norm = path.replace(os.sep, "/")
    return bool(SOFT_DIRS_RE.search(norm) or SOFT_FILE_RE.search(norm))


def fingerprint(rule, path, value):
    h = hashlib.sha256()
    h.update(("%s|%s|%s" % (rule, path.replace(os.sep, "/"), value)).encode("utf-8", "replace"))
    return h.hexdigest()[:16]


def mask(value):
    if len(value) <= 8:
        return value[:2] + "*" * max(0, len(value) - 2)
    return value[:4] + "*" * 6 + value[-4:]


def scan_file(path):
    findings = []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            content = fh.read()
    except (OSError, UnicodeDecodeError):
        return findings
    if "\x00" in content[:2048]:
        return findings

    soft = is_soft_context(path)
    for lineno, line in enumerate(content.splitlines(), 1):
        if len(line) > MAX_LINE_LEN:
            continue
        stripped = line.strip()
        # 跳过明显的注释掉的示例说明（以 # 或 // 开头且含 example/示例）
        if re.match(r"^\s*(#|//|\*)", line) and re.search(r"(?i)(example|示例|e\.g\.|sample)", line):
            continue
        for name, rx, sev, need_entropy in COMPILED:
            for m in rx.finditer(line):
                value = m.group(1) if m.groups() else m.group(0)
                if looks_like_placeholder(value):
                    continue
                ent = shannon_entropy(value)
                if need_entropy and ent < ENTROPY_MIN:
                    continue
                severity = sev
                note = ""
                if soft and severity == "error":
                    severity = "warn"
                    note = "测试/示例路径，已降级为 warn（仍建议确认非真实凭据）"
                findings.append({
                    "rule": name,
                    "severity": severity,
                    "file": path.replace(os.sep, "/"),
                    "line": lineno,
                    "match": mask(value),
                    "entropy": round(ent, 2),
                    "fingerprint": fingerprint(name, path, value),
                    "snippet": (stripped[:110] + "…") if len(stripped) > 110 else stripped,
                    "note": note,
                })
                break  # 同一行同一规则只报一次
    return findings


def load_baseline(path):
    if not path or not os.path.isfile(path):
        return set()
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        return set(data.get("fingerprints", []))
    except (OSError, ValueError):
        return set()


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="密钥与凭据泄露扫描器（正则 + 熵 + 占位符过滤，零依赖、不联网）",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__.split("用法:", 1)[-1],
    )
    ap.add_argument("paths", nargs="*", default=["."], help="要扫描的文件或目录（默认当前目录）")
    ap.add_argument("--strict", action="store_true", help="存在 error 级发现时退出码为 1（适合 CI 门禁）")
    ap.add_argument("--json", action="store_true", dest="as_json", help="以 JSON 输出")
    ap.add_argument("--baseline", metavar="FILE", help="基线文件，只报告基线之外的新增发现")
    ap.add_argument("--write-baseline", metavar="FILE", help="把本次全部发现写入基线文件")
    ap.add_argument("--min-entropy", type=float, default=DEFAULT_ENTROPY_MIN, metavar="N",
                    help="熵阈值，越高越保守（默认 %(default)s）")
    ap.add_argument("--include-soft", action="store_true",
                    help="不对测试/示例路径降级（默认降级为 warn）")
    args = ap.parse_args(argv)

    global ENTROPY_MIN
    ENTROPY_MIN = args.min_entropy

    paths = args.paths or ["."]
    missing = [p for p in paths if not os.path.exists(p)]
    for p in missing:
        print("跳过不存在的路径: %s" % p, file=sys.stderr)
    paths = [p for p in paths if os.path.exists(p)]
    if not paths:
        print("没有可扫描的路径", file=sys.stderr)
        return 2

    findings, scanned = [], 0
    for f in iter_files(paths):
        if not should_scan(f):
            continue
        scanned += 1
        for item in scan_file(f):
            if args.include_soft and item["note"]:
                item["severity"] = "error"
                item["note"] = ""
            findings.append(item)

    if args.write_baseline:
        with open(args.write_baseline, "w", encoding="utf-8") as fh:
            json.dump({"fingerprints": sorted({f["fingerprint"] for f in findings})}, fh,
                      indent=2, ensure_ascii=False)
        print("已写入基线 %s（%d 条）" % (args.write_baseline, len(findings)))
        return 0

    known = load_baseline(args.baseline)
    if known:
        findings = [f for f in findings if f["fingerprint"] not in known]

    errors = [f for f in findings if f["severity"] == "error"]
    warns = [f for f in findings if f["severity"] == "warn"]

    if args.as_json:
        print(json.dumps({
            "scanned_files": scanned,
            "error_count": len(errors),
            "warn_count": len(warns),
            "baseline_suppressed": len(known),
            "findings": findings,
        }, indent=2, ensure_ascii=False))
    else:
        print("\n密钥扫描  扫描文件 %d 个  error %d  warn %d%s"
              % (scanned, len(errors), len(warns),
                 ("  基线抑制 %d" % len(known)) if known else ""))
        print("-" * 78)
        if not findings:
            print("未发现疑似泄露的凭据。")
        for f in sorted(findings, key=lambda x: (x["severity"] != "error", x["file"], x["line"])):
            tag = "ERROR" if f["severity"] == "error" else "WARN "
            print("[%s] %s:%d  %s  熵=%.2f" % (tag, f["file"], f["line"], f["rule"], f["entropy"]))
            print("        %s" % f["snippet"])
            print("        命中值: %s   指纹: %s" % (f["match"], f["fingerprint"]))
            if f["note"]:
                print("        注: %s" % f["note"])
        if errors:
            print("\n处置顺序（不可颠倒）: ① 轮换新密钥 ② 吊销旧密钥 ③ 查调用日志 "
                  "④ 清理 Git 历史 ⑤ 加 CI 门禁")
            print("详见 references/secrets-management.md")

    if args.strict and errors:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
