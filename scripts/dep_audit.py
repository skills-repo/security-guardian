#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""依赖与供应链结构性风险审查器。

与 `npm audit` / `pip-audit` **互补而非重复**：
那些工具查「已知 CVE」，本脚本查「可疑结构」——typosquatting、安装脚本、
协议依赖、锁文件缺失、非官方 registry、浮动版本、未固定的 CI Action。

纯标准库、不联网、不修改任何文件。

用法:
    python3 dep_audit.py [项目目录] [选项]

示例:
    python3 dep_audit.py .
    python3 dep_audit.py . --strict            # 有 error 即退出码 1
    python3 dep_audit.py /path/to/repo --json
"""

import argparse
import json
import os
import re
import sys

# 常被抢注形近包名的流行包（编辑距离 ≤2 即告警）
POPULAR_NPM = [
    "lodash", "react", "react-dom", "express", "axios", "chalk", "commander", "debug",
    "moment", "request", "underscore", "webpack", "babel-core", "typescript", "jquery",
    "cross-env", "dotenv", "uuid", "async", "colors", "eslint", "prettier", "vue",
    "next", "socket.io", "mongoose", "redis", "bluebird", "rimraf", "glob", "yargs",
]
POPULAR_PYPI = [
    "requests", "urllib3", "numpy", "pandas", "flask", "django", "setuptools", "six",
    "pytest", "click", "jinja2", "pyyaml", "cryptography", "boto3", "sqlalchemy",
    "beautifulsoup4", "pillow", "scipy", "matplotlib", "certifi", "colorama", "tqdm",
]

INSTALL_HOOKS = ("preinstall", "install", "postinstall", "prepare", "prepublish")
OFFICIAL_NPM_HOSTS = ("registry.npmjs.org",)
OFFICIAL_PYPI_HOSTS = ("pypi.org", "files.pythonhosted.org")


def levenshtein(a, b, cutoff=3):
    """编辑距离，超过 cutoff 提前退出。"""
    if abs(len(a) - len(b)) > cutoff:
        return cutoff + 1
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        if min(cur) > cutoff:
            return cutoff + 1
        prev = cur
    return prev[-1]


def typo_candidates(name, popular):
    """返回该包名疑似仿冒的流行包名（排除自身）。"""
    n = name.lower().split("/")[-1]
    hits = []
    for p in popular:
        if n == p:
            return []          # 就是本尊
        d = levenshtein(n, p, 2)
        if d <= 2:
            hits.append((p, d))
    return sorted(hits, key=lambda x: x[1])


class Report(object):
    def __init__(self):
        self.items = []

    def add(self, sev, code, where, msg, fix=""):
        self.items.append({"severity": sev, "code": code, "where": where,
                           "message": msg, "fix": fix})

    @property
    def errors(self):
        return [i for i in self.items if i["severity"] == "error"]

    @property
    def warns(self):
        return [i for i in self.items if i["severity"] == "warn"]


# ------------------------------------------------------------------ npm

def audit_npm(root, rep):
    pkg_path = os.path.join(root, "package.json")
    if not os.path.isfile(pkg_path):
        return False
    try:
        with open(pkg_path, "r", encoding="utf-8") as fh:
            pkg = json.load(fh)
    except (OSError, ValueError) as e:
        rep.add("error", "parse-error", "package.json", "无法解析: %s" % e)
        return True

    # 锁文件
    locks = [f for f in ("package-lock.json", "npm-shrinkwrap.json", "yarn.lock",
                         "pnpm-lock.yaml", "bun.lockb") if os.path.isfile(os.path.join(root, f))]
    if not locks:
        rep.add("error", "no-lockfile", "package.json",
                "缺少锁文件，每次构建装到的可能是不同代码，构建不可复现",
                "提交 package-lock.json，CI 用 `npm ci` 而非 `npm install`")
    elif len(locks) > 1:
        rep.add("warn", "multi-lockfile", ", ".join(locks),
                "存在多个包管理器的锁文件，实际生效的依赖版本不确定",
                "只保留团队实际使用的那一个")

    # 本项目自身的安装脚本
    for hook in INSTALL_HOOKS:
        script = (pkg.get("scripts") or {}).get(hook)
        if script:
            rep.add("warn", "own-install-hook", "package.json scripts.%s" % hook,
                    "本项目定义了安装钩子: %s" % script[:70],
                    "确认其内容；安装钩子会在依赖方安装时自动执行")

    deps = {}
    for field in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        for name, spec in (pkg.get(field) or {}).items():
            deps.setdefault(name, (field, spec))

    for name, (field, spec) in sorted(deps.items()):
        is_dev = field == "devDependencies"
        where = "package.json %s.%s" % (field, name)
        if not isinstance(spec, str):
            continue
        s = spec.strip()

        if s.startswith(("git+", "git:", "github:", "gitlab:", "bitbucket:")) or \
           re.match(r"^[\w\-]+/[\w\-.]+(#.*)?$", s):
            rep.add("warn" if is_dev else "error", "git-dependency", where,
                    "直接依赖 Git 仓库: %s —— 内容可被随时改写，无 integrity 校验" % s,
                    "改为发布到 registry 的固定版本")
        elif s.startswith("http://"):
            rep.add("error", "insecure-url-dependency", where,
                    "通过明文 HTTP 拉取依赖: %s，可被中间人替换" % s, "改用 https 或 registry")
        elif s.startswith(("https://", "file:", "link:")):
            rep.add("warn", "url-dependency", where,
                    "非 registry 来源的依赖: %s" % s, "确认来源可信且内容不可变")
        elif s in ("*", "latest", "") or s.lower() == "x":
            rep.add("error", "floating-version", where,
                    "版本范围为 '%s'，任意一次安装都可能引入未审查的新版本" % s,
                    "固定到具体版本或使用 caret 范围并提交锁文件")
        elif s.startswith(">=") and "<" not in s:
            rep.add("warn", "open-ended-range", where,
                    "开放式版本范围 '%s'，无上界" % s, "补上界，如 '>=1.2.0 <2.0.0'")

        for cand, dist in typo_candidates(name, POPULAR_NPM):
            rep.add("warn", "typosquat-suspect", where,
                    "包名 '%s' 与流行包 '%s' 编辑距离仅 %d，疑似仿冒" % (name, cand, dist),
                    "核对官方文档确认包名拼写；这是 typosquatting 的典型特征")
            break

    # 锁文件内部检查
    lock_path = os.path.join(root, "package-lock.json")
    if os.path.isfile(lock_path):
        try:
            with open(lock_path, "r", encoding="utf-8") as fh:
                lock = json.load(fh)
        except (OSError, ValueError) as e:
            rep.add("error", "parse-error", "package-lock.json", "无法解析: %s" % e)
        else:
            entries = lock.get("packages") or lock.get("dependencies") or {}
            hosts, no_integrity = set(), []
            for key, meta in entries.items():
                if not isinstance(meta, dict):
                    continue
                resolved = meta.get("resolved") or ""
                if resolved.startswith(("http://", "https://")):
                    host = resolved.split("/")[2]
                    hosts.add(host)
                    if resolved.startswith("http://"):
                        rep.add("error", "lock-insecure-resolved", "package-lock.json",
                                "锁文件中存在明文 HTTP 下载地址: %s" % resolved[:70],
                                "改用 https registry")
                    if not meta.get("integrity") and key:
                        no_integrity.append(key)
                if meta.get("hasInstallScript"):
                    rep.add("warn", "dep-install-script", "package-lock.json",
                            "依赖 %s 带安装脚本，安装即执行代码" % (key or "?"),
                            "CI 使用 `npm ci --ignore-scripts`，对确需脚本的包单独放行")
            foreign = [h for h in hosts if not any(h.endswith(o) for o in OFFICIAL_NPM_HOSTS)]
            if foreign:
                rep.add("warn", "foreign-registry", "package-lock.json",
                        "锁文件混入非官方 registry: %s" % ", ".join(sorted(foreign)[:5]),
                        "确认这些源可信；混源是依赖混淆攻击的常见入口")
            if no_integrity:
                rep.add("error", "missing-integrity", "package-lock.json",
                        "%d 个依赖缺少 integrity 哈希（如 %s）" % (
                            len(no_integrity), no_integrity[0]),
                        "重新生成锁文件；无哈希意味着无法检测 registry 侧内容被替换")
    return True


# ------------------------------------------------------------------ Python

def audit_python(root, rep):
    found = False
    req = os.path.join(root, "requirements.txt")
    if os.path.isfile(req):
        found = True
        try:
            with open(req, "r", encoding="utf-8", errors="replace") as fh:
                lines = fh.read().splitlines()
        except OSError:
            lines = []
        pinned, total = 0, 0
        has_hash = "--hash" in "\n".join(lines)
        for lineno, raw in enumerate(lines, 1):
            line = raw.split("#")[0].strip()
            if not line or line.startswith("-r") or line.startswith("--hash"):
                continue
            where = "requirements.txt:%d" % lineno
            if line.startswith(("-i ", "--index-url", "--extra-index-url")):
                url = line.split(None, 1)[-1].strip()
                host = url.split("/")[2] if "://" in url else url
                if not any(host.endswith(o) for o in OFFICIAL_PYPI_HOSTS):
                    rep.add("warn", "foreign-index", where,
                            "配置了非官方 PyPI 源: %s" % host,
                            "混源会引入依赖混淆风险；确认该源可信并考虑用 --index-url 独占")
                if url.startswith("http://"):
                    rep.add("error", "insecure-index", where,
                            "明文 HTTP 的包索引: %s" % url, "改用 https")
                continue
            if line.startswith(("git+", "http://", "https://")):
                sev = "error" if line.startswith(("git+", "http://")) else "warn"
                rep.add(sev, "url-dependency", where,
                        "非 registry 来源的依赖: %s" % line[:70],
                        "改为 PyPI 上的固定版本；URL 依赖内容可被替换")
                continue
            total += 1
            name = re.split(r"[=<>!~\[ ]", line, maxsplit=1)[0].strip()
            if "==" in line:
                pinned += 1
            elif re.search(r"[<>~!]", line):
                rep.add("warn", "unpinned-version", where,
                        "依赖 '%s' 未固定到确切版本" % line[:50],
                        "应用项目建议用 == 固定，并配合定期自动升级")
            else:
                rep.add("error", "no-version", where,
                        "依赖 '%s' 完全没有版本约束" % name,
                        "任意一次安装都可能装到不同版本，构建不可复现")
            for cand, dist in typo_candidates(name, POPULAR_PYPI):
                rep.add("warn", "typosquat-suspect", where,
                        "包名 '%s' 与流行包 '%s' 编辑距离仅 %d，疑似仿冒" % (name, cand, dist),
                        "核对官方文档确认包名拼写")
                break
        if total and not has_hash:
            rep.add("warn", "no-hash-pinning", "requirements.txt",
                    "未使用 --hash 固定包哈希（%d 个依赖）" % total,
                    "生产环境建议 `pip-compile --generate-hashes` + `pip install --require-hashes`")

    for f in ("pyproject.toml", "Pipfile", "setup.py"):
        if os.path.isfile(os.path.join(root, f)):
            found = True
    if found:
        locks = [f for f in ("poetry.lock", "Pipfile.lock", "requirements.lock", "uv.lock")
                 if os.path.isfile(os.path.join(root, f))]
        if os.path.isfile(os.path.join(root, "pyproject.toml")) and not locks \
                and not os.path.isfile(req):
            rep.add("warn", "no-lockfile", "pyproject.toml",
                    "未发现锁文件，依赖版本不可复现",
                    "用 poetry lock / uv lock / pip-compile 生成并提交")
    return found


# ------------------------------------------------------------------ Go

def audit_go(root, rep):
    gomod = os.path.join(root, "go.mod")
    if not os.path.isfile(gomod):
        return False
    if not os.path.isfile(os.path.join(root, "go.sum")):
        rep.add("error", "no-gosum", "go.mod",
                "存在 go.mod 但缺少 go.sum，无法校验依赖内容完整性",
                "执行 `go mod tidy` 并提交 go.sum")
    try:
        with open(gomod, "r", encoding="utf-8", errors="replace") as fh:
            content = fh.read()
    except OSError:
        return True
    for m in re.finditer(r"^\s*replace\s+(\S+)\s*=>\s*(\S+)", content, re.M):
        target = m.group(2)
        if target.startswith((".", "/", "..")):
            rep.add("warn", "local-replace", "go.mod",
                    "replace 指向本地路径: %s => %s" % (m.group(1), target),
                    "本地 replace 不应出现在发布版本中，会导致他人无法构建")
    if re.search(r"^\s*//\s*indirect.*v0\.0\.0-00010101", content, re.M):
        rep.add("warn", "placeholder-version", "go.mod", "存在占位版本号", "执行 go mod tidy")
    return True


# ------------------------------------------------------------------ CI

def audit_github_actions(root, rep):
    wf_dir = os.path.join(root, ".github", "workflows")
    if not os.path.isdir(wf_dir):
        return False
    for fn in sorted(os.listdir(wf_dir)):
        if not fn.endswith((".yml", ".yaml")):
            continue
        path = os.path.join(wf_dir, fn)
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                lines = fh.read().splitlines()
        except OSError:
            continue
        for lineno, line in enumerate(lines, 1):
            m = re.search(r"^\s*-?\s*uses:\s*['\"]?([^'\"\s#]+)['\"]?", line)
            if not m:
                continue
            ref = m.group(1)
            if ref.startswith(("./", "docker://")):
                continue
            where = ".github/workflows/%s:%d" % (fn, lineno)
            if "@" not in ref:
                rep.add("error", "action-unpinned", where,
                        "Action '%s' 未指定版本" % ref, "固定到 commit SHA")
                continue
            repo, at = ref.rsplit("@", 1)
            if not re.fullmatch(r"[0-9a-f]{40}", at):
                sev = "warn" if repo.startswith("actions/") else "error"
                rep.add(sev, "action-tag-not-sha", where,
                        "Action '%s' 固定到可变的 tag/分支 '%s'，tag 可被 owner 移动到恶意 commit" % (repo, at),
                        "改为固定 commit SHA：uses: %s@<40位 SHA>  # %s" % (repo, at))
    return True


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="依赖与供应链结构性风险审查（不联网，与 npm audit / pip-audit 互补）",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__.split("用法:", 1)[-1],
    )
    ap.add_argument("path", nargs="?", default=".", help="项目根目录（默认当前目录）")
    ap.add_argument("--strict", action="store_true", help="存在 error 时退出码为 1")
    ap.add_argument("--json", action="store_true", dest="as_json", help="以 JSON 输出")
    args = ap.parse_args(argv)

    root = args.path
    if not os.path.isdir(root):
        print("目录不存在: %s" % root, file=sys.stderr)
        return 2

    rep = Report()
    ecosystems = []
    if audit_npm(root, rep):
        ecosystems.append("npm")
    if audit_python(root, rep):
        ecosystems.append("python")
    if audit_go(root, rep):
        ecosystems.append("go")
    if audit_github_actions(root, rep):
        ecosystems.append("github-actions")

    if not ecosystems:
        msg = "未在 %s 下发现可识别的依赖清单（package.json / requirements.txt / pyproject.toml / go.mod / .github/workflows）" % root
        if args.as_json:
            print(json.dumps({"error_count": 0, "warn_count": 0, "ecosystems": [],
                              "findings": [], "note": msg}, indent=2, ensure_ascii=False))
        else:
            print(msg)
        return 0

    if args.as_json:
        print(json.dumps({
            "ecosystems": ecosystems,
            "error_count": len(rep.errors),
            "warn_count": len(rep.warns),
            "findings": rep.items,
        }, indent=2, ensure_ascii=False))
    else:
        print("\n依赖供应链审查  生态: %s   error %d   warn %d"
              % ("/".join(ecosystems), len(rep.errors), len(rep.warns)))
        print("-" * 78)
        if not rep.items:
            print("未发现结构性供应链风险。")
        for it in sorted(rep.items, key=lambda x: (x["severity"] != "error", x["where"])):
            print("[%s] %s" % ("ERROR" if it["severity"] == "error" else "WARN ", it["where"]))
            print("        %s" % it["message"])
            if it["fix"]:
                print("        → %s" % it["fix"])
        print("\n提示: 本脚本只查结构性风险。已知 CVE 请另跑生态原生工具："
              "\n  npm audit / pip-audit / govulncheck ./...  （govulncheck 带可达性分析，噪声最低）"
              "\n分诊方法见 references/dependency-supply-chain.md")

    if args.strict and rep.errors:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
