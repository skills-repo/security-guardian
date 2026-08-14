#!/usr/bin/env python3
"""CVSS v3.1 base-score calculator.

Deterministic, zero-dependency (stdlib only) companion to
`references/vuln-triage.md`. Turns a CVSS v3.1 vector string into a
base score + severity rating, or walks you through the metrics
interactively when you don't remember the vector syntax.

Examples
--------
    python3 scripts/cvss_score.py --vector "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    python3 scripts/cvss_score.py --interactive

Reference: FIRST.org CVSS v3.1 Specification, §7.1 (Base Score equations
and the Roundup function).
"""

import argparse
import math
import sys

# --- weight tables (CVSS v3.1) ------------------------------------------------
AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
AC = {"L": 0.77, "H": 0.44}
PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}   # scope unchanged
PR_C = {"N": 0.85, "L": 0.68, "H": 0.50}   # scope changed
UI = {"N": 0.85, "R": 0.62}
CIA = {"H": 0.56, "L": 0.22, "N": 0.0}

METRICS = {
    "AV": ("N", "A", "L", "P"),
    "AC": ("L", "H"),
    "PR": ("N", "L", "H"),
    "UI": ("N", "R"),
    "S":  ("U", "C"),
    "C":  ("H", "L", "N"),
    "I":  ("H", "L", "N"),
    "A":  ("H", "L", "N"),
}

PROMPTS = {
    "AV": "Attack Vector  (N=Network, A=Adjacent, L=Local, P=Physical)",
    "AC": "Attack Complexity  (L=Low, H=High)",
    "PR": "Privileges Required  (N=None, L=Low, H=High)",
    "UI": "User Interaction  (N=None, R=Required)",
    "S":  "Scope  (U=Unchanged, C=Changed)",
    "C":  "Confidentiality  (H=High, L=Low, N=None)",
    "I":  "Integrity  (H=High, L=Low, N=None)",
    "A":  "Availability  (H=High, L=Low, N=None)",
}


def roundup(x: float) -> float:
    """Smallest number >= x with exactly one decimal place (CVSS spec)."""
    return math.ceil(x * 10 - 1e-6) / 10


def severity(score: float) -> str:
    if score == 0.0:
        return "None"
    if score < 4.0:
        return "Low"
    if score < 7.0:
        return "Medium"
    if score < 9.0:
        return "High"
    return "Critical"


def parse_vector(vector: str) -> dict:
    v = vector.strip()
    if not v.startswith("CVSS:3.1/"):
        raise ValueError("vector must start with 'CVSS:3.1/'")
    parts = v[len("CVSS:3.1/"):].split("/")
    vals = {}
    for part in parts:
        if not part:
            continue
        if ":" not in part:
            raise ValueError(f"malformed metric '{part}' (expected KEY:VALUE)")
        key, val = part.split(":", 1)
        key, val = key.strip().upper(), val.strip().upper()
        if key not in METRICS:
            raise ValueError(f"unknown metric '{key}'")
        if val not in METRICS[key]:
            raise ValueError(f"invalid value '{val}' for metric '{key}' "
                             f"(allowed: {','.join(METRICS[key])})")
        vals[key] = val
    missing = [k for k in METRICS if k not in vals]
    if missing:
        raise ValueError("missing metrics: " + ",".join(missing))
    return vals


def score(vals: dict) -> float:
    av, ac = AV[vals["AV"]], AC[vals["AC"]]
    pr = (PR_U if vals["S"] == "U" else PR_C)[vals["PR"]]
    ui = UI[vals["UI"]]
    exploitability = 8.22 * av * ac * pr * ui

    c, i, a = CIA[vals["C"]], CIA[vals["I"]], CIA[vals["A"]]
    iss = 1 - (1 - c) * (1 - i) * (1 - a)
    if vals["S"] == "U":
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15

    if impact <= 0:
        return 0.0
    if vals["S"] == "U":
        base = min(impact + exploitability, 10.0)
    else:
        base = min(1.08 * (impact + exploitability), 10.0)
    return roundup(base)


def interactive() -> dict:
    print("CVSS v3.1 interactive — pick a value for each metric:")
    vals = {}
    for key, prompt in PROMPTS.items():
        allowed = "/".join(METRICS[key])
        while True:
            ans = input(f"  {key} [{allowed}]  {prompt}\n    > ").strip().upper()
            if ans in METRICS[key]:
                vals[key] = ans
                break
            print(f"    ! expected one of: {allowed}")
    return vals


def main() -> int:
    p = argparse.ArgumentParser(
        description="CVSS v3.1 base-score calculator (vector string or "
                    "interactive). Zero-dependency companion to "
                    "references/vuln-triage.md.")
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--vector", metavar="STR",
                   help='CVSS v3.1 vector, e.g. '
                        '"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"')
    g.add_argument("--interactive", action="store_true",
                   help="prompt for each metric one by one")
    p.add_argument("--explain", action="store_true",
                   help="print the per-metric breakdown")
    args = p.parse_args()

    try:
        vals = interactive() if args.interactive else parse_vector(args.vector)
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    s = score(vals)
    sev = severity(s)
    print(f"Base Score: {s:.1f}  ({sev})")
    if args.explain:
        print("  metrics: " + " ".join(f"{k}={v}" for k, v in vals.items()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
