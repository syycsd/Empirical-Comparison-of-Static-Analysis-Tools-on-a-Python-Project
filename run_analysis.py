#!/usr/bin/env python3
"""Run Pylint, Bandit, Ruff on target project and export normalized CSV."""

from __future__ import annotations

import csv
import json
import subprocess
import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent
TARGET_SRC = ROOT / "target" / "requests" / "src" / "requests"
RAW_DIR = ROOT / "results" / "raw"
OUT_DIR = ROOT / "results"


@dataclass(frozen=True)
class Issue:
    tool: str
    rule_id: str
    severity: str
    message: str
    file: str
    line: int
    column: int | None = None

    @property
    def key(self) -> tuple[str, str, int, str]:
        rel = self.file.replace("\\", "/")
        if rel.startswith("src/requests/"):
            rel = rel[len("src/requests/") :]
        return (rel, self.rule_id, self.line, self.tool)


def run_cmd(cmd: list[str]) -> subprocess.CompletedProcess[str]:
    print("+", " ".join(cmd))
    return subprocess.run(cmd, capture_output=True, text=True, cwd=ROOT)


def normalize_severity(tool: str, raw: str) -> str:
    raw_l = (raw or "unknown").lower()
    if tool == "pylint":
        mapping = {
            "fatal": "critical",
            "error": "high",
            "warning": "medium",
            "convention": "low",
            "refactor": "low",
            "info": "info",
        }
        return mapping.get(raw_l, raw_l)
    if tool == "bandit":
        mapping = {
            "high": "high",
            "medium": "medium",
            "low": "low",
        }
        return mapping.get(raw_l, raw_l)
    if tool == "ruff":
        return raw_l
    return raw_l


def run_pylint() -> list[Issue]:
    out = RAW_DIR / "pylint.json"
    cmd = [
        sys.executable,
        "-m",
        "pylint",
        str(TARGET_SRC),
        "--output-format=json",
        "--score=n",
        "--reports=n",
        "--disable=import-error,no-member",
    ]
    proc = run_cmd(cmd)
    RAW_DIR.mkdir(parents=True, exist_ok=True)
    out.write_text(proc.stdout or "[]", encoding="utf-8")
    if proc.returncode not in (0, 1, 2, 4, 8, 16, 32):
        print(proc.stderr, file=sys.stderr)

    data = json.loads(proc.stdout or "[]")
    issues: list[Issue] = []
    for item in data:
        path = Path(item.get("path", ""))
        try:
            rel = path.relative_to(TARGET_SRC.parent.parent).as_posix()
        except ValueError:
            rel = path.as_posix()
        issues.append(
            Issue(
                tool="pylint",
                rule_id=item.get("symbol") or item.get("message-id", "unknown"),
                severity=normalize_severity("pylint", item.get("type", "unknown")),
                message=(item.get("message") or "").replace("\n", " "),
                file=rel,
                line=int(item.get("line") or 0),
                column=int(item.get("column") or 0) or None,
            )
        )
    return issues


def run_bandit() -> list[Issue]:
    out = RAW_DIR / "bandit.json"
    cmd = [
        sys.executable,
        "-m",
        "bandit",
        "-r",
        str(TARGET_SRC),
        "-f",
        "json",
        "-ll",
    ]
    proc = run_cmd(cmd)
    out.write_text(proc.stdout or "{}", encoding="utf-8")
    if proc.returncode not in (0, 1):
        print(proc.stderr, file=sys.stderr)

    payload = json.loads(proc.stdout or "{}")
    issues: list[Issue] = []
    for item in payload.get("results", []):
        path = item.get("filename", "")
        try:
            rel = Path(path).relative_to(TARGET_SRC.parent.parent).as_posix()
        except ValueError:
            rel = Path(path).name
        issues.append(
            Issue(
                tool="bandit",
                rule_id=item.get("test_id", "unknown"),
                severity=normalize_severity("bandit", item.get("issue_severity", "unknown")),
                message=(item.get("issue_text") or "").replace("\n", " "),
                file=rel,
                line=int(item.get("line_number") or 0),
                column=int(item.get("col_offset") or 0) or None,
            )
        )
    return issues


def run_ruff(select: str, tool_name: str, ignore: str | None = "D,ANN,COM812,ISC001") -> list[Issue]:
    out = RAW_DIR / f"{tool_name}.json"
    cmd = [
        sys.executable,
        "-m",
        "ruff",
        "check",
        str(TARGET_SRC),
        "--output-format=json",
        f"--select={select}",
    ]
    if ignore:
        cmd.append(f"--ignore={ignore}")
    proc = run_cmd(cmd)
    out.write_text(proc.stdout or "[]", encoding="utf-8")
    if proc.returncode not in (0, 1):
        print(proc.stderr, file=sys.stderr)

    data = json.loads(proc.stdout or "[]")
    issues: list[Issue] = []
    for item in data:
        path = item.get("filename", "")
        try:
            rel = Path(path).relative_to(TARGET_SRC.parent.parent).as_posix()
        except ValueError:
            rel = Path(path).name
        code = item.get("code", "unknown")
        sev = "high" if str(code).startswith("S") and str(code) in {"S602", "S607", "S608"} else "medium"
        if str(code).startswith("S"):
            sev = "high" if code in {"S602", "S607", "S608", "S501"} else "medium"
        issues.append(
            Issue(
                tool=tool_name,
                rule_id=code,
                severity=normalize_severity("ruff", sev),
                message=(item.get("message") or "").replace("\n", " "),
                file=rel,
                line=int(item.get("location", {}).get("row") or 0),
                column=int(item.get("location", {}).get("column") or 0) or None,
            )
        )
    return issues


def run_ruff_quality() -> list[Issue]:
    return run_ruff(
        select="E,F,W,PL,TRY,EM,FBT,N,PERF,UP,RET,RUF,ICN,PIE,SIM,LOG,PT",
        tool_name="ruff",
    )


def run_ruff_security() -> list[Issue]:
    return run_ruff(select="S,B", tool_name="ruff_security", ignore=None)


def write_issues_csv(path: Path, issues: list[Issue]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f)
        w.writerow(["tool", "rule_id", "severity", "file", "line", "column", "message"])
        for i in sorted(issues, key=lambda x: (x.tool, x.file, x.line, x.rule_id)):
            w.writerow(
                [i.tool, i.rule_id, i.severity, i.file, i.line, i.column or "", i.message]
            )


def jaccard(a: set, b: set) -> float:
    if not a and not b:
        return 1.0
    union = a | b
    if not union:
        return 0.0
    return len(a & b) / len(union)


def overlap_key(issue: Issue) -> tuple[str, str, int]:
    rel = issue.file.replace("\\", "/")
    if rel.startswith("src/requests/"):
        rel = rel[len("src/requests/") :]
    return (rel, issue.rule_id, issue.line)


def summarize(issues: list[Issue]) -> dict:
    by_tool: dict[str, list[Issue]] = {}
    for issue in issues:
        by_tool.setdefault(issue.tool, []).append(issue)

    summary = {"tools": {}, "overlap": {}}
    sets: dict[str, set[tuple[str, str, int]]] = {}
    for tool, tool_issues in by_tool.items():
        sev = Counter(i.severity for i in tool_issues)
        rules = Counter(i.rule_id for i in tool_issues)
        sets[tool] = {overlap_key(i) for i in tool_issues}
        summary["tools"][tool] = {
            "total": len(tool_issues),
            "severity": dict(sorted(sev.items())),
            "top_rules": rules.most_common(10),
        }

    tools = sorted(sets)
    for i, t1 in enumerate(tools):
        for t2 in tools[i + 1 :]:
            summary["overlap"][f"{t1}_vs_{t2}"] = {
                "jaccard_location_rule": round(jaccard(sets[t1], sets[t2]), 4),
                "intersection": len(sets[t1] & sets[t2]),
                "union": len(sets[t1] | sets[t2]),
            }

    if len(tools) == 3:
        inter = sets[tools[0]] & sets[tools[1]] & sets[tools[2]]
        union = sets[tools[0]] | sets[tools[1]] | sets[tools[2]]
        summary["overlap"]["three_way"] = {
            "intersection": len(inter),
            "union": len(union),
            "intersection_over_union": round(len(inter) / len(union), 4) if union else 0.0,
        }

    return summary


def main() -> int:
    if not TARGET_SRC.is_dir():
        print(f"Target not found: {TARGET_SRC}", file=sys.stderr)
        return 1

    RAW_DIR.mkdir(parents=True, exist_ok=True)
    all_issues: list[Issue] = []
    pylint_issues = run_pylint()
    bandit_issues = run_bandit()
    ruff_issues = run_ruff_quality()
    ruff_sec_issues = run_ruff_security()
    all_issues = pylint_issues + bandit_issues + ruff_issues + ruff_sec_issues

    bandit_meta = {
        "bandit_result_count": len(bandit_issues),
        "bandit_note": (
            "Bandit 1.8.2 on Python 3.14 raised scan exceptions on all files; "
            "ruff_security (--select=S,B) used as security-oriented comparator."
        ),
    }
    (RAW_DIR / "bandit_meta.json").write_text(
        json.dumps(bandit_meta, indent=2, ensure_ascii=False), encoding="utf-8"
    )

    write_issues_csv(OUT_DIR / "all_issues.csv", all_issues)
    for tool in ("pylint", "bandit", "ruff", "ruff_security"):
        write_issues_csv(
            OUT_DIR / f"{tool}_issues.csv",
            [i for i in all_issues if i.tool == tool],
        )

    summary = summarize(all_issues)
    (OUT_DIR / "summary.json").write_text(
        json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8"
    )

    print(json.dumps(summary, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
