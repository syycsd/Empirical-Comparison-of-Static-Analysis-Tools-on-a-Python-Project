#!/usr/bin/env python3
"""Post-process static analysis results: overlap, sampling, annotation stats."""

from __future__ import annotations

import csv
import json
import random
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent
RESULTS = ROOT / "results"
SAMPLE_SIZE = 30
SEED = 42

# Heuristic labels for common rules (course experiment; user may refine in CSV)
RULE_LABELS: dict[str, tuple[str, str, str]] = {
    # rule_id: (default_label, fix_cost, rationale)
    "unused-import": ("TP", "low", "未使用导入可安全删除"),
    "F401": ("TP", "low", "未使用导入可安全删除"),
    "raise-missing-from": ("TP", "low", "异常链缺失影响调试"),
    "B904": ("TP", "low", "raise-without-from-inside-except"),
    "line-too-long": ("FP", "low", "纯风格问题"),
    "E501": ("FP", "low", "纯风格问题"),
    "missing-function-docstring": ("FP", "low", "文档风格非功能缺陷"),
    "missing-module-docstring": ("FP", "low", "文档风格非功能缺陷"),
    "invalid-name": ("FP", "low", "命名风格"),
    "N806": ("FP", "low", "变量命名风格"),
    "wrong-import-position": ("FP", "low", "import 顺序"),
    "wrong-import-order": ("FP", "low", "import 顺序"),
    "E402": ("FP", "low", "module-import-not-at-top"),
    "consider-using-f-string": ("FP", "low", "可读性建议"),
    "duplicate-code": ("FP", "medium", "结构相似不等于缺陷"),
    "protected-access": ("UNK", "medium", "需结合 API 设计判断"),
    "redefined-builtin": ("UNK", "medium", "库内可能刻意重导出异常名"),
    "redefined-outer-name": ("FP", "low", "测试/版本检测上下文常见"),
    "too-many-branches": ("FP", "medium", "复杂度启发式"),
    "too-many-arguments": ("FP", "medium", "复杂度启发式"),
    "PLR0912": ("FP", "medium", "too-many-branches"),
    "PLR0913": ("FP", "medium", "too-many-arguments"),
    "TRY003": ("FP", "low", "异常消息风格"),
    "EM101": ("FP", "low", "异常字符串字面量风格"),
    "EM102": ("FP", "low", "异常 f-string 风格"),
    "PLR2004": ("FP", "low", "magic value 在 HTTP 库中常见"),
    "FBT002": ("FP", "low", "布尔参数位置风格"),
    "S113": ("TP", "medium", "requests 无 timeout 可能导致挂起"),
    "S501": ("UNK", "medium", "verify=False 需看是否测试代码"),
    "S602": ("TP", "high", "subprocess shell=True 安全风险"),
    "S603": ("TP", "medium", "subprocess 调用需审计"),
}


def load_issues(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8-sig") as f:
        return list(csv.DictReader(f))


def loc_key(row: dict[str, str]) -> tuple[str, int]:
    file_path = row["file"].replace("\\", "/")
    if file_path.startswith("target/requests/src/requests/"):
        file_path = file_path[len("target/requests/src/requests/") :]
    elif file_path.startswith("src/requests/"):
        file_path = file_path[len("src/requests/") :]
    return (file_path, int(row["line"] or 0))


def compute_overlap(issues: list[dict[str, str]]) -> dict:
    by_tool: dict[str, set[tuple[str, int]]] = defaultdict(set)
    by_tool_rule: dict[str, set[tuple[str, str, int]]] = defaultdict(set)
    for row in issues:
        tool = row["tool"]
        by_tool[tool].add(loc_key(row))
        by_tool_rule[tool].add((*loc_key(row), row["rule_id"]))

    def jaccard(a: set, b: set) -> float:
        u = a | b
        return len(a & b) / len(u) if u else 0.0

    tools = sorted(by_tool)
    out: dict = {"by_location": {}, "by_location_rule": {}, "counts": {}}
    for t in tools:
        out["counts"][t] = len(by_tool[t])

    for i, t1 in enumerate(tools):
        for t2 in tools[i + 1 :]:
            out["by_location"][f"{t1}_vs_{t2}"] = {
                "jaccard": round(jaccard(by_tool[t1], by_tool[t2]), 4),
                "intersection": len(by_tool[t1] & by_tool[t2]),
                "union": len(by_tool[t1] | by_tool[t2]),
            }
            out["by_location_rule"][f"{t1}_vs_{t2}"] = {
                "jaccard": round(jaccard(by_tool_rule[t1], by_tool_rule[t2]), 4),
                "intersection": len(by_tool_rule[t1] & by_tool_rule[t2]),
                "union": len(by_tool_rule[t1] | by_tool_rule[t2]),
            }

    if len(tools) == 3:
        inter = by_tool[tools[0]] & by_tool[tools[1]] & by_tool[tools[2]]
        union = by_tool[tools[0]] | by_tool[tools[1]] | by_tool[tools[2]]
        out["three_way_location"] = {
            "intersection": len(inter),
            "union": len(union),
            "ratio": round(len(inter) / len(union), 4) if union else 0.0,
        }
    return out


def stratified_sample(rows: list[dict[str, str]], n: int, rng: random.Random) -> list[dict[str, str]]:
    by_sev: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in rows:
        by_sev[row["severity"]].append(row)
    if len(rows) <= n:
        return rows

    picked: list[dict[str, str]] = []
    severities = sorted(by_sev, key=lambda s: len(by_sev[s]), reverse=True)
    remaining = n
    for i, sev in enumerate(severities):
        bucket = by_sev[sev]
        if i == len(severities) - 1:
            take = remaining
        else:
            take = max(1, round(n * len(bucket) / len(rows)))
            take = min(take, remaining, len(bucket))
        picked.extend(rng.sample(bucket, min(take, len(bucket))))
        remaining -= min(take, len(bucket))
    if len(picked) < n:
        pool = [r for r in rows if r not in picked]
        picked.extend(rng.sample(pool, min(n - len(picked), len(pool))))
    return picked[:n]


def default_annotation(row: dict[str, str]) -> dict[str, str]:
    rule = row["rule_id"]
    label, cost, note = RULE_LABELS.get(rule, ("UNK", "medium", "需人工复核"))
    return {
        **row,
        "label": label,
        "fix_cost": cost if label == "TP" else "",
        "annotator_note": note,
    }


def annotation_stats(rows: list[dict[str, str]]) -> dict:
    by_tool: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in rows:
        by_tool[row["tool"]].append(row)

    stats: dict = {}
    for tool, items in by_tool.items():
        labels = Counter(r["label"] for r in items)
        total = len(items)
        tp_items = [r for r in items if r["label"] == "TP"]
        costs = Counter(r["fix_cost"] for r in tp_items if r["fix_cost"])
        fp_rules = Counter(r["rule_id"] for r in items if r["label"] == "FP")
        stats[tool] = {
            "sample_size": total,
            "TP_pct": round(100 * labels["TP"] / total, 1) if total else 0,
            "FP_pct": round(100 * labels["FP"] / total, 1) if total else 0,
            "UNK_pct": round(100 * labels["UNK"] / total, 1) if total else 0,
            "tp_fix_cost": dict(costs),
            "top_fp_rules": fp_rules.most_common(5),
        }
    return stats


def main() -> None:
    issues = load_issues(RESULTS / "all_issues.csv")
    overlap = compute_overlap(issues)
    (RESULTS / "overlap.json").write_text(
        json.dumps(overlap, indent=2, ensure_ascii=False), encoding="utf-8"
    )

    rng = random.Random(SEED)
    samples: list[dict[str, str]] = []
    for tool in sorted({i["tool"] for i in issues}):
        tool_rows = [i for i in issues if i["tool"] == tool]
        if not tool_rows:
            continue
        n = min(SAMPLE_SIZE, len(tool_rows))
        for row in stratified_sample(tool_rows, n, rng):
            samples.append(default_annotation(row))

    sample_path = RESULTS / "annotation_sample.csv"
    fields = [
        "tool",
        "rule_id",
        "severity",
        "file",
        "line",
        "column",
        "message",
        "label",
        "fix_cost",
        "annotator_note",
    ]
    with sample_path.open("w", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(samples)

    stats = annotation_stats(samples)
    (RESULTS / "annotation_stats.json").write_text(
        json.dumps(stats, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    print(json.dumps({"overlap": overlap, "annotation": stats}, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
