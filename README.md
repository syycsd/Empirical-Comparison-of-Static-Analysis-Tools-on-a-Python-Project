# 静态分析实验复现指南

## 环境

- Python 3.11+（本机实测 3.14.3）
- Git

## 一键复现

```powershell
cd experiments
python -m pip install -r requirements.txt
python run_analysis.py
python post_process.py
```

## 输出文件

| 文件 | 说明 |
|------|------|
| `results/all_issues.csv` | 全部告警（归一化） |
| `results/pylint_issues.csv` | Pylint 告警 |
| `results/ruff_issues.csv` | Ruff 质量规则告警 |
| `results/ruff_security_issues.csv` | Ruff 安全/缺陷规则 (S,B) |
| `results/summary.json` | 告警计数与规则 Top10 |
| `results/overlap.json` | 工具间 Jaccard 重叠度 |
| `results/annotation_sample.csv` | 分层抽样 90 条 + 默认标注 |
| `results/annotation_stats.json` | RQ2/RQ3 统计 |
| `results/raw/` | 各工具原始 JSON |

## 工具说明

| 工具 | 版本 | 角色 |
|------|------|------|
| Pylint | 3.3.3 | 传统 Python 质量分析 |
| Ruff | 0.9.6 | 现代 linter（质量规则子集） |
| Ruff-Security | 0.9.6 | `--select=S,B`，安全向规则 |
| Bandit | 1.8.2 | 在 Python 3.14 上扫描异常，结果为空；见 `raw/bandit_meta.json` |

## 靶项目

- 路径：`target/requests/`
- Tag：`v2.32.3`，Commit：`0e322af87745eff34caffe4df68456ebc20d9068`
- 扫描范围：`src/requests/`（4560 行，18 文件）

## 标注说明

`annotation_sample.csv` 中 `label`/`fix_cost` 由规则启发式生成，可由人工复核并修改 `post_process.py` 中 `RULE_LABELS` 后重新运行 `post_process.py`。
