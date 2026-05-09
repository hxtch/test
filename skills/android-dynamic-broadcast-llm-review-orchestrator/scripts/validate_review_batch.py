from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

from review_common import load_json, write_json


REQUIRED_RESULT_FIELDS = (
    "finding_id",
    "kind",
    "analysis_attempt",
    "resolved_app_root",
    "candidate_source_roots",
    "input_action_list",
    "traced_action_list",
    "custom_action_list",
    "action_classification_evidence",
    "trace_status",
    "trace_hops_used",
    "matched_custom_actions",
    "onreceive_entry_method",
    "matched_branch_evidence",
    "dataflow_trace_summary",
    "visited_methods",
    "visited_sinks",
    "guard_summary",
    "trace_stop_reason",
    "onreceive_hops_used",
    "ui_operations",
    "sensitive_operations",
    "poc_command",
    "poc_preconditions",
    "poc_expected_effect",
    "poc_minimal_extras",
    "onreceive_analysis_status",
    "custom_branches_analyzed",
    "final_subagent_verdict",
    "needs_main_agent_attention",
)

CHINESE_REPORT_FIELDS = (
    "vulnerability_analysis",
    "attack_path",
    "root_cause",
    "impact",
    "fix_recommendation",
)


def contains_chinese(value: Any) -> bool:
    text = str(value or "")
    return any("\u4e00" <= char <= "\u9fff" for char in text)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Validate review batch output and flag forced remediation cases.")
    parser.add_argument("--batch-result", required=True)
    parser.add_argument("--out", required=True)
    return parser.parse_args()


def collect_missing_fields(result: dict[str, Any]) -> list[str]:
    return [field for field in REQUIRED_RESULT_FIELDS if field not in result]


def remediation_reasons(result: dict[str, Any]) -> list[str]:
    reasons: list[str] = []
    verdict = result.get("final_subagent_verdict")
    if not result.get("matched_branch_evidence"):
        reasons.append("missing_matched_branch_evidence")
    if not result.get("dataflow_trace_summary"):
        reasons.append("missing_dataflow_trace_summary")
    if not result.get("visited_methods"):
        reasons.append("missing_visited_methods")
    if verdict == "confirmed_sensitive" and not result.get("visited_sinks"):
        reasons.append("confirmed_sensitive_missing_visited_sinks")
    if verdict == "confirmed_sensitive" and not result.get("poc_command"):
        reasons.append("confirmed_sensitive_missing_poc_command")
    if verdict == "confirmed_sensitive" and not result.get("vulnerability_analysis"):
        reasons.append("confirmed_sensitive_missing_vulnerability_analysis")
    if verdict == "confirmed_sensitive" and not result.get("attack_path"):
        reasons.append("confirmed_sensitive_missing_attack_path")
    if verdict == "confirmed_sensitive" and not result.get("root_cause"):
        reasons.append("confirmed_sensitive_missing_root_cause")
    if verdict == "confirmed_sensitive" and not result.get("impact"):
        reasons.append("confirmed_sensitive_missing_impact")
    if verdict == "confirmed_sensitive" and not result.get("fix_recommendation"):
        reasons.append("confirmed_sensitive_missing_fix_recommendation")
    if verdict == "confirmed_sensitive":
        for field in CHINESE_REPORT_FIELDS:
            if result.get(field) and not contains_chinese(result.get(field)):
                reasons.append(f"confirmed_sensitive_{field}_not_chinese")
    if verdict == "confirmed_sensitive" and not result.get("vuln_code_blocks"):
        reasons.append("confirmed_sensitive_missing_vuln_code_blocks")
    if verdict == "confirmed_sensitive" and not result.get("vuln_code_paths"):
        reasons.append("confirmed_sensitive_missing_vuln_code_paths")
    if not result.get("input_action_list") and not result.get("traced_action_list") and not result.get("custom_action_list"):
        reasons.append("empty_action_list_without_trace")
    trace_summary = str(result.get("dataflow_trace_summary", "")).strip().lower()
    if "未见明显风险" in trace_summary or "read onreceive" in trace_summary or "onreceive exists" in trace_summary:
        reasons.append("shallow_onreceive_analysis")
    return reasons


def main() -> None:
    args = parse_args()
    payload = load_json(Path(args.batch_result))
    results = payload.get("results", [])
    validation: dict[str, Any] = {
        "batch_id": payload.get("batch_id"),
        "task_type": payload.get("task_type"),
        "valid": True,
        "result_count": len(results),
        "items": [],
    }
    for result in results:
        missing = collect_missing_fields(result)
        remediation = remediation_reasons(result)
        item_validation = {
            "finding_id": result.get("finding_id"),
            "missing_fields": missing,
            "forced_remediation_reasons": remediation,
            "is_valid": not missing and not remediation,
        }
        if missing or remediation:
            validation["valid"] = False
        validation["items"].append(item_validation)
    write_json(Path(args.out), validation)


if __name__ == "__main__":
    main()
