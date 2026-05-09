from __future__ import annotations

import argparse
import re
from pathlib import Path
from typing import Any

from review_common import load_json, write_json, write_jsonl


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Merge review batches into final report artifacts.")
    parser.add_argument("--review-dir", required=True)
    return parser.parse_args()


def summarize_item(item: dict[str, Any]) -> str:
    lines = [
        f"- `{item.get('finding_id')}` `{item.get('kind')}` `{item.get('final_subagent_verdict')}`",
        f"  - 入口类: `{item.get('declaring_class', 'unknown')}`",
        f"  - 自定义 action: {item.get('custom_action_list', [])}",
        f"  - 敏感 sink: {item.get('visited_sinks', [])}",
        f"  - 追踪停止原因: `{item.get('trace_stop_reason')}`",
    ]
    if item.get("poc_command"):
        lines.append(f"  - PoC: `{item['poc_command']}`")
    return "\n".join(lines)


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


def normalize_snippet_text(text: str) -> str:
    normalized = (
        str(text)
        .replace("\\r\\n", "\n")
        .replace("\\n", "\n")
        .replace('\\"', '"')
        .strip()
    )
    return normalized


def infer_declaring_class(item: dict[str, Any]) -> str:
    class_name = str(item.get("declaring_class") or "").strip()
    if class_name:
        return class_name
    entry = str(item.get("onreceive_entry_method") or "").strip()
    if "#" in entry:
        return entry.split("#", 1)[0].strip()
    branch_evidence = item.get("matched_branch_evidence") or []
    for evidence in branch_evidence:
        if isinstance(evidence, dict):
            path = str(evidence.get("path") or "").strip()
            if path:
                stem = Path(path).stem
                if stem:
                    return stem
    return "unknown"


def extract_snippet(text: str, pattern: str, radius: int = 3) -> str | None:
    lines = text.splitlines()
    for idx, line in enumerate(lines):
        if pattern in line:
            start = max(0, idx - radius)
            end = min(len(lines), idx + radius + 1)
            return "\n".join(lines[start:end]).strip()
    return None


def resolve_receiver_source_paths(item: dict[str, Any]) -> list[str]:
    class_name = item.get("declaring_class") or ""
    app_root_text = item.get("resolved_app_root")
    if not class_name or not app_root_text:
        return []
    app_root = Path(app_root_text)
    rel_candidates = [
        class_name.replace(".", "/") + suffix
        for suffix in (".java", ".kt", ".smali")
    ]
    rel_candidates.extend(
        class_name.replace("$", "/").replace(".", "/") + suffix
        for suffix in (".java", ".kt", ".smali")
    )
    hits: list[str] = []
    for root_text in item.get("candidate_source_roots", []):
        root = Path(root_text)
        for rel in rel_candidates:
            candidate = root / rel
            if candidate.exists():
                hits.append(str(candidate))
                break
    if hits:
        return sorted(set(hits))
    for rel in rel_candidates:
        candidate = app_root / rel
        if candidate.exists():
            hits.append(str(candidate))
    return sorted(set(hits))


def resolve_manifest_path(item: dict[str, Any]) -> str | None:
    app_root_text = item.get("resolved_app_root")
    if not app_root_text:
        return None
    app_root = Path(app_root_text)
    direct = app_root / "AndroidManifest.xml"
    if direct.exists():
        return str(direct)
    manifests = sorted(path for path in app_root.rglob("AndroidManifest.xml") if path.is_file())
    return str(manifests[0]) if manifests else None


def build_fallback_vuln_code(item: dict[str, Any]) -> list[dict[str, str]]:
    blocks: list[dict[str, str]] = []

    manifest_path = resolve_manifest_path(item)
    if manifest_path:
        manifest_text = read_text(Path(manifest_path))
        class_name = item.get("declaring_class", "")
        snippet = extract_snippet(manifest_text, class_name, radius=4)
        if snippet:
            blocks.append({"title": "外部可触发入口代码（Manifest）", "code": snippet, "path": manifest_path})

    source_paths = resolve_receiver_source_paths(item)
    for source_path in source_paths[:1]:
        source_text = read_text(Path(source_path))
        preview = "\n".join(source_text.splitlines()[:60]).strip()
        if preview and all(block["code"] != preview for block in blocks):
            blocks.append({"title": "Receiver 入口源码（前 60 行）", "code": preview, "path": source_path})

    return blocks


def normalize_vuln_code_blocks(item: dict[str, Any]) -> list[dict[str, str]]:
    raw_blocks = item.get("vuln_code_blocks")
    raw_paths = item.get("vuln_code_paths")
    blocks: list[dict[str, str]] = []
    paths: list[str] = []
    if isinstance(raw_blocks, list):
        for idx, block in enumerate(raw_blocks, start=1):
            if isinstance(block, dict):
                code = normalize_snippet_text(str(block.get("code", "")))
                title = str(block.get("title", f"漏洞代码 {idx}")).strip() or f"漏洞代码 {idx}"
                block_path = str(block.get("path", "")).strip()
            else:
                code = normalize_snippet_text(str(block))
                title = f"漏洞代码 {idx}"
                block_path = ""
            if code:
                code_lines = code.splitlines()
                if code_lines and re.search(r"\.(java|kt|smali|xml)$", code_lines[0].strip()):
                    title = code_lines[0].strip()
                    code = "\n".join(code_lines[1:]).strip()
                blocks.append({"title": title, "code": code, "path": block_path})
    if isinstance(raw_paths, list):
        for path in raw_paths:
            path_text = str(path).strip()
            if path_text:
                paths.append(path_text)
    unique_paths = list(dict.fromkeys(paths))
    candidate_source_roots = [
        Path(str(root_text))
        for root_text in item.get("candidate_source_roots", [])
        if str(root_text).strip()
    ]
    if blocks:
        for idx, block in enumerate(blocks):
            if block.get("path"):
                continue
            if unique_paths:
                matched_path = ""
                title_name = str(block.get("title", "")).strip()
                if re.search(r"\.(java|kt|smali|xml)$", title_name):
                    for candidate_path in unique_paths:
                        if Path(candidate_path).name == title_name:
                            matched_path = candidate_path
                            break
                    if not matched_path:
                        for root in candidate_source_roots:
                            resolved = next(root.rglob(title_name), None)
                            if resolved and resolved.is_file():
                                matched_path = str(resolved)
                                break
                block["path"] = matched_path or unique_paths[min(idx, len(unique_paths) - 1)]
        return blocks
    return build_fallback_vuln_code(item)


def render_text_or_list(value: Any, fallback: str = "未提供") -> list[str]:
    if isinstance(value, list):
        items = [str(item).strip() for item in value if str(item).strip()]
        return [f"- {item}" for item in items] if items else [fallback]
    if isinstance(value, dict):
        items = [f"{key}: {val}" for key, val in value.items() if str(val).strip()]
        return [f"- {item}" for item in items] if items else [fallback]
    text = str(value or "").strip()
    return [text] if text else [fallback]


def fallback_attack_path(item: dict[str, Any]) -> list[str]:
    steps: list[str] = []
    actions = item.get("matched_custom_actions") or item.get("custom_action_list") or []
    action_text = ", ".join(str(action) for action in actions) if actions else "目标 action"
    steps.append(f"攻击者发送广播 `{action_text}`")
    entry = item.get("onreceive_entry_method")
    if entry:
        steps.append(f"广播进入 `{entry}`")
    branch_raw = item.get("matched_branch_evidence")
    if isinstance(branch_raw, list):
        branch = "; ".join(
            str(e.get("code") or e.get("path") or e) if isinstance(e, dict) else str(e)
            for e in branch_raw
            if e
        ).strip()
    else:
        branch = str(branch_raw or "").strip()
    if branch:
        steps.append(f"命中分支：{branch}")
    visited = item.get("visited_methods", [])
    if len(visited) > 1:
        steps.append(f"经过调用链：`{' -> '.join(str(m) for m in visited)}`")
    elif visited:
        steps.append(f"继续调用 `{visited[0]}`")
    sinks = item.get("visited_sinks") or []
    if sinks:
        steps.append(f"最终到达敏感 sink：`{sinks[-1]}`")
    return steps


def fallback_root_cause(item: dict[str, Any]) -> str:
    guard = str(item.get("guard_summary") or "").strip()
    permission = item.get("broadcast_permission")
    protection = item.get("permission_protection_level")
    parts = []
    if permission:
        parts.append(f"广播权限为 `{permission}`，保护级别为 `{protection}`。")
    else:
        parts.append("动态注册 receiver 未指定广播发送方权限。")
    if guard:
        parts.append(f"已见 guard：{guard}")
    else:
        parts.append("未见 caller、uid、签名权限或业务态校验。")
    return " ".join(parts)


def fallback_impact(item: dict[str, Any]) -> str:
    operations = item.get("sensitive_operations") or item.get("visited_sinks") or []
    if operations:
        return "外部应用可通过广播触发以下敏感行为：" + "；".join(str(op) for op in operations)
    return "外部应用可通过广播触发 receiver 内部敏感分支，具体影响以 sink 行为为准。"


def fallback_fix_recommendation(item: dict[str, Any]) -> list[str]:
    recommendations = [
        "注册动态 receiver 时指定签名级广播权限，或在 Android 13+ 使用 `Context.RECEIVER_NOT_EXPORTED`。",
        "在命中自定义 action 后校验调用方身份、UID、签名或可信业务态。",
        "对会触发敏感 sink 的分支增加不可由外部伪造的 guard，并避免仅依赖 action 字符串作为授权边界。",
    ]
    if item.get("poc_minimal_extras"):
        recommendations.append("对所有 extras 做完整校验，拒绝缺失、异常或不可信参数。")
    return recommendations


def render_confirmed_detail(item: dict[str, Any], index: int) -> str:
    vuln_blocks = normalize_vuln_code_blocks(item)
    title_suffix = infer_declaring_class(item)
    short_title = title_suffix.split(".")[-1] if isinstance(title_suffix, str) else "unknown"
    custom_actions = item.get("custom_action_list", [])
    sinks = item.get("visited_sinks", [])
    primary_sink = sinks[0] if sinks else "unknown_sink"
    risk_level = str(item.get("severity") or item.get("risk_level") or "HIGH").upper()
    lines = [
        f"## 漏洞 {index}：{short_title} 可被外部广播触发并触达敏感操作",
        "",
        f"- 告警编号: `{item.get('finding_id')}`",
        f"- 风险等级: `{risk_level}`",
        f"- 广播类型: `{item.get('kind')}`",
        f"- 入口类: `{title_suffix}`",
        f"- 自定义 action: `{', '.join(custom_actions) if custom_actions else '<empty>'}`",
        f"- 敏感 sink: `{primary_sink}`",
        f"- 追踪停止原因: `{item.get('trace_stop_reason')}`",
        "",
        "### 漏洞描述",
        *render_text_or_list(item.get("vulnerability_analysis") or item.get("dataflow_trace_summary")),
        "",
        "### 攻击路径",
    ]
    attack_path = item.get("attack_path") or fallback_attack_path(item)
    for step_index, step in enumerate(render_text_or_list(attack_path), start=1):
        step_text = step[2:] if step.startswith("- ") else step
        step_text = re.sub(r"^\s*\d+[\.)]\s*", "", step_text)
        lines.append(f"{step_index}. {step_text}")
    lines.extend([
        "",
        "### 漏洞成因",
        *render_text_or_list(item.get("root_cause") or fallback_root_cause(item)),
        "",
        "### 影响",
        *render_text_or_list(item.get("impact") or fallback_impact(item)),
        "",
        "### Guard / 校验情况",
        *render_text_or_list(item.get("guard_summary")),
        "",
        "### 漏洞代码与证据",
        "",
    ])
    if vuln_blocks:
        for idx, block in enumerate(vuln_blocks, start=1):
            lines.append(f"#### {idx}. {block['title']}")
            lines.append("")
            path_text = str(block.get("path", "")).strip()
            if path_text:
                lines.append("路径：")
                lines.append(f"`{path_text}`")
                lines.append("")
            lines.append("```")
            lines.append(block["code"])
            lines.append("```")
            lines.append("")
    else:
        lines.append("`(未提供漏洞代码)`")
        lines.append("")
    lines.extend(["### PoC", ""])
    if item.get("poc_command"):
        lines.append("```bash")
        lines.append(str(item["poc_command"]))
        lines.append("```")
    else:
        lines.append("`(无 PoC)`")
    lines.extend([
        "",
        "### 复现前提",
        *render_text_or_list(item.get("poc_preconditions")),
        "",
        "### 预期效果",
        *render_text_or_list(item.get("poc_expected_effect")),
        "",
        "### 修复建议",
        *render_text_or_list(item.get("fix_recommendation") or fallback_fix_recommendation(item)),
    ])
    return "\n".join(lines)


def render_coverage_label(key: str) -> str:
    labels = {
        "finding_count": "总 finding 数",
        "dynamic_receiver_count": "已确认动态广播漏洞数",
        "static_receiver_count": "已确认静态广播漏洞数",
        "confirmed_sensitive_count": "最终确认漏洞数",
        "needs_more_evidence_count": "证据不足数量",
        "system_only_after_trace_count": "追溯后仅系统广播数量",
        "incomplete_subagent_analysis_count": "子 agent 分析不完整数量",
        "forced_remediation_count": "强制补分析数量",
        "main_agent_correction_count": "主 agent 修正数量",
        "batch_count": "批次数量",
        "wave_count": "波次数量",
        "manifest_backed_app_count": "Manifest 支撑应用数",
        "source_only_app_count": "纯源码索引应用数",
        "unresolved_finding_count": "未解决 finding 数",
        "completed_audit_count": "实际审计完成数",
        "downgraded_to_needs_more_evidence_count": "降级为证据不足数量",
        "no_sensitive_behavior_found_count": "未发现敏感行为数",
    }
    return labels.get(key, key)


def main() -> None:
    args = parse_args()
    review_dir = Path(args.review_dir).resolve()
    intermediate_dir = review_dir / "intermediate"
    partition_plan = load_json(review_dir / "partition-plan.json", default={"batches": []})

    batch_results: list[dict[str, Any]] = []
    for batch in partition_plan.get("batches", []):
        result_path = intermediate_dir / f"{batch['batch_id']}.json"
        if result_path.exists():
            batch_results.append(load_json(result_path))

    findings: list[dict[str, Any]] = []
    remediation_count = 0
    corrections = 0
    for payload in batch_results:
        for result in payload.get("results", []):
            findings.append(result)
            if result.get("remediation_required"):
                remediation_count += 1
            if result.get("main_agent_correction"):
                corrections += 1

    confirmed = [item for item in findings if item.get("final_subagent_verdict") == "confirmed_sensitive"]
    needs_more = [item for item in findings if item.get("final_subagent_verdict") == "needs_more_evidence"]
    system_only = [item for item in findings if item.get("final_subagent_verdict") == "system-only-after-trace"]
    no_sensitive = [item for item in findings if item.get("final_subagent_verdict") == "no_sensitive_behavior_found"]
    incomplete = [item for item in findings if item.get("final_subagent_verdict") == "incomplete_subagent_analysis"]

    reviewed_payload = {
        "batch_count": len(batch_results),
        "findings": findings,
    }
    write_json(review_dir / "reviewed-findings.json", reviewed_payload)
    write_jsonl(review_dir / "reviewed-findings.jsonl", findings)

    completed_audit_count = len(confirmed) + len(system_only) + len(no_sensitive)
    coverage = {
        "finding_count": len(findings),
        "dynamic_receiver_count": sum(1 for item in confirmed if item.get("kind") == "dynamic_receiver"),
        "static_receiver_count": sum(1 for item in confirmed if item.get("kind") == "static_receiver"),
        "confirmed_sensitive_count": len(confirmed),
        "needs_more_evidence_count": len(needs_more),
        "system_only_after_trace_count": len(system_only),
        "no_sensitive_behavior_found_count": len(no_sensitive),
        "incomplete_subagent_analysis_count": len(incomplete),
        "forced_remediation_count": remediation_count,
        "main_agent_correction_count": corrections,
        "batch_count": len(batch_results),
        "wave_count": partition_plan.get("wave_count", 1 if batch_results else 0),
        "manifest_backed_app_count": sum(1 for item in findings if item.get("app_index_mode") == "manifest_backed"),
        "source_only_app_count": sum(1 for item in findings if item.get("app_index_mode") == "source_only"),
        "unresolved_finding_count": sum(1 for item in findings if item.get("app_index_mode") == "unresolved"),
        "completed_audit_count": completed_audit_count,
        "downgraded_to_needs_more_evidence_count": sum(
            1 for item in needs_more if item.get("attempt_status") == "finalized" and item.get("previous_attempt_id")
        ),
    }
    write_json(review_dir / "coverage-summary.json", coverage)

    lines = [
        "# 动态广播漏洞报告",
        "",
        "## 概览",
        f"- 总 finding 数: {len(findings)}",
        f"- 最终确认漏洞数: {len(confirmed)}",
    ]
    if confirmed:
        lines.append("")
        for idx, item in enumerate(confirmed, start=1):
            lines.append(render_confirmed_detail(item, idx))
            lines.append("")
    lines.extend(["## 覆盖率统计"])
    for key, value in coverage.items():
        lines.append(f"- {render_coverage_label(key)}: {value}")
    (review_dir / "final-review-report.md").write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
