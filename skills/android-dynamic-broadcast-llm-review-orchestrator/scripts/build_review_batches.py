from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

from review_common import (
    best_manifest_path,
    collect_source_roots,
    find_sample_roots,
    load_jsonl,
    render_template,
    resolve_app_for_class,
    slugify,
    write_json,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build fixed 3-batch inputs for broadcast review subagents.")
    parser.add_argument("--findings", required=True, help="Path to dangerous_dynamic_broadcasts.jsonl")
    parser.add_argument("--reverse-root", required=True, help="Path to decompiled source root")
    parser.add_argument("--system-broadcast-file", required=True, help="Path to system/protected broadcast file")
    parser.add_argument("--out-dir", required=True, help="Output review directory")
    parser.add_argument("--trace-max-hops", type=int, default=3)
    parser.add_argument("--onreceive-max-hops", type=int, default=3)
    parser.add_argument("--batch-size", type=int, default=4)
    parser.add_argument(
        "--template",
        default=str(Path(__file__).resolve().parents[1] / "templates" / "subagent-batch-template.md"),
    )
    return parser.parse_args()


def infer_kind(finding: dict[str, Any], index: int) -> str:
    explicit = finding.get("kind")
    if explicit in {"dynamic_receiver", "static_receiver"}:
        return explicit
    if finding.get("declaring_method") == "unknown":
        return "static_receiver"
    return "dynamic_receiver"


def build_app_index(reverse_root: Path) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for app_root in find_sample_roots(reverse_root):
        source_roots = [str(path) for path in collect_source_roots(app_root)]
        manifest_path = best_manifest_path(app_root)
        entries.append(
            {
                "app_id": slugify(app_root.name),
                "app_root": str(app_root),
                "manifest_path": str(manifest_path) if manifest_path else None,
                "package_name": None,
                "candidate_source_roots": source_roots,
                "index_mode": "manifest_backed" if manifest_path else "source_only",
            }
        )
    return entries


def clean_action_list(raw_actions: Any) -> list[str]:
    if not isinstance(raw_actions, list):
        return []
    cleaned: list[str] = []
    for action in raw_actions:
        if not isinstance(action, str):
            continue
        value = action.strip()
        if not value or value == "unknown_action":
            continue
        if value.startswith("<runtime>") or value.startswith("<unknown"):
            continue
        cleaned.append(value)
    return list(dict.fromkeys(cleaned))


def build_items(findings: list[dict[str, Any]], app_entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for index, finding in enumerate(findings, start=1):
        kind = infer_kind(finding, index)
        finding_id = f"finding-{index}"
        app_entry, matched_roots = resolve_app_for_class(app_entries, finding["declaring_class"])
        if app_entry is None:
            if len(app_entries) == 1:
                app_entry = app_entries[0]
                matched_roots = app_entry.get("candidate_source_roots", [])
                app_index_mode = app_entry["index_mode"] if matched_roots else "unresolved"
            else:
                app_index_mode = "unresolved"
        else:
            app_index_mode = app_entry["index_mode"]
        normalized_finding = {**finding, "action_list": clean_action_list(finding.get("action_list", []))}
        items.append(
            {
                **normalized_finding,
                "finding_id": finding_id,
                "kind": kind,
                "resolved_app_root": app_entry["app_root"] if app_entry else None,
                "candidate_source_roots": matched_roots,
                "app_index_mode": app_index_mode,
            }
        )
    return items


def chunked(items: list[dict[str, Any]], batch_size: int) -> list[list[dict[str, Any]]]:
    return [items[idx : idx + batch_size] for idx in range(0, len(items), batch_size)]


def main() -> None:
    args = parse_args()
    findings_path = Path(args.findings).resolve()
    reverse_root = Path(args.reverse_root).resolve()
    out_dir = Path(args.out_dir).resolve()
    intermediate_dir = out_dir / "intermediate"
    intermediate_dir.mkdir(parents=True, exist_ok=True)

    findings = load_jsonl(findings_path)
    app_entries = build_app_index(reverse_root)
    items = build_items(findings, app_entries)
    batches = chunked(items, args.batch_size)
    template_text = Path(args.template).read_text(encoding="utf-8")

    input_summary = {
        "finding_count": len(items),
        "dynamic_receiver_count": sum(1 for item in items if item["kind"] == "dynamic_receiver"),
        "static_receiver_count": sum(1 for item in items if item["kind"] == "static_receiver"),
        "empty_action_list_count": sum(1 for item in items if not item.get("action_list")),
        "non_empty_action_list_count": sum(1 for item in items if item.get("action_list")),
        "normal_permission_count": sum(1 for item in items if item.get("permission_protection_level") == "normal"),
        "unknown_permission_count": sum(1 for item in items if item.get("permission_protection_level") == "unknown"),
    }
    write_json(out_dir / "input-summary.json", input_summary)
    write_json(out_dir / "app-index.json", {"apps": app_entries})

    MAX_CONCURRENT = 5
    partition_batches: list[dict[str, Any]] = []
    for index, batch_items in enumerate(batches, start=1):
        batch_id = f"batch-{index:04d}"
        wave_id = (index - 1) // MAX_CONCURRENT + 1
        kind_partition = {
            "dynamic_receiver_count": sum(1 for item in batch_items if item["kind"] == "dynamic_receiver"),
            "static_receiver_count": sum(1 for item in batch_items if item["kind"] == "static_receiver"),
        }
        batch_payload = {
            "batch_id": batch_id,
            "analysis_scope": "mixed_broadcast_review",
            "kind_partition": kind_partition,
            "items": [
                {
                    "finding_id": item["finding_id"],
                    "kind": item["kind"],
                    "jar_path": item.get("jar_path"),
                    "declaring_class": item.get("declaring_class"),
                    "declaring_method": item.get("declaring_method"),
                    "input_action_list": item.get("action_list", []),
                    "broadcast_permission": item.get("broadcast_permission"),
                    "permission_protection_level": item.get("permission_protection_level"),
                    "resolved_app_root": item.get("resolved_app_root"),
                    "candidate_source_roots": item.get("candidate_source_roots", []),
                    "app_index_mode": item.get("app_index_mode"),
                    "evidence": item.get("evidence"),
                }
                for item in batch_items
            ],
            "resolved_app_root": sorted({item.get("resolved_app_root") for item in batch_items if item.get("resolved_app_root")}),
            "candidate_source_roots": sorted(
                {
                    source_root
                    for item in batch_items
                    for source_root in item.get("candidate_source_roots", [])
                }
            ),
            "system_broadcast_file": str(Path(args.system_broadcast_file).resolve()),
            "trace_max_hops": args.trace_max_hops,
            "onreceive_max_hops": args.onreceive_max_hops,
            "attempt": 1,
        }
        batch_input_path = intermediate_dir / f"{batch_id}-input.json"
        batch_output_json_path = intermediate_dir / f"{batch_id}.json"
        batch_output_md_path = intermediate_dir / f"{batch_id}.md"
        write_json(batch_input_path, batch_payload)

        prompt_text = render_template(
            template_text,
            {
                "batch_id": batch_id,
                "task_type": "TASK_ANALYZE_MIXED_BROADCAST_BATCH",
                "finding_ids": ", ".join(item["finding_id"] for item in batch_items),
                "resolved_app_root": "\n".join(batch_payload["resolved_app_root"]) or "(none)",
                "candidate_source_roots": "\n".join(batch_payload["candidate_source_roots"]) or "(empty)",
                "system_broadcast_file": batch_payload["system_broadcast_file"],
                "output_json_path": str(batch_output_json_path),
                "output_md_path": str(batch_output_md_path),
                "onreceive_max_hops": str(args.onreceive_max_hops),
                "trace_max_hops": str(args.trace_max_hops),
                "batch_input_json_path": str(batch_input_path),
            },
        )
        (intermediate_dir / f"{batch_id}-prompt.md").write_text(prompt_text, encoding="utf-8")

        partition_batches.append(
            {
                "batch_id": batch_id,
                "wave_id": wave_id,
                "finding_ids": [item["finding_id"] for item in batch_items],
                "kind_partition": kind_partition,
                "resolved_app_root": batch_payload["resolved_app_root"],
                "candidate_source_roots": batch_payload["candidate_source_roots"],
                "batch_input_json": str(batch_input_path),
                "batch_prompt_md": str(intermediate_dir / f"{batch_id}-prompt.md"),
            }
        )

    wave_count = max(batch["wave_id"] for batch in partition_batches) if partition_batches else 0
    partition_plan = {
        "total_findings": len(items),
        "batch_count": len(partition_batches),
        "wave_count": wave_count,
        "batches": partition_batches,
    }
    write_json(out_dir / "partition-plan.json", partition_plan)


if __name__ == "__main__":
    main()
