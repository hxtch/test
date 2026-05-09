from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any


SOURCE_DIR_NAMES = (
    "src",
    "sources",
    "java",
    "kotlin",
    "smali",
    "jadx-sources",
    "jadx_sources",
    "decompiled",
)


def load_json(path: Path, default: Any | None = None) -> Any:
    if not path.exists():
        if default is None:
            raise FileNotFoundError(path)
        return default
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if stripped:
            rows.append(json.loads(stripped))
    return rows


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    body = "\n".join(json.dumps(row, ensure_ascii=False) for row in rows)
    path.write_text((body + "\n") if body else "", encoding="utf-8")


def slugify(text: str) -> str:
    lowered = text.strip().lower()
    cleaned = re.sub(r"[^a-z0-9]+", "-", lowered).strip("-")
    return cleaned or "item"


def find_sample_roots(reverse_root: Path) -> list[Path]:
    if has_manifest(reverse_root) or collect_source_roots(reverse_root):
        return [reverse_root]
    roots = [child for child in sorted(reverse_root.iterdir()) if child.is_dir()]
    return roots or [reverse_root]


def has_manifest(app_root: Path) -> bool:
    return any(candidate.is_file() for candidate in app_root.rglob("AndroidManifest.xml"))


def collect_source_roots(app_root: Path) -> list[Path]:
    roots: list[Path] = []
    seen: set[str] = set()
    for candidate in sorted(app_root.rglob("*")):
        if not candidate.is_dir():
            continue
        name = candidate.name
        if not (
            name in SOURCE_DIR_NAMES
            or name.startswith("smali_classes")
        ):
            continue
        if not contains_source_files(candidate):
            continue
        key = str(candidate.resolve())
        if key not in seen:
            roots.append(candidate)
            seen.add(key)
    return minimize_source_roots(roots)


def contains_source_files(path: Path) -> bool:
    for ext in (".java", ".kt", ".smali"):
        if next(path.rglob(f"*{ext}"), None):
            return True
    return False


def minimize_source_roots(roots: list[Path]) -> list[Path]:
    resolved = list(dict.fromkeys(root.resolve() for root in roots))
    kept: list[Path] = []
    for root in resolved:
        if any(other != root and root.is_relative_to(other) for other in resolved):
            continue
        kept.append(root)
    return sorted(kept)


def best_manifest_path(app_root: Path) -> Path | None:
    manifests = [path for path in app_root.rglob("AndroidManifest.xml") if path.is_file()]
    if not manifests:
        return None
    manifests.sort(key=lambda path: (len(path.parts), len(str(path))))
    return manifests[0]


def class_to_relative_paths(class_name: str) -> list[str]:
    dot_to_slash = class_name.replace(".", "/")
    dollar_expanded = dot_to_slash.replace("$", "/")
    paths: list[str] = []
    for stem in dict.fromkeys([dot_to_slash, dollar_expanded]):
        for ext in (".java", ".kt", ".smali"):
            paths.append(f"{stem}{ext}")
    return paths


def resolve_app_for_class(app_entries: list[dict[str, Any]], class_name: str) -> tuple[dict[str, Any] | None, list[str]]:
    rel_candidates = class_to_relative_paths(class_name)
    matched_apps: list[dict[str, Any]] = []
    matched_roots: list[str] = []
    for entry in app_entries:
        entry_hits: list[str] = []
        for root_text in entry.get("candidate_source_roots", []):
            root = Path(root_text)
            for rel_path in rel_candidates:
                if (root / rel_path).exists():
                    entry_hits.append(root_text)
                    break
        if entry_hits:
            matched_apps.append(entry)
            matched_roots.extend(entry_hits)
    if len(matched_apps) == 1:
        unique_roots = sorted(set(matched_roots))
        return matched_apps[0], unique_roots
    return None, []


def render_template(template_text: str, values: dict[str, str]) -> str:
    rendered = template_text
    for key, value in values.items():
        rendered = rendered.replace(f"{{{{{key}}}}}", value)
    return rendered


def ensure_parent(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
