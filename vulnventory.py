#!/usr/bin/env python3
"""
Vulnventory
===========

A lightweight local evidence manager and report assistant.

The tool does not discover findings, write final reports, run scans, or make
security decisions. It helps you keep findings, screenshots, notes, scan output,
captions, and report-ready exports organised while you write the final report
yourself.
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import glob
import hashlib
import json
import os
import re
import shutil
import sys
import zipfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table

    HAS_RICH = True
except ImportError:
    Console = None
    Panel = None
    Table = None
    HAS_RICH = False


console = Console() if HAS_RICH else None
error_console = Console(stderr=True) if HAS_RICH else None


APP_DIR = ".evidence_manager"
EVIDENCE_INDEX = "evidence_index.json"
FINDINGS_INDEX = "findings.json"
ENGAGEMENT_META = "engagement.json"

FOLDERS = [
    "00_scope",
    "01_recon",
    "02_scans",
    "03_evidence",
    "04_notes",
    "05_findings",
    "06_report",
    "99_archive",
]

VALID_EVIDENCE_TYPES = {
    "screenshot",
    "scan",
    "note",
    "exploit-output",
    "config",
    "credential-evidence",
    "other",
}

VALID_SEVERITIES = ["Critical", "High", "Medium", "Low", "Informational"]
TEXT_EVIDENCE_TYPES = {"scan", "note", "exploit-output", "config"}


@dataclass
class EvidenceItem:
    evidence_id: str
    original_path: str
    stored_path: str
    file_name: str
    evidence_type: str
    finding_id: str
    host: str
    description: str
    sha256: str
    size_bytes: int
    imported_at: str
    extracted_summary: str = ""


@dataclass
class Finding:
    finding_id: str
    title: str
    severity: str
    affected: str
    summary: str
    impact: str
    likelihood: str
    recommendation: str
    status: str
    created_at: str
    updated_at: str


class EvidenceManagerError(Exception):
    pass


def print_success(message: str) -> None:
    if HAS_RICH:
        console.print(f"[green][+][/green] {message}")
    else:
        print(f"[+] {message}")


def print_warning(message: str) -> None:
    if HAS_RICH:
        console.print(f"[yellow][!][/yellow] {message}")
    else:
        print(f"[!] {message}")


def print_error(message: str) -> None:
    if HAS_RICH:
        error_console.print(f"[red][-][/red] {message}")
    else:
        print(f"[-] {message}", file=sys.stderr)


def print_info(message: str) -> None:
    if HAS_RICH:
        console.print(message)
    else:
        print(message)


def print_panel(title: str, message: str, style: str = "cyan") -> None:
    if HAS_RICH:
        console.print(Panel(message, title=title, border_style=style))
    else:
        print(f"{title}\n{message}")


def print_table(title: str, columns: List[str], rows: List[List[Any]]) -> None:
    if HAS_RICH:
        table = Table(title=title, show_lines=False)
        for column in columns:
            table.add_column(column)
        for row in rows:
            table.add_row(*(str(value) for value in row))
        console.print(table)
        return

    print(f"{title}\n")
    print(" | ".join(columns))
    print(" | ".join("---" for _ in columns))
    for row in rows:
        print(" | ".join(str(value) for value in row))


def now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).astimezone().isoformat(timespec="seconds")


def safe_slug(value: str, fallback: str = "item", max_len: int = 90) -> str:
    value = value.strip()
    value = re.sub(r"[^A-Za-z0-9._-]+", "_", value)
    value = re.sub(r"_+", "_", value).strip("._-")
    value = value[:max_len].strip("._-")
    return value or fallback


def engagement_path(path_arg: str) -> Path:
    return Path(path_arg).expanduser().resolve()


def app_path(root: Path) -> Path:
    return root / APP_DIR


def evidence_index_path(root: Path) -> Path:
    return app_path(root) / EVIDENCE_INDEX


def findings_index_path(root: Path) -> Path:
    return app_path(root) / FINDINGS_INDEX


def engagement_meta_path(root: Path) -> Path:
    return app_path(root) / ENGAGEMENT_META


def ensure_engagement(root: Path) -> None:
    if not root.exists():
        raise EvidenceManagerError(f"Engagement path does not exist: {root}")
    if not app_path(root).exists():
        raise EvidenceManagerError(
            f"This does not look like an evidence-manager engagement: {root}\n"
            f"Missing {APP_DIR}. Run the init command first."
        )


def read_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    try:
        with path.open("r", encoding="utf-8") as f:
            return json.load(f)
    except json.JSONDecodeError as exc:
        raise EvidenceManagerError(f"Invalid JSON file: {path}: {exc}") from exc


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
        f.write("\n")


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def load_evidence(root: Path) -> List[Dict[str, Any]]:
    return read_json(evidence_index_path(root), [])


def save_evidence(root: Path, items: List[Dict[str, Any]]) -> None:
    write_json(evidence_index_path(root), items)


def load_findings(root: Path) -> List[Dict[str, Any]]:
    return read_json(findings_index_path(root), [])


def save_findings(root: Path, items: List[Dict[str, Any]]) -> None:
    write_json(findings_index_path(root), items)


def load_meta(root: Path) -> Dict[str, Any]:
    return read_json(engagement_meta_path(root), {"name": root.name})


def save_meta(root: Path, meta: Dict[str, Any]) -> None:
    write_json(engagement_meta_path(root), meta)


def find_finding(root: Path, finding_id: str) -> Optional[Dict[str, Any]]:
    wanted = finding_id.lower()
    for finding in load_findings(root):
        if finding.get("finding_id", "").lower() == wanted:
            return finding
    return None


def find_evidence(items: List[Dict[str, Any]], evidence_id: str) -> Optional[Dict[str, Any]]:
    wanted = evidence_id.lower()
    for item in items:
        if item.get("evidence_id", "").lower() == wanted:
            return item
    return None


def stored_evidence_path(root: Path, item: Dict[str, Any]) -> Path:
    stored_path = item.get("stored_path", "").strip()
    if not stored_path:
        raise EvidenceManagerError(f"Evidence has no stored file path: {item.get('evidence_id', '')}")
    path = Path(stored_path)
    if path.is_absolute():
        resolved = path.resolve()
    else:
        resolved = (root / path).resolve()
    try:
        resolved.relative_to(root.resolve())
    except ValueError as exc:
        raise EvidenceManagerError(
            f"Refusing to delete stored file outside the engagement folder: {resolved}"
        ) from exc
    return resolved


def next_evidence_id(existing: List[Dict[str, Any]]) -> str:
    max_num = 0
    for item in existing:
        match = re.match(r"^E-(\d+)$", item.get("evidence_id", ""))
        if match:
            max_num = max(max_num, int(match.group(1)))
    return f"E-{max_num + 1:04d}"


def normalise_severity(value: str) -> str:
    lookup = {severity.lower(): severity for severity in VALID_SEVERITIES}
    lookup["info"] = "Informational"
    normalised = lookup.get(value.strip().lower())
    if not normalised:
        raise EvidenceManagerError(
            f"Invalid severity: {value}\n"
            f"Valid severities: {', '.join(VALID_SEVERITIES)}"
        )
    return normalised


def severity_sort_key(finding: Dict[str, Any]) -> int:
    order = {severity: idx for idx, severity in enumerate(VALID_SEVERITIES)}
    return order.get(finding.get("severity", "Informational"), 999)


def ordered_findings(root: Path) -> List[Dict[str, Any]]:
    return sorted(load_findings(root), key=lambda f: (severity_sort_key(f), f.get("finding_id", "")))


def evidence_for_finding(root: Path, finding_id: str) -> List[Dict[str, Any]]:
    wanted = finding_id.lower()
    return [item for item in load_evidence(root) if item.get("finding_id", "").lower() == wanted]


def screenshots_for_finding(root: Path, finding_id: str) -> List[Dict[str, Any]]:
    return [
        item for item in evidence_for_finding(root, finding_id)
        if item.get("evidence_type") == "screenshot"
    ]


def markdown_escape(value: Any) -> str:
    return str(value).replace("|", "\\|").strip()


def markdown_image_path(value: str, prefix: str = "..") -> str:
    value = value.replace("\\", "/").strip()
    if not prefix:
        return value
    return f"{prefix.rstrip('/')}/{value.lstrip('/')}"


def markdown_file_reference(value: str) -> str:
    return value.replace("\\", "/").strip()


def markdown_alt_text(value: str) -> str:
    return value.replace("\n", " ").replace("]", ")").strip()


def evidence_caption(item: Dict[str, Any]) -> str:
    return (
        item.get("description", "").strip()
        or item.get("file_name", "").strip()
        or item.get("evidence_id", "").strip()
        or "Screenshot evidence"
    )


def missing_fields(finding: Dict[str, Any]) -> List[str]:
    required = ["summary", "impact", "likelihood", "recommendation"]
    return [field for field in required if not finding.get(field, "").strip()]


def create_engagement_readme(root: Path, name: str) -> None:
    readme = root / "README.md"
    if readme.exists():
        return
    readme.write_text(
        "\n".join([
            f"# {name}",
            "",
            "Local penetration testing evidence workspace.",
            "",
            "Suggested flow:",
            "",
            "1. Put scope files in `00_scope/`.",
            "2. Save your normal screenshot folder with `set-inbox`.",
            "3. Add findings with `add-finding`.",
            "4. Import screenshots with `import-new`, or import specific files with `import`.",
            "5. Improve screenshot captions with `caption-evidence`.",
            "6. Run `missing` before writing the report.",
            "7. Run `build-brief`, `export-figures`, or `package-report`.",
            "",
        ]),
        encoding="utf-8",
    )


def cmd_init(args: argparse.Namespace) -> None:
    root = engagement_path(args.name)
    if root.exists() and any(root.iterdir()) and not args.force:
        raise EvidenceManagerError(
            f"Directory already exists and is not empty: {root}\n"
            "Use --force if you intentionally want to initialise inside it."
        )

    root.mkdir(parents=True, exist_ok=True)
    for folder in FOLDERS:
        (root / folder).mkdir(parents=True, exist_ok=True)

    if not evidence_index_path(root).exists():
        save_evidence(root, [])
    if not findings_index_path(root).exists():
        save_findings(root, [])
    if not engagement_meta_path(root).exists():
        save_meta(root, {
            "name": root.name,
            "created_at": now_iso(),
            "scope": {
                "in_scope": "",
                "out_of_scope": "",
                "rules": "",
                "objectives": "",
                "window": "",
                "tester": "",
            },
            "inbox": {
                "screenshots": "",
            },
        })

    create_engagement_readme(root, root.name)
    print_success(f"Created engagement workspace: {root}")
    print_success("Next step: add a finding or import evidence.")


def detect_destination_folder(root: Path, evidence_type: str, finding_id: str, host: str) -> Path:
    finding = safe_slug(finding_id, "UNASSIGNED")
    host_slug = safe_slug(host, "unknown")
    if evidence_type == "scan":
        return root / "02_scans" / finding / host_slug
    if evidence_type == "note":
        return root / "04_notes" / finding / host_slug
    return root / "03_evidence" / finding / host_slug


def extract_nmap_summary(text: str) -> str:
    hosts: List[str] = []
    open_ports: List[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("Nmap scan report for "):
            hosts.append(stripped.replace("Nmap scan report for ", "", 1))
        if re.match(r"^\d+/(tcp|udp)\s+open\s+", stripped):
            open_ports.append(stripped)
    parts: List[str] = []
    if hosts:
        parts.append("Hosts observed:\n" + "\n".join(f"- {host}" for host in hosts[:20]))
    if open_ports:
        parts.append("Open services:\n" + "\n".join(f"- {port}" for port in open_ports[:80]))
    return "\n\n".join(parts)


def extract_ffuf_summary(text: str) -> str:
    hits = []
    for line in text.splitlines():
        if "Status:" in line and "Size:" in line:
            hits.append(line.strip())
    if not hits:
        return ""
    return "FFUF-style hits:\n" + "\n".join(f"- {hit}" for hit in hits[:80])


def extract_basic_summary(path: Path, evidence_type: str) -> str:
    if evidence_type not in TEXT_EVIDENCE_TYPES:
        return ""
    try:
        raw = path.read_bytes()[:512_000]
        text = raw.decode("utf-8", errors="replace")
    except OSError:
        return ""

    lowered = path.name.lower()
    if "nmap" in lowered:
        summary = extract_nmap_summary(text)
        if summary:
            return summary
    if "ffuf" in lowered:
        summary = extract_ffuf_summary(text)
        if summary:
            return summary

    preview = "\n".join(text.splitlines()[:40]).strip()
    return f"Text preview:\n{preview}" if preview else ""


def has_glob_pattern(value: str) -> bool:
    return any(char in value for char in "*?[")


def expand_import_sources(file_args: Iterable[str], recursive: bool = False) -> List[Path]:
    sources: List[Path] = []
    seen = set()

    def add_file(path: Path) -> None:
        resolved = path.expanduser().resolve()
        if not resolved.exists() or not resolved.is_file():
            print_warning(f"Skipping missing/non-file path: {resolved}")
            return
        key = str(resolved).lower()
        if key in seen:
            return
        seen.add(key)
        sources.append(resolved)

    for file_arg in file_args:
        expanded = os.path.expanduser(file_arg)
        if has_glob_pattern(expanded):
            matches = sorted(Path(match) for match in glob.glob(expanded, recursive=recursive))
            if not matches:
                print_warning(f"No files matched pattern: {file_arg}")
            for match in matches:
                add_file(match)
            continue

        src = Path(expanded)
        if src.exists() and src.is_dir():
            pattern = "**/*" if recursive else "*"
            for child in sorted(p for p in src.glob(pattern) if p.is_file()):
                add_file(child)
            continue

        add_file(src)

    return sources


def cmd_import(args: argparse.Namespace) -> None:
    root = engagement_path(args.engagement)
    ensure_engagement(root)

    imported = import_sources(
        root=root,
        sources=expand_import_sources(args.files, recursive=args.recursive),
        evidence_type=args.type,
        finding_id=args.finding,
        host=args.host,
        description=args.description,
    )

    if not imported:
        print_warning("No evidence imported.")
        return
    for item in imported:
        print_success(f"Imported {item['evidence_id']}: {item['stored_path']}")


def import_sources(
    root: Path,
    sources: List[Path],
    evidence_type: str,
    finding_id: str,
    host: str,
    description: str = "",
) -> List[Dict[str, Any]]:
    evidence_type = evidence_type.strip().lower()
    if evidence_type not in VALID_EVIDENCE_TYPES:
        raise EvidenceManagerError(
            f"Invalid evidence type: {evidence_type}\n"
            f"Valid types: {', '.join(sorted(VALID_EVIDENCE_TYPES))}"
        )

    if finding_id != "UNASSIGNED" and find_finding(root, finding_id) is None:
        print_warning(f"Finding {finding_id} does not exist yet. Evidence will still be imported.")

    items = load_evidence(root)
    imported: List[Dict[str, Any]] = []

    for src in sources:
        evidence_id = next_evidence_id(items)
        timestamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
        dest_dir = detect_destination_folder(root, evidence_type, finding_id, host)
        dest_dir.mkdir(parents=True, exist_ok=True)
        stored_name = "_".join([
            evidence_id,
            timestamp,
            safe_slug(finding_id, "UNASSIGNED"),
            safe_slug(host, "unknown"),
            safe_slug(src.name, "evidence"),
        ])
        dest = dest_dir / stored_name
        shutil.copy2(src, dest)

        item_description = description.strip()
        if not item_description and evidence_type == "screenshot":
            item_description = src.stem.replace("_", " ").replace("-", " ").strip()

        item = EvidenceItem(
            evidence_id=evidence_id,
            original_path=str(src),
            stored_path=str(dest.relative_to(root)),
            file_name=src.name,
            evidence_type=evidence_type,
            finding_id=finding_id,
            host=host,
            description=item_description,
            sha256=sha256_file(dest),
            size_bytes=dest.stat().st_size,
            imported_at=now_iso(),
            extracted_summary=extract_basic_summary(dest, evidence_type),
        )
        item_dict = asdict(item)
        items.append(item_dict)
        imported.append(item_dict)

    save_evidence(root, items)
    return imported


def cmd_add_finding(args: argparse.Namespace) -> None:
    root = engagement_path(args.engagement)
    ensure_engagement(root)

    severity = normalise_severity(args.severity)
    findings = load_findings(root)
    existing = None
    for idx, item in enumerate(findings):
        if item.get("finding_id", "").lower() == args.id.lower():
            existing = idx
            break

    if existing is not None and not args.update:
        raise EvidenceManagerError(f"Finding already exists: {args.id}\nUse --update to replace/update it.")

    created_at = findings[existing].get("created_at", now_iso()) if existing is not None else now_iso()
    finding = Finding(
        finding_id=args.id,
        title=args.title,
        severity=severity,
        affected=args.affected,
        summary=args.summary,
        impact=args.impact,
        likelihood=args.likelihood,
        recommendation=args.recommendation,
        status=args.status,
        created_at=created_at,
        updated_at=now_iso(),
    )

    if existing is None:
        findings.append(asdict(finding))
        action = "Added"
    else:
        findings[existing] = asdict(finding)
        action = "Updated"
    save_findings(root, findings)
    print_success(f"{action} finding {args.id}: {args.title}")


def cmd_set_scope(args: argparse.Namespace) -> None:
    root = engagement_path(args.engagement)
    ensure_engagement(root)

    meta = load_meta(root)
    scope = meta.setdefault("scope", {})
    for key in ["in_scope", "out_of_scope", "rules", "objectives", "window", "tester"]:
        value = getattr(args, key)
        if value is not None:
            scope[key] = value
    meta["updated_at"] = now_iso()
    save_meta(root, meta)
    print_success(f"Updated scope metadata for {root.name}")


def cmd_set_inbox(args: argparse.Namespace) -> None:
    root = engagement_path(args.engagement)
    ensure_engagement(root)

    screenshot_path = Path(args.screenshots).expanduser().resolve()
    if not screenshot_path.exists() or not screenshot_path.is_dir():
        raise EvidenceManagerError(f"Screenshot inbox folder does not exist: {screenshot_path}")

    meta = load_meta(root)
    inbox = meta.setdefault("inbox", {})
    inbox["screenshots"] = str(screenshot_path)
    meta["updated_at"] = now_iso()
    save_meta(root, meta)
    print_success(f"Saved screenshot inbox: {screenshot_path}")


SCREENSHOT_EXTENSIONS = {".png", ".jpg", ".jpeg", ".bmp", ".gif", ".webp"}


def imported_original_paths(root: Path) -> set[str]:
    paths = set()
    for item in load_evidence(root):
        original_path = item.get("original_path", "")
        if not original_path:
            continue
        try:
            paths.add(str(Path(original_path).expanduser().resolve()).lower())
        except OSError:
            paths.add(original_path.lower())
    return paths


def newest_screenshots(
    inbox: Path,
    count: int,
    root: Path,
    since_minutes: Optional[int] = None,
    include_imported: bool = False,
) -> List[Path]:
    if count < 1:
        raise EvidenceManagerError("--count must be 1 or greater")
    if not inbox.exists() or not inbox.is_dir():
        raise EvidenceManagerError(f"Screenshot inbox folder does not exist: {inbox}")

    cutoff = None
    if since_minutes is not None:
        if since_minutes < 1:
            raise EvidenceManagerError("--since-minutes must be 1 or greater")
        cutoff = dt.datetime.now().timestamp() - (since_minutes * 60)

    already_imported = imported_original_paths(root) if not include_imported else set()
    candidates = []
    for path in inbox.iterdir():
        if not path.is_file() or path.suffix.lower() not in SCREENSHOT_EXTENSIONS:
            continue
        resolved_key = str(path.resolve()).lower()
        if resolved_key in already_imported:
            continue
        modified = path.stat().st_mtime
        if cutoff is not None and modified < cutoff:
            continue
        candidates.append(path)

    candidates.sort(key=lambda p: (p.stat().st_mtime, p.name.lower()), reverse=True)
    return candidates[:count]


def cmd_import_new(args: argparse.Namespace) -> None:
    root = engagement_path(args.engagement)
    ensure_engagement(root)

    meta = load_meta(root)
    inbox_path = args.path or meta.get("inbox", {}).get("screenshots", "")
    if not inbox_path:
        raise EvidenceManagerError(
            "No screenshot inbox configured. Run set-inbox first or pass --path."
        )

    inbox = Path(inbox_path).expanduser().resolve()
    sources = newest_screenshots(
        inbox=inbox,
        count=args.count,
        root=root,
        since_minutes=args.since_minutes,
        include_imported=args.include_imported,
    )
    if not sources:
        print_warning("No new screenshots found in the inbox.")
        return

    imported = import_sources(
        root=root,
        sources=sources,
        evidence_type="screenshot",
        finding_id=args.finding,
        host=args.host,
        description=args.description,
    )
    for item in imported:
        print_success(f"Imported {item['evidence_id']}: {item['stored_path']}")


def cmd_list_findings(args: argparse.Namespace) -> None:
    root = engagement_path(args.engagement)
    ensure_engagement(root)
    findings = ordered_findings(root)
    if not findings:
        print_warning("No findings yet.")
        return
    rows = []
    for finding in findings:
        missing = missing_fields(finding)
        rows.append([
            finding.get("finding_id", ""),
            finding.get("severity", ""),
            finding.get("title", ""),
            finding.get("affected", ""),
            finding.get("status", ""),
            ", ".join(missing) if missing else "none",
        ])
    print_table(
        f"Findings for {root.name}",
        ["ID", "Severity", "Title", "Affected", "Status", "Missing"],
        rows,
    )


def cmd_list_evidence(args: argparse.Namespace) -> None:
    root = engagement_path(args.engagement)
    ensure_engagement(root)

    items = load_evidence(root)
    if args.finding:
        items = [item for item in items if item.get("finding_id", "").lower() == args.finding.lower()]
    if args.host:
        items = [item for item in items if item.get("host", "").lower() == args.host.lower()]
    if args.type:
        items = [item for item in items if item.get("evidence_type", "").lower() == args.type.lower()]

    if not items:
        print_warning("No evidence found.")
        return
    rows = []
    for item in items:
        rows.append([
            item.get("evidence_id", ""),
            item.get("evidence_type", ""),
            item.get("finding_id", ""),
            item.get("host", ""),
            evidence_caption(item),
            item.get("stored_path", ""),
        ])
    print_table(
        f"Evidence for {root.name}",
        ["ID", "Type", "Finding", "Host", "Caption", "File"],
        rows,
    )


def cmd_caption_evidence(args: argparse.Namespace) -> None:
    root = engagement_path(args.engagement)
    ensure_engagement(root)

    items = load_evidence(root)
    item = find_evidence(items, args.evidence_id)
    if not item:
        raise EvidenceManagerError(f"Evidence not found: {args.evidence_id}")

    if args.caption is not None:
        item["description"] = args.caption
    if args.finding is not None:
        item["finding_id"] = args.finding
    if args.host is not None:
        item["host"] = args.host
    item["updated_at"] = now_iso()
    save_evidence(root, items)
    print_success(f"Updated {item.get('evidence_id')}: {evidence_caption(item)}")


def delete_evidence_items(
    root: Path,
    items: List[Dict[str, Any]],
    evidence_ids: Iterable[str],
    delete_files: bool = False,
) -> List[Dict[str, Any]]:
    wanted = {evidence_id.lower() for evidence_id in evidence_ids}
    remaining: List[Dict[str, Any]] = []
    deleted: List[Dict[str, Any]] = []

    for item in items:
        if item.get("evidence_id", "").lower() in wanted:
            deleted.append(item)
        else:
            remaining.append(item)

    found = {item.get("evidence_id", "").lower() for item in deleted}
    missing = sorted(wanted - found)
    if missing:
        raise EvidenceManagerError(f"Evidence not found: {', '.join(missing)}")

    if delete_files:
        for item in deleted:
            path = stored_evidence_path(root, item)
            if path.exists():
                path.unlink()
                print_success(f"Deleted file for {item.get('evidence_id')}: {path}")
            else:
                print_warning(f"Stored file already missing for {item.get('evidence_id')}: {path}")

    return remaining


def cmd_delete_evidence(args: argparse.Namespace) -> None:
    root = engagement_path(args.engagement)
    ensure_engagement(root)

    items = load_evidence(root)
    remaining = delete_evidence_items(root, items, args.evidence_ids, delete_files=args.delete_file)
    save_evidence(root, remaining)

    action = "Deleted evidence and stored file" if args.delete_file else "Deleted evidence index entry"
    for evidence_id in args.evidence_ids:
        print_success(f"{action}: {evidence_id}")


def cmd_delete_finding(args: argparse.Namespace) -> None:
    root = engagement_path(args.engagement)
    ensure_engagement(root)

    if args.delete_files and not args.delete_evidence:
        raise EvidenceManagerError("--delete-files can only be used with --delete-evidence")

    wanted = args.finding_id.lower()
    findings = load_findings(root)
    finding = next((item for item in findings if item.get("finding_id", "").lower() == wanted), None)
    if not finding:
        raise EvidenceManagerError(f"Finding not found: {args.finding_id}")

    evidence_items = load_evidence(root)
    linked = [item for item in evidence_items if item.get("finding_id", "").lower() == wanted]
    if linked and not args.delete_evidence:
        linked_ids = ", ".join(item.get("evidence_id", "") for item in linked)
        raise EvidenceManagerError(
            f"Finding {args.finding_id} still has linked evidence: {linked_ids}\n"
            "Delete the linked evidence first, or use --delete-evidence to remove it with the finding."
        )

    if args.delete_evidence:
        remaining = delete_evidence_items(
            root,
            evidence_items,
            [item.get("evidence_id", "") for item in linked],
            delete_files=args.delete_files,
        )
        save_evidence(root, remaining)
        if linked:
            print_success(f"Deleted {len(linked)} evidence item(s) linked to {args.finding_id}.")

    findings = [item for item in findings if item.get("finding_id", "").lower() != wanted]
    save_findings(root, findings)
    print_success(f"Deleted finding {finding.get('finding_id')}: {finding.get('title', '')}")


def render_evidence_table(items: List[Dict[str, Any]]) -> List[str]:
    lines = [
        "| Evidence ID | Type | Host | Caption |",
        "|---|---|---|---|",
    ]
    for item in items:
        lines.append(
            "| "
            + " | ".join([
                markdown_escape(item.get("evidence_id", "")),
                markdown_escape(item.get("evidence_type", "")),
                markdown_escape(item.get("host", "")),
                markdown_escape(evidence_caption(item)),
            ])
            + " |"
        )
    return lines


def build_figure_plan(root: Path, finding_filter: Optional[str] = None) -> List[Dict[str, Any]]:
    figures: List[Dict[str, Any]] = []
    figure_number = 1
    for finding in ordered_findings(root):
        finding_id = finding.get("finding_id", "")
        if finding_filter and finding_id.lower() != finding_filter.lower():
            continue
        screenshots = sorted(
            screenshots_for_finding(root, finding_id),
            key=lambda item: (item.get("imported_at", ""), item.get("evidence_id", "")),
        )
        for item in screenshots:
            figures.append({
                "number": figure_number,
                "finding_id": finding_id,
                "finding_title": finding.get("title", ""),
                "caption": evidence_caption(item),
                "evidence": item,
            })
            figure_number += 1
    return figures


def render_finding_brief(
    root: Path,
    finding: Dict[str, Any],
    figures: List[Dict[str, Any]],
    asset_prefix: str = "..",
    figure_path_map: Optional[Dict[str, str]] = None,
) -> str:
    finding_id = finding.get("finding_id", "")
    items = evidence_for_finding(root, finding_id)
    lines = [
        f"## {finding_id} - {finding.get('title', '')}",
        "",
        f"**Severity:** {finding.get('severity', '')}",
        "",
        f"**Affected:** {finding.get('affected', '')}",
        "",
        "### Current Finding Text",
        "",
        "**Summary:**",
        "",
        finding.get("summary", "").strip() or "TBC.",
        "",
        "**Impact:**",
        "",
        finding.get("impact", "").strip() or "TBC.",
        "",
        "**Likelihood:**",
        "",
        finding.get("likelihood", "").strip() or "TBC.",
        "",
        "**Recommendation:**",
        "",
        finding.get("recommendation", "").strip() or "TBC.",
        "",
    ]

    missing = missing_fields(finding)
    if missing:
        lines.extend([
            "### Missing Items",
            "",
            *[f"- {field}" for field in missing],
            "",
        ])

    lines.extend([
        "### Related Evidence",
        "",
    ])
    if items:
        lines.extend(render_evidence_table(items))
        lines.extend([
            "",
            "#### Evidence File References",
            "",
        ])
        for item in items:
            lines.append(f"- **{item.get('evidence_id')}**: {markdown_file_reference(item.get('stored_path', ''))}")
        lines.append("")
    else:
        lines.extend(["No evidence linked to this finding yet.", ""])

    finding_figures = [figure for figure in figures if figure["finding_id"].lower() == finding_id.lower()]
    if finding_figures:
        lines.extend([
            "### Figures",
            "",
        ])
        for figure in finding_figures:
            item = figure["evidence"]
            figure_id = f"Figure {figure['number']} ({finding_id})"
            image_path = None
            if figure_path_map:
                image_path = figure_path_map.get(item.get("evidence_id", ""))
            if not image_path:
                image_path = markdown_image_path(item.get("stored_path", ""), asset_prefix)
            lines.extend([
                f"**{figure_id}: {figure['caption']}**",
                "",
                f"![{markdown_alt_text(figure_id + ': ' + figure['caption'])}]({image_path})",
                "",
            ])

    extracted = [item for item in items if item.get("extracted_summary")]
    if extracted:
        lines.extend([
            "### Extracted Text Summaries",
            "",
        ])
        for item in extracted:
            lines.extend([
                f"**{item.get('evidence_id')} - {item.get('file_name')}**",
                "",
                "```text",
                item.get("extracted_summary", "").strip(),
                "```",
                "",
            ])

    return "\n".join(lines)


def render_missing_section(root: Path) -> List[str]:
    lines = ["## Missing / Ready Checklist", ""]
    findings = ordered_findings(root)
    if not findings:
        return lines + ["No findings have been added yet.", ""]
    for finding in findings:
        finding_id = finding.get("finding_id", "")
        missing = missing_fields(finding)
        evidence_count = len(evidence_for_finding(root, finding_id))
        screenshot_count = len(screenshots_for_finding(root, finding_id))
        ready = not missing and evidence_count > 0
        lines.append(f"### {finding_id} - {finding.get('title', '')}")
        lines.append("")
        lines.append(f"- Ready for report writing: {'yes' if ready else 'no'}")
        lines.append(f"- Evidence items: {evidence_count}")
        lines.append(f"- Screenshots: {screenshot_count}")
        if missing:
            lines.append(f"- Missing fields: {', '.join(missing)}")
        else:
            lines.append("- Missing fields: none")
        lines.append("")
    return lines


def render_scope_section(meta: Dict[str, Any]) -> List[str]:
    scope = meta.get("scope", {})
    return [
        "## Scope Notes",
        "",
        f"**In scope:** {scope.get('in_scope') or 'TBC'}",
        "",
        f"**Out of scope:** {scope.get('out_of_scope') or 'TBC'}",
        "",
        f"**Rules / constraints:** {scope.get('rules') or 'TBC'}",
        "",
        f"**Objectives:** {scope.get('objectives') or 'TBC'}",
        "",
        f"**Assessment window:** {scope.get('window') or 'TBC'}",
        "",
        f"**Tester:** {scope.get('tester') or 'TBC'}",
        "",
    ]


def render_brief(
    root: Path,
    asset_prefix: str = "..",
    figure_path_map: Optional[Dict[str, str]] = None,
) -> str:
    meta = load_meta(root)
    findings = ordered_findings(root)
    figures = build_figure_plan(root)
    evidence_items = load_evidence(root)

    lines = [
        f"# Report Writing Brief - {meta.get('name', root.name)}",
        "",
        f"Generated: {now_iso()}",
        "",
        "This is not a final client report. Use it as a writing pack while preparing the final report in Word, RStudio, or another editor.",
        "",
        "## How To Use This Brief",
        "",
        "- Use the checklist to see what is missing before writing.",
        "- Use the figure labels and exported figures in your report.",
        "- Keep evidence IDs with screenshots while drafting.",
        "- Rewrite the final report manually using the evidence below.",
        "",
    ]
    lines.extend(render_scope_section(meta))
    lines.extend(render_missing_section(root))

    lines.extend([
        "## Findings Summary",
        "",
    ])
    if findings:
        lines.extend([
            "| ID | Severity | Finding | Affected | Evidence | Screenshots |",
            "|---|---|---|---|---:|---:|",
        ])
        for finding in findings:
            finding_id = finding.get("finding_id", "")
            lines.append(
                "| "
                + " | ".join([
                    markdown_escape(finding_id),
                    markdown_escape(finding.get("severity", "")),
                    markdown_escape(finding.get("title", "")),
                    markdown_escape(finding.get("affected", "")),
                    str(len(evidence_for_finding(root, finding_id))),
                    str(len(screenshots_for_finding(root, finding_id))),
                ])
                + " |"
            )
        lines.append("")
    else:
        lines.extend(["No findings have been added yet.", ""])

    lines.extend([
        "## Finding Briefs",
        "",
    ])
    for finding in findings:
        lines.append(render_finding_brief(root, finding, figures, asset_prefix, figure_path_map))
        lines.append("\n---\n")

    lines.extend([
        "## Evidence Inventory",
        "",
    ])
    if evidence_items:
        lines.extend(render_evidence_table(evidence_items))
        lines.extend([
            "",
            "### Evidence File References",
            "",
        ])
        for item in evidence_items:
            lines.append(f"- **{item.get('evidence_id')}** ({item.get('finding_id')}): {markdown_file_reference(item.get('stored_path', ''))}")
        lines.append("")
    else:
        lines.extend(["No evidence has been imported yet.", ""])

    return "\n".join(lines)


def cmd_draft(args: argparse.Namespace) -> None:
    root = engagement_path(args.engagement)
    ensure_engagement(root)

    finding = find_finding(root, args.finding)
    if not finding:
        raise EvidenceManagerError(f"Finding not found: {args.finding}")

    out_dir = root / "05_findings"
    out_dir.mkdir(parents=True, exist_ok=True)
    figures = build_figure_plan(root, args.finding)
    out_path = out_dir / f"{safe_slug(finding['finding_id'])}_{safe_slug(finding['title'])}_brief.md"
    out_path.write_text(render_finding_brief(root, finding, figures), encoding="utf-8")
    print_success(f"Wrote finding brief: {out_path}")


def cmd_build_brief(args: argparse.Namespace) -> None:
    root = engagement_path(args.engagement)
    ensure_engagement(root)
    out_dir = root / "06_report"
    out_dir.mkdir(parents=True, exist_ok=True)
    output = args.output or "report_brief.md"
    out_path = out_dir / output
    out_path.write_text(render_brief(root), encoding="utf-8")
    print_success(f"Wrote report brief: {out_path}")


def cmd_build_report(args: argparse.Namespace) -> None:
    print_warning("build-report is now a compatibility alias for build-brief.")
    cmd_build_brief(args)


def cmd_missing(args: argparse.Namespace) -> None:
    root = engagement_path(args.engagement)
    ensure_engagement(root)
    findings = ordered_findings(root)
    if not findings:
        print_warning("No findings have been added yet.")
        return
    rows = []
    for finding in findings:
        finding_id = finding.get("finding_id", "")
        missing = missing_fields(finding)
        evidence_count = len(evidence_for_finding(root, finding_id))
        screenshot_count = len(screenshots_for_finding(root, finding_id))
        ready = "yes" if not missing and evidence_count > 0 else "no"
        rows.append([
            finding_id,
            finding.get("title", ""),
            ready,
            evidence_count,
            screenshot_count,
            ", ".join(missing) if missing else "none",
        ])
    print_table(
        f"Missing / Ready Checklist for {root.name}",
        ["ID", "Finding", "Ready", "Evidence", "Screenshots", "Missing"],
        rows,
    )


def export_figure_files(root: Path, out_dir: Path, finding: Optional[str] = None) -> Dict[str, str]:
    out_dir.mkdir(parents=True, exist_ok=True)
    mapping: Dict[str, str] = {}
    for figure in build_figure_plan(root, finding):
        item = figure["evidence"]
        source = root / item.get("stored_path", "")
        if not source.exists():
            print_warning(f"Missing screenshot file for {item.get('evidence_id')}: {source}")
            continue
        suffix = source.suffix or ".png"
        base_name = "_".join([
            f"Figure_{figure['number']:02d}",
            safe_slug(figure["finding_id"], "UNASSIGNED", 24),
            safe_slug(item.get("evidence_id", ""), "evidence", 16),
            safe_slug(figure["caption"], "screenshot", 70),
        ])
        dest = out_dir / f"{base_name}{suffix}"
        shutil.copy2(source, dest)
        mapping[item.get("evidence_id", "")] = dest.name
        print_success(f"Figure {figure['number']}: {dest}")
    return mapping


def cmd_export_figures(args: argparse.Namespace) -> None:
    root = engagement_path(args.engagement)
    ensure_engagement(root)
    out_dir = root / "06_report" / args.output
    mapping = export_figure_files(root, out_dir, args.finding)
    if not mapping:
        print_warning("No figures exported.")


def evidence_inventory_rows(root: Path) -> List[Dict[str, Any]]:
    return [
        {
            "evidence_id": item.get("evidence_id", ""),
            "finding_id": item.get("finding_id", ""),
            "type": item.get("evidence_type", ""),
            "host": item.get("host", ""),
            "caption": evidence_caption(item),
            "file": markdown_file_reference(item.get("stored_path", "")),
        }
        for item in load_evidence(root)
    ]


def write_evidence_inventory_csv(root: Path, out_path: Path) -> None:
    rows = evidence_inventory_rows(root)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["evidence_id", "finding_id", "type", "host", "caption", "file"])
        writer.writeheader()
        writer.writerows(rows)


def cmd_package_report(args: argparse.Namespace) -> None:
    root = engagement_path(args.engagement)
    ensure_engagement(root)

    package_dir = root / "06_report" / args.output
    package_dir.mkdir(parents=True, exist_ok=True)
    figures_dir = package_dir / "figures"
    figure_names = export_figure_files(root, figures_dir)
    figure_path_map = {evidence_id: f"figures/{name}" for evidence_id, name in figure_names.items()}

    brief_path = package_dir / "report_brief.md"
    brief_path.write_text(render_brief(root, asset_prefix="figures", figure_path_map=figure_path_map), encoding="utf-8")
    write_evidence_inventory_csv(root, package_dir / "evidence_inventory.csv")
    shutil.copy2(findings_index_path(root), package_dir / "findings.json")
    shutil.copy2(evidence_index_path(root), package_dir / "evidence_index.json")

    if args.zip:
        zip_path = root / "06_report" / f"{safe_slug(args.output, 'report_package')}.zip"
        with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            for path in package_dir.rglob("*"):
                if path.is_file():
                    zf.write(path, path.relative_to(package_dir.parent))
        print_success(f"Wrote package zip: {zip_path}")

    print_success(f"Wrote report package: {package_dir}")


def cmd_add_note(args: argparse.Namespace) -> None:
    root = engagement_path(args.engagement)
    ensure_engagement(root)

    notes_dir = root / "04_notes"
    notes_dir.mkdir(parents=True, exist_ok=True)

    timestamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    finding = safe_slug(args.finding, "general")
    title = safe_slug(args.title, "note")
    out_path = notes_dir / f"{timestamp}_{finding}_{title}.md"
    out_path.write_text(
        "\n".join([
            f"# {args.title}",
            "",
            f"Created: {now_iso()}",
            f"Finding: {args.finding}",
            f"Host: {args.host}",
            "",
            "## Note",
            "",
            args.body.strip(),
            "",
        ]),
        encoding="utf-8",
    )

    sub_args = argparse.Namespace(
        engagement=args.engagement,
        files=[str(out_path)],
        finding=args.finding,
        host=args.host,
        type="note",
        description=f"Note: {args.title}",
        recursive=False,
    )
    cmd_import(sub_args)
    print_success(f"Wrote note: {out_path}")


def cmd_status(args: argparse.Namespace) -> None:
    root = engagement_path(args.engagement)
    ensure_engagement(root)
    findings = load_findings(root)
    evidence_items = load_evidence(root)

    severity_counts: Dict[str, int] = {severity: 0 for severity in VALID_SEVERITIES}
    for finding in findings:
        severity = finding.get("severity", "Informational")
        severity_counts[severity] = severity_counts.get(severity, 0) + 1

    evidence_by_type: Dict[str, int] = {}
    for item in evidence_items:
        evidence_type = item.get("evidence_type", "other")
        evidence_by_type[evidence_type] = evidence_by_type.get(evidence_type, 0) + 1

    incomplete = sum(1 for finding in findings if missing_fields(finding))
    uncaptured = sum(1 for finding in findings if not evidence_for_finding(root, finding.get("finding_id", "")))

    summary = "\n".join([
        f"Findings: {len(findings)}",
        f"Incomplete findings: {incomplete}",
        f"Findings with no evidence: {uncaptured}",
        f"Evidence items: {len(evidence_items)}",
    ])
    print_panel(f"Status for {root.name}", summary, "cyan")

    severity_rows = [[severity, severity_counts.get(severity, 0)] for severity in VALID_SEVERITIES]
    print_table("Findings by Severity", ["Severity", "Count"], severity_rows)

    evidence_rows = [[evidence_type, count] for evidence_type, count in sorted(evidence_by_type.items())]
    if evidence_rows:
        print_table("Evidence by Type", ["Type", "Count"], evidence_rows)


def cmd_tree(args: argparse.Namespace) -> None:
    root = engagement_path(args.engagement)
    ensure_engagement(root)

    def walk(path: Path, prefix: str = "", depth: int = 0) -> None:
        if depth > args.depth:
            return
        entries = sorted(path.iterdir(), key=lambda p: (not p.is_dir(), p.name.lower()))
        for idx, entry in enumerate(entries):
            connector = "`-- " if idx == len(entries) - 1 else "|-- "
            print(prefix + connector + entry.name)
            if entry.is_dir() and entry.name != APP_DIR:
                extension = "    " if idx == len(entries) - 1 else "|   "
                walk(entry, prefix + extension, depth + 1)

    print(root.name)
    walk(root)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Organise pentest evidence and generate report-writing support files.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_init = sub.add_parser("init", help="Create a new engagement workspace")
    p_init.add_argument("name", help="Engagement folder name/path")
    p_init.add_argument("--force", action="store_true", help="Initialise even if folder already contains files")
    p_init.set_defaults(func=cmd_init)

    p_scope = sub.add_parser("set-scope", help="Save scope notes for the engagement brief")
    p_scope.add_argument("engagement", help="Engagement folder")
    p_scope.add_argument("--in-scope", dest="in_scope", help="In-scope targets/assets")
    p_scope.add_argument("--out-of-scope", dest="out_of_scope", help="Out-of-scope targets/assets")
    p_scope.add_argument("--rules", help="Rules of engagement or constraints")
    p_scope.add_argument("--objectives", help="Assessment objectives")
    p_scope.add_argument("--window", help="Assessment window")
    p_scope.add_argument("--tester", help="Tester/author name")
    p_scope.set_defaults(func=cmd_set_scope)

    p_inbox = sub.add_parser("set-inbox", help="Save screenshot inbox folder for import-new")
    p_inbox.add_argument("engagement", help="Engagement folder")
    p_inbox.add_argument("--screenshots", required=True, help="Folder where screenshots are normally saved")
    p_inbox.set_defaults(func=cmd_set_inbox)

    p_import = sub.add_parser("import", help="Import evidence files into the engagement")
    p_import.add_argument("engagement", help="Engagement folder")
    p_import.add_argument("files", nargs="+", help="Evidence file(s), folders, or glob patterns")
    p_import.add_argument("--finding", default="UNASSIGNED", help="Finding ID, e.g. F-001")
    p_import.add_argument("--host", default="unknown", help="Affected host or asset")
    p_import.add_argument("--type", default="other", help=f"Evidence type: {', '.join(sorted(VALID_EVIDENCE_TYPES))}")
    p_import.add_argument("--description", default="", help="Evidence caption/description")
    p_import.add_argument("--recursive", action="store_true", help="Import files from folders recursively")
    p_import.set_defaults(func=cmd_import)

    p_import_new = sub.add_parser("import-new", help="Import newest screenshots from the saved inbox")
    p_import_new.add_argument("engagement", help="Engagement folder")
    p_import_new.add_argument("--finding", required=True, help="Finding ID, e.g. F-001")
    p_import_new.add_argument("--host", default="unknown", help="Affected host or asset")
    p_import_new.add_argument("--count", type=int, default=1, help="Number of newest screenshots to import")
    p_import_new.add_argument("--description", default="", help="Shared caption/description for imported screenshots")
    p_import_new.add_argument("--since-minutes", type=int, help="Only consider screenshots modified within this many minutes")
    p_import_new.add_argument("--path", help="Override saved screenshot inbox for this import")
    p_import_new.add_argument("--include-imported", action="store_true", help="Allow files already imported from the inbox")
    p_import_new.set_defaults(func=cmd_import_new)

    p_add = sub.add_parser("add-finding", help="Add or update a manually identified finding")
    p_add.add_argument("engagement", help="Engagement folder")
    p_add.add_argument("--id", required=True, help="Finding ID, e.g. F-001")
    p_add.add_argument("--title", required=True, help="Finding title")
    p_add.add_argument("--severity", required=True, help="Critical, High, Medium, Low, or Informational")
    p_add.add_argument("--affected", required=True, help="Affected assets")
    p_add.add_argument("--summary", default="", help="Finding summary")
    p_add.add_argument("--impact", default="", help="Business/technical impact")
    p_add.add_argument("--likelihood", default="", help="Likelihood statement")
    p_add.add_argument("--recommendation", default="", help="Recommended remediation")
    p_add.add_argument("--status", default="Open", help="Internal finding status")
    p_add.add_argument("--update", action="store_true", help="Update existing finding if it exists")
    p_add.set_defaults(func=cmd_add_finding)

    p_caption = sub.add_parser("caption-evidence", help="Update an evidence caption or assignment")
    p_caption.add_argument("engagement", help="Engagement folder")
    p_caption.add_argument("evidence_id", help="Evidence ID, e.g. E-0001")
    p_caption.add_argument("--caption", help="New evidence caption")
    p_caption.add_argument("--finding", help="Move/link evidence to this finding ID")
    p_caption.add_argument("--host", help="Update related host/asset")
    p_caption.set_defaults(func=cmd_caption_evidence)

    p_delete_e = sub.add_parser("delete-evidence", help="Delete evidence from the index")
    p_delete_e.add_argument("engagement", help="Engagement folder")
    p_delete_e.add_argument("evidence_ids", nargs="+", help="Evidence ID(s), e.g. E-0001")
    p_delete_e.add_argument("--delete-file", action="store_true", help="Also delete the stored evidence file")
    p_delete_e.set_defaults(func=cmd_delete_evidence)

    p_delete_f = sub.add_parser("delete-finding", help="Delete a finding")
    p_delete_f.add_argument("engagement", help="Engagement folder")
    p_delete_f.add_argument("finding_id", help="Finding ID, e.g. F-001")
    p_delete_f.add_argument("--delete-evidence", action="store_true", help="Also delete evidence linked to this finding")
    p_delete_f.add_argument("--delete-files", action="store_true", help="With --delete-evidence, also delete linked stored files")
    p_delete_f.set_defaults(func=cmd_delete_finding)

    p_list_f = sub.add_parser("list-findings", help="List findings")
    p_list_f.add_argument("engagement", help="Engagement folder")
    p_list_f.set_defaults(func=cmd_list_findings)

    p_list_e = sub.add_parser("list-evidence", help="List evidence")
    p_list_e.add_argument("engagement", help="Engagement folder")
    p_list_e.add_argument("--finding", help="Filter by finding ID")
    p_list_e.add_argument("--host", help="Filter by host")
    p_list_e.add_argument("--type", help="Filter by evidence type")
    p_list_e.set_defaults(func=cmd_list_evidence)

    p_missing = sub.add_parser("missing", help="Show missing finding text/evidence checklist")
    p_missing.add_argument("engagement", help="Engagement folder")
    p_missing.set_defaults(func=cmd_missing)

    p_draft = sub.add_parser("draft", help="Generate a Markdown brief for one finding")
    p_draft.add_argument("engagement", help="Engagement folder")
    p_draft.add_argument("--finding", required=True, help="Finding ID")
    p_draft.set_defaults(func=cmd_draft)

    p_brief = sub.add_parser("build-brief", help="Generate a report-writing brief")
    p_brief.add_argument("engagement", help="Engagement folder")
    p_brief.add_argument("--output", help="Output file name inside 06_report")
    p_brief.set_defaults(func=cmd_build_brief)

    p_report = sub.add_parser("build-report", help="Compatibility alias for build-brief")
    p_report.add_argument("engagement", help="Engagement folder")
    p_report.add_argument("--output", help="Output file name inside 06_report")
    p_report.set_defaults(func=cmd_build_report)

    p_fig = sub.add_parser("export-figures", help="Copy report-ready screenshots into 06_report/figures")
    p_fig.add_argument("engagement", help="Engagement folder")
    p_fig.add_argument("--finding", help="Only export screenshots for one finding")
    p_fig.add_argument("--output", default="figures", help="Output folder name inside 06_report")
    p_fig.set_defaults(func=cmd_export_figures)

    p_pkg = sub.add_parser("package-report", help="Create a report writing package with brief, figures, inventory, and JSON")
    p_pkg.add_argument("engagement", help="Engagement folder")
    p_pkg.add_argument("--output", default="report_package", help="Output folder name inside 06_report")
    p_pkg.add_argument("--zip", action="store_true", help="Also create a zip archive")
    p_pkg.set_defaults(func=cmd_package_report)

    p_note = sub.add_parser("add-note", help="Create a Markdown note and import it as evidence")
    p_note.add_argument("engagement", help="Engagement folder")
    p_note.add_argument("--title", required=True, help="Note title")
    p_note.add_argument("--body", required=True, help="Note body")
    p_note.add_argument("--finding", default="UNASSIGNED", help="Finding ID")
    p_note.add_argument("--host", default="unknown", help="Host or asset")
    p_note.set_defaults(func=cmd_add_note)

    p_status = sub.add_parser("status", help="Show engagement status")
    p_status.add_argument("engagement", help="Engagement folder")
    p_status.set_defaults(func=cmd_status)

    p_tree = sub.add_parser("tree", help="Print engagement folder tree")
    p_tree.add_argument("engagement", help="Engagement folder")
    p_tree.add_argument("--depth", type=int, default=3, help="Maximum folder depth")
    p_tree.set_defaults(func=cmd_tree)

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        args.func(args)
        return 0
    except EvidenceManagerError as exc:
        print_error(str(exc))
        return 2
    except KeyboardInterrupt:
        print_error("Interrupted")
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
