"""Read-only, offline static-site checks. Original source, MIT-licensed.

The optional environment kill switch SITE_AUDIT_ENABLED=0 restores the
pre-tool behavior: no file reads, writes, stdout, or exit-code changes.
"""
from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass, field
from html.parser import HTMLParser
import json
import os
from pathlib import Path
import posixpath
import re
import sys
from typing import Any
from urllib.parse import unquote, urljoin, urlsplit


_FLAG_NAME = "SITE_AUDIT_ENABLED"
_DISABLED = frozenset({"0", "false", "no", "off"})
_HOST = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$", re.I)
_ACCOUNT_ID = re.compile(r"^[^\s,;#]+$")
_CERT_ID = re.compile(r"^[^\s,;#]+$")
_VARIABLE = re.compile(r"^([a-z][a-z0-9_]*)\s*=\s*(.*)$", re.I)
_KNOWN_VARIABLES = frozenset({"OWNERDOMAIN", "MANAGERDOMAIN", "INVENTORYPARTNERDOMAIN", "INVENTORYDOMAIN", "SUBDOMAIN", "CONTACT"})
_IGNORE_DIRS = frozenset({".git", "node_modules", ".venv", "venv", "__pycache__", ".pytest_cache"})
_SCHEMA_HOST = "schema.org"  # JSON-LD vocabulary namespace, not a network dependency.


def feature_enabled(environ: dict[str, str] | os._Environ[str] | None = None) -> bool:
    """ON when unset, and OFF only when explicitly disabled."""
    if environ is None:
        environ = os.environ
    return str(environ.get(_FLAG_NAME, "1")).strip().lower() not in _DISABLED


@dataclass(frozen=True, order=True)
class Finding:
    path: str
    line: int
    code: str
    severity: str
    message: str

    def as_json(self) -> dict[str, str | int]:
        return asdict(self)


@dataclass(frozen=True)
class Seller:
    domain: str
    account_id: str
    relationship: str
    authority_id: str | None
    line: int
    extension: str | None = None


@dataclass
class AdsAudit:
    sellers: list[Seller] = field(default_factory=list)
    variables: dict[str, list[str]] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)


@dataclass(frozen=True)
class Link:
    tag: str
    attribute: str
    value: str
    line: int


@dataclass(frozen=True)
class Script:
    source: str
    line: int


class DocumentParser(HTMLParser):
    """HTML tokenization uses the standard parser, not a tag-matching regex."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[Link] = []
        self.images: list[tuple[int, bool]] = []
        self.anchors: set[str] = set()
        self.scripts: list[Script] = []
        self.base_href: str | None = None
        self._script_chunks: list[str] | None = None
        self._script_start = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag = tag.lower()
        attr = dict(attrs)
        line, _ = self.getpos()
        node_id = attr.get("id")
        if node_id:
            self.anchors.add(node_id)
        if tag == "a" and attr.get("name"):
            self.anchors.add(attr["name"] or "")
        if tag == "base" and self.base_href is None and attr.get("href") is not None:
            self.base_href = attr["href"]
        elif attr.get("href") is not None:
            self.links.append(Link(tag, "href", attr["href"] or "", line))
        if tag == "img":
            self.images.append((line, "alt" in attr))
            if attr.get("src") is not None:
                self.links.append(Link(tag, "src", attr["src"] or "", line))
        if tag == "script" and (attr.get("type") or "").strip().lower().split(";")[0] == "application/ld+json":
            self._script_chunks = []
            self._script_start = line

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.handle_starttag(tag, attrs)
        self.handle_endtag(tag)

    def handle_data(self, data: str) -> None:
        if self._script_chunks is not None:
            self._script_chunks.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "script" and self._script_chunks is not None:
            self.scripts.append(Script("".join(self._script_chunks), self._script_start))
            self._script_chunks = None

    def close(self) -> None:
        super().close()
        if self._script_chunks is not None:
            self.scripts.append(Script("".join(self._script_chunks), self._script_start))
            self._script_chunks = None


def _finding(path: str, line: int, code: str, message: str, severity: str = "error") -> Finding:
    return Finding(path, line, code, severity, message)


def _host(value: str) -> bool:
    return bool(_HOST.fullmatch(value)) and ".." not in value


def parse_app_ads(content: str, path: str = "app-ads.txt") -> AdsAudit:
    """Parse sellers and directives without making any HTTP requests.

    Seller records have three required comma-separated fields and an optional
    fourth; semicolon extensions are retained without interpreting them.
    """
    out = AdsAudit()
    seen: set[tuple[str, str, str]] = set()
    seen_manager_markets: set[str] = set()
    for lineno, raw in enumerate(content.lstrip("\ufeff").splitlines(), 1):
        stripped = raw.split("#", 1)[0].strip()
        if not stripped:
            continue
        variable = _VARIABLE.fullmatch(stripped)
        if variable:
            key, value = variable.group(1).upper(), variable.group(2).strip()
            if not value:
                out.findings.append(_finding(path, lineno, "ADS_EMPTY_DIRECTIVE", f"{key} needs a value"))
                continue
            if key not in _KNOWN_VARIABLES:
                out.findings.append(_finding(path, lineno, "ADS_UNKNOWN_DIRECTIVE", f"Unrecognized directive: {key}", "warning"))
            if key in {"OWNERDOMAIN", "SUBDOMAIN", "INVENTORYDOMAIN", "INVENTORYPARTNERDOMAIN"} and not _host(value):
                out.findings.append(_finding(path, lineno, "ADS_BAD_DIRECTIVE_DOMAIN", f"{key} needs a domain"))
            if key == "OWNERDOMAIN" and out.variables.get(key):
                out.findings.append(_finding(path, lineno, "ADS_DUPLICATE_OWNER", "Only the first OWNERDOMAIN is authoritative", "warning"))
            if key == "MANAGERDOMAIN":
                components = [piece.strip() for piece in value.split(",")]
                if len(components) not in {1, 2} or not _host(components[0]) or (len(components) == 2 and not re.fullmatch(r"[a-zA-Z]{2}", components[1])):
                    out.findings.append(_finding(path, lineno, "ADS_BAD_MANAGER", "MANAGERDOMAIN needs a domain and optional two-letter market"))
                else:
                    market = components[1].upper() if len(components) == 2 else "GLOBAL"
                    if market in seen_manager_markets:
                        out.findings.append(_finding(path, lineno, "ADS_DUPLICATE_MANAGER", f"Repeated manager market: {market}", "warning"))
                    seen_manager_markets.add(market)
            out.variables.setdefault(key, []).append(value)
            continue
        if "=" in stripped and "," not in stripped:
            out.findings.append(_finding(path, lineno, "ADS_BAD_DIRECTIVE", "Directive names must use letters, digits or underscores"))
            continue
        record, sep, extension = stripped.partition(";")
        cells = [cell.strip() for cell in record.split(",")]
        if len(cells) not in {3, 4} or any(not cell for cell in cells):
            out.findings.append(_finding(path, lineno, "ADS_FIELD_COUNT", "Seller record requires three fields and optional fourth"))
            continue
        domain, account, relationship = cells[:3]
        authority = cells[3] if len(cells) == 4 else None
        if not _host(domain):
            out.findings.append(_finding(path, lineno, "ADS_DOMAIN", "Seller domain is malformed"))
        if not _ACCOUNT_ID.fullmatch(account):
            out.findings.append(_finding(path, lineno, "ADS_ACCOUNT", "Seller account ID cannot contain whitespace or separators"))
        normalized_relation = relationship.upper()
        if normalized_relation not in {"DIRECT", "RESELLER"}:
            out.findings.append(_finding(path, lineno, "ADS_RELATIONSHIP", "Relationship must be DIRECT or RESELLER"))
        if authority is not None and not _CERT_ID.fullmatch(authority):
            out.findings.append(_finding(path, lineno, "ADS_AUTHORITY", "Certification authority ID has invalid separators"))
        if sep and not extension.strip():
            out.findings.append(_finding(path, lineno, "ADS_EMPTY_EXTENSION", "Semicolon extension is empty", "warning"))
        dedup_key = (domain.lower(), account, normalized_relation)
        if dedup_key in seen:
            out.findings.append(_finding(path, lineno, "ADS_DUPLICATE_SELLER", "Repeated seller declaration", "warning"))
        seen.add(dedup_key)
        out.sellers.append(Seller(domain.lower(), account, normalized_relation, authority, lineno, extension.strip() if sep else None))
    if not out.sellers:
        out.findings.append(_finding(path, 1, "ADS_NO_SELLERS", "No authorized-seller records; use a formatted placeholder if intended"))
    return out


def _namespace_url(candidate: object) -> bool:
    if not isinstance(candidate, str):
        return False
    try:
        parsed = urlsplit(candidate.strip())
    except ValueError:
        return False
    return parsed.scheme in {"http", "https"} and parsed.hostname == _SCHEMA_HOST and parsed.path in {"", "/"} and not parsed.query and not parsed.fragment


def _has_schema_context(value: object) -> bool:
    if isinstance(value, str):
        return _namespace_url(value)
    if isinstance(value, list):
        return any(_has_schema_context(item) for item in value)
    if isinstance(value, dict):
        return any(_namespace_url(item) for key, item in value.items() if key == "@vocab" or key.isidentifier())
    return False


def _valid_type(value: Any) -> bool:
    if isinstance(value, str):
        return bool(value.strip()) and not any(ch.isspace() for ch in value)
    return isinstance(value, list) and bool(value) and all(_valid_type(entry) for entry in value if isinstance(entry, str)) and all(isinstance(entry, str) for entry in value)


def validate_json_ld(source: str, path: str, line: int) -> list[Finding]:
    """Structural JSON-LD lint. Deliberately does not maintain a class registry."""
    issues: list[Finding] = []
    duplicates: set[str] = set()

    def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                duplicates.add(key)
            result[key] = value
        return result

    try:
        payload = json.loads(source, object_pairs_hook=reject_duplicate_keys)
    except json.JSONDecodeError as exc:
        return [_finding(path, line + exc.lineno - 1, "LD_JSON_SYNTAX", f"JSON cannot be parsed: {exc.msg}")]
    for key in sorted(duplicates):
        issues.append(_finding(path, line, "LD_DUPLICATE_KEY", f"Duplicate JSON key: {key}"))
    if not isinstance(payload, (dict, list)) or isinstance(payload, list) and not payload:
        return issues + [_finding(path, line, "LD_ROOT", "JSON-LD root must be a nonempty object or array")]

    def inspect(obj: object, inherited_context: bool, loc: str) -> None:
        if not isinstance(obj, dict):
            issues.append(_finding(path, line, "LD_NODE", f"{loc} must be a JSON object"))
            return
        has_context = _has_schema_context(obj.get("@context")) if "@context" in obj else inherited_context
        if "@context" in obj and not has_context:
            issues.append(_finding(path, line, "LD_CONTEXT", f"{loc} needs a recognized JSON-LD vocabulary context"))
        if not has_context:
            issues.append(_finding(path, line, "LD_CONTEXT_MISSING", f"{loc} has no usable vocabulary context"))
        if "@id" in obj and (not isinstance(obj["@id"], str) or not obj["@id"].strip()):
            issues.append(_finding(path, line, "LD_ID", f"{loc} @id must be a nonempty string"))
        if "@graph" in obj:
            graph = obj["@graph"]
            if not isinstance(graph, list) or not graph:
                issues.append(_finding(path, line, "LD_GRAPH", f"{loc} @graph must be a nonempty array"))
            else:
                for i, child in enumerate(graph):
                    inspect(child, has_context, f"{loc}.@graph[{i}]")
        elif "@type" not in obj:
            issues.append(_finding(path, line, "LD_TYPE_MISSING", f"{loc} needs @type or @graph"))
        if "@type" in obj and not _valid_type(obj["@type"]):
            issues.append(_finding(path, line, "LD_TYPE", f"{loc} @type must be a nonempty string or string array"))

    if isinstance(payload, list):
        for i, member in enumerate(payload):
            inspect(member, False, f"$[{i}]")
    else:
        inspect(payload, False, "$")
    return issues


@dataclass
class SiteReport:
    enabled: bool = True
    html_files: int = 0
    local_references: int = 0
    ads_sellers: int = 0
    json_ld_blocks: int = 0
    findings: list[Finding] = field(default_factory=list)

    def as_json(self) -> dict[str, Any]:
        return {
            "enabled": self.enabled,
            "html_files": self.html_files,
            "local_references": self.local_references,
            "ads_sellers": self.ads_sellers,
            "json_ld_blocks": self.json_ld_blocks,
            "errors": sum(f.severity == "error" for f in self.findings),
            "warnings": sum(f.severity == "warning" for f in self.findings),
            "findings": [f.as_json() for f in sorted(self.findings)],
        }


def _origin_tuple(url: str) -> tuple[str, str, int | None]:
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password or parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        raise ValueError("site-origin must be an HTTP(S) origin with no path, query or fragment")
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("Invalid site-origin port") from exc
    if port == (443 if parsed.scheme == "https" else 80):
        port = None
    return (parsed.scheme, parsed.hostname.lower(), port)


def _target_is_local(value: str, source_path: str, base: str | None, site_origin: str | None) -> tuple[str, str] | None:
    """Return local URL path and fragment, or None for nonlocal schemes."""
    reference = value.strip()
    if not reference:
        return None
    parts = urlsplit(reference)
    if parts.scheme.lower() in {"mailto", "tel", "sms", "data", "blob"}:
        return None
    if parts.scheme and parts.scheme.lower() not in {"http", "https"}:
        return None
    if not site_origin and (parts.netloc or parts.scheme):
        return None
    origin = site_origin or "https://offline.invalid"
    page_url = origin.rstrip("/") + "/" + source_path.lstrip("/")
    current_base = urljoin(page_url, base) if base else page_url
    resolved = urlsplit(urljoin(current_base, reference))
    resolved_port = resolved.port
    if resolved_port == (443 if resolved.scheme == "https" else 80):
        resolved_port = None
    if (resolved.scheme, (resolved.hostname or "").lower(), resolved_port) != _origin_tuple(origin):
        return None
    return (unquote(resolved.path), unquote(resolved.fragment))


def _resolve_disk_target(root: Path, urlpath: str) -> tuple[Path | None, str | None]:
    # Avoid direct OS path interpretation of URL escapes and Windows backslashes.
    if "\\" in urlpath or "\x00" in urlpath:
        return None, "unsafe"
    posix_path = posixpath.normpath(urlpath.lstrip("/"))
    rel = "" if posix_path == "." else posix_path
    raw = root / rel
    try:
        actual = raw.resolve()
        if not actual.is_relative_to(root):
            return None, "unsafe"
        candidates = [actual]
        if actual.is_dir() or urlpath.endswith("/") or not rel:
            candidates = [actual / "index.html", actual / "index.htm"]
        elif not actual.suffix:
            candidates.extend([Path(f"{actual}.html"), actual / "index.html", actual / "index.htm"])
        for item in candidates:
            resolved = item.resolve()
            if not resolved.is_relative_to(root):
                return None, "unsafe"
            if resolved.is_file():
                return resolved, None
        return None, "missing"
    except (OSError, RuntimeError):
        return None, "unsafe"


def audit_site(root: Path | str, site_origin: str | None = None, *, enabled: bool | None = None) -> SiteReport:
    """Audit one on-disk site snapshot without writing to it or fetching URLs."""
    if enabled is None:
        enabled = feature_enabled()
    report = SiteReport(enabled=enabled)
    if not enabled:
        return report
    if site_origin is not None:
        _origin_tuple(site_origin)
    root = Path(root).expanduser().resolve()
    if not root.is_dir():
        report.findings.append(_finding(".", 1, "SITE_ROOT", "Site root is not a directory"))
        return report
    ads_path = root / "app-ads.txt"
    if ads_path.is_file():
        try:
            ads = parse_app_ads(ads_path.read_text(encoding="utf-8"))
            report.ads_sellers = len(ads.sellers)
            report.findings.extend(ads.findings)
        except (OSError, UnicodeError):
            report.findings.append(_finding("app-ads.txt", 1, "ADS_READ", "Cannot decode root seller declarations"))
    else:
        report.findings.append(_finding("app-ads.txt", 1, "ADS_FILE_MISSING", "Root seller declarations not found"))

    docs: dict[str, DocumentParser] = {}
    for directory, subdirs, filenames in os.walk(root, topdown=True, followlinks=False):
        subdirs[:] = sorted(
            name for name in subdirs
            if name not in _IGNORE_DIRS and not name.startswith(".")
            and not (Path(directory) / name).is_symlink()
        )
        for name in sorted(filenames):
            path = Path(directory) / name
            if name.startswith(".") or path.is_symlink() or path.suffix.lower() not in {".htm", ".html"}:
                continue
            relpath = path.relative_to(root).as_posix()
            parser = DocumentParser()
            try:
                parser.feed(path.read_text(encoding="utf-8"))
                parser.close()
            except (OSError, UnicodeError, ValueError) as exc:
                report.findings.append(_finding(relpath, 1, "HTML_READ", f"Cannot parse HTML: {type(exc).__name__}"))
                continue
            docs[relpath] = parser
            report.html_files += 1
            for line, has_alt in parser.images:
                if not has_alt:
                    report.findings.append(_finding(relpath, line, "IMG_ALT_MISSING", "Image needs an alt attribute; use alt=\"\" for decorative images"))
            report.json_ld_blocks += len(parser.scripts)
            for script in parser.scripts:
                report.findings.extend(validate_json_ld(script.source, relpath, script.line))

    for relpath, parser in docs.items():
        for link in parser.links:
            try:
                target = _target_is_local(link.value, relpath, parser.base_href, site_origin)
            except ValueError:
                report.findings.append(_finding(relpath, link.line, "LINK_BAD_URL", "Reference contains an invalid URL"))
                continue
            if target is None:
                if link.tag == "img" and link.attribute == "src" and not link.value.strip():
                    report.findings.append(_finding(relpath, link.line, "IMG_SRC_EMPTY", "Image src is empty"))
                if urlsplit(link.value.strip()).scheme.lower() == "javascript":
                    report.findings.append(_finding(relpath, link.line, "LINK_SCRIPT_SCHEME", "Script URL is discouraged", "warning"))
                continue
            report.local_references += 1
            disk, problem = _resolve_disk_target(root, target[0])
            if problem == "unsafe":
                report.findings.append(_finding(relpath, link.line, "LINK_UNSAFE_PATH", f"{link.attribute} resolves outside site root"))
            elif disk is None:
                code = "IMG_SRC_MISSING" if link.tag == "img" and link.attribute == "src" else "LINK_TARGET_MISSING"
                report.findings.append(_finding(relpath, link.line, code, f"Local {link.attribute} target not present: {target[0]}"))
            elif target[1] and disk.suffix.lower() in {".html", ".htm"}:
                destination = disk.relative_to(root).as_posix()
                if destination not in docs:
                    continue
                if target[1] not in docs[destination].anchors:
                    report.findings.append(_finding(relpath, link.line, "LINK_FRAGMENT_MISSING", f"Fragment not found: {destination}#{target[1]}"))
    return report


def main(argv: list[str] | None = None) -> int:
    if not feature_enabled():
        # Bit-for-bit legacy behavior: the absent auditor emits no output.
        return 0
    ap = argparse.ArgumentParser(description="Read-only offline site audit")
    ap.add_argument("--root", default=".", help="Site root containing app-ads.txt and HTML")
    ap.add_argument("--site-origin", help="Optional public origin for checking same-origin absolute URLs")
    ap.add_argument("--format", choices=["text", "json"], default="text")
    ap.add_argument("--fail-on", choices=["error", "warning", "none"], default="error")
    args = ap.parse_args(argv)
    try:
        report = audit_site(args.root, site_origin=args.site_origin)
    except ValueError as exc:
        ap.error(str(exc))
    data = report.as_json()
    if args.format == "json":
        print(json.dumps(data, indent=2, sort_keys=True, ensure_ascii=False))
    else:
        print(f"site-audit: html={data['html_files']} links={data['local_references']} sellers={data['ads_sellers']} jsonld={data['json_ld_blocks']} errors={data['errors']} warnings={data['warnings']}")
        for item in data["findings"]:
            print(f"{item['path']}:{item['line']}: {item['severity']} {item['code']}: {item['message']}")
    return int((args.fail_on == "error" and data["errors"] > 0) or (args.fail_on == "warning" and (data["errors"] > 0 or data["warnings"] > 0)))


if __name__ == "__main__":
    sys.exit(main())
