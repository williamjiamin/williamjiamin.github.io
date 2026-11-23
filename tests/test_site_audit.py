"""Offline regression suite for the read-only site auditor."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from tools.site_audit import audit_site, feature_enabled, parse_app_ads, validate_json_ld


TOOL = Path(__file__).resolve().parents[1] / "tools" / "site_audit.py"
ADS = "supply.example, acct_17, DIRECT, abc123\n"
CONTEXT = "https://schema.org"


def site(tmp_path: Path, html: str = "<html><body></body></html>") -> Path:
    (tmp_path / "app-ads.txt").write_text(ADS, encoding="utf-8")
    (tmp_path / "index.html").write_text(html, encoding="utf-8")
    return tmp_path


def codes(result) -> list[str]:
    return [f.code for f in result.findings]


def test_enabled_when_not_configured():
    assert feature_enabled({})
    assert feature_enabled({"SITE_AUDIT_ENABLED": "1"})
    assert feature_enabled({"SITE_AUDIT_ENABLED": "enabled"})


@pytest.mark.parametrize("off", ["0", "off", "FALSE", "No", " 0 "])
def test_explicit_kill_switch(off):
    assert not feature_enabled({"SITE_AUDIT_ENABLED": off})


def test_seller_parses_normalized_relation_and_bom():
    result = parse_app_ads("\ufeff# comment\r\n  SUPPLY.Example, id-2, direct, cert9 # inline\r\n")
    assert result.findings == []
    assert result.sellers[0].domain == "supply.example"
    assert result.sellers[0].relationship == "DIRECT"
    assert result.sellers[0].authority_id == "cert9"
    assert result.sellers[0].line == 2


def test_seller_optional_certification_and_extension():
    result = parse_app_ads("a.example, account, RESELLER; ext=value\n")
    assert result.findings == []
    assert result.sellers[0].authority_id is None
    assert result.sellers[0].extension == "ext=value"


@pytest.mark.parametrize("record,code", [
    ("a.example, account", "ADS_FIELD_COUNT"),
    ("a.example, account, DIRECT, cert, extra", "ADS_FIELD_COUNT"),
    ("a.example, , DIRECT", "ADS_FIELD_COUNT"),
    ("a.example, account, AGENT", "ADS_RELATIONSHIP"),
    ("notadomain, account, DIRECT", "ADS_DOMAIN"),
    ("a.example, two words, DIRECT", "ADS_ACCOUNT"),
    ("a.example, account, DIRECT, two words", "ADS_AUTHORITY"),
])
def test_invalid_seller_records(record, code):
    assert code in codes(parse_app_ads(record))


def test_duplicate_sellers_warn_and_first_record_kept():
    result = parse_app_ads("a.example, 1, DIRECT\nA.example, 1, direct\n")
    assert "ADS_DUPLICATE_SELLER" in codes(result)
    assert len(result.sellers) == 2
    assert result.findings[0].severity == "warning"


def test_empty_extension_warns():
    assert "ADS_EMPTY_EXTENSION" in codes(parse_app_ads("a.example, 1, DIRECT;   "))


def test_supported_directives_and_case_insensitive_names():
    result = parse_app_ads(
        "ownerdomain=owner.example\nMANAGERDOMAIN=manager.example, US\n"
        "managerdomain=global.example\ninventorypartnerdomain=inventory.example\n"
        "contact=site inbox\nsubdomain=media.owner.example\n" + ADS
    )
    assert result.findings == []
    assert result.variables["OWNERDOMAIN"] == ["owner.example"]
    assert len(result.variables["MANAGERDOMAIN"]) == 2


def test_duplicate_owner_is_a_warning():
    result = parse_app_ads("OWNERDOMAIN=owner.example\nOWNERDOMAIN=other.example\n" + ADS)
    assert "ADS_DUPLICATE_OWNER" in codes(result)


def test_duplicate_manager_market_is_a_warning():
    result = parse_app_ads("MANAGERDOMAIN=one.example, US\nMANAGERDOMAIN=two.example, us\n" + ADS)
    assert "ADS_DUPLICATE_MANAGER" in codes(result)


@pytest.mark.parametrize("directive,code", [
    ("OWNERDOMAIN=", "ADS_EMPTY_DIRECTIVE"),
    ("OWNERDOMAIN=not-a-domain", "ADS_BAD_DIRECTIVE_DOMAIN"),
    ("MANAGERDOMAIN=m.example, USA", "ADS_BAD_MANAGER"),
    ("MANAGERDOMAIN=m.example, US, CA", "ADS_BAD_MANAGER"),
    ("INVALID KEY=aaa", "ADS_BAD_DIRECTIVE"),
    ("FUTURE_KEY=generic", "ADS_UNKNOWN_DIRECTIVE"),
])
def test_malformed_or_forward_compatible_directive(directive, code):
    assert code in codes(parse_app_ads(directive + "\n" + ADS))


def test_seller_free_file_is_reported():
    assert "ADS_NO_SELLERS" in codes(parse_app_ads("# comment\nOWNERDOMAIN=owner.example"))


def test_site_reads_seller_and_html(tmp_path):
    result = audit_site(site(tmp_path))
    assert result.enabled and result.html_files == 1 and result.ads_sellers == 1
    assert result.findings == []


def test_missing_ads_file(tmp_path):
    (tmp_path / "index.html").write_text("<html></html>")
    assert "ADS_FILE_MISSING" in codes(audit_site(tmp_path))


def test_bad_root_is_reported(tmp_path):
    assert "SITE_ROOT" in codes(audit_site(tmp_path / "not-here"))


def test_missing_img_alt_and_decorative_empty_alt_is_valid(tmp_path):
    result = audit_site(site(tmp_path, '<img src="data:image/gif;base64,YQ=="><img src="data:image/gif;base64,YQ==" alt="">'))
    assert codes(result) == ["IMG_ALT_MISSING"]


def test_fake_html_inside_comments_or_scripts_is_ignored(tmp_path):
    result = audit_site(site(tmp_path, '<!-- <img src="none"> --><script>const sample = "<img src=\'none\'>";</script>'))
    assert result.findings == []


def test_good_local_links_assets_and_anchors(tmp_path):
    root = site(tmp_path, '<a href="guide/page.html#info">Guide</a><a href="#home">Top</a><img src="media/a.png" alt="Preview"><div id="home"></div>')
    (root / "guide").mkdir()
    (root / "guide" / "page.html").write_text('<h2 id="info">Help</h2>')
    (root / "media").mkdir()
    (root / "media" / "a.png").write_bytes(b"mock")
    result = audit_site(root)
    assert result.findings == []
    assert result.local_references == 3
    assert result.html_files == 2


def test_href_missing_target_and_img_missing_src(tmp_path):
    result = audit_site(site(tmp_path, '<a href="./not-here">No</a><img alt="ok" src="absent.png">'))
    assert set(codes(result)) == {"LINK_TARGET_MISSING", "IMG_SRC_MISSING"}


def test_missing_fragment_is_reported(tmp_path):
    result = audit_site(site(tmp_path, '<a href="#not-here">Lost</a>'))
    assert "LINK_FRAGMENT_MISSING" in codes(result)


def test_named_anchor_works(tmp_path):
    result = audit_site(site(tmp_path, '<a name="old"></a><a href="#old">Okay</a>'))
    assert result.findings == []


def test_empty_fragment_is_allowed(tmp_path):
    result = audit_site(site(tmp_path, '<a href="#">Page</a>'))
    assert result.findings == []


def test_query_string_does_not_change_local_target(tmp_path):
    result = audit_site(site(tmp_path, '<a href="/?track=yes">Root</a>'))
    assert result.findings == []


def test_directory_and_extensionless_urls_resolve(tmp_path):
    root = site(tmp_path, '<a href="/help/">Help</a><a href="guide">Guide</a>')
    (root / "help").mkdir()
    (root / "help" / "index.html").write_text("Help")
    (root / "guide.html").write_text("Guide")
    assert audit_site(root).findings == []


def test_base_href_is_honored(tmp_path):
    root = site(tmp_path, '<base href="/docs/"><a href="page.html">Page</a>')
    (root / "docs").mkdir()
    (root / "docs" / "page.html").write_text("Page")
    assert audit_site(root).findings == []


def test_external_and_contact_urls_skipped(tmp_path):
    html = '<a href="https://outside.example/nowhere">Out</a><a href="mailto:help@site.example">Mail</a><a href="tel:+11234567890">Call</a><a href="//outside.example/">External</a>'
    result = audit_site(site(tmp_path, html))
    assert result.findings == []
    assert result.local_references == 0


def test_same_origin_absolute_url_checked_only_if_origin_supplied(tmp_path):
    root = site(tmp_path, '<a href="https://site.example/missing/">Local</a>')
    assert audit_site(root).findings == []
    assert "LINK_TARGET_MISSING" in codes(audit_site(root, site_origin="https://site.example"))


def test_same_origin_nondefault_port(tmp_path):
    root = site(tmp_path, '<a href="https://site.example:8443/index.html">Local</a>')
    assert audit_site(root, site_origin="https://site.example:8443").findings == []


def test_site_origin_rejects_paths(tmp_path):
    with pytest.raises(ValueError):
        audit_site(tmp_path, site_origin="https://site.example/a")


def test_encoded_path_traversal_is_rejected(tmp_path):
    root = site(tmp_path, '<a href="/%2e%2e/%2e%2e/hidden.html">Path</a>')
    assert "LINK_UNSAFE_PATH" in codes(audit_site(root))


def test_symlink_escape_is_rejected(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    site(root, '<a href="secret.html">Missing</a>')
    outside = tmp_path / "outside.html"
    outside.write_text("External")
    try:
        (root / "secret.html").symlink_to(outside)
    except (OSError, NotImplementedError):
        pytest.skip("No symbolic links")
    assert "LINK_UNSAFE_PATH" in codes(audit_site(root))


def test_javascript_link_warned(tmp_path):
    result = audit_site(site(tmp_path, '<a href="javascript:void(0)">Bad</a>'))
    assert "LINK_SCRIPT_SCHEME" in codes(result)
    assert result.findings[0].severity == "warning"


def test_json_ld_valid_plain_node():
    content = json.dumps({"@context": CONTEXT, "@type": "WebSite", "name": "Example"})
    assert validate_json_ld(content, "index.html", 7) == []


def test_json_ld_valid_graph_with_inherited_context():
    content = json.dumps({"@context": CONTEXT, "@graph": [{"@type": "WebSite"}, {"@type": ["CreativeWork", "Thing"]}]})
    assert validate_json_ld(content, "index.html", 7) == []


def test_json_ld_vocab_object_context_is_valid():
    content = json.dumps({"@context": {"@vocab": CONTEXT + "/"}, "@type": "CreativeWork"})
    assert validate_json_ld(content, "index.html", 7) == []


def test_json_ld_array_with_per_node_context_valid():
    content = json.dumps([{"@context": CONTEXT, "@type": "WebPage"}, {"@context": CONTEXT, "@type": "Thing"}])
    assert validate_json_ld(content, "index.html", 7) == []


def test_json_ld_malformed_syntax_reports_source_line():
    issues = validate_json_ld('{\n"@context":', "index.html", 8)
    assert issues[0].code == "LD_JSON_SYNTAX"
    assert issues[0].line == 9


@pytest.mark.parametrize("source,code", [
    ('"text"', "LD_ROOT"),
    ('[]', "LD_ROOT"),
    ('{"@type":"Thing"}', "LD_CONTEXT_MISSING"),
    ('{"@context":"https://unrelated.example","@type":"Thing"}', "LD_CONTEXT"),
    ('{"@context":"https://schema.org","@type":[]}', "LD_TYPE"),
    ('{"@context":"https://schema.org","@type":7}', "LD_TYPE"),
    ('{"@context":"https://schema.org","@graph":[]}', "LD_GRAPH"),
    ('{"@context":"https://schema.org","@graph":[4]}', "LD_NODE"),
    ('{"@context":"https://schema.org","name":"value"}', "LD_TYPE_MISSING"),
    ('{"@context":"https://schema.org","@type":"Thing","@id":77}', "LD_ID"),
    ('{"@context":"https://schema.org","@type":"A","@type":"B"}', "LD_DUPLICATE_KEY"),
])
def test_json_ld_invalid_structures(source, code):
    assert code in [finding.code for finding in validate_json_ld(source, "index.html", 1)]


def test_script_type_case_and_attributes_are_supported(tmp_path):
    html = '<script type="APPLICATION/LD+JSON; charset=UTF-8">{"@context":"https://schema.org","@type":"Thing"}</script>'
    result = audit_site(site(tmp_path, html))
    assert result.findings == [] and result.json_ld_blocks == 1


def test_json_ld_bad_inline_block(tmp_path):
    result = audit_site(site(tmp_path, '<script type="application/ld+json">{bad}</script>'))
    assert "LD_JSON_SYNTAX" in codes(result)


def test_lint_does_not_claim_remote_vocabulary_verification():
    content = json.dumps({"@context": CONTEXT, "@type": "FutureUnknownVocabularyClass"})
    assert validate_json_ld(content, "index.html", 4) == []


def test_cli_json_machine_readable_and_clean_exit(tmp_path):
    site(tmp_path)
    process = subprocess.run([sys.executable, str(TOOL), "--root", str(tmp_path), "--format", "json"], capture_output=True, text=True, check=False, env={**os.environ, "SITE_AUDIT_ENABLED": "1"})
    assert process.returncode == 0
    assert json.loads(process.stdout)["errors"] == 0


def test_cli_fails_on_error_by_default(tmp_path):
    site(tmp_path, '<a href="none.html">Broken</a>')
    process = subprocess.run([sys.executable, str(TOOL), "--root", str(tmp_path)], capture_output=True, text=True, check=False, env={**os.environ, "SITE_AUDIT_ENABLED": "1"})
    assert process.returncode == 1
    assert "LINK_TARGET_MISSING" in process.stdout


def test_cli_warning_gate(tmp_path):
    site(tmp_path, '<a href="javascript:void(0)">Script</a>')
    args = [sys.executable, str(TOOL), "--root", str(tmp_path), "--fail-on", "warning"]
    result = subprocess.run(args, capture_output=True, text=True, check=False, env={**os.environ, "SITE_AUDIT_ENABLED": "1"})
    assert result.returncode == 1
    args[-1] = "none"
    assert subprocess.run(args, capture_output=True, text=True, check=False, env={**os.environ, "SITE_AUDIT_ENABLED": "1"}).returncode == 0


def tree_digest(root: Path) -> dict[str, str]:
    return {p.relative_to(root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for p in root.rglob("*") if p.is_file()}


def test_on_is_read_only_and_off_is_bit_identical(tmp_path):
    root = site(tmp_path, '<img src="missing.png"><a href="gone.html">Broken</a>')
    before = tree_digest(root)
    assert audit_site(root, enabled=True).findings
    assert tree_digest(root) == before
    assert not audit_site(root, enabled=False).findings
    assert tree_digest(root) == before
    process = subprocess.run([sys.executable, str(TOOL), "--root", str(root), "--format", "json"], capture_output=True, text=True, check=False, env={**os.environ, "SITE_AUDIT_ENABLED": "0"})
    assert process.returncode == 0 and process.stdout == "" and process.stderr == ""
    assert tree_digest(root) == before


def test_off_does_not_even_need_an_existing_root(tmp_path):
    report = audit_site(tmp_path / "missing", enabled=False)
    assert report.enabled is False and report.findings == []


def test_json_diagnostics_are_stably_sorted(tmp_path):
    root = site(tmp_path, '<img src="not.png"><a href="bad.html">Broken</a>')
    report = audit_site(root)
    serialized = report.as_json()
    assert serialized["findings"] == sorted(serialized["findings"], key=lambda v: (v["path"], v["line"], v["code"], v["severity"], v["message"]))


def test_default_https_port_and_explicit_https_port_are_equivalent(tmp_path):
    root = site(tmp_path, '<a href="https://site.example:443/index.html">Good</a>')
    assert audit_site(root, site_origin="https://site.example").findings == []

def test_blank_image_src_is_invalid(tmp_path):
    assert "IMG_SRC_EMPTY" in codes(audit_site(site(tmp_path, '<img src="" alt="Decorative">')))
