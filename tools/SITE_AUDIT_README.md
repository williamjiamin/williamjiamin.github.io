# Offline site audit

Private, read-only static-site validation for the site owner. Nothing in this package publishes, deploys, contacts a server, or modifies page markup.

## Usage

From the site repository root, with Python 3.11+:

```sh
python tools/site_audit.py --root .
python tools/site_audit.py --root . --format json
python tools/site_audit.py --root . --site-origin https://site.example --fail-on warning
```

Set `--site-origin` to the site's real HTTP(S) origin to include first-party **absolute** URLs in the local link check. Without it, relative and root-relative links are checked, while absolute URLs are treated as external. The audit never follows a remote link.

The script returns exit code `1` when the configured severity gate is met, `0` otherwise, and `2` for malformed CLI options. Its default gate is `error`. The optional warning gate fails on errors and warnings. `--fail-on none` allows an observation-only scan.

```sh
SITE_AUDIT_ENABLED=0 python tools/site_audit.py --root .
```

The environment kill switch above disables all auditing and produces **no stdout, no stderr, no site reads, no writes, and exit code 0**, restoring the prior behavior before the optional audit tool existed. The feature is **ON by default**. No HTML/CSS/image files are edited in either mode, so existing pixels and file bytes remain identical.

## Checks

- **Seller file:** parses the root `app-ads.txt` from disk; accepts `DIRECT` and `RESELLER` case-insensitively, three required and one optional field, comments, semicolon extension fields, ownership/management/domain directives, and forward-compatible unknown directives as warnings. Flags malformed fields and duplicate sellers.
- **Site references:** scans `.html` and `.htm` recursively; checks local `href` and `img[src]` targets, directory index resolution, extensionless pages, relative/absolute paths, HTML fragments, and missing `img[alt]`. An explicitly empty `alt` is allowed for decorative images. Does not follow symlinks out of the root.
- **Structured data:** parses inline `application/ld+json` scripts as strict JSON, detects duplicate keys, validates vocabulary context, checks basic `@type`, `@id`, `@graph` structure, and supports arrays and graph inheritance. This is **structural linting**, not a complete vocabulary, business-schema, or remote semantic validator.

Tool exclusions: hidden folders, dependency and cache directories, external destinations, CSS-generated assets, fetched/remote content, and non-HTML formats. Unavailable files in a partial repository snapshot can appear as missing links, so rerun against the full tree before acting on them.

## Tests

```sh
python -m pytest -q tests
```

The runtime uses only the Python standard library. The test runner is an optional developer dependency and no external libraries or sample assets are bundled.

## Integration

Copy the repo-relative files into the repository root, or use the `source_patch/apply.patch` provided in the return archive from the site root:

```sh
git apply --check /path/to/source_patch/apply.patch
git apply /path/to/source_patch/apply.patch
```

The patch only **adds** the isolated tool, tests, configuration, and this guide. Review it privately. No live branch or public resource is touched by the return archive.
