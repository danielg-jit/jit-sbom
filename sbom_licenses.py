#!/usr/bin/env python3
"""
Jit-SBOM: Clone a GitHub repo, discover manifest files, extract dependencies,
resolve each package's license via ecosystem registries, and write JSON/CSV
with repo name as root and licenses as keys containing package lists.
Private/unresolvable packages are grouped under "private".
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import nullcontext
from pathlib import Path
from typing import Any

try:
    import tomllib
except ImportError:
    import tomli as tomllib

import requests


# Manifest file name -> ecosystem
MANIFEST_ECOSYSTEM = {
    "package.json": "npm",
    "requirements.txt": "pip",
    "Pipfile": "pip",
    "pyproject.toml": "pip",
    "go.mod": "go",
    "Cargo.toml": "rust",
}

REGISTRY_DELAY_SEC = 0.2
MAX_WORKERS = 6

# Map license string variants to a canonical key (SPDX-style where possible).
# Registers return the same license under different names; we consolidate.
LICENSE_NORMALIZE: dict[str, str] = {
    # MIT
    "MIT": "MIT",
    "MIT License": "MIT",
    "MIT license": "MIT",
    "OSI Approved :: MIT License": "MIT",
    # Apache 2.0
    "Apache": "Apache-2.0",
    "Apache 2": "Apache-2.0",
    "Apache 2.0": "Apache-2.0",
    "Apache 2.0 License": "Apache-2.0",
    "Apache License 2.0": "Apache-2.0",
    "Apache License Version 2.0": "Apache-2.0",
    "Apache License, Version 2.0": "Apache-2.0",
    "Apache Software License": "Apache-2.0",
    "Apache Software License 2.0": "Apache-2.0",
    "Apache-2.0": "Apache-2.0",
    "Apache-2.0 license": "Apache-2.0",
    "OSI Approved :: Apache Software License": "Apache-2.0",
    "http://www.apache.org/licenses/LICENSE-2.0": "Apache-2.0",
    # BSD
    "BSD": "BSD-3-Clause",
    "BSD 3-Clause": "BSD-3-Clause",
    "BSD 3-Clause License": "BSD-3-Clause",
    "BSD License": "BSD-3-Clause",
    "new BSD License": "BSD-3-Clause",
    "OSI Approved :: BSD License": "BSD-3-Clause",
    "BSD-2-Clause": "BSD-2-Clause",
    "BSD-3-Clause": "BSD-3-Clause",
    # ISC
    "ISC": "ISC",
    "ISC license": "ISC",
    "OSI Approved :: ISC License (ISCL)": "ISC",
    # LGPL
    "LGPL": "LGPL-3.0-or-later",
    "LGPL v3": "LGPL-3.0-or-later",
    "LGPL-2.1": "LGPL-2.1",
    "LGPL-3.0-or-later": "LGPL-3.0-or-later",
    "OSI Approved :: GNU Library or Lesser General Public License (LGPL)": "LGPL-3.0-or-later",
    # GPL
    "GPL": "GPL-3.0",
    "GPL-2.0": "GPL-2.0",
    "GPL-3.0": "GPL-3.0",
    # MPL
    "MPL-2.0": "MPL-2.0",
    # PSF
    "PSF": "PSF-2.0",
    "PSFL": "PSF-2.0",
    "OSI Approved :: Python Software Foundation License": "PSF-2.0",
    # Unlicense (merge UNLICENSED / Unlicense to same key)
    "Unlicense": "Unlicense",
    "UNLICENSED": "Unlicense",
    "OSI Approved :: The Unlicense (Unlicense)": "Unlicense",
    # Other
    "0BSD": "0BSD",
    "UNKNOWN": "unknown",
    "EPL-2.0": "EPL-2.0",
    "Dual License": "unknown",
    "Universal Permissive License 1.0": "UPL-1.0",
    "UPL-1.0": "UPL-1.0",
}


def normalize_license(license_key: str) -> str:
    """Map common license string variants to a canonical key.
    Long license text from PyPI/registries (full license body) is normalized
    via substring checks so e.g. all Apache 2.0 and BSD-3-Clause text merge.
    """
    s = (license_key or "").strip()
    if not s:
        return "unknown"
    if s in LICENSE_NORMALIZE:
        return LICENSE_NORMALIZE[s]
    s_lower = s.lower()
    # "SEE LICENSE IN <file>" style (license in repo file, not a name)
    if s_lower.startswith("see license in"):
        return "unknown"
    # URL used as license (e.g. http://www.dnspython.org/LICENSE)
    if s.startswith("http://") or s.startswith("https://"):
        return "unknown"
    # Vinay Sajip / "See LICENSE for license" (e.g. Python logging-related)
    if "Vinay Sajip" in s and ("See LICENSE" in s or "All Rights Reserved" in s):
        return "unknown"
    # Multi-license description like "public domain, Python, 2-Clause BSD, GPL 3 (see COPYING.txt)"
    if "public domain" in s_lower and (
        "2-clause bsd" in s_lower or "gpl" in s_lower or "copying" in s_lower
    ):
        return "unknown"
    # Normalize long license text (PyPI often returns full license body)
    if len(s) > 200:
        s_lower = s.lower()
        # Apache License 2.0 (full or truncated text)
        if "apache license" in s_lower and (
            "version 2.0" in s_lower
            or "www.apache.org" in s_lower
            or "terms and conditions" in s_lower
        ):
            return "Apache-2.0"
        # BSD 3-Clause / Modified BSD (Jupyter, IPython, terminado, etc.)
        if (
            "modified bsd" in s_lower
            or "3-clause bsd" in s_lower
            or "revised or 3-clause bsd" in s_lower
            or "bsd 3-clause" in s_lower
            or ("bsd license" in s_lower and "redistribution" in s_lower)
            or ("licensing terms" in s_lower and "modified bsd" in s_lower)
            or ("# licensing terms" in s_lower and "bsd" in s_lower)
        ):
            return "BSD-3-Clause"
        # MIT (long form)
        if "permission is hereby granted" in s_lower and (
            "mit" in s_lower[:200] or "without restriction" in s_lower
        ):
            return "MIT"
    # Shorter but still verbose BSD variants
    if len(s) > 50:
        s_lower = s.lower()
        if "bsd 3-clause license" in s_lower and "redistribution" in s_lower:
            return "BSD-3-Clause"
        if "apache license" in s_lower and "version 2.0" in s_lower:
            return "Apache-2.0"
    # Long license text that is clearly MIT (original heuristic)
    if len(s) > 100 and "Permission is hereby granted" in s and "MIT" in s[:50]:
        return "MIT"
    return s


def _expand_license_key(license_key: str) -> list[str]:
    """
    Return one or more normalized license keys. Only short SPDX-style compound
    expressions (e.g. "(MIT OR GPL-3.0)" or "(Apache-2.0 OR BSD-3-Clause) AND PSF-2.0")
    are expanded so the package appears under each constituent license. Long
    license text is not split (it would create garbage keys from " AND " in prose).
    """
    raw = (license_key or "").strip()
    if not raw:
        return ["unknown"]
    # Only expand short compound expressions; long text often contains " AND " / " OR " in prose
    has_or_and = (
        " OR " in raw or " AND " in raw or " or " in raw or " and " in raw
    )
    is_compound = (
        len(raw) < 120
        and has_or_and
        and (
            "(" in raw
            or raw[0].isalnum()
            or raw.startswith("Apache")
            or raw.startswith("BSD")
            or raw.startswith("MIT")
            or raw.startswith("Universal")
        )
    )
    if not is_compound:
        return [normalize_license(raw)]
    # Split by OR and AND (and lowercase variants), strip parens/whitespace, normalize
    tokens: list[str] = [raw]
    for sep in (" OR ", " AND ", " or ", " and "):
        next_tokens: list[str] = []
        for t in tokens:
            next_tokens.extend(t.split(sep))
        tokens = next_tokens
    seen: set[str] = set()
    result: list[str] = []
    for t in tokens:
        part = t.strip().strip("()").strip()
        if not part or len(part) > 80:
            continue
        norm = normalize_license(part)
        if norm and norm not in seen:
            seen.add(norm)
            result.append(norm)
    return result if result else [normalize_license(raw)]


_thread_local = threading.local()


def _get_session() -> requests.Session:
    """One session per thread for parallel registry requests."""
    if not getattr(_thread_local, "session", None):
        _thread_local.session = requests.Session()
        _thread_local.session.headers.setdefault("User-Agent", "jit-sbom/1.0")
    return _thread_local.session


def _normalize_version(version: str | None) -> str | None:
    """Strip ^ ~ etc. to get a concrete version for registry requests. None if empty."""
    if not version or not isinstance(version, str):
        return None
    v = version.strip().lstrip("^~=>=<!")
    v = v.split()[0] if v else None
    return v if v else None


def normalize_repo_url(repo: str) -> tuple[str, str]:
    """Return (owner/repo, repo_slug) for CLI/URL. repo_slug for filenames."""
    repo = repo.strip().rstrip("/")
    if repo.startswith("https://github.com/"):
        repo = repo.replace("https://github.com/", "")
    elif repo.startswith("git@github.com:"):
        repo = repo.replace("git@github.com:", "").replace(".git", "")
    repo = repo.replace(".git", "")
    if "/" not in repo:
        raise ValueError(
            f"Invalid repo: expected owner/repo or full GitHub URL, got {repo!r}"
        )
    owner, name = repo.split("/", 1)
    repo_slug = f"{owner}-{name}"
    return repo, repo_slug


def clone_repo(repo: str, dest: Path) -> None:
    """Clone repo (owner/repo or URL) into dest. Shallow clone."""
    url = f"https://github.com/{repo}" if "/" in repo and not repo.startswith("http") else repo
    if not url.startswith("https://github.com/"):
        url = f"https://github.com/{repo}"
    subprocess.run(
        ["git", "clone", "--depth", "1", url, str(dest)],
        check=True,
        capture_output=True,
        text=True,
    )


def discover_manifests(clone_dir: Path) -> list[tuple[Path, str]]:
    """Walk clone_dir (skip .git), return (path, ecosystem) for manifest names."""
    out: list[tuple[Path, str]] = []
    for root, _dirs, files in os.walk(clone_dir):
        if ".git" in root:
            continue
        for f in files:
            if f in MANIFEST_ECOSYSTEM:
                out.append((Path(root) / f, MANIFEST_ECOSYSTEM[f]))
    return out


def _parse_package_json(path: Path) -> list[tuple[str, str | None]]:
    """Extract (name, version) from package.json; skip file:/link:/workspace:."""
    out: list[tuple[str, str | None]] = []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return out
    for key in ("dependencies", "devDependencies", "optionalDependencies"):
        deps = data.get(key)
        if not isinstance(deps, dict):
            continue
        for spec, version in deps.items():
            if isinstance(version, str) and (
                version.startswith("file:")
                or version.startswith("link:")
                or version == "workspace:*"
            ):
                continue
            name = (
                spec.removeprefix("npm:") if isinstance(spec, str) else spec
            )
            if name:
                ver = _normalize_version(version) if isinstance(version, str) else None
                out.append((name, ver))
    return out


def _parse_requirements_txt(path: Path) -> list[tuple[str, str | None]]:
    """Extract (name, version) from requirements.txt; skip -r, -e, comments."""
    out: list[tuple[str, str | None]] = []
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return out
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("-r ") or line.startswith("-e ") or line.startswith("--"):
            continue
        base = line.split("[")[0].strip()
        parts = re.split(r"==|>=|<=|!=|~=|>|<", base, maxsplit=1)
        name = parts[0].strip() if parts else ""
        version = parts[1].strip() if len(parts) > 1 else None
        if name:
            out.append((name, _normalize_version(version)))
    return out


def _parse_pipfile(path: Path) -> list[tuple[str, str | None]]:
    """Extract (name, version) from Pipfile [packages] and [dev-packages]."""
    out: list[tuple[str, str | None]] = []
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (tomllib.TOMLDecodeError, OSError):
        return out
    for key in ("packages", "dev-packages"):
        section = data.get(key)
        if not isinstance(section, dict):
            continue
        for name, val in section.items():
            if not isinstance(name, str) or not name:
                continue
            ver = None
            if isinstance(val, str) and val != "*":
                ver = _normalize_version(val)
            elif isinstance(val, dict) and "version" in val:
                ver = _normalize_version(str(val["version"]))
            out.append((name, ver))
    return out


def _parse_pyproject_toml(path: Path) -> list[tuple[str, str | None]]:
    """Extract (name, version) from pyproject.toml project.dependencies (PEP 621)."""
    out: list[tuple[str, str | None]] = []
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (tomllib.TOMLDecodeError, OSError):
        return out
    project = data.get("project")
    if not isinstance(project, dict):
        return out
    deps = project.get("dependencies")
    if not isinstance(deps, list):
        return out
    for spec in deps:
        if not isinstance(spec, str):
            continue
        base = spec.strip().split("[")[0].strip()
        parts = re.split(r"==|>=|<=|!=|~=|>|<", base, maxsplit=1)
        name = parts[0].strip() if parts else ""
        version = parts[1].strip() if len(parts) > 1 else None
        if name:
            out.append((name, _normalize_version(version)))
    return out


def _parse_go_mod(path: Path) -> list[tuple[str, str | None]]:
    """Extract (module_path, version) from go.mod require block."""
    out: list[tuple[str, str | None]] = []
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return out
    in_require = False
    for line in text.splitlines():
        line = line.strip()
        if line == "require (":
            in_require = True
            continue
        if in_require:
            if line == ")":
                break
            parts = line.split()
            if len(parts) >= 2:
                mod = parts[0]
                ver = parts[1].strip() if len(parts) > 1 else None
                out.append((mod, _normalize_version(ver)))
    return out


def _parse_cargo_toml(path: Path) -> list[tuple[str, str | None]]:
    """Extract (crate_name, version) from Cargo.toml deps; skip path =."""
    out: list[tuple[str, str | None]] = []
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (tomllib.TOMLDecodeError, OSError):
        return out
    for key in ("dependencies", "dev-dependencies"):
        section = data.get(key)
        if not isinstance(section, dict):
            continue
        for name, val in section.items():
            if isinstance(val, dict) and val.get("path") is not None:
                continue
            if not isinstance(name, str) or not name:
                continue
            ver = None
            if isinstance(val, str):
                ver = _normalize_version(val)
            elif isinstance(val, dict) and "version" in val:
                ver = _normalize_version(str(val["version"]))
            out.append((name, ver))
    return out


def extract_packages(
    manifest_path: Path, ecosystem: str
) -> list[tuple[str, str | None]]:
    """Parse manifest and return list of (package_name, version)."""
    if ecosystem == "npm":
        return _parse_package_json(manifest_path)
    if ecosystem == "pip":
        if manifest_path.name == "requirements.txt":
            return _parse_requirements_txt(manifest_path)
        if manifest_path.name == "Pipfile":
            return _parse_pipfile(manifest_path)
        if manifest_path.name == "pyproject.toml":
            return _parse_pyproject_toml(manifest_path)
    if ecosystem == "go":
        return _parse_go_mod(manifest_path)
    if ecosystem == "rust":
        return _parse_cargo_toml(manifest_path)
    return []


def resolve_license_npm(
    package_name: str,
    session: requests.Session,
    version: str | None = None,
    errors: list[str] | None = None,
    errors_lock: threading.Lock | None = None,
) -> str:
    """Resolve npm package license; return 'private' on 404 or private."""
    if version:
        url = f"https://registry.npmjs.org/{package_name}/{version}"
    else:
        url = f"https://registry.npmjs.org/{package_name}"
    try:
        r = session.get(url, timeout=15)
        if r.status_code == 404:
            return "private"
        r.raise_for_status()
        data = r.json()
        if data.get("private") is True:
            return "private"
        license_val = data.get("license")
        if isinstance(license_val, str) and license_val:
            return license_val.strip() or "unknown"
        licenses = data.get("licenses")
        if isinstance(licenses, list) and licenses:
            first = licenses[0]
            if isinstance(first, dict) and first.get("type"):
                return str(first["type"]).strip() or "unknown"
        return "unknown"
    except Exception as e:
        if errors is not None:
            if errors_lock is not None:
                with errors_lock:
                    errors.append(f"npm/{package_name}: {e!r}")
            else:
                errors.append(f"npm/{package_name}: {e!r}")
        return "private"


def resolve_license_pypi(
    package_name: str,
    session: requests.Session,
    version: str | None = None,
    errors: list[str] | None = None,
    errors_lock: threading.Lock | None = None,
) -> str:
    """Resolve PyPI package license; return 'private' on 404 or private."""
    if version:
        url = f"https://pypi.org/pypi/{package_name}/{version}/json"
    else:
        url = f"https://pypi.org/pypi/{package_name}/json"
    try:
        r = session.get(url, timeout=15)
        if r.status_code == 404:
            return "private"
        r.raise_for_status()
        data = r.json()
        info = data.get("info") or {}
        license_str = info.get("license") or info.get("license_text")
        if isinstance(license_str, str) and license_str.strip():
            return license_str.strip()
        classifiers = info.get("classifiers") or []
        for c in classifiers:
            if isinstance(c, str) and c.startswith("License ::"):
                return c.replace("License ::", "").strip() or "unknown"
        return "unknown"
    except Exception as e:
        if errors is not None:
            if errors_lock is not None:
                with errors_lock:
                    errors.append(f"pip/{package_name}: {e!r}")
            else:
                errors.append(f"pip/{package_name}: {e!r}")
        return "private"


def resolve_license_crates(
    package_name: str,
    session: requests.Session,
    version: str | None = None,
    errors: list[str] | None = None,
    errors_lock: threading.Lock | None = None,
) -> str:
    """Resolve crates.io license; return 'private' on 404 or private."""
    url = (
        f"https://crates.io/api/v1/crates/{package_name}/{version}"
        if version
        else f"https://crates.io/api/v1/crates/{package_name}"
    )
    try:
        r = session.get(url, timeout=15)
        if r.status_code == 404 and version:
            url = f"https://crates.io/api/v1/crates/{package_name}"
            r = session.get(url, timeout=15)
        if r.status_code == 404:
            return "private"
        r.raise_for_status()
        data = r.json()
        crate = data.get("crate") or data
        if not isinstance(crate, dict):
            return "private"
        license_val = crate.get("license")
        if isinstance(license_val, str) and license_val.strip():
            return license_val.strip()
        return "unknown"
    except Exception as e:
        if errors is not None:
            if errors_lock is not None:
                with errors_lock:
                    errors.append(f"rust/{package_name}: {e!r}")
            else:
                errors.append(f"rust/{package_name}: {e!r}")
        return "private"


def resolve_license_go(
    module_path: str,
    session: requests.Session,
    version: str | None = None,
    errors: list[str] | None = None,
    errors_lock: threading.Lock | None = None,
) -> str:
    """Resolve Go module; if inaccessible return 'private'."""
    if version:
        url = f"https://proxy.golang.org/{module_path}/@v/{version}.info"
    else:
        url = f"https://proxy.golang.org/{module_path}/@v/list"
    try:
        r = session.get(url, timeout=15)
        if r.status_code == 404:
            return "private"
        r.raise_for_status()
        return "private"
    except Exception as e:
        if errors is not None:
            if errors_lock is not None:
                with errors_lock:
                    errors.append(f"go/{module_path}: {e!r}")
            else:
                errors.append(f"go/{module_path}: {e!r}")
        return "private"


def resolve_license(
    ecosystem: str,
    package_name: str,
    session: requests.Session,
    version: str | None = None,
    errors: list[str] | None = None,
    errors_lock: threading.Lock | None = None,
    license_cache: dict[tuple[str, str, str | None], str] | None = None,
    license_cache_lock: threading.Lock | None = None,
) -> str:
    """Resolve license for (ecosystem, package_name[, version]). Returns str or 'private'."""
    cache_key = (ecosystem, package_name, version)
    if license_cache is not None:
        with (license_cache_lock if license_cache_lock else nullcontext()):
            if cache_key in license_cache:
                return license_cache[cache_key]
    time.sleep(REGISTRY_DELAY_SEC)
    if ecosystem == "npm":
        result = resolve_license_npm(
            package_name, session, version, errors, errors_lock
        )
    elif ecosystem == "pip":
        result = resolve_license_pypi(
            package_name, session, version, errors, errors_lock
        )
    elif ecosystem == "rust":
        result = resolve_license_crates(
            package_name, session, version, errors, errors_lock
        )
    elif ecosystem == "go":
        result = resolve_license_go(
            package_name, session, version, errors, errors_lock
        )
    else:
        result = "private"
    result = (result.strip() or "private")
    if license_cache is not None and license_cache_lock is not None:
        with license_cache_lock:
            license_cache[cache_key] = result
    return result


def _resolve_one(
    item: tuple[str, str, str | None],
    errors: list[str],
    errors_lock: threading.Lock,
    license_cache: dict[tuple[str, str, str | None], str] | None = None,
    license_cache_lock: threading.Lock | None = None,
) -> tuple[str, str]:
    """Worker: resolve license for one package; return (name, license_key)."""
    ecosystem, name, version = item
    session = _get_session()
    license_key = resolve_license(
        ecosystem,
        name,
        session,
        version,
        errors,
        errors_lock,
        license_cache,
        license_cache_lock,
    )
    return (name, normalize_license(license_key.strip() or "private"))


def aggregate_by_license(
    packages: list[tuple[str, str, str | None]],
    session: requests.Session,
    errors: list[str] | None = None,
    license_cache: dict[tuple[str, str, str | None], str] | None = None,
    license_cache_lock: threading.Lock | None = None,
) -> dict[str, list[str]]:
    """Dedupe by (ecosystem, name), resolve license in parallel; return {license: [pkg]}."""
    seen: set[tuple[str, str]] = set()
    deduped: list[tuple[str, str, str | None]] = []
    for ecosystem, name, version in packages:
        key = (ecosystem, name)
        if key in seen:
            continue
        seen.add(key)
        deduped.append((ecosystem, name, version))
    by_license: dict[str, list[str]] = {}
    if errors is None:
        errors = []
    errors_lock = threading.Lock()
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {
            executor.submit(
                _resolve_one,
                item,
                errors,
                errors_lock,
                license_cache,
                license_cache_lock,
            ): item
            for item in deduped
        }
        for future in as_completed(futures):
            try:
                name, license_key = future.result()
                if license_key not in by_license:
                    by_license[license_key] = []
                by_license[license_key].append(name)
            except Exception:
                pass
    return by_license


def _print_errors(errors: list[str]) -> None:
    """Print all collected errors to stderr for debugging."""
    if not errors:
        return
    print(f"\nErrors ({len(errors)}):", file=sys.stderr)
    for err in errors:
        print(f"  - {err}", file=sys.stderr)


def _print_summary_table(
    summary: list[tuple[str, str, float, int, list[str]]],
    total_duration: float,
) -> None:
    """Print summary table: repo, status, duration, error count. Then total duration."""
    print("\n" + "=" * 80, file=sys.stderr)
    print("SUMMARY", file=sys.stderr)
    print("=" * 80, file=sys.stderr)
    col_repo = 42
    col_status = 22
    col_duration = 10
    col_errors = 8
    header = (
        f"{'Repo':<{col_repo}} "
        f"{'Status':<{col_status}} "
        f"{'Duration':<{col_duration}} "
        f"{'Errors':<{col_errors}}"
    )
    print(header, file=sys.stderr)
    print("-" * (col_repo + col_status + col_duration + col_errors + 3), file=sys.stderr)
    for repo, status, duration_sec, error_count, repo_errors in summary:
        repo_short = repo if len(repo) <= col_repo else "..." + repo[-(col_repo - 3) :]
        print(
            f"{repo_short:<{col_repo}} "
            f"{status:<{col_status}} "
            f"{duration_sec:.1f}s     "
            f"{error_count:<{col_errors}}",
            file=sys.stderr,
        )
        if repo_errors:
            for err in repo_errors[:3]:
                print(f"    - {err}", file=sys.stderr)
            if len(repo_errors) > 3:
                print(f"    ... and {len(repo_errors) - 3} more", file=sys.stderr)
    print("-" * (col_repo + col_status + col_duration + col_errors + 3), file=sys.stderr)
    print(f"Total duration: {total_duration:.1f}s", file=sys.stderr)
    print("=" * 80, file=sys.stderr)


def write_output(
    repo_slug: str,
    result: dict[str, list[str]],
    output_dir: Path,
    json_only: bool,
) -> None:
    """Write licenses_<repo_slug>.json and optionally licenses_<repo_slug>.csv."""
    output_dir.mkdir(parents=True, exist_ok=True)
    payload: dict[str, Any] = {repo_slug: result}
    json_path = output_dir / f"licenses_{repo_slug}.json"
    json_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    if not json_only:
        csv_path = output_dir / f"licenses_{repo_slug}.csv"
        with csv_path.open("w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["repo", "license", "package"])
            for license_key, pkgs in result.items():
                for pkg in pkgs:
                    w.writerow([repo_slug, license_key, pkg])


def build_license_summary(results_dir: Path) -> dict[str, dict[str, list[str]]]:
    """
    Read all licenses_<repo>.json in results_dir and build a single summary:
    license -> package -> list of repo_slugs where that package appears under that license.
    Repo-specific result files are not modified or removed.
    License keys are normalized so variants (e.g. Apache License 2.0 / Apache-2.0) merge.
    """
    summary: dict[str, dict[str, list[str]]] = {}
    pattern = "licenses_*.json"
    for path in results_dir.glob(pattern):
        if path.name == "licenses_summary.json":
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue
        if not isinstance(data, dict) or len(data) != 1:
            continue
        repo_slug, by_license = next(iter(data.items()))
        if not isinstance(by_license, dict):
            continue
        for license_key, packages in by_license.items():
            raw_key = (
                license_key.strip() if isinstance(license_key, str) else str(license_key)
            )
            # Expand OR/AND so package appears under each license key, not under a combined key
            norm_licenses = _expand_license_key(raw_key)
            for pkg in packages if isinstance(packages, list) else []:
                if not isinstance(pkg, str) or not pkg:
                    continue
                for norm_license in norm_licenses:
                    if norm_license not in summary:
                        summary[norm_license] = {}
                    if pkg not in summary[norm_license]:
                        summary[norm_license][pkg] = []
                    if repo_slug not in summary[norm_license][pkg]:
                        summary[norm_license][pkg].append(repo_slug)
    for license_key in summary:
        summary[license_key] = dict(sorted(summary[license_key].items()))
    return dict(sorted(summary.items()))


def write_summary_file(summary: dict[str, dict[str, list[str]]], output_dir: Path) -> Path:
    """Write licenses_summary.json; create output_dir if needed. Returns path written."""
    output_dir.mkdir(parents=True, exist_ok=True)
    out_path = output_dir / "licenses_summary.json"
    out_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return out_path


def process_repo(
    repo: str,
    output_dir: Path,
    json_only: bool,
    license_cache: dict[tuple[str, str, str | None], str] | None = None,
    license_cache_lock: threading.Lock | None = None,
) -> tuple[dict[str, Any], list[str]]:
    """
    Clone repo, discover manifests, extract packages, resolve licenses, write.
    Always removes the temporary clone (in finally). Never raises; errors are
    collected and printed at the end.
    Returns (result, errors) where result is {repo_slug: {license: [pkgs]}}.
    """
    errors: list[str] = []
    try:
        repo_normalized, repo_slug = normalize_repo_url(repo)
    except Exception as e:
        errors.append(f"Invalid repo: {e!r}")
        _print_errors(errors)
        return ({}, errors)
    clone_dir = Path(tempfile.mkdtemp(prefix=f"jit_sbom_{repo_slug}_"))
    start = time.perf_counter()
    try:
        print("Cloning repo...", file=sys.stderr)
        try:
            clone_repo(repo_normalized, clone_dir)
        except Exception as e:
            errors.append(f"Clone: {e!r}")
        print("Done cloning repo.", file=sys.stderr)
        print("Discovering manifests...", file=sys.stderr)
        try:
            manifests = discover_manifests(clone_dir)
        except Exception as e:
            errors.append(f"Discover manifests: {e!r}")
            manifests = []
        print(f"Found {len(manifests)} manifest(s).", file=sys.stderr)
        if not manifests:
            print("Warning: no manifest files found.", file=sys.stderr)
        print("Extracting packages...", file=sys.stderr)
        all_packages: list[tuple[str, str, str | None]] = []
        for path, ecosystem in manifests:
            try:
                for name, version in extract_packages(path, ecosystem):
                    all_packages.append((ecosystem, name, version))
            except Exception as e:
                errors.append(f"Extract {path}: {e!r}")
        print(f"Found {len(all_packages)} package(s).", file=sys.stderr)
        print("Resolving licenses...", file=sys.stderr)
        session = requests.Session()
        session.headers.setdefault("User-Agent", "jit-sbom/1.0")
        by_license = aggregate_by_license(
            all_packages,
            session,
            errors,
            license_cache,
            license_cache_lock,
        )
        print("Writing output...", file=sys.stderr)
        try:
            write_output(repo_slug, by_license, output_dir, json_only)
        except Exception as e:
            errors.append(f"Write output: {e!r}")
        elapsed = time.perf_counter() - start
        print(f"Done in {elapsed:.1f}s.", file=sys.stderr)
        _print_errors(errors)
        return ({repo_slug: by_license}, errors)
    finally:
        if clone_dir.exists():
            shutil.rmtree(clone_dir, ignore_errors=True)


def _get_repo_list(args: argparse.Namespace) -> list[str]:
    """Build list of repos from --repos-file, --repos, or positional repo."""
    if args.repos_file is not None:
        path = Path(args.repos_file)
        if not path.exists():
            raise FileNotFoundError(f"Repos file not found: {path}")
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, list):
            raise ValueError("Repos file must be a JSON array of repo strings")
        return [str(r).strip() for r in data if r]
    if args.repos is not None:
        return [r.strip() for r in args.repos.split(",") if r.strip()]
    if args.repo:
        return [args.repo.strip()]
    raise ValueError(
        "Provide one of: repo (positional), --repos-file FILE, or --repos repo1,repo2,..."
    )


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Clone GitHub repo(s), extract deps from manifests, "
            "resolve licenses, write JSON/CSV."
        )
    )
    parser.add_argument(
        "repo",
        nargs="?",
        default=None,
        help="Single repo: owner/repo or URL (omit if using --repos-file or --repos)",
    )
    parser.add_argument(
        "--repos-file",
        "-f",
        type=Path,
        default=None,
        help="JSON file with array of repo strings (e.g. [\"owner/repo\", ...])",
    )
    parser.add_argument(
        "--repos",
        type=str,
        default=None,
        help="Comma-separated repos: repo1,repo2,...",
    )
    parser.add_argument(
        "--output-dir",
        "-o",
        type=Path,
        default=Path.cwd() / "results",
        help="Dir for licenses_<repo>.json and .csv (default: ./results)",
    )
    parser.add_argument(
        "--csv",
        action="store_true",
        help="Also write CSV files (default: JSON only)",
    )
    parser.add_argument(
        "--no-summary",
        action="store_true",
        help="Do not build licenses_summary.json after processing (summary is on by default).",
    )
    parser.add_argument(
        "--summary-only",
        action="store_true",
        help="Only build licenses_summary.json from existing files in --output-dir; do not process repos.",
    )
    args = parser.parse_args()
    write_csv = args.csv
    output_dir = args.output_dir
    if args.summary_only:
        if not output_dir.exists():
            print(f"Error: output dir does not exist: {output_dir}", file=sys.stderr)
            return 1
        summary_data = build_license_summary(output_dir)
        out_path = write_summary_file(summary_data, output_dir)
        print(f"Wrote summary to {out_path}", file=sys.stderr)
        return 0
    try:
        repos = _get_repo_list(args)
    except (ValueError, FileNotFoundError) as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    try:
        if len(repos) == 1:
            process_repo(repos[0], output_dir, not write_csv)
            if not args.no_summary:
                summary_data = build_license_summary(output_dir)
                out_path = write_summary_file(summary_data, output_dir)
                print(f"Wrote summary to {out_path}", file=sys.stderr)
            return 0
        # Multi-repo: shared license cache, per-repo timing, summary table
        license_cache: dict[tuple[str, str, str | None], str] = {}
        license_cache_lock = threading.Lock()
        summary: list[tuple[str, str, float, int, list[str]]] = []
        total_start = time.perf_counter()
        for i, repo in enumerate(repos):
            print(f"\n[{i + 1}/{len(repos)}] {repo}", file=sys.stderr)
            repo_start = time.perf_counter()
            result, errors = process_repo(
                repo,
                output_dir,
                not write_csv,
                license_cache,
                license_cache_lock,
            )
            duration_sec = time.perf_counter() - repo_start
            status = "ok" if not errors else "completed_with_errors"
            summary.append((repo, status, duration_sec, len(errors), errors))
        total_duration = time.perf_counter() - total_start
        _print_summary_table(summary, total_duration)
        if not args.no_summary:
            summary_data = build_license_summary(output_dir)
            out_path = write_summary_file(summary_data, output_dir)
            print(f"Wrote summary to {out_path}", file=sys.stderr)
        return 0
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
