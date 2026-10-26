#!/usr/bin/env python3
"""Read the licence and notice inventory out of the artifacts themselves.

A licence matrix that is typed by hand is a claim about what someone remembered.
This script answers the questions a redistribution review actually asks, from the
bytes that will be shipped:

  * which distribution is this, which version, which licence does its metadata
    declare (PEP 639 `License-Expression` first, then the legacy `License`
    field and the Trove classifiers),
  * which licence and notice FILES does the wheel carry, and what is in them
    (first line, size, sha256) — an Apache-2.0 component with no `NOTICE` file
    is a different situation from one that has it,
  * does the source distribution carry the project's own LICENSE and the
    third-party notice file.

Usage:

    python scripts/license_matrix.py --set <dir> [--json out.json]

Exit code 0 = every distribution carries at least one licence file (the
mechanical minimum for redistribution); 1 = at least one carries none, which is
a real gap and is printed as such. Nothing here decides whether a licence
PERMITS redistribution — that is the counsel question, and the script says so
instead of pretending to answer it.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import tarfile
import zipfile
from pathlib import Path

#: A licence FILE is one of these names (case-insensitive stem). "notice" and
#: "authors" are deliberately NOT hints: a wheel that carries only an AUTHORS.md
#: and no licence text passed an earlier version of this check (independent
#: review, 2026-10-20), which is the one thing it must never do.
LICENCE_STEMS = {
    "license",
    "licence",
    "license.txt",
    "licence.txt",
    "license.md",
    "copying",
    "copying.txt",
}


def _is_licence_file(leaf: str) -> bool:
    return leaf.lower() in LICENCE_STEMS


def _looks_like_a_licence(data: bytes) -> bool:
    """Non-empty and not a placeholder.

    A zero-byte LICENSE satisfies a file-existence check and nothing else. The
    bar here is low but real: the text must be longer than a copyright line and
    must not be the string "TODO".
    """
    text = data.decode("utf-8", "replace").strip()
    return len(text) > 200 and text.lower() not in {"todo", "tbd", ""}


def _wheel_metadata(archive: zipfile.ZipFile) -> dict[str, str]:
    name = next(n for n in archive.namelist() if n.endswith(".dist-info/METADATA"))
    text = archive.read(name).decode("utf-8", "replace")
    fields: dict[str, str] = {}
    classifiers: list[str] = []
    for line in text.splitlines():
        if not line:
            break
        key, _, value = line.partition(": ")
        if key == "Classifier" and value.startswith("License ::"):
            classifiers.append(value)
        elif key and value:
            fields.setdefault(key, value)
    if classifiers:
        fields["Classifiers"] = "; ".join(classifiers)
    return fields


def _first_line(data: bytes) -> str:
    for raw in data.decode("utf-8", "replace").splitlines():
        if raw.strip():
            return raw.strip()[:120]
    return ""


def _notice_guest_digest(
    archive: zipfile.ZipFile, notice: str
) -> tuple[str, str] | None:
    """The digest of the embedded guest binary, and the digest its notice names.

    A guest wheel ships a notice that identifies the embedded runtime *by digest*.
    That identification is only worth something if the two agree, so they are
    compared here instead of being trusted: a notice that names a stale build is
    a redistribution-accuracy defect, not decoration.
    """
    guests = [n for n in archive.namelist() if n.endswith("/guest.wasm")]
    if len(guests) != 1:
        return None
    actual = hashlib.sha256(archive.read(guests[0])).hexdigest()
    text = archive.read(notice).decode("utf-8", "replace")
    match = re.search(r"sha256\s+([0-9a-f]{64})", text)
    return actual, (match.group(1) if match else "")


def inspect_wheel(path: Path) -> dict:
    with zipfile.ZipFile(path) as archive:
        meta = _wheel_metadata(archive)
        licence_files = []
        for member in sorted(archive.namelist()):
            leaf = member.rsplit("/", 1)[-1]
            if _is_licence_file(leaf) and "dist-info/" in member:
                data = archive.read(member)
                licence_files.append(
                    {
                        "member": member.split("dist-info/")[-1],
                        "size": len(data),
                        "sha256": hashlib.sha256(data).hexdigest(),
                        "first_line": _first_line(data),
                        "substantive": _looks_like_a_licence(data),
                    }
                )
        guest_digest = None
        notice = next(
            (m for m in archive.namelist() if m.endswith("/THIRD_PARTY_NOTICES.md")),
            None,
        )
        if notice and any(n.endswith("/guest.wasm") for n in archive.namelist()):
            pair = _notice_guest_digest(archive, notice)
            if pair:
                guest_digest = {"actual": pair[0], "notice_names": pair[1]}
    return {
        "name": meta.get("Name", ""),
        "version": meta.get("Version", ""),
        "license_expression": meta.get("License-Expression", ""),
        "license_field": meta.get("License", ""),
        "classifiers": meta.get("Classifiers", ""),
        "requires_dist": meta.get("Requires-Dist", ""),
        "license_files": licence_files,
        "guest_binary": guest_digest,
    }


def inspect_sdist(path: Path) -> dict:
    with tarfile.open(path) as archive:
        names = [m.name for m in archive.getmembers() if m.isfile()]
        found = []
        for name in names:
            leaf = name.rsplit("/", 1)[-1].lower()
            if (
                leaf in ("license", "license.txt", "license.md")
                or leaf == "third_party_notices.md"
            ):
                member = archive.extractfile(name)
                data = member.read() if member else b""
                found.append(
                    {
                        "member": name.split("/", 1)[-1],
                        "size": len(data),
                        "sha256": hashlib.sha256(data).hexdigest(),
                        "first_line": _first_line(data),
                    }
                )
    return {"name": path.name, "files": found}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--set", required=True, type=Path)
    parser.add_argument("--json", type=Path, default=None)
    args = parser.parse_args(argv)

    wheels = sorted(args.set.glob("*.whl"))
    sdists = sorted(args.set.glob("*.tar.gz"))
    if not wheels or not sdists:
        print(f"FAIL: {args.set} carries no wheels or no sdist")
        return 1

    report: dict[str, object] = {
        "wheels": [inspect_wheel(w) for w in wheels],
        "sdist": [inspect_sdist(s) for s in sdists],
    }

    gaps: list[str] = []
    for wheel in report["wheels"]:
        declared = wheel["license_expression"] or wheel["license_field"] or "—"
        print(f"\n{wheel['name']} {wheel['version']}")
        print(f"  declared licence : {declared}")
        if wheel["classifiers"]:
            print(f"  classifiers      : {wheel['classifiers']}")
        if wheel["requires_dist"]:
            print(f"  requires         : {wheel['requires_dist']}")
        if not wheel["license_files"]:
            gaps.append(f"{wheel['name']}: carries no licence file")
            print("  licence files    : NONE")
        elif not any(entry["substantive"] for entry in wheel["license_files"]):
            gaps.append(
                f"{wheel['name']}: every licence file is empty or a placeholder"
            )
        for entry in wheel["license_files"]:
            flag = "" if entry["substantive"] else "  [NOT A LICENCE TEXT]"
            print(
                f"  file {entry['member']:<34} {entry['size']:>7} B  "
                f"sha256 {entry['sha256'][:16]}  | {entry['first_line']}{flag}"
            )
        guest = wheel.get("guest_binary")
        if guest:
            ok = guest["actual"] == guest["notice_names"]
            print(
                f"  guest binary    : sha256 {guest['actual'][:16]}… "
                f"| notice names {guest['notice_names'][:16] or '(none)'}… "
                f"| {'match' if ok else 'MISMATCH'}"
            )
            if not ok:
                gaps.append(
                    f"{wheel['name']}: the notice names a different guest binary "
                    f"than the wheel contains"
                )
    for sdist in report["sdist"]:
        print(f"\n{sdist['name']}")
        for entry in sdist["files"]:
            print(
                f"  file {entry['member']:<34} {entry['size']:>7} B  "
                f"sha256 {entry['sha256'][:16]}  | {entry['first_line']}"
            )
        if not sdist["files"]:
            gaps.append(f"{sdist['name']}: carries no LICENSE")

    if args.json:
        args.json.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    print()
    if gaps:
        for gap in gaps:
            print(f"GAP: {gap}")
        return 1
    print(
        "OK: every distribution carries at least one licence file. Whether a licence "
        "PERMITS redistribution is a counsel question — see docs/license_matrix.md."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
