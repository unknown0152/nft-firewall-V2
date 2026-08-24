#!/usr/bin/env python3
"""Conservative source-shape check used for the v2.0.1 red proof.

This is not packet evidence.  Candidate Go and Stage R2 namespace tests must
prove behavior; this check only prevents accepting a repair that retains the
known broad reply rule or omits the declared provenance primitives entirely.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path


def go_source(root: Path, *subtrees: str) -> str:
    paths = sorted(
        path
        for subtree in subtrees
        for path in (root / subtree).glob("*.go")
        if not path.name.endswith("_test.go")
    )
    if not paths:
        raise RuntimeError(f"no Go source found under {', '.join(subtrees)}")
    return "\n".join(path.read_text(encoding="utf-8") for path in paths)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-root", required=True, type=Path)
    args = parser.parse_args()
    root = args.source_root.resolve()

    failures: list[str] = []
    try:
        config = go_source(root, "internal/config")
        compiler = go_source(root, "internal/compiler", "internal/provenance")
    except (OSError, RuntimeError) as exc:
        print(f"STAGE_R_PROVENANCE_CONTRACT: ERROR: {exc}", file=sys.stderr)
        return 2

    if not re.search(r"ProvenanceID\s+[^\n]+`toml:\"provenance_id\"`", config):
        failures.append("CONFIG_PROVENANCE_ID_MISSING")
    if "0xff000000" not in compiler:
        failures.append("PROVENANCE_MASK_MISSING")
    if "0x00ffffff" not in compiler:
        failures.append("PROVENANCE_KEEP_MASK_MISSING")
    if "ct direction original" not in compiler or "ct mark &" not in compiler:
        failures.append("WRITE_ONCE_ORIGINAL_DIRECTION_TAG_MISSING")

    # The compiler deliberately constructs provenance comments from the chain
    # name.  Require both the constructor and every expected call site so a
    # refactor cannot satisfy this check with an unused marker literal.
    marker_shapes = {
        "nftfw:provenance-tag-input:": (
            '"nftfw:provenance-tag-"+chain+":"',
            'emitProvenanceTags(b, c.Interfaces, "input")',
        ),
        "nftfw:provenance-tag-forward:": (
            '"nftfw:provenance-tag-"+chain+":"',
            'emitProvenanceTags(b, c.Interfaces, "forward")',
        ),
        "nftfw:provenance-reply-output:": (
            '"nftfw:provenance-reply-"+chain+":"',
            'emitProvenanceReplies(b, c.Interfaces, "output")',
        ),
        "nftfw:provenance-reply-forward:": (
            '"nftfw:provenance-reply-"+chain+":"',
            'emitProvenanceReplies(b, c.Interfaces, "forward")',
        ),
        "nftfw:input-reply-only": ("nftfw:input-reply-only",),
    }
    missing_markers = [
        marker
        for marker, required_shapes in marker_shapes.items()
        if not all(shape in compiler for shape in required_shapes)
    ]
    if missing_markers:
        failures.append("PROVENANCE_RULE_MARKERS_MISSING")

    broad_reply = re.compile(
        r'oifname %s ct direction reply ct state established,related accept '
        r'comment \\"nftfw:(?:uplink|forward-uplink)-reply-only\\"'
    )
    if broad_reply.search(compiler):
        failures.append("UNPROVEN_UPLINK_REPLY_STILL_PRESENT")
    if "nftfw:forward-established" in compiler:
        failures.append("BROAD_FORWARD_ESTABLISHED_STILL_PRESENT")

    if failures:
        print("STAGE_R_PROVENANCE_CONTRACT: FAIL: " + ",".join(failures))
        return 1
    print("STAGE_R_PROVENANCE_CONTRACT: PASS (SOURCE SHAPE ONLY; NOT PACKET PROOF)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
