#!/usr/bin/env python3
"""Collapse near-duplicate log lines into fingerprints with counts and first/last seen.

Usage:
    fingerprint.py app.log                     # all lines
    fingerprint.py app.log --grep 'ERROR|WARN' # only matching lines (regex)
    fingerprint.py a.log b.log.gz --top 30
    kubectl logs pod | fingerprint.py -        # stdin
    fingerprint.py app.log --sort first        # order by first appearance (find the earliest error)

Masks the parts of a line that vary between occurrences (timestamps, UUIDs,
hex, IPs, emails, quoted strings, numbers) so that lines differing only in
those parts share one fingerprint. For each fingerprint it prints count, first
and last line number (and the timestamp, if one was found), and one raw
example line.

JSON-lines logs are handled: if a line parses as a JSON object, the message
field (msg/message/error/event) plus level is fingerprinted instead of the
whole object.

Standard library only.
"""

from __future__ import annotations

import argparse
import gzip
import json
import re
import sys
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import TextIO

TS_RE = re.compile(
    r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?"
    r"|\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) +\d{1,2} \d{2}:\d{2}:\d{2}"
    r"|\b\d{2}/(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)/\d{4}:\d{2}:\d{2}:\d{2}(?: [+-]\d{4})?"
)

# Order matters: specific patterns before the generic number mask.
MASKS: list[tuple[re.Pattern[str], str]] = [
    (TS_RE, "<TS>"),
    (re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"), "<UUID>"),
    (re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b"), "<EMAIL>"),
    (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\b"), "<IP>"),
    (re.compile(r"\b0x[0-9a-fA-F]+\b"), "<HEX>"),
    (re.compile(r"\b(?=[0-9a-fA-F]*\d)(?=[0-9a-fA-F]*[a-fA-F])[0-9a-fA-F]{8,}\b"), "<HEX>"),
    (re.compile(r"\"(?:[^\"\\]|\\.){0,200}\""), '"<STR>"'),
    (re.compile(r"'(?:[^'\\]|\\.){0,200}'"), "'<STR>'"),
    (re.compile(r"(?<![\w<])[-+]?\d+(?:\.\d+)?(?:ms|s|us|ns|KB|MB|GB|B|%)?\b"), "<N>"),
]
# A bare 1xx-5xx token between spaces is almost always an HTTP status; keep it,
# since "GET /x 200" and "GET /x 500" must not share a fingerprint.
STATUS_RE = re.compile(r"(?<=\s)([1-5]\d\d)(?=\s|$)")
MSG_KEYS = ("msg", "message", "error", "err", "event")
LEVEL_KEYS = ("level", "severity", "lvl")
TS_KEYS = ("ts", "time", "timestamp", "@timestamp", "t")


@dataclass
class Bucket:
    count: int = 0
    first_line: int = 0
    last_line: int = 0
    first_ts: str = ""
    last_ts: str = ""
    example: str = ""
    sources: set[str] = field(default_factory=set)


def mask(text: str) -> str:
    text = STATUS_RE.sub(lambda m: f"<S{m.group(1)}>", text)
    for pattern, repl in MASKS:
        text = pattern.sub(repl, text)
    text = re.sub(r"<S(\d{3})>", r"\1", text)
    return re.sub(r"\s+", " ", text).strip()


def key_and_ts(line: str) -> tuple[str, str]:
    """Return (fingerprint, timestamp-or-empty) for a raw line."""
    stripped = line.strip()
    if stripped.startswith("{"):
        try:
            obj = json.loads(stripped)
        except ValueError:
            obj = None
        if isinstance(obj, dict):
            msg = next((str(obj[k]) for k in MSG_KEYS if k in obj), "")
            lvl = next((str(obj[k]) for k in LEVEL_KEYS if k in obj), "")
            ts = next((str(obj[k]) for k in TS_KEYS if k in obj), "")
            if msg:
                return f"{lvl.upper()} {mask(msg)}".strip(), ts
    m = TS_RE.search(line)
    return mask(line), (m.group(0) if m else "")


def open_source(path: str) -> TextIO:
    if path == "-":
        return sys.stdin
    if path.endswith(".gz"):
        return gzip.open(path, "rt", errors="replace")
    return open(path, errors="replace")


def lines(paths: list[str]) -> Iterator[tuple[str, int, str]]:
    for path in paths:
        with open_source(path) as fh:
            for n, line in enumerate(fh, 1):
                yield path, n, line.rstrip("\n")


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("paths", nargs="+", help="log files (.gz ok) or - for stdin")
    p.add_argument("--grep", help="only fingerprint lines matching this regex (case-insensitive)")
    p.add_argument("--top", type=int, default=25, help="how many fingerprints to print (default 25, 0 = all)")
    p.add_argument("--sort", choices=("count", "first", "last"), default="count")
    p.add_argument("--width", type=int, default=220, help="truncate example lines to this width")
    args = p.parse_args(argv)

    want = re.compile(args.grep, re.IGNORECASE) if args.grep else None
    buckets: dict[str, Bucket] = {}
    total = matched = 0
    for src, n, line in lines(args.paths):
        total += 1
        if not line.strip() or (want and not want.search(line)):
            continue
        matched += 1
        key, ts = key_and_ts(line)
        b = buckets.get(key)
        if b is None:
            b = buckets[key] = Bucket(first_line=n, first_ts=ts, example=line)
        b.count += 1
        b.last_line, b.last_ts = n, ts or b.last_ts
        b.sources.add(src)

    order = {
        "count": lambda kv: -kv[1].count,
        "first": lambda kv: (kv[1].first_ts or "~", kv[1].first_line),
        "last": lambda kv: (kv[1].last_ts or "", kv[1].last_line),
    }[args.sort]
    items = sorted(buckets.items(), key=order, reverse=args.sort == "last")
    if args.top:
        items = items[: args.top]

    print(f"# {total} lines read, {matched} matched, {len(buckets)} distinct fingerprints (sorted by {args.sort})")
    multi = len(args.paths) > 1
    for key, b in items:
        when = f"{b.first_ts or 'L' + str(b.first_line)} .. {b.last_ts or 'L' + str(b.last_line)}"
        where = f" in {','.join(sorted(b.sources))}" if multi else ""
        print(f"\n{b.count:>7}x  lines {b.first_line}-{b.last_line}  [{when}]{where}")
        print(f"  key: {key[: args.width]}")
        print(f"  e.g. {b.example[: args.width]}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except BrokenPipeError:
        sys.exit(0)
