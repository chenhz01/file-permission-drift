#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""file-permission-drift — reconcile a declared permission baseline against the
actual on-disk modes and flag abnormal widenings (group/other write bits added).
Pure standard library, single file, offline.
"""
import argparse, json, os, sys, tempfile, time


def scan_tree(root):
    """Return entries [{path, mode, type}] relative to root. Pure os.stat."""
    entries = []
    for dirpath, dirnames, filenames in os.walk(root):
        for name in sorted(dirnames):
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, root).replace("\\", "/")
            try:
                st = os.stat(full)
            except OSError:
                continue
            entries.append({"path": rel, "mode": st.st_mode & 0o7777, "type": "dir"})
        for name in sorted(filenames):
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, root).replace("\\", "/")
            try:
                st = os.stat(full)
            except OSError:
                continue
            entries.append({"path": rel, "mode": st.st_mode & 0o7777, "type": "file"})
    return entries


def validate_baseline(baseline):
    findings = []
    if not isinstance(baseline, dict):
        findings.append({"rule": "R0", "severity": "error", "message": "baseline must be a JSON object"})
        return findings
    entries = baseline.get("entries")
    if not isinstance(entries, list):
        findings.append({"rule": "R1", "severity": "error", "message": "entries must be a list"})
        return findings
    seen = set()
    for i, e in enumerate(entries):
        ref = e.get("path") if isinstance(e, dict) else "#%d" % (i + 1)
        if not isinstance(e, dict):
            findings.append({"rule": "R2", "severity": "error", "message": "entry is not an object", "ref": ref})
            continue
        p = e.get("path")
        if not isinstance(p, str) or not p:
            findings.append({"rule": "R2", "severity": "error", "message": "path must be a non-empty string", "ref": ref})
            continue
        if p in seen:
            findings.append({"rule": "R2", "severity": "error", "message": "duplicate path", "ref": p})
            continue
        seen.add(p)
        m = e.get("mode")
        if not isinstance(m, int) or isinstance(m, bool) or not (0 <= m <= 0o7777):
            findings.append({"rule": "R2", "severity": "error", "message": "mode must be an integer in [0, 0o7777]", "ref": p})
            continue
        t = e.get("type")
        if t not in ("file", "dir"):
            findings.append({"rule": "R2", "severity": "error", "message": "type must be 'file' or 'dir'", "ref": p})
    return findings


def check_drift(baseline, current):
    """Compare current scan against baseline. Returns findings list."""
    findings = []
    if not isinstance(baseline, dict) or not isinstance(baseline.get("entries"), list):
        findings.append({"rule": "R1", "severity": "error", "message": "baseline has no entries list"})
        return findings
    base = {e.get("path"): e for e in baseline["entries"] if isinstance(e, dict)}
    cur = {e["path"]: e for e in current if isinstance(e, dict)}
    for p, e in sorted(cur.items()):
        b = base.get(p)
        if b is None:
            findings.append({"rule": "A1", "severity": "warning", "message": "added: not in baseline", "ref": p})
            continue
        old, new = b.get("mode"), e.get("mode")
        if new == old:
            continue
        widen_w = (new & 0o022) & ~(old or 0) & 0o022
        widen_r = (new & 0o044) & ~(old or 0) & 0o044
        if widen_w:
            findings.append({"rule": "W1", "severity": "error",
                             "message": "widened: group/other write bit added (%s -> %s)"
                                        % (oct(old), oct(new)), "ref": p})
        elif widen_r:
            findings.append({"rule": "W2", "severity": "warning",
                             "message": "widened: group/other read bit added (%s -> %s)"
                                        % (oct(old), oct(new)), "ref": p})
        else:
            findings.append({"rule": "D1", "severity": "warning",
                             "message": "drift: mode changed (%s -> %s)" % (oct(old), oct(new)), "ref": p})
    for p in sorted(set(base) - set(cur)):
        findings.append({"rule": "A2", "severity": "warning", "message": "removed: in baseline, gone on disk", "ref": p})
    return findings


def _has_error(findings):
    return any(f["severity"] == "error" for f in findings)


def _load(path):
    with open(path, "r", encoding="utf-8-sig") as fh:
        return json.load(fh)


def _print(findings, as_json):
    if as_json:
        print(json.dumps({"findings": findings}, ensure_ascii=False, indent=2))
    else:
        if not findings:
            print("OK: no findings")
        for f in findings:
            ref = " [%s]" % f["ref"] if f.get("ref") else ""
            print("%-7s %-4s%s %s" % (f["severity"], f["rule"], ref, f["message"]))


def _positive_int(text):
    try:
        v = int(text)
    except ValueError:
        raise argparse.ArgumentTypeError("not an integer: %r" % text)
    if v < 1:
        raise argparse.ArgumentTypeError("must be >= 1")
    return v


def bench(n):
    root = tempfile.mkdtemp(prefix="fpd-bench-")
    for i in range(n):
        with open(os.path.join(root, "f%06d.txt" % i), "w", newline="") as fh:
            fh.write("x")
    t0 = time.perf_counter()
    entries = scan_tree(root)
    t1 = time.perf_counter()
    baseline = {"root": root, "entries": entries}
    check_drift(baseline, scan_tree(root))
    t2 = time.perf_counter()
    for fn in os.listdir(root):
        os.remove(os.path.join(root, fn))
    os.rmdir(root)
    return len(entries), t1 - t0, t2 - t1


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="file-permission-drift",
        description="Reconcile a declared file-permission baseline against on-disk modes.")
    sub = ap.add_subparsers(dest="cmd", required=True)

    ps = sub.add_parser("scan", help="capture a baseline from a directory tree")
    ps.add_argument("--root", required=True)
    ps.add_argument("--out", help="write baseline JSON here (default: stdout)")
    ps.add_argument("--json", action="store_true", help="pretty-print JSON output")

    pv = sub.add_parser("validate", help="structural validation of a baseline file")
    pv.add_argument("baseline")
    pv.add_argument("--json", action="store_true")

    pc = sub.add_parser("check", help="compare a baseline against the current tree")
    pc.add_argument("baseline")
    pc.add_argument("--root", required=True)
    pc.add_argument("--json", action="store_true")
    pc.add_argument("--strict", action="store_true",
                    help="treat any finding as an error for exit-code purposes")

    pb = sub.add_parser("bench", help="scan + check a synthetic tree and time it")
    pb.add_argument("--files", type=_positive_int, default=5000)

    args = ap.parse_args(argv)
    if args.cmd == "bench":
        n, dt_s, dt_c = bench(args.files)
        print("files=%d scan=%.4fs (%.0f files/s) check=%.4fs"
              % (n, dt_s, n / dt_s if dt_s else 0, dt_c))
        sys.exit(0)

    if args.cmd == "scan":
        if not os.path.isdir(args.root):
            print("error: --root is not a directory: %s" % args.root, file=sys.stderr)
            sys.exit(1)
        baseline = {"root": os.path.abspath(args.root), "entries": scan_tree(args.root)}
        text = json.dumps(baseline, ensure_ascii=False, indent=2 if args.json else None)
        if args.out:
            with open(args.out, "w", encoding="utf-8", newline="\n") as fh:
                fh.write(text + "\n")
            print("baseline written: %s (%d entries)" % (args.out, len(baseline["entries"])))
        else:
            print(text)
        sys.exit(0)

    try:
        baseline = _load(args.baseline)
    except OSError as exc:
        print("error: cannot read %s: %s" % (args.baseline, exc), file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as exc:
        print("error: invalid JSON in %s: %s" % (args.baseline, exc), file=sys.stderr)
        sys.exit(1)

    if args.cmd == "validate":
        findings = validate_baseline(baseline)
        _print(findings, args.json)
        sys.exit(1 if _has_error(findings) else 0)

    if not os.path.isdir(args.root):
        print("error: --root is not a directory: %s" % args.root, file=sys.stderr)
        sys.exit(1)
    findings = check_drift(baseline, scan_tree(args.root))
    _print(findings, args.json)
    bad = _has_error(findings) or (args.strict and findings)
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
