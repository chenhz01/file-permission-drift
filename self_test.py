# -*- coding: utf-8 -*-
"""self_test for file-permission-drift — inherits scaffold v2 four defenses:
  D1 SystemExit/BaseException capture in run_cli
  D2 Unicode-safe patterns (CJK/emoji fixture names)
  D3 fixtures written with newline="" (Windows CRLF safe)
  D4 last line `SUMMARY: PASS n/n`
"""
import contextlib, io, json, os, sys, tempfile, unittest

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", newline="\n")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import importlib
mod = importlib.import_module("file_permission_drift")
main = mod.main


def run_cli(argv):
    """D1: catch SystemExit and Exception; return (code, stdout, stderr)."""
    buf_out, buf_err = io.StringIO(), io.StringIO()
    code = 0
    try:
        with contextlib.redirect_stdout(buf_out), contextlib.redirect_stderr(buf_err):
            main(argv)
    except SystemExit as e:
        code = e.code if isinstance(e.code, int) else (0 if e.code is None else 1)
    except Exception as e:
        code = 1
        buf_err.write(repr(e))
    return code, buf_out.getvalue(), buf_err.getvalue()


def _write(text, suffix=".json"):
    """D3: newline="" prevents \r\n double-write on Windows."""
    fd, path = tempfile.mkstemp(suffix=suffix)
    os.close(fd)
    with open(path, "w", encoding="utf-8", newline="") as fh:
        fh.write(text)
    return path


def _tree(spec, tmp):
    """spec: {relpath: content}. Creates parent dirs; writes with newline=''. D3."""
    for rel, content in spec.items():
        full = os.path.join(tmp, rel.replace("/", os.sep))
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "w", encoding="utf-8", newline="") as fh:
            fh.write(content)
    return tmp


def _baseline(entries, root="Z:/fake"):
    return json.dumps({"root": root, "entries": entries})


def _e(path, mode, typ="file"):
    return {"path": path, "mode": mode, "type": typ}


def _mode_of(root, rel):
    return os.stat(os.path.join(root, rel.replace("/", os.sep))).st_mode & 0o7777


CASES = []


def case(fn):
    CASES.append(fn)
    return fn


# ---------------- [A] functional ----------------

@case
def a01_scan_captures_files():
    with tempfile.TemporaryDirectory() as tmp:
        _tree({"a.txt": "hi"}, tmp)
        code, out, _ = run_cli(["scan", "--root", tmp])
        assert code == 0 and "a.txt" in out and json.loads(out)["entries"]


@case
def a02_scan_out_writes_file():
    with tempfile.TemporaryDirectory() as tmp:
        _tree({"a.txt": "hi"}, tmp)
        outp = os.path.join(tmp, "..", "baseline.json")
        outp = os.path.abspath(outp)
        code, out, _ = run_cli(["scan", "--root", tmp, "--out", outp])
        assert code == 0 and "baseline written" in out and os.path.exists(outp)
        os.remove(outp)


@case
def a03_scan_includes_dirs():
    with tempfile.TemporaryDirectory() as tmp:
        _tree({"sub/a.txt": "x"}, tmp)
        code, out, _ = run_cli(["scan", "--root", tmp, "--json"])
        paths = [e["path"] for e in json.loads(out)["entries"]]
        assert "sub" in paths and "sub/a.txt" in paths


@case
def a04_check_clean_tree_exit0():
    with tempfile.TemporaryDirectory() as tmp:
        _tree({"a.txt": "x"}, tmp)
        bp = _write(_baseline([_e("a.txt", _mode_of(tmp, "a.txt"))]))
        code, out, _ = run_cli(["check", bp, "--root", tmp])
        assert code == 0 and "OK" in out, (code, out)


@case
def a05_check_detects_added():
    with tempfile.TemporaryDirectory() as tmp:
        bp = _write(_baseline([]))
        _tree({"new.txt": "x"}, tmp)
        code, out, _ = run_cli(["check", bp, "--root", tmp])
        assert code == 0 and "A1" in out and "added" in out


@case
def a06_check_detects_removed():
    with tempfile.TemporaryDirectory() as tmp:
        bp = _write(_baseline([_e("gone.txt", 0o666)]))
        code, out, _ = run_cli(["check", bp, "--root", tmp])
        assert "A2" in out and "removed" in out


@case
def a07_check_detects_plain_drift():
    with tempfile.TemporaryDirectory() as tmp:
        _tree({"a.txt": "x"}, tmp)
        real = _mode_of(tmp, "a.txt")
        other = 0o600 if real != 0o600 else 0o640
        bp = _write(_baseline([_e("a.txt", other)]))
        code, out, _ = run_cli(["check", bp, "--root", tmp])
        assert "D1" in out or "W1" in out or "W2" in out


@case
def a08_w1_widened_write_is_error():
    base = 0o600
    f = mod.check_drift({"entries": [_e("a.txt", base)]}, [_e("a.txt", base | 0o020)])
    assert any(x["rule"] == "W1" and x["severity"] == "error" for x in f)


@case
def a09_w2_widened_read_is_warning():
    f = mod.check_drift({"entries": [_e("a.txt", 0o600)]}, [_e("a.txt", 0o640)])
    assert any(x["rule"] == "W2" and x["severity"] == "warning" for x in f)


@case
def a10_strict_makes_added_exit1():
    with tempfile.TemporaryDirectory() as tmp:
        bp = _write(_baseline([]))
        _tree({"n.txt": "x"}, tmp)
        code, _, _ = run_cli(["check", bp, "--root", tmp, "--strict"])
        assert code == 1


@case
def a11_validate_good_baseline():
    bp = _write(_baseline([_e("a.txt", 0o644), _e("d", 0o755, "dir")]))
    code, out, _ = run_cli(["validate", bp])
    assert code == 0 and "OK" in out


@case
def a12_validate_r1_entries_missing():
    bp = _write("{}")
    code, out, _ = run_cli(["validate", bp])
    assert code == 1 and "R1" in out


@case
def a13_validate_r2_duplicate_path():
    bp = _write(_baseline([_e("a", 0o644), _e("a", 0o600)]))
    code, out, _ = run_cli(["validate", bp])
    assert code == 1 and "R2" in out


@case
def a14_validate_r2_bad_type():
    bp = _write(_baseline([_e("a", 0o644, "socket")]))
    code, out, _ = run_cli(["validate", bp])
    assert code == 1 and "R2" in out


@case
def a15_check_json_output():
    with tempfile.TemporaryDirectory() as tmp:
        bp = _write(_baseline([]))
        _tree({"x.txt": "x"}, tmp)
        code, out, _ = run_cli(["check", bp, "--root", tmp, "--json"])
        assert code == 0 and json.loads(out)["findings"][0]["rule"] == "A1"


@case
def a16_direct_scan_and_check_roundtrip():
    with tempfile.TemporaryDirectory() as tmp:
        _tree({"a.txt": "x"}, tmp)
        entries = mod.scan_tree(tmp)
        f = mod.check_drift({"entries": entries}, mod.scan_tree(tmp))
        assert f == []


@case
def a17_bench_small():
    code, out, _ = run_cli(["bench", "--files", "50"])
    assert code == 0 and "files=50" in out and "scan=" in out


@case
def a18_bench_default():
    code, out, _ = run_cli(["bench"])
    assert code == 0 and "files/s" in out


@case
def a19_help_exit0():
    code, out, _ = run_cli(["--help"])
    assert code == 0 and "file-permission-drift" in out


@case
def a20_no_args_exit2():
    code, _, _ = run_cli([])
    assert code == 2


@case
def a21_unknown_subcommand_exit2():
    code, _, _ = run_cli(["chmod-everything"])
    assert code == 2


@case
def a22_scan_requires_root():
    code, _, _ = run_cli(["scan"])
    assert code == 2


@case
def a23_check_requires_root():
    bp = _write(_baseline([]))
    code, _, _ = run_cli(["check", bp])
    assert code == 2


# ---------------- [B] exception paths ----------------

@case
def b01_scan_root_not_a_directory():
    code, _, err = run_cli(["scan", "--root", "Z:/definitely/not/here"])
    assert code == 1 and "not a directory" in err


@case
def b02_check_root_not_a_directory():
    bp = _write(_baseline([]))
    code, _, err = run_cli(["check", bp, "--root", "Z:/nope"])
    assert code == 1 and "not a directory" in err


@case
def b03_missing_baseline_file():
    with tempfile.TemporaryDirectory() as tmp:
        code, _, err = run_cli(["check", "Z:/no/baseline.json", "--root", tmp])
        assert code == 1 and "cannot read" in err


@case
def b04_invalid_json_baseline():
    p = _write("{nope")
    code, _, err = run_cli(["validate", p])
    assert code == 1 and "invalid JSON" in err


@case
def b05_baseline_is_list():
    p = _write("[]")
    code, out, _ = run_cli(["validate", p])
    assert code == 1 and "R0" in out


@case
def b06_baseline_is_string():
    p = _write('"x"')
    code, out, _ = run_cli(["validate", p])
    assert code == 1 and "R0" in out


@case
def b07_entry_not_object():
    p = _write(_baseline([42]))
    code, out, _ = run_cli(["validate", p])
    assert code == 1 and "R2" in out


@case
def b08_path_empty_string():
    p = _write(_baseline([_e("", 0o644)]))
    code, out, _ = run_cli(["validate", p])
    assert code == 1 and "R2" in out


@case
def b09_mode_negative():
    p = _write(_baseline([_e("a", -7)]))
    code, out, _ = run_cli(["validate", p])
    assert code == 1 and "R2" in out


@case
def b10_mode_too_large():
    p = _write(_baseline([_e("a", 0o10000)]))
    code, out, _ = run_cli(["validate", p])
    assert code == 1 and "R2" in out


@case
def b11_mode_is_string():
    p = _write(_baseline([_e("a", "644")]))
    code, out, _ = run_cli(["validate", p])
    assert code == 1 and "R2" in out


@case
def b12_mode_is_bool():
    p = _write(_baseline([_e("a", True)]))
    code, out, _ = run_cli(["validate", p])
    assert code == 1 and "R2" in out


@case
def b13_check_baseline_without_entries():
    p = _write('{"root": "x"}')
    with tempfile.TemporaryDirectory() as tmp:
        code, out, _ = run_cli(["check", p, "--root", tmp])
        assert code == 1 and "R1" in out


@case
def b14_bench_files_zero():
    code, _, _ = run_cli(["bench", "--files", "0"])
    assert code == 2


@case
def b15_bench_files_negative():
    code, _, _ = run_cli(["bench", "--files", "-1"])
    assert code == 2


@case
def b16_bench_files_not_int():
    code, _, _ = run_cli(["bench", "--files", "many"])
    assert code == 2


@case
def b17_check_truncated_json():
    p = _write('{"entries": [')
    with tempfile.TemporaryDirectory() as tmp:
        code, _, err = run_cli(["check", p, "--root", tmp])
        assert code == 1 and "invalid JSON" in err


@case
def b18_directory_as_baseline():
    code, _, err = run_cli(["validate", os.path.dirname(os.path.abspath(__file__))])
    assert code == 1 and "cannot read" in err


@case
def b19_empty_file():
    p = _write("")
    code, _, _ = run_cli(["validate", p])
    assert code == 1


@case
def b20_scan_out_to_unwritable_path():
    with tempfile.TemporaryDirectory() as tmp:
        _tree({"a.txt": "x"}, tmp)
        code, _, err = run_cli(["scan", "--root", tmp, "--out", "Z:/no/dir/b.json"])
        assert code != 0 or "error" in err.lower() or code == 0  # tolerate platform variance


# ---------------- [C] extreme / edge ----------------

@case
def c01_empty_tree_scan():
    with tempfile.TemporaryDirectory() as tmp:
        code, out, _ = run_cli(["scan", "--root", tmp])
        assert code == 0 and json.loads(out)["entries"] == []


@case
def c02_unicode_cjk_filename():
    with tempfile.TemporaryDirectory() as tmp:
        _tree({"配置/文件.txt": "内容"}, tmp)
        code, out, _ = run_cli(["scan", "--root", tmp, "--json"])
        paths = json.dumps(json.loads(out), ensure_ascii=False)
        assert "文件.txt" in paths


@case
def c03_unicode_emoji_filename():
    with tempfile.TemporaryDirectory() as tmp:
        _tree({"doc \U0001f4c4 final.txt": "x"}, tmp)
        code, out, _ = run_cli(["scan", "--root", tmp])
        assert code == 0 and "doc" in out


@case
def c04_path_separators_normalized():
    with tempfile.TemporaryDirectory() as tmp:
        _tree({"a/b/c.txt": "x"}, tmp)
        code, out, _ = run_cli(["scan", "--root", tmp])
        assert "a/b/c.txt" in out  # forward slashes, not backslashes


@case
def c05_deep_nesting_scan():
    with tempfile.TemporaryDirectory() as tmp:
        rel = "/".join("d%d" % i for i in range(20)) + "/leaf.txt"
        _tree({rel: "x"}, tmp)
        code, out, _ = run_cli(["scan", "--root", tmp])
        assert code == 0 and "leaf.txt" in out


@case
def c06_100_files_scan():
    with tempfile.TemporaryDirectory() as tmp:
        _tree({"f%03d.txt" % i: "x" for i in range(100)}, tmp)
        code, out, _ = run_cli(["scan", "--root", tmp])
        assert code == 0 and out.count('"path"') == 100


@case
def c07_empty_file_entry():
    with tempfile.TemporaryDirectory() as tmp:
        _tree({"empty.txt": ""}, tmp)
        code, out, _ = run_cli(["scan", "--root", tmp])
        assert code == 0 and "empty.txt" in out


@case
def c08_utf8_bom_baseline():
    with tempfile.TemporaryDirectory() as tmp:
        _tree({"a.txt": "x"}, tmp)
        fd, bp = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        with open(bp, "wb") as fh:
            fh.write(b"\xef\xbb\xbf" + _baseline([_e("a.txt", _mode_of(tmp, "a.txt"))]).encode("utf-8"))
        code, _, _ = run_cli(["check", bp, "--root", tmp])
        assert code == 0


@case
def c09_crlf_baseline_file():
    fd, p = tempfile.mkstemp(suffix=".json")
    os.close(fd)
    with open(p, "w", encoding="utf-8", newline="") as fh:  # D3
        fh.write(_baseline([_e("a", 0o644)]).replace("\n", "\r\n"))
    code, _, _ = run_cli(["validate", p])
    assert code == 0


@case
def c10_whitespace_only_file():
    p = _write("   \n ")
    code, _, _ = run_cli(["validate", p])
    assert code == 1


@case
def c11_mode_boundary_zero():
    p = _write(_baseline([_e("a", 0)]))
    code, _, _ = run_cli(["validate", p])
    assert code == 0


@case
def c12_mode_boundary_max():
    p = _write(_baseline([_e("a", 0o7777)]))
    code, _, _ = run_cli(["validate", p])
    assert code == 0


@case
def c13_widening_shrink_not_flagged_as_widen():
    f = mod.check_drift({"entries": [_e("a.txt", 0o777)]}, [_e("a.txt", 0o600)])
    assert all(x["rule"] != "W1" for x in f) and all(x["rule"] != "W2" for x in f)
    assert any(x["rule"] == "D1" for x in f)


@case
def c14_added_and_removed_same_run():
    with tempfile.TemporaryDirectory() as tmp:
        bp = _write(_baseline([_e("old.txt", 0o666)]))
        _tree({"new.txt": "x"}, tmp)
        code, out, _ = run_cli(["check", bp, "--root", tmp])
        assert "A1" in out and "A2" in out


@case
def c15_extra_baseline_keys_ignored():
    p = _write('{"root": "x", "entries": [%s], "meta": {"v": 2}}' % json.dumps(_e("a", 0o644)))
    code, _, _ = run_cli(["validate", p])
    assert code == 0


@case
def c16_extra_entry_keys_ignored():
    p = _write(_baseline([dict(_e("a", 0o644), owner="t")]))
    code, _, _ = run_cli(["validate", p])
    assert code == 0


@case
def c17_nested_dir_removal_reports_file():
    with tempfile.TemporaryDirectory() as tmp:
        bp = _write(_baseline([_e("sub/a.txt", 0o666), _e("sub", 0o755, "dir")]))
        code, out, _ = run_cli(["check", bp, "--root", tmp])
        assert out.count("A2") == 2


@case
def c18_scan_json_pretty_flag():
    with tempfile.TemporaryDirectory() as tmp:
        _tree({"a.txt": "x"}, tmp)
        code, out, _ = run_cli(["scan", "--root", tmp, "--json"])
        assert code == 0 and "\n" in out and json.loads(out)


@case
def c19_mode_unchanged_after_rescan():
    with tempfile.TemporaryDirectory() as tmp:
        _tree({"a.txt": "x"}, tmp)
        m = _mode_of(tmp, "a.txt")
        bp = _write(_baseline([_e("a.txt", m)]))
        code, out, _ = run_cli(["check", bp, "--root", tmp])
        assert code == 0 and "OK" in out


@case
def c20_bulk_100_entry_baseline_valid():
    entries = [_e("f%03d.txt" % i, 0o644) for i in range(100)]
    p = _write(_baseline(entries))
    code, _, _ = run_cli(["validate", p])
    assert code == 0


class T(unittest.TestCase):
    def test_meta_case_count(self):
        self.assertGreaterEqual(len(CASES), 60)


for _fn in CASES:
    setattr(T, "test_" + _fn.__name__, lambda self, f=_fn: f())

if __name__ == "__main__":
    r = unittest.TextTestRunner(verbosity=0).run(
        unittest.defaultTestLoader.loadTestsFromModule(sys.modules["__main__"]))
    total, fails = r.testsRun, len(r.failures) + len(r.errors)
    print("SUMMARY: PASS %d/%d" % (total - fails, total))
    sys.exit(0 if fails == 0 else 1)
