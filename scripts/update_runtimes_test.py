import io
import json
import os
import tarfile
import tempfile
import unittest

import update_runtimes as u


def tar_of(entries):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        for name, kind, mode, uid, gid in entries:
            ti = tarfile.TarInfo(name)
            ti.mode, ti.uid, ti.gid = mode, uid, gid
            if kind == "dir":
                ti.type = tarfile.DIRTYPE
            elif kind == "sym":
                ti.type, ti.linkname = tarfile.SYMTYPE, "x"
            else:
                ti.size = 0
            tf.addfile(ti, io.BytesIO(b""))
    buf.seek(0)
    return buf


class ScanTest(unittest.TestCase):
    def scan(self, entries):
        return u.top_paths(u.scan_stream(tar_of(entries)))

    def test_world_writable_and_owned_entries_are_found(self):
        got = self.scan([
            ("tmp/", "dir", 0o1777, 0, 0),
            ("var/tmp/", "dir", 0o1777, 0, 0),
            ("var/tmp/x", "file", 0o666, 0, 0),
            ("run/lock/", "dir", 0o1777, 0, 0),
            ("usr/bin/node", "file", 0o755, 0, 0),
            ("home/u/", "dir", 0o755, u.JOB_UID, 0),
            ("srv/g/", "dir", 0o775, 0, u.JOB_UID),
            ("srv/ro/", "dir", 0o755, 0, u.JOB_UID),
        ])
        self.assertEqual(got, ["/home/u", "/run/lock", "/srv/g", "/tmp", "/var/tmp"])

    def test_dot_names_and_engine_paths(self):
        got = self.scan([
            (".dockerenv", "file", 0o666, 0, 0),
            ("./dev/shm/", "dir", 0o1777, 0, 0),
            ("proc/x", "file", 0o666, 0, 0),
        ])
        self.assertEqual(got, ["/.dockerenv"])

    def test_symlinks_count_only_by_owner(self):
        self.assertEqual(self.scan([("a", "sym", 0o777, 0, 0)]), [])
        self.assertEqual(self.scan([("b", "sym", 0o777, u.JOB_UID, 0)]), ["/b"])


class TableTest(unittest.TestCase):
    def test_mark_tested_records_the_platform_digest(self):
        table = {"schema": 1, "runtimes": [
            {"id": "node24", "image": "node", "platforms": {"linux/amd64": "sha256:a", "linux/arm64": "sha256:b"}, "tested": {}},
            {"id": "node20"},
        ]}
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "t.json")
            u.save(p, table)
            args = type("A", (), {"table": p, "platform": "linux/amd64", "only": ["node24"]})()
            u.cmd_mark_tested(args)
            got = u.load(p)
        self.assertEqual(got["runtimes"][0]["tested"], {"linux/amd64": "sha256:a"})
        self.assertNotIn("tested", got["runtimes"][1])

    def test_only_the_named_runtimes_are_recorded(self):
        table = {"schema": 1, "runtimes": [
            {"id": "node24", "image": "node", "platforms": {"linux/amd64": "sha256:a"}, "tested": {}},
            {"id": "node22", "image": "node", "platforms": {"linux/amd64": "sha256:b"}, "tested": {}},
        ]}
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "t.json")
            u.save(p, table)
            u.cmd_mark_tested(type("A", (), {"table": p, "platform": "linux/amd64", "only": ["node24"]})())
            got = u.load(p)
        self.assertEqual(got["runtimes"][1]["tested"], {})

    def test_mark_tested_needs_the_runtimes_named(self):
        with self.assertRaises(SystemExit):
            u.main(["mark-tested"])

    def test_the_shipped_table_round_trips(self):
        here = os.path.dirname(os.path.abspath(__file__))
        path = os.path.join(here, "..", u.TABLE)
        with open(path) as f:
            raw = f.read()
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "t.json")
            u.save(p, json.loads(raw))
            with open(p) as f:
                self.assertEqual(f.read(), raw)


class TrivyTest(unittest.TestCase):
    def fake_run(self, rc, out=b"", err=b""):
        return lambda *cmd, **kw: type("P", (), {"returncode": rc, "stdout": out, "stderr": err})()

    def test_a_scan_that_cannot_be_made_is_a_failure(self):
        saved = u.run
        try:
            u.run = self.fake_run(1, err=b"boom")
            with self.assertRaises(u.Failure):
                u.trivy("node@sha256:x", "linux/amd64")
            u.run = self.fake_run(0, out=b"not json")
            with self.assertRaises(u.Failure):
                u.trivy("node@sha256:x", "linux/amd64")
        finally:
            u.run = saved

    def test_findings_are_returned_not_failures(self):
        saved = u.run
        try:
            report = json.dumps({"Results": [{"Vulnerabilities": [
                {"VulnerabilityID": "CVE-1", "PkgName": "libc", "InstalledVersion": "1", "FixedVersion": "2", "Severity": "HIGH"}]}]}).encode()
            u.run = self.fake_run(0, out=report)
            self.assertEqual(u.trivy("node@sha256:x", "linux/amd64"), [("CVE-1", "libc", "1", "2", "HIGH")])
            u.run = self.fake_run(0, out=b"{}")
            self.assertEqual(u.trivy("node@sha256:x", "linux/amd64"), [])
        finally:
            u.run = saved


if __name__ == "__main__":
    unittest.main()
