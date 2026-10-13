import contextlib
import datetime
import io
import json
import os
import tarfile
import tempfile
import unittest
import urllib.error

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


NODE_CYCLES = {
    "27": {"cycle": "27", "releaseDate": "2027-04-20", "eol": "2030-04-30", "lts": "2027-10-26", "support": "2028-10-26"},
    "26": {"cycle": "26", "releaseDate": "2026-05-05", "eol": "2029-04-30", "lts": "2026-10-28", "support": "2027-10-27"},
    "25": {"cycle": "25", "releaseDate": "2025-10-15", "eol": "2026-06-01", "lts": False, "support": "2026-04-01"},
    "24": {"cycle": "24", "releaseDate": "2025-05-06", "eol": "2028-04-30", "lts": "2025-10-28", "support": "2026-10-20"},
    "3": {"cycle": "3", "releaseDate": "2015-01-01", "eol": False, "lts": False, "support": False},
}
PYTHON_CYCLES = {
    "3.16": {"cycle": "3.16", "releaseDate": "2027-10-06", "eol": "2032-10-31", "support": "2029-10-06"},
    "3.15": {"cycle": "3.15", "releaseDate": "2026-10-09", "eol": "2031-10-31", "support": "2028-10-09"},
    "3.14": {"cycle": "3.14", "releaseDate": "2025-10-07", "eol": "2030-10-31", "support": "2027-10-01"},
    "3.13": {"cycle": "3.13", "releaseDate": "2024-10-07", "eol": "2029-10-31", "support": "2026-10-01"},
}


def table_of(*rows):
    return {"schema": 1, "runtimes": [dict(r) for r in rows]}


class SupportTest(unittest.TestCase):
    def test_node_state_follows_the_lts_and_maintenance_dates(self):
        c = NODE_CYCLES["26"]
        self.assertEqual(u.support_state("node", c, "2026-10-27"), "current")
        self.assertEqual(u.support_state("node", c, "2026-10-28"), "lts")
        self.assertEqual(u.support_state("node", c, "2027-10-27"), "maintenance")
        self.assertEqual(u.support_state("node", c, "2029-05-01"), "end_of_life")
        self.assertEqual(u.support_state("node", NODE_CYCLES["25"], "2026-01-01"), "current")

    def test_python_state_follows_the_bugfix_end(self):
        c = PYTHON_CYCLES["3.13"]
        self.assertEqual(u.support_state("python", c, "2026-09-30"), "bugfix")
        self.assertEqual(u.support_state("python", c, "2026-10-01"), "security")
        self.assertEqual(u.support_state("python", c, "2029-11-01"), "end_of_life")

    def test_facts_carry_the_lts_date_only_for_node(self):
        self.assertEqual(u.support_facts("node", NODE_CYCLES["26"], "2026-10-13"),
                         {"eol": "2029-04-30", "support": "current", "lts_from": "2026-10-28"})
        self.assertEqual(u.support_facts("node", NODE_CYCLES["25"], "2026-01-01"), {"eol": "2026-06-01", "support": "current"})
        self.assertEqual(u.support_facts("python", PYTHON_CYCLES["3.15"], "2026-10-13"), {"eol": "2031-10-31", "support": "bugfix"})
        with self.assertRaises(u.Failure):
            u.support_facts("node", NODE_CYCLES["3"], "2026-10-13")

    def test_support_dates_come_from_endoflife_date(self):
        saved = u.fetch_json
        try:
            u.fetch_json = lambda url: list(NODE_CYCLES.values()) if "nodejs" in url else list(PYTHON_CYCLES.values())
            got = u.support_dates("2026-10-13")
        finally:
            u.fetch_json = saved
        self.assertEqual(got["node26"]["lts_from"], "2026-10-28")
        self.assertEqual(got["python3.13"], {"eol": "2029-10-31", "support": "security"})
        self.assertNotIn("node3", got)

    def test_dates_that_cannot_be_read_leave_the_rows_alone(self):
        saved = u.fetch_json
        try:
            def boom(url):
                raise OSError("offline")
            u.fetch_json = boom
            self.assertEqual(u.support_dates("2026-10-13"), {})
        finally:
            u.fetch_json = saved

    def test_a_month_only_date_is_replaced_by_the_full_date(self):
        row = {"id": "python3.11", "eol": "2027-10-01", "eol_month_only": True, "support": "security"}
        u.refresh_facts(row, {"eol": "2027-10-31", "support": "security"})
        self.assertEqual(row, {"id": "python3.11", "eol": "2027-10-31", "support": "security"})
        node = {"id": "node22", "lts_from": "2024-10-29"}
        u.refresh_facts(node, {"eol": "2027-04-30", "support": "maintenance"})
        self.assertNotIn("lts_from", node)


class NewSeriesTest(unittest.TestCase):
    def table(self):
        return table_of({"id": "node22", "kind": "node", "series": "22"}, {"id": "node24", "kind": "node", "series": "24"},
                        {"id": "python3.14", "kind": "python", "series": "3.14"}, {"id": "python3.13", "kind": "python", "series": "3.13"})

    def test_released_supported_series_with_an_image_are_found_oldest_first(self):
        got = u.new_series(self.table(), "node", NODE_CYCLES, "2027-05-01", exists=lambda k, s: True)
        self.assertEqual([s for s, _ in got], ["26", "27"])
        self.assertEqual(got[0][1]["support"], "lts")

    def test_a_series_that_is_not_released_ended_or_without_a_tag_is_left_out(self):
        got = u.new_series(self.table(), "node", NODE_CYCLES, "2026-10-13", exists=lambda k, s: True)
        self.assertEqual([s for s, _ in got], ["26"])  # 27 is not released, 25 has ended
        got = u.new_series(self.table(), "node", NODE_CYCLES, "2026-10-13", exists=lambda k, s: False)
        self.assertEqual(got, [])
        got = u.new_series(self.table(), "python", PYTHON_CYCLES, "2026-10-13", exists=lambda k, s: s == "3.15")
        self.assertEqual([s for s, _ in got], ["3.15"])

    def test_a_series_already_in_the_table_or_older_is_not_added(self):
        t = self.table()
        t["runtimes"].append({"id": "node26", "kind": "node", "series": "26"})
        self.assertEqual(u.new_series(t, "node", NODE_CYCLES, "2026-10-13", exists=lambda k, s: True), [])

    def test_the_tag_check_treats_only_a_404_as_absent(self):
        saved = u.urllib.request.urlopen
        try:
            def fake(code):
                def f(url, timeout=0):
                    self.assertEqual(url, "https://hub.docker.com/v2/repositories/library/node/tags/27-trixie-slim")
                    raise urllib.error.HTTPError(url, code, "x", {}, None)
                return f
            u.urllib.request.urlopen = fake(404)
            self.assertFalse(u.tag_exists("node", "27"))
            u.urllib.request.urlopen = fake(503)
            with self.assertRaises(u.Failure):
                u.tag_exists("node", "27")
        finally:
            u.urllib.request.urlopen = saved

    def test_a_new_row_starts_from_the_standard_safety_record_and_is_ordered(self):
        row = u.skeleton("python", "3.15", {"eol": "2031-10-31", "support": "bugfix"}, "2026-10-13")
        self.assertEqual(row["tag"], "3.15-slim-trixie")
        self.assertEqual(row["image"], "python")
        self.assertEqual(row["covered_paths"], ["/tmp", "/var/tmp", "/run/lock"])
        self.assertEqual(row["tested"], {})
        keys = list(u.ordered(dict(reversed(list(row.items())), version="3.15.0")))
        self.assertEqual(keys, [k for k in u.FIELD_ORDER if k in keys])

    def test_resolve_adds_the_row_after_the_last_of_its_kind_and_runs_the_checks(self):
        saved = (u.cycles_of, u.tag_exists, u.resolve_row, u.support_dates)
        checked = []
        try:
            u.cycles_of = lambda kind: NODE_CYCLES if kind == "node" else PYTHON_CYCLES
            u.tag_exists = lambda kind, series: True
            u.support_dates = lambda today: {}

            def fake_resolve(row, facts, today, report):
                checked.append(row["id"])
                new = dict(row, version=row["series"] + ".0")
                return new
            u.resolve_row = fake_resolve
            table = table_of(
                {"id": "node24", "kind": "node", "series": "24", "image": "node", "eol": "2028-04-30"},
                {"id": "python3.14", "kind": "python", "series": "3.14", "image": "python", "eol": "2030-10-31"},
            )
            with tempfile.TemporaryDirectory() as d:
                p, rep = os.path.join(d, "t.json"), os.path.join(d, "r.md")
                u.save(p, table)
                args = type("A", (), {"table": p, "report": rep, "only": ["node26"]})()
                with contextlib.redirect_stdout(io.StringIO()):
                    u.cmd_resolve(args)
                got = u.load(p)
                with open(rep) as f:
                    self.assertIn("node26: added", f.read())
        finally:
            u.cycles_of, u.tag_exists, u.resolve_row, u.support_dates = saved
        self.assertEqual([r["id"] for r in got["runtimes"]], ["node24", "node26", "python3.14"])
        self.assertEqual(checked, ["node26"])
        self.assertEqual(got["runtimes"][1]["tested"], {})


class DateTest(unittest.TestCase):
    def test_only_calendar_dates_are_dates(self):
        for v in ("2026-10-13", "2028-02-29"):
            self.assertTrue(u.is_date(v), v)
        for v in ("0000-00-00", "2026-13-01", "2026-02-30", "2027-02-29", "20261013", "2026-1-13", "2026-10-13T00:00", "", None, False, 20261013):
            self.assertFalse(u.is_date(v), v)

    def test_a_bad_release_date_adds_no_row(self):
        table = table_of({"id": "node24", "kind": "node", "series": "24"})
        for bad in ("0000-00-00", "2026-02-30", "soon", False, None):
            cycles = {"26": dict(NODE_CYCLES["26"], releaseDate=bad)}
            self.assertEqual(u.new_series(table, "node", cycles, "2026-10-13", exists=lambda k, s: True), [], bad)

    def test_dates_out_of_order_add_no_row(self):
        table = table_of({"id": "node24", "kind": "node", "series": "24"})
        for name, patch in (
            ("lts before the release", {"lts": "2026-01-01"}),
            ("lts after the end", {"lts": "2030-01-01"}),
            ("release after the end", {"releaseDate": "2029-05-01", "lts": False}),
            ("a bad lts date", {"lts": "2026-99-99"}),
        ):
            cycles = {"26": dict(NODE_CYCLES["26"], **patch)}
            got = u.new_series(table, "node", cycles, "2029-06-01" if "release after" in name else "2026-11-01", exists=lambda k, s: True)
            self.assertEqual(got, [], name)

    def test_an_lts_that_is_not_a_date_is_not_read_as_none(self):
        table = table_of({"id": "node24", "kind": "node", "series": "24"})
        for bad in ("2026-99-99", "soon", True, 20261028, None):
            cycles = {"26": dict(NODE_CYCLES["26"], lts=bad)}
            self.assertEqual(u.new_series(table, "node", cycles, "2026-11-01", exists=lambda k, s: True), [], bad)
            with self.assertRaises(u.Failure):
                u.support_facts("node", cycles["26"], "2026-11-01")
        # false and an absent key are the way to say there is none; an explicit
        # null is not.
        facts = u.support_facts("node", dict(NODE_CYCLES["26"], lts=False), "2026-11-01")
        self.assertNotIn("lts_from", facts)
        self.assertNotIn("lts_from", u.support_facts("node", {k: v for k, v in NODE_CYCLES["26"].items() if k != "lts"}, "2026-11-01"))

    def test_the_release_date_is_required(self):
        for bad in (None, False, "", "0000-00-00"):
            with self.assertRaises(u.Failure, msg=repr(bad)):
                u.support_facts("node", dict(NODE_CYCLES["26"], releaseDate=bad), "2026-11-01")
        with self.assertRaises(u.Failure):
            u.support_facts("node", {k: v for k, v in NODE_CYCLES["26"].items() if k != "releaseDate"}, "2026-11-01")

    def test_a_bad_support_date_is_a_failure(self):
        with self.assertRaises(u.Failure):
            u.support_facts("python", dict(PYTHON_CYCLES["3.15"], support="2028-13-01"), "2026-10-13")

    def test_existing_rows_keep_their_support_facts_when_the_answer_is_bad(self):
        saved = u.fetch_json
        try:
            for patch in ({"lts": "2026-99-99"}, {"lts": None}, {"support": None}, {"releaseDate": None}, {"eol": "2029-02-30"}):
                bad = dict(NODE_CYCLES["26"], **patch)
                u.fetch_json = lambda url, bad=bad: [bad, NODE_CYCLES["24"]] if "nodejs" in url else []
                with contextlib.redirect_stderr(io.StringIO()):
                    got = u.support_dates("2026-11-01")
                self.assertNotIn("node26", got, patch)
                self.assertIn("node24", got)
        finally:
            u.fetch_json = saved

    def test_support_dates_skip_an_entry_that_does_not_hold_together(self):
        saved = u.fetch_json
        bad = dict(NODE_CYCLES["26"], lts="2026-01-01")
        try:
            u.fetch_json = lambda url: [bad, NODE_CYCLES["24"]] if "nodejs" in url else []
            with contextlib.redirect_stderr(io.StringIO()):
                got = u.support_dates("2026-10-13")
        finally:
            u.fetch_json = saved
        self.assertNotIn("node26", got)
        self.assertIn("node24", got)

    def test_today_is_the_date_in_utc(self):
        jst = datetime.timezone(datetime.timedelta(hours=9))
        # 00:30 on the 14th in Japan is still the 13th in UTC.
        self.assertEqual(u.today_utc(datetime.datetime(2026, 10, 14, 0, 30, tzinfo=jst)), "2026-10-13")
        self.assertEqual(u.today_utc(datetime.datetime(2026, 10, 14, 9, 0, tzinfo=jst)), "2026-10-14")
        self.assertEqual(u.today_utc(datetime.datetime(2026, 10, 13, 15, 0, tzinfo=datetime.timezone.utc)), "2026-10-13")
        self.assertEqual(u.today_utc(datetime.datetime(2026, 10, 13, 15, 0)).count("-"), 2)

    def test_a_series_released_in_japan_today_is_not_released_yet_in_utc(self):
        jst = datetime.timezone(datetime.timedelta(hours=9))
        table = table_of({"id": "node24", "kind": "node", "series": "24"})
        cycles = {"26": dict(NODE_CYCLES["26"], releaseDate="2026-10-14")}
        early = u.today_utc(datetime.datetime(2026, 10, 14, 0, 30, tzinfo=jst))
        later = u.today_utc(datetime.datetime(2026, 10, 14, 9, 0, tzinfo=jst))
        self.assertEqual(u.new_series(table, "node", cycles, early, exists=lambda k, s: True), [])
        self.assertEqual([s for s, _ in u.new_series(table, "node", cycles, later, exists=lambda k, s: True)], ["26"])

    def test_resolve_uses_the_utc_date(self):
        saved = (u.now_utc, u.cycles_of, u.support_dates, u.resolve_row)
        seen = []
        jst = datetime.timezone(datetime.timedelta(hours=9))
        try:
            u.now_utc = lambda: datetime.datetime(2026, 10, 14, 0, 30, tzinfo=jst)
            u.cycles_of = lambda kind: {}
            u.support_dates = lambda today: seen.append(today) or {}
            u.resolve_row = lambda row, facts, today, report: seen.append(today) or dict(row)
            table = table_of({"id": "node24", "kind": "node", "series": "24", "image": "node", "eol": "2028-04-30"})
            with tempfile.TemporaryDirectory() as d:
                p = os.path.join(d, "t.json")
                u.save(p, table)
                with contextlib.redirect_stdout(io.StringIO()):
                    u.cmd_resolve(type("A", (), {"table": p, "report": os.path.join(d, "r.md"), "only": None})())
        finally:
            u.now_utc, u.cycles_of, u.support_dates, u.resolve_row = saved
        self.assertEqual(seen, ["2026-10-13", "2026-10-13"])


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
