#!/usr/bin/env python3
"""Update internal/worker/runtimes.json from the official Node.js and Python images.

The update containers run in the official images the table pins by digest. This
script moves the pins forward and checks that the new images are still safe to
use. It needs the docker CLI (with buildx); Trivy runs from its container image.

  resolve      follow each series tag to its image index, run the image for both
               platforms to read the exact versions, read the image configuration,
               scan the final filesystem for what the job user could write, run
               Trivy, refresh the support dates, and write the candidate table
               and a report (the body of the pull request)
  mark-tested  record the manifest digest of a platform for the runtimes named
               with --only, the ones whose fixtures passed on it; no other row
               is recorded
  scan-tar     print what a filesystem tar holds that the job user could write

Any check that fails ends the script with a non-zero status and leaves the
table as it was.
"""

import argparse
import datetime
import hashlib
import json
import os
import subprocess
import sys
import tarfile
import urllib.request

TABLE = "internal/worker/runtimes.json"
JOB_UID = 10001
PLATFORMS = ("linux/amd64", "linux/arm64")
TRIVY_IMAGE = "aquasec/trivy:0.71.2"
NODE_SCHEDULE = "https://raw.githubusercontent.com/nodejs/Release/main/schedule.json"
PYTHON_CYCLE = "https://peps.python.org/api/release-cycle.json"


class Failure(Exception):
    pass


def run(*cmd, check=True, input=None):
    p = subprocess.run(cmd, capture_output=True, input=input)
    if check and p.returncode != 0:
        raise Failure("%s failed (%d): %s" % (" ".join(cmd), p.returncode, p.stderr.decode(errors="replace").strip()[-600:]))
    return p


def load(path):
    with open(path) as f:
        return json.load(f)


def save(path, table):
    with open(path, "w") as f:
        json.dump(table, f, indent=2)
        f.write("\n")


# ---- the image index ----

def resolve_index(image, tag):
    """Return (index digest, {platform: manifest digest}) of image:tag."""
    ref = "%s:%s" % (image, tag)
    raw = run("docker", "buildx", "imagetools", "inspect", "--raw", ref).stdout
    index = json.loads(raw)
    digest = "sha256:" + hashlib.sha256(raw).hexdigest()
    found = {}
    for m in index.get("manifests", []):
        p = m.get("platform", {})
        plat = "%s/%s" % (p.get("os"), p.get("architecture"))
        if plat in PLATFORMS and "vnd.docker.reference.type" not in m.get("annotations", {}):
            if plat in found:
                raise Failure("%s lists %s twice" % (ref, plat))
            found[plat] = m["digest"]
    if set(found) != set(PLATFORMS):
        raise Failure("%s does not have both platforms: %s" % (ref, sorted(found)))
    return digest, found


# ---- running the image ----

def docker_run(pinned, platform, *args):
    return run("docker", "run", "--rm", "--platform", platform, "--network", "none", "--entrypoint", args[0], pinned, *args[1:]).stdout.decode().strip()


def exact_versions(row, pinned, platform):
    """Return (language version, pip version) the image reports for a platform."""
    if row["kind"] == "node":
        out = docker_run(pinned, platform, "node", "--version")
        if not out.startswith("v"):
            raise Failure("node --version printed %r" % out)
        return out[1:], ""
    py = "python" + row["series"]
    out = docker_run(pinned, platform, py, "--version")
    if not out.startswith("Python "):
        raise Failure("%s --version printed %r" % (py, out))
    pip = docker_run(pinned, platform, py, "-m", "pip", "--version").split()
    if len(pip) < 2 or pip[0] != "pip":
        raise Failure("pip --version printed %r" % " ".join(pip))
    return out.split()[1], pip[1]


def image_config(pinned, platform):
    out = run("docker", "image", "inspect", "--platform", platform, "--format", "{{json .Config}}", pinned).stdout
    return json.loads(out)


# ---- the final filesystem ----

def writable_by_job(member):
    """Whether the job user could write the entry, from the tar header alone."""
    if member.issym():
        return member.uid == JOB_UID
    if member.uid == JOB_UID:
        return True
    if member.mode & 0o002:
        return True
    if member.gid == JOB_UID and member.mode & 0o020:
        return True
    acl = member.pax_headers.get("SCHILY.acl.access", "")
    return any(("user:%d:" % JOB_UID) in e and "w" in e.split(":")[-1] for e in acl.split(",") if e)


def scan_stream(fileobj):
    """Return the entries of a filesystem tar the job user could write."""
    found = []
    with tarfile.open(fileobj=fileobj, mode="r|") as tf:
        for m in tf:
            if writable_by_job(m):
                name = m.name[2:] if m.name.startswith("./") else m.name
                found.append("/" + name.rstrip("/"))
    return found


# The engine mounts these when it starts a container; their contents are not
# part of the image.
ENGINE_PATHS = ("/proc", "/sys", "/dev")


def top_paths(paths):
    """Keep the entries not below another entry of the list, and leave out the
    engine's own mount points."""
    out = []
    for p in sorted(set(paths)):
        if any(p == e or p.startswith(e + "/") for e in ENGINE_PATHS):
            continue
        if not any(p == q or p.startswith(q + "/") for q in out):
            out.append(p)
    return out


def scan_image(pinned, platform):
    cid = run("docker", "create", "--platform", platform, pinned).stdout.decode().strip()
    try:
        exp = subprocess.Popen(["docker", "export", cid], stdout=subprocess.PIPE)
        found = scan_stream(exp.stdout)
        exp.stdout.close()
        if exp.wait() != 0:
            raise Failure("docker export failed")
    finally:
        run("docker", "rm", "-f", cid, check=False)
    return top_paths(found)


# ---- Trivy ----

def trivy(pinned, platform):
    """Return the findings Trivy reports for the image. A scan that cannot be
    made or read is a Failure: an image that was not checked is not pinned."""
    p = run("docker", "run", "--rm", "-v", "/var/run/docker.sock:/var/run/docker.sock", TRIVY_IMAGE, "image", "--quiet",
            "--platform", platform, "--scanners", "vuln", "--severity", "HIGH,CRITICAL", "--ignore-unfixed", "--format", "json", pinned,
            check=False)
    if p.returncode != 0:
        raise Failure("Trivy could not scan %s (%d): %s" % (pinned, p.returncode, p.stderr.decode(errors="replace").strip()[-300:]))
    try:
        results = json.loads(p.stdout).get("Results") or []
    except (ValueError, AttributeError) as e:
        raise Failure("Trivy's report for %s cannot be read: %s" % (pinned, e))
    findings = []
    for r in results:
        for v in r.get("Vulnerabilities") or []:
            findings.append((v["VulnerabilityID"], v["PkgName"], v.get("InstalledVersion", ""), v.get("FixedVersion", ""), v.get("Severity", "")))
    return findings


# ---- support dates ----

def fetch_json(url):
    with urllib.request.urlopen(url, timeout=30) as r:
        return json.load(r)


def support_dates():
    """Return {runtime id: (eol, month_only)} from the projects' own schedules."""
    out = {}
    try:
        for key, v in fetch_json(NODE_SCHEDULE).items():
            if key.startswith("v") and key[1:].isdigit() and "end" in v:
                out["node" + key[1:]] = (v["end"], False)
        for key, v in fetch_json(PYTHON_CYCLE).items():
            end = v.get("end_of_life", "")
            if key.startswith("3.") and end:
                out["python" + key] = (end + "-01", True) if len(end) == 7 else (end, False)
    except Exception as e:  # the dates are refreshed when they can be read
        print("support dates not refreshed: %s" % e, file=sys.stderr)
    return out


# ---- the commands ----

def cmd_resolve(args):
    table = load(args.table)
    today = datetime.date.today().isoformat()
    dates = support_dates()
    report = ["# Runtime table update", ""]
    changed = False
    for row in table["runtimes"]:
        rid = row["id"]
        if args.only and rid not in args.only:
            continue
        if "image" not in row:
            if rid in dates and dates[rid][0] != row["eol"]:
                report.append("- %s: end of support %s -> %s" % (rid, row["eol"], dates[rid][0]))
                row["eol"], changed = dates[rid][0], True
            continue
        index, manifests = resolve_index(row["image"], row["tag"])
        pinned = "%s@%s" % (row["image"], index)
        versions = set()
        for plat in PLATFORMS:
            run("docker", "pull", "--quiet", "--platform", plat, pinned)
            versions.add(exact_versions(row, pinned, plat))
            cfg = image_config(pinned, plat)
            if cfg.get("Volumes"):
                raise Failure("%s %s declares volumes: %s" % (rid, plat, sorted(cfg["Volumes"])))
            if cfg.get("Healthcheck"):
                raise Failure("%s %s declares a health check" % (rid, plat))
            env = dict(e.split("=", 1) for e in cfg.get("Env") or [])
            key = "NODE_VERSION" if row["kind"] == "node" else "PYTHON_VERSION"
            if env.get(key) != next(iter(versions))[0]:
                raise Failure("%s %s: %s is %r, the executable reports %r" % (rid, plat, key, env.get(key), next(iter(versions))[0]))
            writable = scan_image(pinned, plat)
            if sorted(writable) != sorted(row["covered_paths"]):
                raise Failure("%s %s: the job user could write %s, the table covers %s" % (rid, plat, writable, row["covered_paths"]))
        if len(versions) != 1:
            raise Failure("%s: the platforms report different versions: %s" % (rid, sorted(versions)))
        version, pip = versions.pop()
        findings = trivy(pinned, "linux/amd64")
        new = dict(row)
        new.update(version=version, index_digest=index, platforms=manifests, exact_tag=version + row["tag"][len(row["series"]):])
        if row["kind"] == "python":
            new["pip"] = pip
        if rid in dates:
            new["eol"] = dates[rid][0]
            if dates[rid][1] or "eol_month_only" in new:
                new["eol_month_only"] = dates[rid][1]
        if new != row:
            new["checked"], new["tested"] = today, {}
            report.append("- %s: %s (pip %s) %s -> %s" % (rid, version, pip or "-", row.get("index_digest", "")[:19], index[:19]))
            changed = True
        else:
            new["checked"] = today
        report.append("  - Trivy (HIGH, CRITICAL, fixed): %d finding(s)%s" % (len(findings), "".join("\n    - %s %s %s -> %s" % (f[0], f[1], f[2], f[3]) for f in findings[:20])))
        row.clear()
        row.update(new)
    if not changed:
        print("no change")
        return 0
    save(args.table, table)
    with open(args.report, "w") as f:
        f.write("\n".join(report) + "\n")
    print("\n".join(report))
    return 0


def cmd_mark_tested(args):
    table = load(args.table)
    for row in table["runtimes"]:
        if row.get("image") and row["id"] in args.only:
            row.setdefault("tested", {})[args.platform] = row["platforms"][args.platform]
    save(args.table, table)
    return 0


def cmd_scan_tar(args):
    with open(args.file, "rb") as f:
        print("\n".join(top_paths(scan_stream(f))))
    return 0


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("resolve")
    r.add_argument("--table", default=TABLE)
    r.add_argument("--report", default="runtimes-report.md")
    r.add_argument("--only", nargs="*", help="update only these runtime ids")
    r.set_defaults(fn=cmd_resolve)
    m = sub.add_parser("mark-tested")
    m.add_argument("--table", default=TABLE)
    m.add_argument("--platform", default="linux/amd64", choices=PLATFORMS)
    m.add_argument("--only", nargs="+", required=True,
                   help="the runtimes whose fixtures were run; only these are recorded")
    m.set_defaults(fn=cmd_mark_tested)
    s = sub.add_parser("scan-tar")
    s.add_argument("file")
    s.set_defaults(fn=cmd_scan_tar)
    args = ap.parse_args(argv)
    try:
        return args.fn(args)
    except Failure as e:
        print("error: %s" % e, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
