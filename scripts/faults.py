#!/usr/bin/env python3
"""Fault-injection scenarios from the command line (issue #25).

Talks to a running NetMind server (make run), so injected faults, alerts and results are the same
ones the Scenarios page shows.

Usage (lab up, server running on http://127.0.0.1:8000):
    python3 scripts/faults.py list                         # scenarios and their possible targets
    python3 scripts/faults.py inject branch-latency fw-branch2
    python3 scripts/faults.py status                       # every run and whether it was detected
    python3 scripts/faults.py revert f1a2b3c4               # undo one fault
    python3 scripts/faults.py revert --all                 # undo every active fault
    python3 scripts/faults.py run-all                      # each scenario once: inject, wait for
                                                           # the alert, revert, wait for recovery

run-all writes fault-results.json and prints a table: scenario, target, detected or not, and the
seconds from injection to the first alert. Uses the standard library only.
"""
import argparse
import json
import sys
import time
import urllib.error
import urllib.request


def call(base, method, path, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(base + path, data=data, method=method,
                                 headers={"Content-Type": "application/json"} if data else {})
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return json.loads(r.read() or b"null")
    except urllib.error.HTTPError as e:
        try:
            return json.loads(e.read())
        except ValueError:
            return {"error": f"HTTP {e.code}"}


def find_run(base, run_id):
    return next((r for r in call(base, "GET", "/api/faults")["runs"] if r["id"] == run_id), None)


def wait_for(base, run_id, timeout):
    """Polls until the run is detected or `timeout` seconds pass. -> the run."""
    deadline = time.time() + timeout
    while True:
        run = find_run(base, run_id)
        if run is None or run.get("detected") or time.time() >= deadline:
            return run
        time.sleep(1)


def table(rows):
    print(f"{'scenario':26} {'target':14} {'detected':9} {'seconds':>7}  other alerts")
    for r in rows:
        secs = "" if r.get("detection_seconds") is None else f"{r['detection_seconds']:.1f}"
        flag = "yes" if r.get("detected") else ("ERROR" if r.get("error") else "no")
        print(f"{r['scenario']:26} {r['target']:14} {flag:9} {secs:>7}  {len(r.get('other_alerts') or [])}")


def main():
    p = argparse.ArgumentParser(description="NetMind fault-injection scenarios")
    p.add_argument("--base", default="http://127.0.0.1:8000")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("list")
    sub.add_parser("status")
    i = sub.add_parser("inject")
    i.add_argument("scenario")
    i.add_argument("target")
    r = sub.add_parser("revert")
    r.add_argument("run", nargs="?")
    r.add_argument("--all", action="store_true")
    a = sub.add_parser("run-all")
    a.add_argument("--detect-timeout", type=int, default=60, help="seconds to wait for the alert")
    a.add_argument("--settle", type=int, default=20, help="seconds to let the lab recover between scenarios")
    a.add_argument("--only", nargs="*", help="scenario ids to run (default: all)")
    args = p.parse_args()
    base = args.base.rstrip("/")

    if args.cmd == "list":
        for s in call(base, "GET", "/api/faults")["scenarios"]:
            print(f"{s['id']:26} {s['title']:36} targets: {', '.join(s['targets'])}")
    elif args.cmd == "status":
        table(call(base, "GET", "/api/faults")["runs"])
    elif args.cmd == "inject":
        print(json.dumps(call(base, "POST", "/api/faults/inject", {"scenario": args.scenario, "target": args.target}), indent=2))
    elif args.cmd == "revert":
        path = "/api/faults/revert-all" if args.all else f"/api/faults/{args.run}/revert"
        if not args.all and not args.run:
            sys.exit("give a run id, or --all")
        print(json.dumps(call(base, "POST", path), indent=2))
    elif args.cmd == "run-all":
        scenarios = call(base, "GET", "/api/faults")["scenarios"]
        rows = []
        for s in scenarios:
            if args.only and s["id"] not in args.only:
                continue
            if not s["targets"]:
                continue
            target = s["targets"][-1]
            print(f"-> {s['id']} on {target} ...", flush=True)
            run = call(base, "POST", "/api/faults/inject", {"scenario": s["id"], "target": target})
            if run.get("error"):
                rows.append({"scenario": s["id"], "target": target, "error": run["error"]})
                print(f"   could not inject: {run['error']}")
                continue
            run = wait_for(base, run["id"], args.detect_timeout) or run
            call(base, "POST", f"/api/faults/{run['id']}/revert")
            rows.append(find_run(base, run["id"]) or run)
            time.sleep(args.settle)
        with open("fault-results.json", "w") as f:
            json.dump(rows, f, indent=2)
        table(rows)
        detected = [r for r in rows if r.get("detected")]
        if rows:
            print(f"\ndetected {len(detected)} of {len(rows)}"
                  + (f", average {sum(r['detection_seconds'] for r in detected) / len(detected):.1f} s" if detected else ""))


if __name__ == "__main__":
    main()
