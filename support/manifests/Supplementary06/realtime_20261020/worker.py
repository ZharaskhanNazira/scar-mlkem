#!/usr/bin/env python3
"""Sequential native campaign worker for Raspberry Pi 5.
Runs every planned process exactly once in registered order. No retry, no selection,
no analysis. Every outcome, including failures, is recorded."""
import hashlib, json, os, platform, re, signal, subprocess, sys, time
from pathlib import Path

def sha(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()

def write(path, obj):
    path = Path(path); path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".partial")
    tmp.write_text(json.dumps(obj, sort_keys=True, indent=2, allow_nan=False) + "\n")
    os.replace(tmp, path)

def read_sys(p):
    try:
        return Path(p).read_text().strip()
    except OSError as exc:
        return "unavailable:" + type(exc).__name__

def environment(cpu):
    try:
        throttled = subprocess.run(["vcgencmd", "get_throttled"], capture_output=True, text=True, timeout=5).stdout.strip()
    except (OSError, subprocess.SubprocessError) as exc:
        throttled = "unavailable:" + type(exc).__name__
    return dict(governor=read_sys(f"/sys/devices/system/cpu/cpu{cpu}/cpufreq/scaling_governor"),
                frequency_khz=read_sys(f"/sys/devices/system/cpu/cpu{cpu}/cpufreq/scaling_cur_freq"),
                temperature_millic=read_sys("/sys/class/thermal/thermal_zone0/temp"),
                throttled=throttled, loadavg=read_sys("/proc/loadavg"), kernel=platform.release(),
                machine=platform.machine(), utc=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))

def kv(text):
    values = {}
    for key, val in re.findall(r"([A-Za-z_]\w*)=([^\s]+)", text):
        if key in values and values[key] != val:
            values[key + "__conflict"] = val
        values.setdefault(key, val)
    return values

def main():
    assert len(sys.argv) == 3, "usage: worker.py SPEC_JSON SPEC_SHA256"
    spec_path, expected = Path(sys.argv[1]), sys.argv[2]
    assert sha(spec_path) == expected, "spec digest mismatch"
    spec = json.loads(spec_path.read_text())
    root = Path(spec["remote_root"]); os.chdir(root)
    assert sha(spec["binary"]) == spec["binary_sha256"] and sha(spec["library"]) == spec["library_sha256"]
    raw = root / spec["raw_dir"]; raw.mkdir(parents=True, exist_ok=False)
    write(raw / "spec.json", spec)
    cpu, names = spec["cpu"], spec["cost_names"]
    cost_args = [format(spec["costs_ns"][k], ".17g") for k in names]
    records, passed, failed, aborted = [], 0, 0, None
    first_env = environment(cpu)
    for index, row in enumerate(spec["plan"]):
        before = environment(cpu)
        before["scheduler"] = os.sched_getscheduler(0)
        wrong_frequency = "frequency_khz" in spec and before["frequency_khz"] != str(spec["frequency_khz"])
        if before["governor"] != spec["governor"] or not before["throttled"].endswith("=0x0") or wrong_frequency:
            aborted = dict(index=index, reason="environment", environment=before); break
        args = ["run", row["session_id"], row["family"], str(row["seed"]), str(spec["requests"]),
                str(spec["contexts"]), str(spec["interval_us"]), spec["split"], row["policy"],
                str(row["arena_bytes"]), str(row["ttl_ms"]), str(spec["guard_us"]), str(spec["horizon_ms"]),
                str(spec["history_capacity"]), str(row["components"])] + cost_args + [str(spec["drift"])]
        argv = ["taskset", "-c", str(cpu), spec["binary"]] + args
        env = {k: v for k, v in os.environ.items() if not k.startswith("SCAR_")}
        if row["policy"] == "scar":
            env.update(SCAR_K=str(spec["scar"]["k"]), SCAR_NU=str(spec["scar"]["nu"]), SCAR_MARGIN=str(spec["scar"]["margin"]))
        base = raw / row["session_id"]
        started = time.monotonic()
        with open(str(base) + ".stdout.csv", "wb") as out, open(str(base) + ".stderr.txt", "wb") as err:
            proc = subprocess.Popen(argv, stdout=out, stderr=err, env=env, stdin=subprocess.DEVNULL, start_new_session=True)
            try:
                rc = proc.wait(timeout=spec["timeout_seconds"])
            except subprocess.TimeoutExpired:
                os.killpg(proc.pid, signal.SIGKILL); rc = proc.wait()
        wall = time.monotonic() - started
        after = environment(cpu)
        meta = kv(Path(str(base) + ".stderr.txt").read_text(errors="replace"))
        rows = sum(1 for _ in open(str(base) + ".stdout.csv", "rb")) - 1
        ok = rc == 0 and meta.get("native_success") == "1" and meta.get("request_count") == str(spec["requests"]) and rows == spec["requests"]
        status = "passed" if ok else "failed"
        passed += ok; failed += (not ok)
        record = dict(index=index, row=row, argv=argv, before=before, after=after, returncode=rc,
                      wall_seconds=wall, status=status, metadata=meta, stdout_rows=rows,
                      stdout_sha256=sha(str(base) + ".stdout.csv"), stderr_sha256=sha(str(base) + ".stderr.txt"))
        write(str(base) + ".record.json", record); records.append(record)
        write(raw / "progress.json", dict(attempted=index + 1, passed=passed, failed=failed, planned=len(spec["plan"])))
        time.sleep(spec["cooldown_seconds"])
    files = {str(p.relative_to(raw)): sha(p) for p in sorted(raw.rglob("*")) if p.is_file() and p.name != "progress.json"}
    write(raw / "done.json", dict(status="aborted" if aborted else "completed", aborted=aborted,
          attempted=len(records), passed=passed, failed=failed, planned=len(spec["plan"]),
          spec_sha256=expected, environment_first=first_env, environment_last=environment(cpu),
          python=platform.python_version(), files=files))

if __name__ == "__main__":
    main()
