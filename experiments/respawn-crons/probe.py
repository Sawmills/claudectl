"""Offline transport proof: real claudectl + native hc, synthetic Claude/CronList.

No provider or production terminal is used. A restart waits the real 600 seconds.
Synthetic tool results prove wrapper wiring, not Claude/provider compliance.
"""
import argparse
import concurrent.futures
import hashlib
import http.server
import json
import os
from pathlib import Path
import subprocess
import threading
import time
import urllib.parse

WORK, SPARE = "a" * 64, "b" * 64
FAKE = r'''import json,os,select,signal,subprocess,sys,time,tty
from pathlib import Path
home=Path(os.environ["HOME"]);mode=os.environ["FIXTURE_MODE"]
args=sys.argv[1:];resumed="--resume" in args
settings=json.load(open(args[args.index("--settings")+1])) if mode!="control" else None
def hook(name,**extra):
 if settings:
  command=settings["hooks"][name][0]["hooks"][0]["command"]
  subprocess.run(["/bin/sh","-c",command],input=json.dumps(
   dict(hook_event_name=name,session_id="fixture-session",**extra)).encode(),check=True)
def state(name):
 os.write(1,("\x1b]7501;app=claude-code:state="+name+"\x07").encode())
def line():
 data=b""
 deadline=time.monotonic()+120
 while time.monotonic()<deadline:
  ready,_,_=select.select([0],[],[],min(5,max(0,deadline-time.monotonic())))
  if not ready:continue
  char=os.read(0,1)
  if char in (b"\r",b"\n"):return data
  assert char,"stdin closed"
  data+=char
 raise AssertionError("fixture input timeout")
signal.signal(signal.SIGTERM,lambda *_:sys.exit(143))
deadline=time.monotonic()+5
while os.tcgetpgrp(0)!=os.getpgrp() and time.monotonic()<deadline:time.sleep(.01)
assert os.tcgetpgrp(0)==os.getpgrp(),"child not foreground"
tty.setraw(0)
os.write(1,b"\x1b]7501;?\x07")
ready,_,_=select.select([0],[],[],5)
reply=os.read(0,4096) if ready else b""
assert b"7501;?" in reply,("missing capability reply",reply)
with (home/"launches.jsonl").open("a") as f:
 f.write(json.dumps(dict(resumed=resumed,args=args,foreground=True,capability_hex=reply.hex(),run=os.environ.get("CLAUDECTL_SERVER_RUN")))+"\n")
saved=[dict(id=job_id,cron=schedule,prompt=(home/file).read_text(),
 recurring=True,durable=False) for job_id,file,schedule in
 [("old-one","first.txt","*/5 * * * *"),("old-two","second.txt","24 8 * * *")]]
hook("SessionStart")
if mode!="control" and not resumed:
 (home/"initial-jobs.json").write_text(json.dumps(saved))
 if mode=="failover":hook("StopFailure",error="rate_limit")
 else:hook("Stop")
 state("idle");(home/"initial-ready").touch();os.write(1,b"D3_INITIAL_READY")
 while True:signal.pause()
jobs=saved[:1] if resumed and mode=="renewal" else []
note=args[-1] if resumed else ""
if resumed and "cron recovery attempt" in note:
 assert str(home/"first.txt") in note and str(home/"second.txt") in note
 existing=list(jobs)
 if "Keep every matching listed job" not in note:jobs=[]
 for job in saved:
  assert job["cron"] in note
  if not any(j["cron"]==job["cron"] and j["prompt"]==job["prompt"] for j in jobs):
   jobs.append(dict(job,id="saved-"+str(len(jobs)+1)))
 rows=[dict(type="user",sessionId="fixture-session",message=dict(content=note))]
 for i,inventory in enumerate([existing,jobs]):
  call="list-"+str(i);uuid="assistant-"+str(i)
  rows.append(dict(type="assistant",sessionId="fixture-session",uuid=uuid,
   message=dict(content=[dict(type="tool_use",name="CronList",id=call,input={})])))
  rows.append(dict(type="user",sessionId="fixture-session",sourceToolAssistantUUID=uuid,
   message=dict(content=[dict(type="tool_result",tool_use_id=call,content="inventory")]),
   toolUseResult=dict(jobs=inventory)))
 transcript=home/"transcript.jsonl"
 transcript.write_text("\n".join(map(json.dumps,rows))+"\n")
 card=home/"Code/.fleet/fixture/operator.md"
 text=card.read_text().splitlines()
 card.write_text("\n".join(x for x in text if not x.startswith(("cron_ids:","claude_session_file:")))+
  "\ncron_ids: "+" ".join(j["id"] for j in jobs)+"\nclaude_session_file: "+str(transcript)+"\n")
 hook("Stop",transcript_path=str(transcript))
else:hook("Stop")
(home/"resumed-jobs.json").write_text(json.dumps(dict(jobs=jobs,
 asks_missed_fire_replay="run that job's prompt ONCE now" in note)))
state("idle");(home/"resumed-ready").touch();os.write(1,b"D3_RESUMED_READY")
assert line()==b"fixture-input"
hook("UserPromptSubmit");state("working")
(home/"working").touch();os.write(1,b"D3_WORKING")
assert line()==b"fixture-finish"
hook("Stop")
sys.exit(7)
'''


def identity(account):
    name = "work" if account == WORK else "spare"
    return dict(account_uuid="claude-" + name, organization_uuid="org-" + name)


class Server(http.server.ThreadingHTTPServer):
    def __init__(self, mode):
        super().__init__(("127.0.0.1", 0), Handler)
        self.mode, self.requests = mode, []


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def answer(self, body):
        raw = json.dumps(body).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        query = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
        if "accounts" in self.path:
            self.answer([dict(provider="anthropic", account_id=a, alias=name,
                              identity=identity(a), available=True)
                         for a, name in [(WORK, "work"), (SPARE, "spare")]])
        elif "usage" in self.path:
            account = query.get("account_id", [WORK])[0]
            full = self.server.mode == "failover" and account == WORK
            self.answer(dict(data=dict(five_hour=dict(utilization=100 if full else 10),
                                       seven_day=dict(utilization=20),
                                       extra_usage=dict(is_enabled=False)),
                             observed_at=int(time.time() * 1000),
                             next_retry_at=0, stale=False, error=None))
        else:
            self.send_error(404)

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        account = body["account_id"]
        observed = body.get("observe", False)
        generation = 2 if observed else 1
        self.server.requests.append(dict(account=account, observe=observed))
        self.answer(dict(provider="anthropic", account_id=account, user_id="person",
                         identity=identity(account), access_token="synthetic-" + str(generation),
                         expires_at=int(time.time() * 1000) + generation * 3_600_000,
                         scopes=["user:inference", "user:profile"],
                         revision="revision-" + str(generation), generation=generation))


def private(path, body):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(body))
    path.chmod(0o600)


class Core:
    def __init__(self, receipt):
        info = json.loads(receipt.read_text())
        root = Path(info["root"])
        self.expected = json.loads(info["stdout"])["core"]["id"]
        self.env = dict(os.environ, HC_SESSION="flt675-offline-probe",
                        XDG_CONFIG_HOME=str(root / "config"), XDG_STATE_HOME=str(root / "state"),
                        XDG_CACHE_HOME=str(root / "cache"), XDG_DATA_HOME=str(root / "data"),
                        XDG_RUNTIME_DIR=str(root / "runtime"))
        self.env.pop("HC_TERMINAL_ID", None)
        assert self.call("server", "status")["core"]["id"] == self.expected

    def call(self, *args):
        result = subprocess.run(["hc", *args], env=self.env, capture_output=True,
                                text=True, timeout=55)
        if result.returncode:
            raise RuntimeError(result.stderr or result.stdout)
        return json.loads(result.stdout)

    def phase(self, terminal, home, name, marker, limit):
        deadline = time.monotonic() + limit
        expected = "working" if name == "working" else "idle"
        while time.monotonic() < deadline:
            current = self.call("get", terminal)
            if (home / name).exists() and current.get("status", {}).get("state") == expected:
                return
            if current["state"] == "finished":
                break
            if (home / name).exists():
                time.sleep(0.05)
            else:
                self.call("wait", terminal, "--output", marker, "--timeout", "45")
        raise AssertionError(name + " missing or native status not " + expected)


def case(core, binary, mode, output):
    home = output / mode
    home.mkdir(parents=True, exist_ok=False)
    server = Server(mode)
    serving = threading.Thread(target=server.serve_forever)
    serving.start()
    terminal = None
    started = time.monotonic()
    result = dict(mode=mode, provider="synthetic", actual_herdr_core=core.expected)
    try:
        fake = home / "fake-claude"
        fake.write_text("#!/usr/bin/python3\n" + FAKE)
        fake.chmod(0o755)
        folder = home / ".claudectl/server"
        private(folder / "connection.json",
                dict(server=f"http://127.0.0.1:{server.server_port}", user_id="person",
                     token_file=str(folder / "machine.json")))
        private(folder / "machine.json", "synthetic-machine")
        private(folder / "qualified-host-config-builds.json",
                [dict(sha256=hashlib.sha256(fake.read_bytes()).hexdigest(),
                      platform="linux", qualified_at="fixture", check="supervised_host_config")])
        (home / "first.txt").write_text("Check fixture-only lanes.\n")
        (home / "second.txt").write_text("Read fixture-only evidence.\n")
        card = home / "Code/.fleet/fixture/operator.md"
        card.parent.mkdir(parents=True)
        card.write_text("operator_tab: fixture-tab\ncron_ids: old-one old-two\ncron_prompts: " +
                        str(home / "first.txt") + " */5 * * * *; " +
                        str(home / "second.txt") + " 24 8 * * *\n")
        program = [str(fake)] if mode == "control" else [
            str(binary), "server", "run", "work", "--claude", str(fake)]
        if mode == "failover":
            program += ["--failover"]
        launched = core.call("run", "--bg", "--no-parent", "--no-notify",
                             "--name", "flt675-" + mode, "--label", "task=FLT675-offline",
                             "--cwd", str(home), "--", "/usr/bin/env", "-i",
                             "HOME=" + str(home), "PATH=/usr/bin:/bin",
                             "TERM=xterm-256color", "TERM_PROGRAM=herdr",
                             "CLAUDECTL_ALLOW_INSECURE_LOOPBACK=1",
                             "HERDR_TAB_ID=fixture-tab", "FIXTURE_MODE=" + mode, *program)
        terminal = launched["address"]
        private(home / "launch.json", launched)
        if mode != "control":
            core.phase(terminal, home, "initial-ready", "D3_INITIAL_READY", 30)
            initial = core.call("get", terminal)
            private(home / "initial-status.json", initial)
            assert initial["status"]["state"] == "idle"
        core.phase(terminal, home, "resumed-ready", "D3_RESUMED_READY", 690)
        resumed = core.call("get", terminal)
        private(home / "resumed-status.json", resumed)
        assert resumed["status"]["state"] == "idle"
        core.call("send", "--if", "idle", terminal, "fixture-input")
        core.phase(terminal, home, "working", "D3_WORKING", 30)
        working = core.call("get", terminal)
        private(home / "working-status.json", working)
        assert working["status"]["state"] == "working"
        core.call("send", "--if", "working", terminal, "fixture-finish")
        core.call("wait", terminal, "--timeout", "30")
        final = core.call("get", terminal)
        private(home / "final.json", final)
        assert final["state"] == "finished" and final["exit_code"] == 7, final
        jobs = json.loads((home / "resumed-jobs.json").read_text())
        launches = [json.loads(x) for x in (home / "launches.jsonl").read_text().splitlines()]
        result.update(elapsed=time.monotonic() - started, launches=len(launches),
                      cron_jobs=len(jobs["jobs"]), idle=True, working=True,
                      foreground=all(x["foreground"] for x in launches),
                      asks_missed_fire_replay=jobs["asks_missed_fire_replay"])
        if mode != "control":
            assert len(launches) == 2 and launches[1]["resumed"]
            assert len(jobs["jobs"]) == 2
            assert {x["cron"] for x in jobs["jobs"]} == {"*/5 * * * *", "24 8 * * *"}
            original = json.loads((home / "initial-jobs.json").read_text())
            definition = lambda job: (job["cron"], job["prompt"], job["recurring"], job["durable"])
            assert sorted(map(definition, jobs["jobs"])) == sorted(map(definition, original))
            if mode == "renewal":
                assert jobs["jobs"][0]["id"] == "old-one"
                assert launches[0]["run"] == launches[1]["run"]
            else:
                assert launches[0]["run"] != launches[1]["run"]
                assert any(request["account"] == SPARE for request in server.requests)
            assert not jobs["asks_missed_fire_replay"]
            journal = home / ".claudectl/server/cron-recovery.jsonl"
            assert "cron recovery verified: 2/2 saved jobs" in journal.read_text()
        result["pass"] = True
    except Exception as error:
        result.update(error=repr(error), elapsed=time.monotonic() - started, **{"pass": False})
    finally:
        try:
            if terminal:
                capture = subprocess.run(["hc", "read", terminal, "--lines", "120"],
                                         env=core.env, capture_output=True, text=True, timeout=20)
                (home / "screen.txt").write_text(capture.stdout + capture.stderr)
                current = core.call("get", terminal)
                private(home / "cleanup-state.json", current)
                assert current["labels"].get("task") == "FLT675-offline"
                if current["state"] == "live":
                    core.call("kill", terminal)
                core.call("rm", terminal)
        except Exception as error:
            result.update(cleanup_error=repr(error), **{"pass": False})
        server.shutdown()
        server.server_close()
        serving.join()
        private(home / "result.json", result)
        print(json.dumps(result), flush=True)
    return result["pass"]


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--core-receipt", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--case", choices=["control", "renewal", "failover"],
                        action="append", required=True)
    options = parser.parse_args()
    options.output = options.output.resolve()
    core = Core(options.core_receipt)
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(options.case)) as workers:
        results = list(workers.map(lambda mode: case(core, options.binary, mode, options.output),
                                  options.case))
    raise SystemExit(0 if all(results) else 1)
