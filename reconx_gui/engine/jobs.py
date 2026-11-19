"""Background job manager: runs a tool in a thread, streams log lines, stores
results. Resolution order per job: ReconX module -> builtin -> error.
"""
from __future__ import annotations

import time
import queue
import threading
import traceback
from datetime import datetime

from . import registry, bridge, builtins


class Job:
    def __init__(self, jid, tool):
        self.id = jid
        self.tool = tool
        self.tool_id = tool["id"]
        self.status = "queued"          # queued|running|done|error|cancelled
        self.engine = "?"               # module|builtin
        self.created = time.time()
        self.started = None
        self.finished = None
        self.summary = ""
        self.findings = []
        self.result = None
        self.error = ""
        self.lines = []                 # full backlog
        self._subs = []                 # live SSE queues
        self._cancel = threading.Event()
        self._lock = threading.Lock()

    # ---- logging fan-out ----
    def log(self, msg):
        line = str(msg)
        with self._lock:
            self.lines.append(line)
            for q in list(self._subs):
                try:
                    q.put_nowait(("log", line))
                except Exception:
                    pass

    def _emit(self, kind, payload):
        with self._lock:
            for q in list(self._subs):
                try:
                    q.put_nowait((kind, payload))
                except Exception:
                    pass

    def subscribe(self):
        q = queue.Queue(maxsize=10000)
        with self._lock:
            for ln in self.lines:          # replay backlog to new subscriber
                q.put_nowait(("log", ln))
            if self.status in ("done", "error", "cancelled"):
                q.put_nowait(("status", self.status))
                q.put_nowait(("end", self.status))
            self._subs.append(q)
        return q

    def unsubscribe(self, q):
        with self._lock:
            if q in self._subs:
                self._subs.remove(q)

    def cancel(self):
        self._cancel.set()

    def to_dict(self, full=False):
        d = {"id": self.id, "tool_id": self.tool_id, "tool": self.tool["name"],
             "icon": self.tool.get("icon", ""), "cat": self.tool.get("cat", ""),
             "danger": self.tool.get("danger", "info"), "status": self.status,
             "engine": self.engine, "summary": self.summary,
             "findings_count": len(self.findings),
             "created": datetime.fromtimestamp(self.created).strftime("%H:%M:%S"),
             "duration": round((self.finished or time.time()) - (self.started or self.created), 1)
             if self.started else 0}
        if full:
            d["findings"] = self.findings
            d["result"] = self.result
            d["error"] = self.error
            d["lines"] = self.lines
        return d


class JobManager:
    def __init__(self):
        self.jobs = {}
        self._n = 0
        self._lock = threading.Lock()

    def create(self, tool_id, params):
        tool = registry.BY_ID.get(tool_id)
        if not tool:
            raise KeyError(tool_id)
        with self._lock:
            self._n += 1
            jid = f"job{self._n:04d}"
        job = Job(jid, tool)
        job.params = params
        self.jobs[jid] = job
        threading.Thread(target=self._run, args=(job, params), daemon=True).start()
        return job

    def _run(self, job: Job, params):
        job.status = "running"
        job.started = time.time()
        job._emit("status", "running")
        tool = job.tool
        try:
            use_module = bridge.availability(tool) == "module"
            if use_module:
                job.engine = "module"
                job.log(f"[=] engine: ReconX module ({tool['module']})")
                try:
                    res = bridge.run(job.tool_id, params, job.log, job._cancel)
                except ImportError:
                    use_module = False
                except Exception as e:
                    # module present but failed -> try builtin if any
                    job.log(f"[!] module error: {e}")
                    if tool.get("builtin"):
                        use_module = False
                    else:
                        raise
            if not use_module:
                fn = builtins.BUILTINS.get(tool.get("builtin") or "")
                if not fn:
                    raise RuntimeError(
                        "This tool needs the full ReconX modules/ package "
                        "(or an external binary) which isn't present. "
                        "Drop the GUI inside your ReconX repo to enable it.")
                job.engine = "builtin"
                job.log(f"[=] engine: builtin (stdlib) — {tool['builtin']}")
                res = fn(params, job.log, job._cancel)

            if job._cancel.is_set():
                job.status = "cancelled"
                job.summary = "cancelled"
            else:
                job.result = res.get("data")
                job.findings = res.get("findings", [])
                job.summary = res.get("summary", "done")
                job.status = "done"
                sev_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
                job.findings.sort(key=lambda f: -sev_rank.get(f.get("severity", "info"), 0))
                job.log(f"[✓] {job.summary} — {len(job.findings)} finding(s)")
        except Exception as e:
            job.status = "error"
            job.error = f"{type(e).__name__}: {e}"
            job.summary = job.error
            job.log(f"[✗] {job.error}")
            job.log(traceback.format_exc())
        finally:
            job.finished = time.time()
            job._emit("status", job.status)
            job._emit("result", job.to_dict(full=True))
            job._emit("end", job.status)

    def get(self, jid):
        return self.jobs.get(jid)

    def list(self):
        return [j.to_dict() for j in sorted(self.jobs.values(),
                key=lambda x: -x.created)]
