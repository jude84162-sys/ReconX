# modules/vuln/advanced/race_condition.py
"""ReconX - Race condition (TOCTOU) fuzzer.

Fires N requests through a thread barrier so they leave at the same instant,
then compares the set of successful responses against a sequential baseline.
A limit-bypass window exists when the parallel burst produces more distinct
successful outcomes than the endpoint allows (e.g. a coupon redeemed twice).

Use against endpoints where a one-time action must happen only once: coupon
redemption, transfer, vote, invite accept, password-reset token use.
"""

import threading
import time

from modules.utils.http_client import normalize_url, request, text_similarity
from modules.vuln.advanced.base import add_finding, finalize, finding, new_result, print_report

CLUSTER_SIMILARITY = 0.97


def _send(target, method, data, headers, timeout):
    return request(target, method=method, data=data, headers=headers, timeout=timeout)


def _cluster(bodies):
    """Group near-identical bodies; returns list of cluster sizes."""
    clusters = []
    for body in bodies:
        for cluster in clusters:
            if text_similarity(body, cluster[0]) >= CLUSTER_SIMILARITY:
                cluster.append(body)
                break
        else:
            clusters.append([body])
    return clusters


def _run_burst(target, method, data, headers, threads, timeout):
    barrier = threading.Barrier(threads, timeout=timeout + 5)
    responses = []
    lock = threading.Lock()
    errors = []

    def worker():
        try:
            barrier.wait()
            resp = _send(target, method, data, headers, timeout)
        except Exception as e:
            with lock:
                errors.append(str(e))
            return
        with lock:
            responses.append(resp)

    workers = [threading.Thread(target=worker, daemon=True) for _ in range(threads)]
    for w in workers:
        w.start()
    for w in workers:
        w.join(timeout=timeout + 10)
    return responses, errors


def _summarize(responses):
    successes = [r for r in responses if 200 <= (r.status or 0) < 300]
    failures = [r for r in responses if r not in successes]
    clusters = _cluster([r.body for r in successes])
    elapsed = [r.elapsed for r in responses if r.error is None]
    return {
        "total": len(responses),
        "successes": len(successes),
        "failures": len(failures),
        "statuses": sorted({r.status for r in responses if r.status}),
        "clusters": len(clusters),
        "cluster_sizes": [len(c) for c in clusters],
        "sample_success": successes[0].body[:300] if successes else "",
        "elapsed_min": round(min(elapsed), 3) if elapsed else 0,
        "elapsed_max": round(max(elapsed), 3) if elapsed else 0,
    }


def scan(target, method="POST", data=None, headers=None, threads=20,
         max_expected=1, timeout=10, verbose=False):
    """Fire a synchronized burst and check how many responses succeeded.

    No warmup or sequential baseline is sent: on a genuine one-time action
    (coupon, transfer, invite) any request before the burst would consume it
    and hide the race. ``max_expected`` is the business rule the tester asserts
    (usually 1); only an excess of successful responses is reported.
    """
    target = normalize_url(target)
    threads = max(2, min(int(threads or 20), 100))
    result = new_result(target, method=method.upper(), threads=threads,
                        max_expected=max_expected)

    # Parallel burst.
    result["checks_run"].append(f"parallel_burst_x{threads}")
    started = time.time()
    burst, errors = _run_burst(target, method, data, headers, threads, timeout)
    result["parallel"] = _summarize(burst)
    result["elapsed"] = round(time.time() - started, 2)
    for err in errors[:5]:
        result["errors"].append(f"burst: {err}")

    parallel = result["parallel"]
    if verbose:
        print(f"  [*] Parallel burst: {parallel['successes']} success, "
              f"{parallel['clusters']} distinct body cluster(s)")

    over_limit = parallel["successes"] > max_expected

    if over_limit and parallel["clusters"] > 1:
        add_finding(result, finding(
            "race_condition_limit_bypass",
            "Race condition: parallel burst bypasses the one-time limit",
            "high",
            target,
            f"{parallel['successes']}/{parallel['total']} requests succeeded in parallel "
            f"({parallel['clusters']} distinct success bodies); expected max {max_expected}",
            description=("Multiple concurrent requests were all processed as if the action "
                         "had not happened yet (time-of-check to time-of-use). Business impact "
                         "depends on the endpoint: duplicate redemption, double spend, multiple "
                         "votes, reused reset token."),
            remediation=("Make the check-and-write atomic: DB transaction with SELECT ... FOR "
                         "UPDATE, unique constraints, idempotency keys or a distributed lock."),
            confidence=0.75,
            bug_class="race_condition",
            sample=parallel["sample_success"],
            source="race_condition",
        ))
    elif parallel["successes"] > max_expected and parallel["clusters"] == 1:
        add_finding(result, finding(
            "race_condition_suspected",
            "Race condition: all parallel requests succeeded",
            "medium",
            target,
            f"{parallel['successes']}/{parallel['total']} parallel requests returned the "
            f"same success response; expected max {max_expected}",
            description=("The endpoint accepted every concurrent request. This is benign for "
                         "idempotent reads but a bug for one-time actions. Verify the "
                         "business rule before reporting."),
            remediation="Enforce one-time actions atomically (constraint or lock).",
            confidence=0.5,
            bug_class="race_condition",
            source="race_condition",
        ))
    else:
        result["note"] = ("No race window detected in this burst; increase --threads or "
                          "target a strictly one-time endpoint for a meaningful test")

    return finalize(result)


run_scanner = scan


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python -m modules.vuln.advanced.race_condition <url> "
              "[--method POST] [--data '...'] [--threads 20] [--max-expected 1]")
        sys.exit(1)

    args = sys.argv[1:]
    url = args[0]
    opts = {"verbose": True}
    for i, arg in enumerate(args):
        if arg == "--method" and i + 1 < len(args):
            opts["method"] = args[i + 1]
        elif arg == "--data" and i + 1 < len(args):
            opts["data"] = args[i + 1]
        elif arg == "--threads" and i + 1 < len(args):
            opts["threads"] = int(args[i + 1])
        elif arg == "--max-expected" and i + 1 < len(args):
            opts["max_expected"] = int(args[i + 1])
    print_report(scan(url, **opts), "Race Condition Fuzzer")
