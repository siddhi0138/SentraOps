from collections import defaultdict

from app.metrics import ai_call_duration_seconds, ai_calls_total, ai_cost_usd_total, ai_tokens_total


def get_ai_observability_summary() -> dict:
    """Reads the real, currently-accumulated values straight off this
    process's own Prometheus metric objects (app/metrics.py, populated by
    every Groq call via app/ai.py's _call_groq) - the exact same numbers
    /metrics exposes to Prometheus, just reshaped into a per-feature JSON
    summary for the frontend dashboard. No separate storage, so this can
    never drift from what Prometheus itself would report.

    Per-process, not cluster-wide: with more than one backend replica this
    would only reflect the pod that served the request, same limitation
    every in-process Prometheus client metric has - this app runs the
    backend as a single replica (see the Helm chart), so it's a non-issue
    here, but worth knowing if that ever changes."""
    calls: dict[str, dict[str, float]] = defaultdict(lambda: {"success": 0.0, "error": 0.0})
    for metric in ai_calls_total.collect():
        for s in metric.samples:
            if s.name.endswith("_total"):
                calls[s.labels["feature"]][s.labels["status"]] += s.value

    durations: dict[str, dict[str, float]] = defaultdict(lambda: {"count": 0.0, "sum": 0.0})
    for metric in ai_call_duration_seconds.collect():
        for s in metric.samples:
            if s.name.endswith("_count"):
                durations[s.labels["feature"]]["count"] = s.value
            elif s.name.endswith("_sum"):
                durations[s.labels["feature"]]["sum"] = s.value

    tokens: dict[str, dict[str, float]] = defaultdict(lambda: {"prompt": 0.0, "completion": 0.0})
    for metric in ai_tokens_total.collect():
        for s in metric.samples:
            if s.name.endswith("_total"):
                tokens[s.labels["feature"]][s.labels["token_type"]] += s.value

    cost: dict[str, float] = defaultdict(float)
    for metric in ai_cost_usd_total.collect():
        for s in metric.samples:
            if s.name.endswith("_total"):
                cost[s.labels["feature"]] += s.value

    features = set(calls) | set(durations) | set(tokens) | set(cost)
    rows = []
    for feature in sorted(features):
        c, d, t = calls[feature], durations[feature], tokens[feature]
        total_calls = c["success"] + c["error"]
        rows.append(
            {
                "feature": feature,
                "calls_success": int(c["success"]),
                "calls_error": int(c["error"]),
                "success_rate_pct": round(100 * c["success"] / total_calls, 1) if total_calls else None,
                "avg_duration_seconds": round(d["sum"] / d["count"], 2) if d["count"] else None,
                "prompt_tokens": int(t["prompt"]),
                "completion_tokens": int(t["completion"]),
                # 6 decimals, not 4: a single call at this app's typical
                # token volumes costs a few millionths of a dollar - 4
                # decimals would silently round small-but-real costs to 0.0.
                "estimated_cost_usd": round(cost[feature], 6),
            }
        )

    return {
        "features": rows,
        "totals": {
            "calls": sum(r["calls_success"] + r["calls_error"] for r in rows),
            # Summed from the unrounded per-feature values, not the already-
            # rounded row totals, so this doesn't compound rounding error.
            "estimated_cost_usd": round(sum(cost.values()), 6),
            "prompt_tokens": sum(r["prompt_tokens"] for r in rows),
            "completion_tokens": sum(r["completion_tokens"] for r in rows),
        },
    }
