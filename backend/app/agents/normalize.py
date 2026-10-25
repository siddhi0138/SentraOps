"""Coercion of an AI model's JSON into the shapes the agents rely on.

The agents ask for specific structures (a list of technique objects, a list of action
objects), but models don't always comply: a list of plain strings, a single object,
null. A shape that doesn't match shouldn't crash an investigation, so each value is
coerced to the expected one here."""


def _as_list(value) -> list:
    if value is None or value == "":
        return []
    return value if isinstance(value, list) else [value]


def technique_list(value) -> list[dict]:
    """MITRE techniques as [{"id": ..., ...}]. A bare string becomes {"id": string}."""
    techniques = []
    for item in _as_list(value):
        if isinstance(item, dict):
            techniques.append(item)
        elif isinstance(item, str) and item.strip():
            techniques.append({"id": item.strip()})
    return techniques


def action_list(value) -> list[dict]:
    """Proposed response actions as [{"category": ..., "description": ...}]. A bare
    string becomes a containment action with that description."""
    actions = []
    for item in _as_list(value):
        if isinstance(item, dict):
            actions.append(
                {**item, "category": str(item.get("category") or "containment"), "description": str(item.get("description") or "")}
            )
        elif isinstance(item, str) and item.strip():
            actions.append({"category": "containment", "description": item.strip()})
    return actions
