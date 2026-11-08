"""Minimal read-only Python Activity View plugin example.

Copy this file to %APPDATA%\\PythonActivityView\\plugins only after reviewing it.
The app discovers filenames without importing this module.
"""

PAV_PLUGIN = {
    "name": "Read-only event counter example",
    "version": "1.0.0",
    "read_only": True,
}


def analyze(context: dict) -> dict:
    """Return a small summary without mutating the supplied context."""
    events = context.get("events", [])
    if not isinstance(events, list):
        events = []
    by_source: dict[str, int] = {}
    for event in events:
        if not isinstance(event, dict):
            continue
        source = str(event.get("source", "unknown"))[:200]
        by_source[source] = by_source.get(source, 0) + 1
    return {
        "summary": "Read-only event counts by source",
        "event_count": len(events),
        "events_by_source": by_source,
    }
