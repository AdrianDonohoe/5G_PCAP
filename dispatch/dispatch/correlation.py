"""Deterministic correlation: shared keys link evidence items, the event's
time window is candidate scope only (never a link predicate), and a key
value that identifies more than two items is ambiguous and links nothing."""

from collections import defaultdict


def link(evidence: list[dict], window: tuple[float, float]) -> list[dict]:
    """Link evidence items that share a key value inside the window.

    Returns one ``{a, b, key, value}`` dict per linked pair, ``a``/``b``
    indexing the original evidence list, ordered by ``(a, b)``.
    """
    by_value: dict[tuple[str, object], list[int]] = defaultdict(list)
    for index, item in enumerate(evidence):
        for key, value in item.get("keys", {}).items():
            if value is not None:
                by_value[(key, value)].append(index)

    ambiguous = {kv for kv, idxs in by_value.items() if len(idxs) > 2}
    start, end = window
    links: list[dict] = []
    seen: set[tuple[int, int]] = set()
    for (key, value), indexes in by_value.items():
        if (key, value) in ambiguous:
            continue
        for a in indexes:
            for b in indexes:
                if a >= b or (a, b) in seen:
                    continue
                item_a, item_b = evidence[a], evidence[b]
                in_window = (start <= item_a["ts"] <= end
                             and start <= item_b["ts"] <= end)
                if not in_window:
                    continue
                keys_a, keys_b = item_a.get("keys", {}), item_b.get("keys", {})
                disagree = any(
                    k in keys_b
                    and keys_a[k] is not None
                    and keys_b[k] is not None
                    and keys_a[k] != keys_b[k]
                    for k in keys_a
                )
                if disagree:
                    continue
                seen.add((a, b))
                links.append({"a": a, "b": b, "key": key, "value": value})
    links.sort(key=lambda l: (l["a"], l["b"], l["key"]))
    return links
