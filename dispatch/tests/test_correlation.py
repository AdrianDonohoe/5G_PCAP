"""Correlation graph rules: shared keys link, the window is candidate scope
only, and ambiguous keys link nothing."""

from dispatch.correlation import link


def _item(ts=1750000000.0, **keys):
    return {"source": "pcap", "kind": "k", "ts": ts, "entry": "e",
            "cause": None, "endpoints": None, "keys": keys,
            "citation": f"c-{ts}"}


def test_shared_key_links_within_window():
    items = [_item(ts=1750000000.0, supi="999700000000001"),
             _item(ts=1750000050.0, supi="999700000000001")]
    links = link(items, window=(1749999900.0, 1750000100.0))
    assert len(links) == 1
    assert links[0]["a"] == 0 and links[0]["b"] == 1
    assert links[0]["key"] == "supi"


def test_any_shared_key_links():
    items = [_item(supi="x", teid="0x1"),
             _item(teid="0x1")]
    assert len(link(items, window=(1749999900.0, 1750000100.0))) == 1


def test_window_is_candidate_scope_only():
    # Same key, but one item outside the event's window: no link.
    items = [_item(ts=1750000000.0, supi="x"),
             _item(ts=9999999999.0, supi="x")]
    assert link(items, window=(1749999900.0, 1750000100.0)) == []


def test_window_alone_never_links():
    items = [_item(ts=1750000000.0, supi="x"),
             _item(ts=1750000050.0, supi="y")]
    assert link(items, window=(1749999900.0, 1750000100.0)) == []


def test_ambiguous_key_value_links_nothing():
    # One key value on three items: ambiguous, no links for that value.
    items = [_item(supi="x"), _item(supi="x"), _item(supi="x")]
    assert link(items, window=(1749999900.0, 1750000100.0)) == []


def test_conflicting_keys_link_nothing():
    # Items agree on supi but disagree on teid: ambiguous, never a guess.
    items = [_item(supi="x", teid="0x1"),
             _item(supi="x", teid="0x2")]
    assert link(items, window=(1749999900.0, 1750000100.0)) == []


def test_multiple_shared_keys_link_once():
    items = [_item(supi="x", teid="0x1", nf="upf"),
             _item(supi="x", teid="0x1", nf="upf")]
    links = link(items, window=(1749999900.0, 1750000100.0))
    assert len(links) == 1
