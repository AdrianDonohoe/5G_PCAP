"""Shared schemas: the Alarm event (the per-invocation trigger) and the
Evidence item (the specialist agents' common currency)."""

from typing import Literal

from pydantic import BaseModel, Field


class TimeWindow(BaseModel):
    start: float
    end: float


class AlarmEvent(BaseModel):
    incident_id: str
    detected_at: float
    source: Literal["kpi", "alarm", "human"]
    procedure: str | None = None
    time_window: TimeWindow
    description: str
    kpi: dict | None = None
    captures: dict | None = None


class EvidenceItem(BaseModel):
    source: Literal["pcap", "log", "kpi"]
    kind: str
    ts: float
    entry: str
    cause: str | None = None
    endpoints: list[str] | None = None
    keys: dict = Field(default_factory=dict)
    citation: str
