"""Dataclass for normalized CloudTrail events."""

from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class NormalizedEvent:
    """A normalized representation of a CloudTrail event.

    Flattens the nested CloudTrail JSON structure into a consistent
    dataclass for filtering, display, and export.
    """

    event_time: datetime
    event_name: str
    event_source: str
    principal_id: str
    principal_arn: str
    source_ip: str
    region: str
    user_agent: str
    request_parameters: dict = field(default_factory=dict)
    response_elements: dict = field(default_factory=dict)
    raw: dict = field(default_factory=dict)
