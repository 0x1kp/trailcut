"""Export functions for CloudTrail events to JSON and CSV formats."""

import csv
import io
import json
from datetime import datetime

from trailcut.models import NormalizedEvent


def _serialize_default(obj: object) -> str:
    """JSON serializer for objects not serializable by default json module.

    Args:
        obj: The object to serialize.

    Returns:
        ISO 8601 string for datetime objects.

    Raises:
        TypeError: If the object type is not handled.
    """
    if isinstance(obj, datetime):
        return obj.isoformat()
    raise TypeError(f"Object of type {type(obj).__name__} is not JSON serializable")


def to_json(events: list[NormalizedEvent]) -> str:
    """Export events to a JSON string.

    Args:
        events: List of normalized CloudTrail events.

    Returns:
        A pretty-printed JSON string containing all events.
    """
    records = []
    for e in events:
        records.append(
            {
                "event_time": e.event_time.isoformat(),
                "event_name": e.event_name,
                "event_source": e.event_source,
                "principal_id": e.principal_id,
                "principal_arn": e.principal_arn,
                "source_ip": e.source_ip,
                "region": e.region,
                "user_agent": e.user_agent,
                "request_parameters": e.request_parameters,
                "response_elements": e.response_elements,
            }
        )
    return json.dumps(records, indent=2, default=_serialize_default)


def to_csv(events: list[NormalizedEvent]) -> str:
    """Export events to a CSV string.

    The request_parameters and response_elements dicts are flattened
    to JSON string columns.

    Args:
        events: List of normalized CloudTrail events.

    Returns:
        A CSV-formatted string with headers and one row per event.
    """
    fieldnames = [
        "event_time",
        "event_name",
        "event_source",
        "principal_id",
        "principal_arn",
        "source_ip",
        "region",
        "user_agent",
        "request_parameters",
        "response_elements",
    ]

    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()

    for e in events:
        writer.writerow(
            {
                "event_time": e.event_time.isoformat(),
                "event_name": e.event_name,
                "event_source": e.event_source,
                "principal_id": e.principal_id,
                "principal_arn": e.principal_arn,
                "source_ip": e.source_ip,
                "region": e.region,
                "user_agent": e.user_agent,
                "request_parameters": json.dumps(e.request_parameters),
                "response_elements": json.dumps(e.response_elements),
            }
        )

    return output.getvalue()
