"""Filtering logic for CloudTrail events."""

from datetime import datetime

from trailcut.models import NormalizedEvent


def apply_filters(
    events: list[NormalizedEvent],
    principal: str | None = None,
    source_ip: str | None = None,
    event_name: str | None = None,
    region: str | None = None,
    start: datetime | None = None,
    end: datetime | None = None,
) -> list[NormalizedEvent]:
    """Apply filters to a list of normalized CloudTrail events.

    Each filter is only applied if the corresponding argument is not None.
    String filters use case-insensitive partial matching. Datetime filters
    are inclusive on both ends.

    Args:
        events: The list of events to filter.
        principal: Filter by principalId or userArn (partial, case-insensitive).
        source_ip: Filter by sourceIPAddress (partial, case-insensitive).
        event_name: Filter by eventName (partial, case-insensitive).
        region: Filter by awsRegion (partial, case-insensitive).
        start: Include events at or after this datetime (inclusive).
        end: Include events at or before this datetime (inclusive).

    Returns:
        A new list containing only the events that match all active filters.
    """
    result = events

    if principal is not None:
        principal_lower = principal.lower()
        result = [
            e
            for e in result
            if principal_lower in e.principal_id.lower()
            or principal_lower in e.principal_arn.lower()
        ]

    if source_ip is not None:
        source_ip_lower = source_ip.lower()
        result = [
            e for e in result if source_ip_lower in e.source_ip.lower()
        ]

    if event_name is not None:
        event_name_lower = event_name.lower()
        result = [
            e for e in result if event_name_lower in e.event_name.lower()
        ]

    if region is not None:
        region_lower = region.lower()
        result = [e for e in result if region_lower in e.region.lower()]

    if start is not None:
        result = [e for e in result if e.event_time >= start]

    if end is not None:
        result = [e for e in result if e.event_time <= end]

    return result
