"""Input sources: local CloudTrail JSON files and live CloudTrail API."""

import json
from datetime import datetime, timezone, timedelta
from typing import Any

import boto3

from trailcut.models import NormalizedEvent


def _parse_event_time(raw_time: Any) -> datetime:
    """Parse event time from CloudTrail into a timezone-aware datetime.

    Args:
        raw_time: The eventTime value from a CloudTrail record. Can be an
            ISO 8601 string or an already-parsed datetime.

    Returns:
        A timezone-aware datetime in UTC.
    """
    if isinstance(raw_time, datetime):
        if raw_time.tzinfo is None:
            return raw_time.replace(tzinfo=timezone.utc)
        return raw_time
    time_str = str(raw_time)
    # CloudTrail uses ISO 8601 with trailing Z or offset
    time_str = time_str.replace("Z", "+00:00")
    return datetime.fromisoformat(time_str)


def _normalize_record(record: dict) -> NormalizedEvent:
    """Convert a raw CloudTrail record dict into a NormalizedEvent.

    Args:
        record: A single CloudTrail event record.

    Returns:
        A NormalizedEvent with fields extracted from the record.
    """
    user_identity = record.get("userIdentity", {})
    return NormalizedEvent(
        event_time=_parse_event_time(record.get("eventTime", "")),
        event_name=record.get("eventName", ""),
        event_source=record.get("eventSource", ""),
        principal_id=user_identity.get("principalId", ""),
        principal_arn=user_identity.get("arn", ""),
        source_ip=record.get("sourceIPAddress", ""),
        region=record.get("awsRegion", ""),
        user_agent=record.get("userAgent", ""),
        request_parameters=record.get("requestParameters") or {},
        response_elements=record.get("responseElements") or {},
        raw=record,
    )


def load_from_file(path: str) -> list[NormalizedEvent]:
    """Load CloudTrail events from a local JSON file.

    Handles both single-event JSON objects and multi-record files
    where events are nested under a top-level "Records" key.

    Args:
        path: Filesystem path to a CloudTrail JSON log file.

    Returns:
        A list of NormalizedEvent objects parsed from the file.

    Raises:
        FileNotFoundError: If the file does not exist.
        json.JSONDecodeError: If the file is not valid JSON.
        ValueError: If the JSON structure is not recognized.
    """
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    if isinstance(data, dict):
        if "Records" in data:
            records = data["Records"]
        else:
            # Single event object
            records = [data]
    elif isinstance(data, list):
        records = data
    else:
        raise ValueError(f"Unrecognized CloudTrail JSON structure in {path}")

    return [_normalize_record(r) for r in records]


def load_from_api(profile: str | None, lookback_hours: int) -> list[NormalizedEvent]:
    """Load CloudTrail events from the AWS CloudTrail LookupEvents API.

    Paginates through all available events within the lookback window.

    Args:
        profile: AWS profile name to use. If None, uses the default profile.
        lookback_hours: Number of hours to look back from now. Max 2160 (90 days).

    Returns:
        A list of NormalizedEvent objects from the CloudTrail API.

    Raises:
        ValueError: If lookback_hours exceeds the 90-day API limit.
        botocore.exceptions.ClientError: On AWS API errors.
    """
    max_hours = 90 * 24  # 90 days in hours
    if lookback_hours > max_hours:
        raise ValueError(
            f"lookback_hours={lookback_hours} exceeds the CloudTrail API "
            f"maximum of {max_hours} hours (90 days)."
        )

    session = boto3.Session(profile_name=profile)
    client = session.client("cloudtrail")

    start_time = datetime.now(timezone.utc) - timedelta(hours=lookback_hours)
    end_time = datetime.now(timezone.utc)

    events: list[NormalizedEvent] = []
    paginator = client.get_paginator("lookup_events")
    page_iterator = paginator.paginate(
        StartTime=start_time,
        EndTime=end_time,
    )

    for page in page_iterator:
        for event in page.get("Events", []):
            # The API returns CloudTrailEvent as a JSON string
            raw = json.loads(event.get("CloudTrailEvent", "{}"))
            events.append(_normalize_record(raw))

    return events
