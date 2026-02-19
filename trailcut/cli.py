"""Click-based CLI entry point for trailcut."""

import sys
from datetime import datetime, timezone

import click

from trailcut.exporters import to_csv, to_json
from trailcut.filters import apply_filters
from trailcut.sources import load_from_api, load_from_file


def _parse_datetime(value: str) -> datetime:
    """Parse an ISO 8601 datetime string into a timezone-aware datetime.

    Args:
        value: An ISO 8601 datetime string (e.g. "2024-01-15T00:00:00Z").

    Returns:
        A timezone-aware datetime in UTC.
    """
    value = value.replace("Z", "+00:00")
    dt = datetime.fromisoformat(value)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


@click.group()
@click.version_option(package_name="trailcut")
def cli() -> None:
    """trailcut — CloudTrail log investigation tool for AWS incident response.

    Slice, filter, and export CloudTrail events for rapid triage.
    """


@cli.command()
@click.option("--input", "input_file", type=click.Path(exists=True), default=None, help="Path to local CloudTrail JSON log file.")
@click.option("--principal", default=None, help="Filter by principalId or userArn (partial match).")
@click.option("--source-ip", default=None, help="Filter by sourceIPAddress.")
@click.option("--event-name", default=None, help="Filter by eventName (partial match).")
@click.option("--region", default=None, help="Filter by awsRegion.")
@click.option("--start", default=None, help="Start datetime filter (ISO 8601).")
@click.option("--end", default=None, help="End datetime filter (ISO 8601).")
@click.option("--output-format", type=click.Choice(["json", "csv"]), default="json", help="Output format (default: json).")
@click.option("--output-file", type=click.Path(), default=None, help="Path to write output (default: stdout).")
@click.option("--live", is_flag=True, default=False, help="Pull from CloudTrail API instead of file.")
@click.option("--aws-profile", default=None, help="AWS profile name for live mode.")
@click.option("--lookback-hours", type=int, default=24, help="Hours to look back in live mode (default: 24, max: 90 days).")
def slice(
    input_file: str | None,
    principal: str | None,
    source_ip: str | None,
    event_name: str | None,
    region: str | None,
    start: str | None,
    end: str | None,
    output_format: str,
    output_file: str | None,
    live: bool,
    aws_profile: str | None,
    lookback_hours: int,
) -> None:
    """Slice and filter CloudTrail events for rapid triage.

    Load events from a local JSON file or the CloudTrail API, apply filters,
    and export as JSON or CSV.
    """
    # Load events
    if live:
        events = load_from_api(profile=aws_profile, lookback_hours=lookback_hours)
    elif input_file:
        events = load_from_file(input_file)
    else:
        raise click.UsageError("Provide --input FILE or use --live for CloudTrail API.")

    # Parse datetime filters
    start_dt = _parse_datetime(start) if start else None
    end_dt = _parse_datetime(end) if end else None

    # Apply filters
    filtered = apply_filters(
        events,
        principal=principal,
        source_ip=source_ip,
        event_name=event_name,
        region=region,
        start=start_dt,
        end=end_dt,
    )

    # Export
    if output_format == "csv":
        output = to_csv(filtered)
    else:
        output = to_json(filtered)

    # Write output
    if output_file:
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(output)
        click.echo(f"Wrote {len(filtered)} events to {output_file}")
    else:
        click.echo(output)
