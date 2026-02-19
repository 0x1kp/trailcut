"""Tests for trailcut.filters."""

import os
from datetime import datetime, timezone

import pytest

from trailcut.filters import apply_filters
from trailcut.sources import load_from_file

FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures")
SAMPLE_FILE = os.path.join(FIXTURES_DIR, "sample_cloudtrail.json")


@pytest.fixture
def all_events():
    """Load all sample events from the fixture file."""
    return load_from_file(SAMPLE_FILE)


class TestNoFilter:
    """Tests that no-filter returns all events."""

    def test_no_filter_returns_all(self, all_events: list) -> None:
        """apply_filters with no arguments returns all events."""
        result = apply_filters(all_events)
        assert len(result) == len(all_events)
        assert len(result) == 18


class TestPrincipalFilter:
    """Tests for the principal filter."""

    def test_filter_by_principal_id(self, all_events: list) -> None:
        """Filter by exact principalId substring."""
        result = apply_filters(all_events, principal="AIDAEXAMPLEUSER1")
        assert len(result) == 3
        for e in result:
            assert "AIDAEXAMPLEUSER1" in e.principal_id

    def test_filter_by_principal_arn(self, all_events: list) -> None:
        """Filter by userArn substring matches both principalId and arn."""
        result = apply_filters(all_events, principal="user/bob")
        assert len(result) == 4
        for e in result:
            assert "bob" in e.principal_arn.lower()

    def test_filter_by_principal_case_insensitive(self, all_events: list) -> None:
        """Principal filter is case-insensitive."""
        result = apply_filters(all_events, principal="USER/ALICE")
        assert len(result) == 3

    def test_filter_by_principal_partial(self, all_events: list) -> None:
        """Principal filter supports partial match on arn."""
        result = apply_filters(all_events, principal="mallory")
        assert len(result) == 4


class TestSourceIpFilter:
    """Tests for the source IP filter."""

    def test_filter_by_source_ip_exact(self, all_events: list) -> None:
        """Filter by exact source IP."""
        result = apply_filters(all_events, source_ip="203.0.113.10")
        assert len(result) == 5
        for e in result:
            assert e.source_ip == "203.0.113.10"

    def test_filter_by_source_ip_partial(self, all_events: list) -> None:
        """Partial IP match works."""
        result = apply_filters(all_events, source_ip="198.51.100")
        assert len(result) == 7
        for e in result:
            assert "198.51.100" in e.source_ip

    def test_filter_by_source_ip_no_match(self, all_events: list) -> None:
        """Non-existent IP returns empty list."""
        result = apply_filters(all_events, source_ip="1.2.3.4")
        assert len(result) == 0


class TestEventNameFilter:
    """Tests for the event name filter."""

    def test_filter_by_event_name_exact(self, all_events: list) -> None:
        """Filter by exact event name."""
        result = apply_filters(all_events, event_name="ConsoleLogin")
        assert len(result) == 4
        for e in result:
            assert e.event_name == "ConsoleLogin"

    def test_filter_by_event_name_partial(self, all_events: list) -> None:
        """Partial event name match works."""
        result = apply_filters(all_events, event_name="Describe")
        assert len(result) == 2
        for e in result:
            assert "Describe" in e.event_name

    def test_filter_by_event_name_case_insensitive(self, all_events: list) -> None:
        """Event name filter is case-insensitive."""
        result = apply_filters(all_events, event_name="stoplogging")
        assert len(result) == 1
        assert result[0].event_name == "StopLogging"


class TestRegionFilter:
    """Tests for the region filter."""

    def test_filter_by_region(self, all_events: list) -> None:
        """Filter by exact region."""
        result = apply_filters(all_events, region="us-west-2")
        assert len(result) == 3
        for e in result:
            assert e.region == "us-west-2"

    def test_filter_by_region_partial(self, all_events: list) -> None:
        """Partial region match returns events from matching regions."""
        result = apply_filters(all_events, region="eu-")
        assert len(result) == 1
        assert result[0].region == "eu-west-1"


class TestDatetimeFilters:
    """Tests for start and end datetime filters."""

    def test_filter_by_start(self, all_events: list) -> None:
        """Start filter is inclusive — events at exactly start are included."""
        start = datetime(2024, 6, 15, 10, 0, 0, tzinfo=timezone.utc)
        result = apply_filters(all_events, start=start)
        for e in result:
            assert e.event_time >= start
        # Events at 10:00, 10:01, 10:05, 10:10, 11:00, 12:00, 13:00, 14:00, 15:00
        assert len(result) == 9

    def test_filter_by_end(self, all_events: list) -> None:
        """End filter is inclusive — events at exactly end are included."""
        end = datetime(2024, 6, 15, 8, 5, 0, tzinfo=timezone.utc)
        result = apply_filters(all_events, end=end)
        for e in result:
            assert e.event_time <= end
        # Events at 06:30, 06:31, 06:32, 08:00, 08:05
        assert len(result) == 5

    def test_filter_by_start_and_end(self, all_events: list) -> None:
        """Combined start and end creates a time window."""
        start = datetime(2024, 6, 15, 9, 0, 0, tzinfo=timezone.utc)
        end = datetime(2024, 6, 15, 10, 5, 0, tzinfo=timezone.utc)
        result = apply_filters(all_events, start=start, end=end)
        for e in result:
            assert start <= e.event_time <= end
        # Events at 09:00, 09:15, 10:00, 10:01, 10:05
        assert len(result) == 5

    def test_boundary_exact_match(self, all_events: list) -> None:
        """Exact boundary datetime matches the event (inclusive)."""
        exact = datetime(2024, 6, 15, 13, 0, 0, tzinfo=timezone.utc)
        result = apply_filters(all_events, start=exact, end=exact)
        assert len(result) == 1
        assert result[0].event_name == "PutItem"

    def test_no_events_in_range(self, all_events: list) -> None:
        """Time range with no events returns empty list."""
        start = datetime(2025, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
        end = datetime(2025, 1, 2, 0, 0, 0, tzinfo=timezone.utc)
        result = apply_filters(all_events, start=start, end=end)
        assert len(result) == 0


class TestCombinedFilters:
    """Tests for combining multiple filters."""

    def test_principal_and_event_name(self, all_events: list) -> None:
        """Combining principal and event_name narrows results."""
        result = apply_filters(
            all_events, principal="mallory", event_name="CreateUser"
        )
        assert len(result) == 1
        assert result[0].event_name == "CreateUser"
        assert "mallory" in result[0].principal_arn

    def test_region_and_source_ip(self, all_events: list) -> None:
        """Combining region and source_ip narrows results."""
        result = apply_filters(
            all_events, region="us-west-2", source_ip="198.51.100.25"
        )
        assert len(result) == 3
        for e in result:
            assert e.region == "us-west-2"
            assert e.source_ip == "198.51.100.25"

    def test_all_filters_combined(self, all_events: list) -> None:
        """All filters combined narrows to a specific event."""
        result = apply_filters(
            all_events,
            principal="mallory",
            source_ip="192.0.2.50",
            event_name="StopLogging",
            region="us-east-1",
            start=datetime(2024, 6, 15, 10, 0, 0, tzinfo=timezone.utc),
            end=datetime(2024, 6, 15, 10, 10, 0, tzinfo=timezone.utc),
        )
        assert len(result) == 1
        assert result[0].event_name == "StopLogging"

    def test_contradictory_filters_return_empty(self, all_events: list) -> None:
        """Contradictory filters return empty list."""
        result = apply_filters(
            all_events,
            principal="alice",
            region="eu-west-1",
        )
        assert len(result) == 0
