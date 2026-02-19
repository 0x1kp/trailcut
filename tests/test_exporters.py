"""Tests for trailcut.exporters."""

import csv
import io
import json
import os

import pytest

from trailcut.exporters import to_csv, to_json
from trailcut.sources import load_from_file

FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures")
SAMPLE_FILE = os.path.join(FIXTURES_DIR, "sample_cloudtrail.json")


@pytest.fixture
def all_events():
    """Load all sample events from the fixture file."""
    return load_from_file(SAMPLE_FILE)


class TestJsonExport:
    """Tests for JSON export."""

    def test_output_is_valid_json(self, all_events: list) -> None:
        """to_json produces valid JSON."""
        output = to_json(all_events)
        parsed = json.loads(output)
        assert isinstance(parsed, list)
        assert len(parsed) == 18

    def test_json_fields_present(self, all_events: list) -> None:
        """Each JSON record has the expected fields."""
        output = to_json(all_events)
        parsed = json.loads(output)
        expected_fields = {
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
        }
        for record in parsed:
            assert set(record.keys()) == expected_fields

    def test_json_empty_list(self) -> None:
        """to_json handles empty event list."""
        output = to_json([])
        parsed = json.loads(output)
        assert parsed == []


class TestCsvExport:
    """Tests for CSV export."""

    def test_csv_has_correct_headers(self, all_events: list) -> None:
        """CSV output starts with the expected header row."""
        output = to_csv(all_events)
        reader = csv.reader(io.StringIO(output))
        headers = next(reader)
        expected_headers = [
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
        assert headers == expected_headers

    def test_csv_row_count(self, all_events: list) -> None:
        """CSV has one row per event plus the header."""
        output = to_csv(all_events)
        reader = csv.reader(io.StringIO(output))
        rows = list(reader)
        # header + 18 data rows
        assert len(rows) == 19

    def test_csv_empty_list(self) -> None:
        """to_csv handles empty event list — just a header row."""
        output = to_csv([])
        reader = csv.reader(io.StringIO(output))
        rows = list(reader)
        assert len(rows) == 1  # header only

    def test_csv_flattened_dicts(self, all_events: list) -> None:
        """request_parameters and response_elements are JSON strings in CSV."""
        output = to_csv(all_events)
        reader = csv.DictReader(io.StringIO(output))
        for row in reader:
            # These columns should be valid JSON strings
            json.loads(row["request_parameters"])
            json.loads(row["response_elements"])
