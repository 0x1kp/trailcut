# trailcut

CloudTrail log investigation tool for AWS incident response. Slices, filters, and exports CloudTrail events for rapid triage.

## Installation

```bash
git clone <repo-url>
cd trailcut
pip install -e .
```

## Usage

### Slice events from a local file

```bash
# Show all events from a CloudTrail log file
trailcut slice --input cloudtrail-logs.json

# Filter by principal (partial match, case-insensitive)
trailcut slice --input logs.json --principal mallory

# Filter by event name
trailcut slice --input logs.json --event-name StopLogging

# Filter by source IP
trailcut slice --input logs.json --source-ip 192.0.2.50

# Filter by region
trailcut slice --input logs.json --region us-east-1

# Filter by time window (ISO 8601)
trailcut slice --input logs.json \
  --start 2024-06-15T09:00:00Z \
  --end 2024-06-15T11:00:00Z

# Combine multiple filters
trailcut slice --input logs.json \
  --principal mallory \
  --event-name Create \
  --region us-east-1

# Export as CSV
trailcut slice --input logs.json --output-format csv

# Write output to a file
trailcut slice --input logs.json --output-file results.json
```

### Live mode (CloudTrail API)

```bash
# Pull last 24 hours from CloudTrail API (default)
trailcut slice --live

# Use a specific AWS profile
trailcut slice --live --aws-profile incident-response

# Look back 72 hours
trailcut slice --live --lookback-hours 72

# Combine live mode with filters
trailcut slice --live --aws-profile prod \
  --event-name ConsoleLogin \
  --source-ip 198.51.100.99
```

### Sample output (JSON)

```json
[
  {
    "event_time": "2024-06-15T10:05:00+00:00",
    "event_name": "StopLogging",
    "event_source": "cloudtrail.amazonaws.com",
    "principal_id": "AIDAEXAMPLEUSER3",
    "principal_arn": "arn:aws:iam::123456789012:user/mallory",
    "source_ip": "192.0.2.50",
    "region": "us-east-1",
    "user_agent": "aws-cli/2.15.0 Python/3.11.6",
    "request_parameters": {
      "name": "arn:aws:cloudtrail:us-east-1:123456789012:trail/management-trail"
    },
    "response_elements": {}
  }
]
```

## Security Considerations

- **Read-only operations only.** trailcut never modifies, deletes, or creates AWS resources. File mode reads local JSON. Live mode uses the CloudTrail `LookupEvents` API which is read-only.
- **No external data transmission.** All processing is local. Output goes to stdout or a local file.
- **AWS credentials are never logged or stored** by trailcut. Credential handling is delegated entirely to boto3 and the AWS SDK.

## Limitations

- **CloudTrail API 90-day lookback limit.** The `LookupEvents` API only returns events from the last 90 days. For older events, export CloudTrail logs to S3 and use file mode.
- **API throttling.** CloudTrail `LookupEvents` has a rate limit of 2 requests per second. Large lookback windows with many events may take time to paginate.
- **Event coverage.** `LookupEvents` returns management events by default. Data events (S3 object-level, Lambda invocations) require CloudTrail to be configured with data event logging and may not appear in `LookupEvents` results.

## Development

```bash
pip install -r requirements.txt
pip install -e .
pytest -v
```
