"""Utilities for parsing log files for network events."""

import json
import re
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pydantic import BaseModel


class LoggedEventFromJson(BaseModel):
    """Configuration for parsing events from JSON log lines (one event per line)."""

    start_time_field: str | None = None
    """JSON field name containing the event start timestamp (ISO8601 or Unix timestamp).

    If None, the same field as stop_time_field will be used for both start and stop times
    unless a duration field is set. With a duration field, the start time will be calculated
    from the stop time.
    """

    stop_time_field: str | None = None
    """JSON field name containing the event stop timestamp (ISO8601 or Unix timestamp).

    If None, the same field as start_time_field will be used for both start and stop times
    unless a duration field is set. With a duration field, the stop time will be calculated
    from the start time.
    """

    duration_field: str | None = None
    """JSON field name containing the event duration (in seconds).

    The duration will be either added to the start time if start_time_field is not None, or
    subtracted from the stop time if stop_time_field is not None.

    It is not valid for duration_field to be None if both start_time_field and
    stop_time_field are also None.
    """

    extra_fields: list[str] | None = None
    """List of additional JSON fields to extract as extra data for the event.

    If None, no extra fields will be extracted beyond the timestamps.
    """

    search_text: str | None = None
    """Text to search for in a line to identify lines containing JSON to parse.

    If None (default), assumes each line contains a complete JSON document.
    If provided, only lines containing this text will be parsed as JSON.
    Useful for logs where JSON is embedded within larger log messages.
    """

    json_pattern: str | None = None
    """Regex pattern to extract JSON from lines (when search_text is used).

    If None, assumes the entire line is JSON after the search_text is found.
    The pattern should capture the JSON as group(1).

    Example: r"\\{.*\\}" to extract JSON objects, or r"\\{.*\\}" for JSON arrays.
    """

    file_pattern: str = "*"
    """Glob pattern identifying which files to search for JSON events.

    Defaults to "*" (all files). Examples:
    - "api.log" - only this specific file
    - "**/events.log" - events.log in any subdirectory
    - "logs/*.json" - all .json files in logs/ directory
    """


class LoggedEventFromMultiline(BaseModel):
    """Configuration for parsing events from multi-line log files."""

    start_search_text: str
    """Regex pattern to match in a line to identify the start of an event.

    This is a regex pattern, not a simple substring match.
    The pattern will be compiled and used with re.search().

    Example: r"Starting HTTP request to /api" or r"^\\d{4}-\\d{2}-\\d{2}.*START"
    """

    stop_search_text: str
    """Regex pattern to match in a line to identify the end of an event.

    This is a regex pattern, not a simple substring match.
    The pattern will be compiled and used with re.search().

    Example: r"HTTP request completed" or r"^\\d{4}-\\d{2}-\\d{2}.*END"
    """

    timestamp_format: str = "%Y-%m-%dT%H:%M:%S"  # Default to ISO8601 without timezone
    """Format string for parsing timestamps from log lines.

    The timestamp should be extractable using this format string.
    Common formats:
    - ISO8601: "%Y-%m-%dT%H:%M:%S" or "%Y-%m-%dT%H:%M:%S.%f"
    - With timezone: "%Y-%m-%dT%H:%M:%S%z" or "%Y-%m-%dT%H:%M:%S.%f%z"
    - Custom: Any format supported by datetime.strptime()
    """

    timestamp_line_pattern: str | None = None
    """Regex pattern to extract timestamp from log lines.

    If None, will search for common timestamp patterns automatically.
    The pattern should capture the timestamp as group(1).

    Example: r"(\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2})" for ISO8601 without timezone.
    """

    extra_field_patterns: dict[str, str] | None = None
    """Dictionary mapping extra field names to regex patterns to extract them from log lines.

    Each pattern should capture the desired value as group(1).

    Example: {"status": r"status=\\w+", "response_time": r"response_time=\\d+"}
    """

    start_file_pattern: str = "*"
    """Glob pattern identifying which files may contain event start lines.

    Defaults to "*" (all files). Examples:
    - "client.log" - only this specific file
    - "**/server.log" - server.log in any subdirectory
    - "logs/*.log" - all .log files in logs/ directory
    """

    stop_file_pattern: str = "*"
    """Glob pattern identifying which files may contain event stop lines.

    Defaults to "*" (all files). Examples:
    - "receiver.log" - only this specific file
    - "**/app.log" - app.log in any subdirectory
    - "logs/*.log" - all .log files in logs/ directory
    """


class LoggedEventConfig(BaseModel):
    """Configuration for parsing network events from log files.

    Attributes:
        events: Dictionary mapping event names to their configuration.
            The keys become the event type identifiers in the output.
            Values can be either LoggedEventFromJson (for JSON-based logs)
            or LoggedEventFromMultiline (for multi-line logs).

    Note:
        Events can use different parsing strategies. You can mix JSON and multi-line
        event configurations in the same config. Each event type is handled
        independently based on its configuration.
    """

    events: dict[str, LoggedEventFromJson | LoggedEventFromMultiline]
    """Dictionary mapping of event types to configuration about the event.

    Events can use different parsing strategies. Each event type is handled
    independently based on its configuration. You can mix JSON and multi-line
    event configurations in the same config.
    """


class ParsedEvent(BaseModel):
    """Parsed network event with timestamps and additional metadata.

    Attributes:
        start_ts: Unix timestamp (float) of when the event started.
        stop_ts: Unix timestamp (float) of when the event ended.
        extra: Optional dictionary of additional event metadata.
            Contains fields extracted from the log based on the configuration.
    """

    start_ts: float
    """Unix timestamp (float) of when the event started."""

    stop_ts: float
    """Unix timestamp (float) of when the event ended."""

    extra: dict[str, Any] | None = None
    """Optional dictionary of additional event metadata.

    Contains fields extracted from the log based on the configuration.
    If no extra fields were configured, this will be None.
    """


class ParsedEvents(BaseModel):
    """Collection of parsed events organized by event type.

    Attributes:
        events: Dictionary mapping event type names to lists of parsed events.
            The keys match the event names specified in LoggedEventConfig.
            Each value is a list of ParsedEvent objects, sorted chronologically
            by start_ts (from earliest to latest).

    Example:
        {
            "api_call": [
                ParsedEvent(start_ts=..., stop_ts=..., extra={...}),
                ParsedEvent(start_ts=..., stop_ts=..., extra={...})
            ],
            "http_request": [
                ParsedEvent(start_ts=..., stop_ts=..., extra={...})
            ]
        }
    """

    events: dict[str, list[ParsedEvent]]
    """Dictionary mapping event type names to lists of parsed events.

    The keys match the event names specified in LoggedEventConfig.
    Each value is a list of ParsedEvent objects, sorted chronologically
    by start_ts (from earliest to latest).
    """


class StartEventInfo(BaseModel):
    """Information about an event start that needs to be matched with a stop."""

    timestamp: float
    extra: dict[str, Any] | None = None
    file_path: Path
    line_number: int
    event_id: str  # Unique identifier for matching


class StopEventInfo(BaseModel):
    """Information about an event stop to match with a start."""

    timestamp: float
    extra: dict[str, Any] | None = None
    file_path: Path
    line_number: int
    event_id: str  # Should match corresponding start's event_id


def parse_events(base_dir: str | Path, config: LoggedEventConfig) -> ParsedEvents:
    """Parse log files in base_dir and extract network events based on configuration.

    This implementation supports matching events across multiple files, where an event
    can start in one file and end in another.

    Args:
        base_dir: Path to directory containing log files to parse.
        config: Configuration specifying how to identify and parse events.

    Returns:
        ParsedEvents object containing chronologically ordered events for each event type.
    """
    base_path = Path(base_dir)
    if not base_path.is_dir():
        raise FileNotFoundError(f"Directory not found: {base_dir}")

    # Initialize data structures for collecting starts and stops (for multiline events)
    event_starts = defaultdict(list)  # {event_name: [StartEventInfo]}
    event_stops = defaultdict(list)  # {event_name: [StopEventInfo]}

    # Initialize data structure for JSON events (processed directly)
    json_events = defaultdict(list)  # {event_name: [ParsedEvent]}

    # Build a set of all file patterns we need to match
    file_patterns = set()
    for event_config in config.events.values():
        if isinstance(event_config, LoggedEventFromMultiline):
            multiline_config = event_config
            file_patterns.add(multiline_config.start_file_pattern)
            file_patterns.add(multiline_config.stop_file_pattern)
        else:
            json_config = event_config
            file_patterns.add(json_config.file_pattern)

    # Discover files matching any pattern
    matching_files = []
    for pattern in file_patterns:
        # Handle both simple patterns and recursive patterns
        if "**" in pattern or "/" in pattern or "\\" in pattern:
            # Recursive or path-containing pattern
            matches = list(base_path.glob(pattern))
        else:
            # Simple filename pattern - search recursively
            matches = list(base_path.glob(f"**/{pattern}"))

        for match in matches:
            if match.is_file() and not match.name.startswith("."):
                matching_files.append(match)

    # Remove duplicates while preserving order
    seen = set()
    unique_matching_files = []
    for file_path in matching_files:
        if file_path not in seen:
            seen.add(file_path)
            unique_matching_files.append(file_path)

    # Process each matching file
    for file_path in unique_matching_files:
        # Read file content
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                lines = f.readlines()
        except (UnicodeDecodeError, PermissionError):
            continue

        # Process the file for each event type
        for event_name, event_config in config.events.items():
            # Determine if this file matches the event's file pattern(s)
            if isinstance(event_config, LoggedEventFromMultiline):
                multiline_config = event_config
                matches_start = _matches_file_pattern(
                    file_path.name, multiline_config.start_file_pattern
                )
                matches_stop = _matches_file_pattern(
                    file_path.name, multiline_config.stop_file_pattern
                )

                # Process starts
                if matches_start:
                    starts = _extract_event_starts(lines, multiline_config, file_path)
                    event_starts[event_name].extend(starts)

                # Process stops
                if matches_stop:
                    stops = _extract_event_stops(lines, multiline_config, file_path)
                    event_stops[event_name].extend(stops)
            else:
                json_config = event_config
                if _matches_file_pattern(file_path.relative_to(base_path), json_config.file_pattern):
                    # For JSON events, each event is self-contained with both start and stop
                    # We'll extract them directly as ParsedEvents
                    events = _extract_json_events_as_parsed(
                        lines, json_config, file_path
                    )
                    json_events[event_name].extend(events)

    # Build final result by combining multiline and JSON events
    result_events = {}

    for event_name in config.events.keys():
        event_config = config.events[event_name]

        if isinstance(event_config, LoggedEventFromMultiline):
            # For multiline events, match stops to starts
            starts = event_starts[event_name]
            stops = event_stops[event_name]

            # Sort by timestamp
            starts.sort(key=lambda x: x.timestamp)
            stops.sort(key=lambda x: x.timestamp)

            # Match stops to starts (simple chronological matching)
            matched_events = _match_stops_to_starts(starts, stops, event_name)
            result_events[event_name] = matched_events
        else:
            # For JSON events, use the pre-processed events
            result_events[event_name] = json_events[event_name]

    # Sort all events chronologically by start time
    for event_name in result_events:
        result_events[event_name].sort(key=lambda e: e.start_ts)

    return ParsedEvents(events=result_events)


def _matches_file_pattern(filename: str, pattern: str) -> bool:
    """Check if a filename matches a glob pattern."""
    import fnmatch

    return fnmatch.fnmatch(filename, pattern)


def _extract_event_starts(
    lines: list[str], config: LoggedEventFromMultiline, file_path: Path
) -> list[StartEventInfo]:
    """Extract event start information from log lines."""
    compiled_start = re.compile(config.start_search_text)
    starts = []

    for i, line in enumerate(lines):
        line = line.strip()
        if not line or not compiled_start.search(line):
            continue

        try:
            timestamp = _extract_timestamp_from_line(line, config)
            extra = _extract_extra_fields_from_lines([line], config)

            # Generate a simple event_id based on timestamp and line content
            # This is a fallback for cases where we can't match stops explicitly
            event_id = f"{timestamp:.6f}_{i}"

            starts.append(
                StartEventInfo(
                    timestamp=timestamp,
                    extra=extra if extra else None,
                    file_path=file_path,
                    line_number=i + 1,
                    event_id=event_id,
                )
            )
        except ValueError:
            # Skip lines with invalid timestamps
            continue

    return starts


def _extract_event_stops(
    lines: list[str], config: LoggedEventFromMultiline, file_path: Path
) -> list[StopEventInfo]:
    """Extract event stop information from log lines."""
    compiled_stop = re.compile(config.stop_search_text)
    stops = []

    for i, line in enumerate(lines):
        line = line.strip()
        if not line or not compiled_stop.search(line):
            continue

        try:
            timestamp = _extract_timestamp_from_line(line, config)
            extra = _extract_extra_fields_from_lines([line], config)

            # Generate a simple event_id based on timestamp and line content
            # This is a fallback for cases where we can't match stops explicitly
            event_id = f"{timestamp:.6f}_{i}"

            stops.append(
                StopEventInfo(
                    timestamp=timestamp,
                    extra=extra if extra else None,
                    file_path=file_path,
                    line_number=i + 1,
                    event_id=event_id,
                )
            )
        except ValueError:
            # Skip lines with invalid timestamps
            continue

    return stops


def _extract_json_events_as_parsed(
    lines: list[str], config: LoggedEventFromJson, file_path: Path
) -> list[ParsedEvent]:
    """Extract JSON events from log lines and return as ParsedEvents.

    This is used for JSON-based logs where each line contains a complete event
    with both start and stop timestamps.
    """
    compiled_search = re.compile(config.search_text) if config.search_text else None
    events = []

    for i, line in enumerate(lines):
        line = line.strip()
        if not line:
            continue

        # Check if line contains search_text (if specified)
        if compiled_search and not compiled_search.search(line):
            continue

        # Extract JSON from line
        json_str = _extract_json_from_line(line, config)
        if not json_str:
            continue

        try:
            data = json.loads(json_str)
        except json.JSONDecodeError:
            # Try to handle multi-line JSON by accumulating lines
            json_str = line
            j = i + 1
            while j < len(lines):
                next_line = lines[j].strip()
                json_str += " " + next_line
                try:
                    data = json.loads(json_str)
                    break
                except json.JSONDecodeError:
                    j += 1
            else:
                # Couldn't parse as multi-line JSON
                continue

        # Extract timestamps
        if config.start_time_field:
            start_ts = _parse_timestamp(data[config.start_time_field])

            if config.stop_time_field:
                stop_ts = _parse_timestamp(data[config.stop_time_field])
            elif config.duration_field:
                duration_s = float(data[config.duration_field])
                stop_ts = start_ts + duration_s
            else:
                stop_ts = start_ts
        elif config.stop_time_field:
            stop_ts = _parse_timestamp(data[config.stop_time_field])

            if config.duration_field:
                duration_s = float(data[config.duration_field])
                start_ts = stop_ts - duration_s
            else:
                start_ts = stop_ts
        else:
            raise ValueError("Start and stop time cannot be both be None")

        # Extract extra fields
        extra = {}
        if config.extra_fields:
            for field in config.extra_fields:
                if field in data:
                    extra[field] = data[field]

        events.append(
            ParsedEvent(
                start_ts=start_ts, stop_ts=stop_ts, extra=extra if extra else None
            )
        )

    return events


def _match_stops_to_starts(
    starts: list[StartEventInfo], stops: list[StopEventInfo], event_name: str
) -> list[ParsedEvent]:
    """Match stop events to start events chronologically.

    This uses a simple chronological matching strategy:
    - Starts and stops are matched in the order they appear chronologically
    - The earliest unmatched start is paired with the earliest unmatched stop
    - Event pairs are matched when stop.timestamp >= start.timestamp

    For more sophisticated matching (e.g., based on event_id or content),
    the event configurations should be updated to include identifying
    information in the start/stop patterns and extract them in the
    _extract_event_starts and _extract_event_stops functions.
    """
    matched_events = []
    start_idx = 0
    stop_idx = 0

    # Simple chronological matching
    # Match the earliest start with the earliest stop that comes after or at the same time
    while start_idx < len(starts) and stop_idx < len(stops):
        start = starts[start_idx]
        stop = stops[stop_idx]

        # If event_ids match, use that for pairing (more accurate)
        if start.event_id == stop.event_id:
            matched_events.append(
                ParsedEvent(
                    start_ts=start.timestamp, stop_ts=stop.timestamp, extra=start.extra
                )
            )
            start_idx += 1
            stop_idx += 1
        elif start.timestamp <= stop.timestamp:
            # Start comes before or at the same time as this stop
            # Match them chronologically
            matched_events.append(
                ParsedEvent(
                    start_ts=start.timestamp, stop_ts=stop.timestamp, extra=start.extra
                )
            )
            start_idx += 1
            stop_idx += 1
        else:
            # Stop comes before this start, skip this stop
            # (This stop was already matched or is orphaned)
            stop_idx += 1

    return matched_events


def _extract_json_from_line(line: str, config: LoggedEventFromJson) -> str | None:
    """Extract JSON string from a line."""
    if config.json_pattern:
        match = re.search(config.json_pattern, line)
        if match:
            # Return group(1) if pattern has capturing group, otherwise group(0)
            try:
                return match.group(1)
            except IndexError:
                return match.group(0)
        return None

    # If no json_pattern, look for JSON after search_text or use entire line
    if config.search_text:
        idx = line.find(config.search_text)
        if idx == -1:
            return None
        # Take everything after search_text
        json_part = line[idx + len(config.search_text) :].strip()
        return json_part if json_part else None

    # No search_text, assume entire line is JSON
    return line


def _extract_timestamp_from_line(line: str, config: LoggedEventFromMultiline) -> float:
    """Extract and parse timestamp from a log line."""
    if config.timestamp_line_pattern:
        match = re.search(config.timestamp_line_pattern, line)
        if match:
            timestamp_str = match.group(1)
        else:
            # Fallback: try to find common patterns
            timestamp_str = _find_common_timestamp(line)
    else:
        timestamp_str = _find_common_timestamp(line)

    if not timestamp_str:
        raise ValueError(f"Could not extract timestamp from line: {line}")

    return _parse_timestamp(timestamp_str, config.timestamp_format)


def _find_common_timestamp(line: str) -> str | None:
    """Try to find common timestamp patterns in a line."""
    # Try ISO8601 format with or without timezone
    patterns = [
        r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?)",
        r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?)",
    ]

    for pattern in patterns:
        match = re.search(pattern, line)
        if match:
            return match.group(1)

    return None


def _parse_timestamp(
    timestamp: str | int | float, format_str: str | None = None
) -> float:
    """Parse timestamp string or numeric value into Unix timestamp (float)."""
    # If already a number (Unix timestamp)
    if isinstance(timestamp, (int, float)):
        return float(timestamp)

    # If string, parse it
    if isinstance(timestamp, str):
        if format_str:
            try:
                dt = datetime.strptime(timestamp, format_str).replace(
                    tzinfo=timezone.utc
                )
                return dt.timestamp()
            except ValueError:
                # Try ISO8601 if custom format fails
                pass

        # Try ISO8601 parsing
        try:
            if "T" in timestamp or " " in timestamp:
                # Date and time separated by T or space
                dt = datetime.fromisoformat(timestamp).replace(tzinfo=timezone.utc)
            else:
                # Just a time string, assume today
                now = datetime.now()
                time_part = datetime.strptime(timestamp, "%H:%M:%S")
                dt = datetime(
                    now.year,
                    now.month,
                    now.day,
                    time_part.hour,
                    time_part.minute,
                    time_part.second,
                )
            return dt.timestamp()
        except ValueError as e:
            raise ValueError(f"Could not parse timestamp '{timestamp}': {e}")

    raise ValueError(f"Unsupported timestamp type: {type(timestamp)}")


def _extract_extra_fields_from_lines(
    lines: list[str], config: LoggedEventFromMultiline
) -> dict[str, Any]:
    """Extract extra fields from multiple log lines using regex patterns."""
    extra = {}

    if not config.extra_field_patterns:
        return extra

    for line in lines:
        for field_name, pattern in config.extra_field_patterns.items():
            if field_name in extra:
                continue  # Already found

            match = re.search(pattern, line)
            if match:
                extra[field_name] = match.group(1)

    return extra
