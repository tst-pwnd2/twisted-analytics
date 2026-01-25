import json
import os
import re
from datetime import datetime, timezone

# Configuration
APP_LOG = "app_client.log"
ZEEK_DIR = "zeek/logs/"
OUTPUT_FILE = "summary.json"

ALARM_SCRIPTS = [
    "HTTPS_Upload_Bytes", "HTTPS_Connection_Count", "DDNS_Query_Count", 
    "DNS_Query_Bytes", "DNS_Response_Bytes", "Average_DNS_Query_Size", 
    "Average_DNS_Response_Size", "Average_DNS_Query_Rate", "Average_HTTPS_Upload_Bytes"
]

def parse_app_log(filepath):
    start_time = None
    stop_time = None
    
    start_pattern = re.compile(r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3}) INFO Sending File 0 via Raceboat")
    stop_pattern = re.compile(r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3}) INFO TCP handler task cancelled")

    if not os.path.exists(filepath):
        return None, None

    with open(filepath, 'r') as f:
        for line in f:
            start_match = start_pattern.search(line)
            if start_match:
                # Force UTC timezone awareness
                dt = datetime.strptime(start_match.group(1), "%Y-%m-%d %H:%M:%S.%f")
                start_time = dt.replace(tzinfo=timezone.utc)
            
            stop_match = stop_pattern.search(line)
            if stop_match:
                dt = datetime.strptime(stop_match.group(1), "%Y-%m-%d %H:%M:%S.%f")
                stop_time = dt.replace(tzinfo=timezone.utc)
                
    return start_time, stop_time

def parse_zeek_logs(directory, start_time):
    # Dictionaries to track the first occurrence in each log type
    pre_nat_alarms = {}
    post_nat_alarms = {}

    if not os.path.exists(directory):
        return pre_nat_alarms, post_nat_alarms

    for filename in os.listdir(directory):
        # Identify which dictionary to update
        if filename.endswith('pre-nat.log'):
            target_dict = pre_nat_alarms
        elif filename.endswith('post-nat.log'):
            target_dict = post_nat_alarms
        else:
            continue

        path = os.path.join(directory, filename)
        with open(path, 'r') as f:
            for line in f:
                try:
                    data = json.loads(line)
                    script_name = data.get("script")
                    msg = data.get("msg", "")
                    
                    if script_name in ALARM_SCRIPTS:
                        if "raising NOTICE" in msg or "notice_fired" in msg:
                            # Only record the first occurrence for this specific dictionary
                            if script_name not in target_dict:
                                # Convert epoch to UTC-aware datetime
                                alarm_ts = datetime.fromtimestamp(data["ts"], tz=timezone.utc)
                                relative_time = (alarm_ts - start_time).total_seconds()
                                target_dict[script_name] = f"{relative_time:.3f}s"
                except (json.JSONDecodeError, KeyError, TypeError):
                    continue
                    
    return pre_nat_alarms, post_nat_alarms

def main():
    start_dt, stop_dt = parse_app_log(APP_LOG)
    
    if not start_dt or not stop_dt:
        print("Error: Could not find both start and stop markers in app_client.log.")
        return

    total_latency = (stop_dt - start_dt).total_seconds()
    pre_alarms, post_alarms = parse_zeek_logs(ZEEK_DIR, start_dt)

    summary = {
        "total_latency_seconds": total_latency,
        "alarms_relative_to_start": {
            "pre-nat": pre_alarms,
            "post-nat": post_alarms
        }
    }

    with open(OUTPUT_FILE, 'w') as out:
        json.dump(summary, out, indent=4)
    
    print(f"Summary generated: {OUTPUT_FILE}")

if __name__ == "__main__":
    main()
