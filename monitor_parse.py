import subprocess
import json
from collections import defaultdict
import numpy as np
from scipy.stats import wasserstein_distance
from datetime import datetime
import re
import os
import sys

# --- Configuration (LOG_FILE is set in __main__ via CLI) ---

# --- Analysis 1: Original num_images/elapsed_time (Single Line) ---
ORIGINAL_STATS_CMD = "grep \"STATS.*num_to_post\" {log_file} | cut -d'=' -f2"

# --- Analysis 2: Attachments/Elapsed_time (Two Lines) ---
DOWNLOAD_CMD = "grep 'Downloading [0-9]\\+ attachment' {log_file} | grep -oE '[0-9]+'"
MONITOR_STATS_CMD = "grep 'STATS.*monitor_download' {log_file} | cut -d' ' -f6-"

# --- Analysis 3: Post Durations (Three Lines) ---
POST_NUM_IMAGES_CMD = "grep \"PluginMastodon::enqueueContent: called with params.linkId\" {log_file} | cut -d' ' -f10,11"
POST_START_CMD = "grep \"Raceboat::TransportComponentWrapper::doAction: called with handlesJson\" {log_file} | cut -d' ' -f2,11"
POST_STOP_CMD = "grep \"PluginCommsTwoSixStubUserModelReactiveFile::onTransportEvent: called with event.json\" {log_file} | cut -d' ' -f2"

# --- Analysis 4: Hashtag Fetch Duration (Two Lines) ---
FETCH_START_CMD = "grep \"PluginMastodon::doAction: Fetching from single link\" {log_file} | cut -d' ' -f2"
FETCH_END_CMD = "grep \"Link::fetch: .*items for hashtag\" {log_file} | cut -d' ' -f2,8"

# Timestamp format for parsing (H:M:S.microseconds)
TIME_FORMAT = '%H:%M:%S.%f'

# --- Core Utility Functions ---

def execute_shell_command(command, log_file):
    """
    Executes a shell command gracefully.
    Returns lines of output or an empty list if grep returns no matches (exit code 1).
    """
    full_command = command.format(log_file=log_file)
    try:
        result = subprocess.run(
            full_command, 
            capture_output=True, 
            text=True, 
            shell=True,
            check=True
        )
        return result.stdout.strip().split('\n')
    except subprocess.CalledProcessError as e:
        if e.returncode == 1: 
            return []
        print(f"❌ ERROR: Shell command failed: {full_command}. Stderr: {e.stderr.strip()}")
        return []

# --- Analysis 1: Original Stats ---

def parse_original_stream(command_string, log_file):
    """Parses single-line JSON, renaming 'num_to_post' to 'num_images'."""
    lines = execute_shell_command(command_string, log_file)
    if not lines: return []
    
    parsed_data = []
    for line in lines:
        clean_line = line.strip().strip('"')
        if clean_line:
            try:
                data = json.loads(clean_line)
                if 'num_to_post' in data: data['num_images'] = data.pop('num_to_post') 
                if 'num_images' in data and 'elapsed_time' in data: parsed_data.append(data)
                else: raise KeyError("Missing 'num_images' or 'elapsed_time' after parsing.")
            except (json.JSONDecodeError, KeyError) as e:
                print(f"⚠️ ERROR (A1): Skipping line due to {type(e).__name__}: {e}. Data: {clean_line[:60]}")
    return parsed_data

# --- Analysis 2: Attachments ---

def parse_multiline_stream(download_cmd, stats_cmd, log_file):
    """Handles the two-line log entries by zipping the results."""
    counts = [int(c.strip()) for c in execute_shell_command(download_cmd, log_file) if c.strip().isdigit()]
    json_strings = execute_shell_command(stats_cmd, log_file)
        
    if len(counts) != len(json_strings) and (counts or json_strings):
        print(f"⚠️ WARNING (A2): Mismatched counts! Found {len(counts)} counts and {len(json_strings)} JSON objects.")
        
    parsed_data = []
    for count, json_str in zip(counts, json_strings):
        try:
            data = json.loads(json_str.split('=')[1].strip())
            data['num_images'] = count 
            if 'elapsed_time' in data: parsed_data.append(data)
            else: raise KeyError("Missing 'elapsed_time' after parsing.")
        except (json.JSONDecodeError, KeyError) as e:
            print(f"⚠️ ERROR (A2): Skipping pair due to {type(e).__name__}: {e}. JSON: {json_str[:60]}")
            
    return parsed_data

# --- Analysis 3: Post Durations Parsing Helpers ---

def parse_num_images_stream_3(command_string, log_file):
    data_map = {}
    lines = execute_shell_command(command_string, log_file)
    for line in lines:
        try:
            action_id_match = re.search(r'action\.actionId=(\d+)', line)
            json_match = re.search(r'action\.json=({.*}),', line)
            if not action_id_match or not json_match: raise ValueError("Missing action ID or JSON payload.")
            
            action_id = int(action_id_match.group(1))
            data = json.loads(json_match.group(1))
            
            if 'numImages' not in data: raise KeyError("Missing 'numImages' key in JSON payload.")
            data_map[action_id] = {'num_images': data['numImages']}
        except (ValueError, KeyError, json.JSONDecodeError) as e:
            print(f"⚠️ ERROR (A3/Images): Skipping line due to {type(e).__name__}: {e}. Data: {line[:60]}")
    return data_map

def parse_start_stream_3(command_string, log_file):
    data_map = {}
    lines = execute_shell_command(command_string, log_file)
    for line in lines:
        try:
            parts = line.split(': id:'); 
            if len(parts) != 2: raise ValueError("Unexpected log line format (missing ': id:').")
            
            timestamp_str = parts[0].strip()
            action_id = int(parts[1].strip().strip('}'))
            time_obj = datetime.strptime(timestamp_str, TIME_FORMAT)
            data_map[action_id] = {'start_time': time_obj}
        except (ValueError, IndexError) as e:
            print(f"⚠️ ERROR (A3/Start): Skipping line due to {type(e).__name__}: {e}. Data: {line[:60]}")
    return data_map

def parse_stop_stream_3(command_string, log_file):
    time_list = []
    lines = execute_shell_command(command_string, log_file)
    for line in lines:
        try:
            timestamp_str = line.strip().strip(':')
            time_obj = datetime.strptime(timestamp_str, TIME_FORMAT)
            time_list.append(time_obj)
        except (ValueError, IndexError) as e:
            print(f"⚠️ ERROR (A3/Stop): Skipping line due to {type(e).__name__}: {e}. Data: {line[:60]}")
    return time_list

def merge_and_calculate_durations_3(num_images_data, start_data, stop_times):
    merged_by_id = {}; final_data = []
    for action_id, img_data in num_images_data.items():
        if action_id in start_data: merged_by_id[action_id] = {**img_data, **start_data[action_id]}

    sorted_starts = sorted(merged_by_id.values(), key=lambda x: x['start_time'])
    
    for start_event, stop_time in zip(sorted_starts, stop_times):
        try:
            duration = (stop_time - start_event['start_time']).total_seconds()
            if duration <= 0: raise ValueError("Duration is non-positive (stop time <= start time).")
            
            final_data.append({
                'num_images': start_event['num_images'], 
                'elapsed_time': duration
            })
        except ValueError as e:
            print(f"⚠️ ERROR (A3/Merge): Skipping event due to {type(e).__name__}: {e}. Start: {start_event['start_time']}, Stop: {stop_time}")
            
    return final_data

# --- Analysis 4: Hashtag Fetch Duration ---

def parse_hashtag_fetch_stream(start_cmd, end_cmd, log_file):
    """
    Handles the two-line fetch log entries by zipping timestamps and calculating duration,
    using the fetched item count for grouping.
    """
    start_time_strings = execute_shell_command(start_cmd, log_file)
    end_lines = execute_shell_command(end_cmd, log_file)
    
    start_times = []
    for ts_str in start_time_strings:
        try:
            clean_ts_str = ts_str.strip().strip(':')
            start_times.append(datetime.strptime(clean_ts_str, TIME_FORMAT))
        except ValueError as e:
            print(f"⚠️ ERROR (A4/Start): Skipping time due to {type(e).__name__}: {e}. Data: {ts_str[:60]}")
            
    end_events = [] 
    for line in end_lines:
        try:
            parts = line.split()
            if len(parts) != 2: raise ValueError("Unexpected log line format (not 'timestamp count').")
            if not parts[1].isdigit(): raise ValueError("Item count is not a valid integer.")
                
            end_time = datetime.strptime(parts[0].strip().strip(':'), TIME_FORMAT)
            item_count = int(parts[1].strip())
            end_events.append({'end_time': end_time, 'num_images': item_count})
        except (ValueError, IndexError) as e:
            print(f"⚠️ ERROR (A4/End): Skipping line due to {type(e).__name__}: {e}. Data: {line[:60]}")
    
    final_data = []
    if len(start_times) != len(end_events):
        print(f"⚠️ WARNING (A4/Merge): Mismatched counts! Found {len(start_times)} starts and {len(end_events)} ends.")

    for start_time, end_event in zip(start_times, end_events):
        try:
            duration = (end_event['end_time'] - start_time).total_seconds()
            if duration <= 0: raise ValueError("Duration is non-positive (stop time <= start time).")
            
            final_data.append({
                'num_images': end_event['num_images'], 
                'elapsed_time': duration
            })
        except ValueError as e:
            print(f"⚠️ ERROR (A4/Merge): Skipping event due to {type(e).__name__}: {e}.")
            
    return final_data


# --- Statistical Processing (Common to all) ---

def process_and_analyze_data(data):
    """
    Groups the data by 'num_images', calculates statistics for 'elapsed_time',
    and computes the Earth Mover's Distance (EMD).
    """
    grouped_times = defaultdict(list)
    for item in data: grouped_times[item['num_images']].append(item['elapsed_time'])

    analysis_results = {}
    for num_images, times_list in grouped_times.items():
        if len(times_list) < 2: continue
            
        times_array = np.array(times_list)
        
        # Calculate statistics
        min_val = np.min(times_array); max_val = np.max(times_array)
        mean_val = np.mean(times_array); median_val = np.median(times_array)
        std_val = np.std(times_array)

        # Earth Mover's Distance (Wasserstein Distance)
        emd_val = 0.0
        if std_val > 0:
            N = len(times_array) * 10 
            normal_sample = np.random.normal(loc=mean_val, scale=std_val, size=N)
            emd_val = wasserstein_distance(times_array, normal_sample)

        analysis_results[num_images] = (
            times_list, min_val, max_val, mean_val, median_val, std_val, emd_val
        )
    return analysis_results

def print_analysis_results(results, title, time_unit="Time (s)"):
    """Prints the formatted statistical analysis results, sorted by group key."""
    print("\n" + "="*70)
    print(f"📊 {title}")
    print("="*70)

    if not results:
        print("No statistically significant data found (requires at least 2 samples per group).")
        return

    sorted_results = sorted(results.items(), key=lambda item: item[0])

    for num_images, result in sorted_results:
        (times, min_t, max_t, mean_t, median_t, std_t, emd_t) = result
        
        print(f"## Group Size: **{num_images}**")
        print(f"* **Count:** {len(times)}")
        print(f"* **Min/Max {time_unit}:** {min_t:.4f} / {max_t:.4f}")
        print(f"* **Mean/Median {time_unit}:** {mean_t:.4f} / {median_t:.4f}")
        print(f"* **Std Dev {time_unit}:** {std_t:.4f}")
        print(f"* **EMD (vs Normal):** {emd_t:.4f}\n")


# --- Main Execution ---

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python script_name.py <path_to_log_file>")
        sys.exit(1)

    LOG_FILE = sys.argv[1]

    if not os.path.exists(LOG_FILE):
        print(f"❌ Error: Log file not found at '{LOG_FILE}'.")
        sys.exit(1)
    
    print(f"Starting comprehensive analysis on log file: {LOG_FILE}\n")

    
    # =========================================================================
    # 1. ANALYSIS: Original Single-Line Stats
    # =========================================================================
    data_1 = parse_original_stream(ORIGINAL_STATS_CMD, LOG_FILE)
    if data_1:
        results_1 = process_and_analyze_data(data_1)
        print_analysis_results(results_1, "ANALYSIS 1: Original num_to_post Metrics")
        print(f"\nSummary: Found {len(data_1)} total relevant lines for Analysis 1.")
    else:
        print("Skipping ANALYSIS 1: No original STATS entries found.")
    
    print("-" * 70)

    # =========================================================================
    # 2. ANALYSIS: Two-Line Attachments Stats
    # =========================================================================
    data_2 = parse_multiline_stream(DOWNLOAD_CMD, MONITOR_STATS_CMD, LOG_FILE)
    if data_2:
        results_2 = process_and_analyze_data(data_2)
        print_analysis_results(results_2, "ANALYSIS 2: Attachments Download Metrics (2-Line Correlation)")
        print(f"\nSummary: Found {len(data_2)} total valid attachment events for Analysis 2.")
    else:
        print("Skipping ANALYSIS 2: No valid attachment download events found.")
        
    print("-" * 70)

    # =========================================================================
    # 3. ANALYSIS: Three-Line Post Durations
    # =========================================================================
    num_images_data = parse_num_images_stream_3(POST_NUM_IMAGES_CMD, LOG_FILE)
    start_data = parse_start_stream_3(POST_START_CMD, LOG_FILE)
    stop_times = parse_stop_stream_3(POST_STOP_CMD, LOG_FILE)
    
    data_3 = merge_and_calculate_durations_3(num_images_data, start_data, stop_times)

    if data_3:
        results_3 = process_and_analyze_data(data_3)
        print_analysis_results(results_3, "ANALYSIS 3: Post Action Duration Metrics (3-Line Correlation)", time_unit="Duration (s)")
        print(f"\nSummary: Found {len(data_3)} total valid post action events for Analysis 3.")
    else:
        print("Skipping ANALYSIS 3: Not enough corresponding start/stop/numImages entries found.")
        
    print("-" * 70)

    # =========================================================================
    # 4. ANALYSIS: Hashtag Fetch Duration
    # =========================================================================
    data_4 = parse_hashtag_fetch_stream(FETCH_START_CMD, FETCH_END_CMD, LOG_FILE)
    if data_4:
        results_4 = process_and_analyze_data(data_4)
        print_analysis_results(results_4, "ANALYSIS 4: Hashtag Fetch Duration (Items Fetched)", time_unit="Duration (s)")
        print(f"\nSummary: Found {len(data_4)} total valid hashtag fetch events for Analysis 4.")
    else:
        print("Skipping ANALYSIS 4: Not enough corresponding fetch start/end events found.")
