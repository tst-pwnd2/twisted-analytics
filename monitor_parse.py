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
DOWNLOAD_CMD = "grep 'Downloading [0-9]\\+ attachments' {log_file} | grep -oE '[0-9]+'"
MONITOR_STATS_CMD = "grep 'STATS.*monitor_download' {log_file} | grep -oE '{{.*}}'"

# --- Analysis 3: Post Durations (Three Lines) ---
POST_NUM_IMAGES_CMD = "grep \"PluginMastodon::enqueueContent: called with params.linkId\" {log_file} | cut -d' ' -f10,11"
POST_START_CMD = "grep \"Raceboat::TransportComponentWrapper::doAction: called with handlesJson\" {log_file} | cut -d' ' -f2,11"
POST_STOP_CMD = "grep \"PluginCommsTwoSixStubUserModelReactiveFile::onTransportEvent: called with event.json\" {log_file} | cut -d' ' -f2"
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
        # If exit code is 1 (no lines matched), return empty list silently
        if e.returncode == 1: 
            return []
        print(f"❌ Error executing command: {full_command}. Error: {e.stderr.strip()}")
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
                if 'num_to_post' in data:
                    data['num_images'] = data.pop('num_to_post') 
                
                if 'num_images' in data and 'elapsed_time' in data:
                    parsed_data.append(data)
            except json.JSONDecodeError:
                pass 
    return parsed_data

# --- Analysis 2: Attachments ---

def parse_multiline_stream(download_cmd, stats_cmd, log_file):
    """Handles the two-line log entries by zipping the results."""
    counts = [int(c.strip()) for c in execute_shell_command(download_cmd, log_file) if c.strip().isdigit()]
    json_strings = execute_shell_command(stats_cmd, log_file)
        
    if len(counts) != len(json_strings):
        if counts or json_strings:
             print(f"⚠️ Warning (Stream 2): Mismatched counts! Found {len(counts)} counts and {len(json_strings)} JSON objects.")
        
    parsed_data = []
    for count, json_str in zip(counts, json_strings):
        try:
            data = json.loads(json_str.strip())
            data['num_images'] = count 
            
            if 'elapsed_time' in data:
                parsed_data.append(data)
        except json.JSONDecodeError:
            pass
            
    return parsed_data

# --- Analysis 3: Post Durations ---

def parse_num_images_stream_3(command_string, log_file):
    """Parses actionId and numImages (part of Analysis 3)."""
    data_map = {}
    lines = execute_shell_command(command_string, log_file)
    for line in lines:
        try:
            action_id_match = re.search(r'action\.actionId=(\d+)', line)
            json_match = re.search(r'action\.json=({.*}),', line)
            if not action_id_match or not json_match: continue
            
            action_id = int(action_id_match.group(1))
            data = json.loads(json_match.group(1))
            
            if 'numImages' in data:
                data_map[action_id] = {'num_images': data['numImages']}
        except Exception:
            pass
    return data_map

def parse_start_stream_3(command_string, log_file):
    """Parses start timestamp and actionId (part of Analysis 3)."""
    data_map = {}
    lines = execute_shell_command(command_string, log_file)
    for line in lines:
        try:
            parts = line.split(': id:')
            if len(parts) != 2: continue
            
            timestamp_str = parts[0].strip()
            action_id = int(parts[1].strip().strip('}'))
            time_obj = datetime.strptime(timestamp_str, TIME_FORMAT)
            data_map[action_id] = {'start_time': time_obj}
        except Exception:
            pass
    return data_map

def parse_stop_stream_3(command_string, log_file):
    """Parses stop timestamps (part of Analysis 3)."""
    time_list = []
    lines = execute_shell_command(command_string, log_file)
    for line in lines:
        try:
            timestamp_str = line.strip().strip(':')
            time_obj = datetime.strptime(timestamp_str, TIME_FORMAT)
            time_list.append(time_obj)
        except Exception:
            pass
    return time_list

def merge_and_calculate_durations_3(num_images_data, start_data, stop_times):
    """Merges data by action ID and calculates duration."""
    merged_by_id = {}
    for action_id, img_data in num_images_data.items():
        if action_id in start_data:
            merged_by_id[action_id] = {**img_data, **start_data[action_id]}

    sorted_starts = sorted(merged_by_id.values(), key=lambda x: x['start_time'])
    
    final_data = []
    for start_event, stop_time in zip(sorted_starts, stop_times):
        duration = (stop_time - start_event['start_time']).total_seconds()
        if duration > 0:
            final_data.append({
                'num_images': start_event['num_images'],
                'elapsed_time': duration
            })
    return final_data

# --- Statistical Processing (Common to all) ---

def process_and_analyze_data(data):
    """
    Groups the data by 'num_images', calculates statistics for 'elapsed_time',
    and computes the Earth Mover's Distance (EMD).
    """
    grouped_times = defaultdict(list)
    for item in data:
        grouped_times[item['num_images']].append(item['elapsed_time'])

    analysis_results = {}
    for num_images, times_list in grouped_times.items():
        if len(times_list) < 2:
            continue
            
        times_array = np.array(times_list)
        
        # Calculate statistics
        min_val = np.min(times_array)
        max_val = np.max(times_array)
        mean_val = np.mean(times_array)
        median_val = np.median(times_array)
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

def print_analysis_results(results, title):
    """Prints the formatted statistical analysis results."""
    print("\n" + "="*70)
    print(f"📊 {title}")
    print("="*70)

    if not results:
        print("No statistically significant data found (requires at least 2 samples per group).")
        return

    for num_images, result in results.items():
        (times, min_t, max_t, mean_t, median_t, std_t, emd_t) = result
        
        print(f"## Group Size: **{num_images}**")
        print(f"* **Count:** {len(times)}")
        print(f"* **Min/Max Time (s):** {min_t:.4f} / {max_t:.4f}")
        print(f"* **Mean/Median Time (s):** {mean_t:.4f} / {median_t:.4f}")
        print(f"* **Std Dev Time (s):** {std_t:.4f}")
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
        print(f"Found {len(data_1)} total relevant lines.")
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
        print(f"Found {len(data_2)} total valid attachment events.")
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
        print_analysis_results(results_3, "ANALYSIS 3: Post Action Duration Metrics (3-Line Correlation)")
        print(f"Found {len(data_3)} total valid post action events.")
    else:
        print("Skipping ANALYSIS 3: Not enough corresponding start/stop/numImages entries found.")
