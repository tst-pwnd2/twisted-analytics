import subprocess
import json
from collections import defaultdict
import numpy as np
from scipy.stats import wasserstein_distance
from datetime import datetime
import re
import os
import sys

# --- Command Definitions (Using {log_file} placeholder) ---

# 1. tgenPosting
TGEN_POSTING_CMD = "grep \"STATS.*num_to_post\" {log_file} | cut -d'=' -f2"

# 2. tgenFetching
MONITOR_STATS_CMD = "grep 'STATS.*download' {log_file} | cut -d' ' -f4-"

# 3. raceboatPosting
RACEBOAT_POSTING_IMAGES_CMD = "grep \"PluginMastodon::enqueueContent: called with params.linkId\" {log_file} | cut -d' ' -f10,11,12"
RACEBOAT_POSTING_START_CMD = "grep \"Raceboat::TransportComponentWrapper::doAction: called with handlesJson\" {log_file} | cut -d' ' -f1,2,11"
RACEBOAT_POSTING_STOP_CMD = "grep \"PluginCommsTwoSixStubUserModelReactiveFile::onTransportEvent: called with event.json\" {log_file} | cut -d' ' -f1,2"

# 4. raceboatFetching
RACEBOAT_FETCHING_START_CMD = "grep \"PluginMastodon::doAction: Fetching from single link\" {log_file} | cut -d' ' -f1,2"
RACEBOAT_FETCHING_END_CMD = "grep \"Link::fetch: .*items for hashtag\" {log_file} | cut -d' ' -f1,2,8"

# 5. Iodine Analysis
IODINE_UPSTREAM_SEND_CMD = "grep \"Sending .*via Iodine\" {log_file} | cut -d' ' -f1,2"
IODINE_UPSTREAM_RECV_CMD = "grep \"Received Iodine Control Message Type:\" {log_file} | cut -d' ' -f1,2"

IODINE_DOWNSTREAM_SEND_CMD = "grep \"Sending .*via Iodine\" {log_file} | cut -d' ' -f1,2"
IODINE_DOWNSTREAM_RECV_CMD = "grep \"Recieved Iodine Message for File\" {log_file} | cut -d' ' -f1,2"

# Timestamp format for parsing (H:M:S.microseconds)
TIME_FORMAT = '%Y-%m-%d %H:%M:%S.%f'

# --- Core Utility Functions ---

def execute_shell_command(command, log_file):
    """Executes a shell command gracefully and returns lines."""
    if not log_file or not os.path.exists(log_file):
        return []
        
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

def process_and_analyze_data(data, include_sizes=True):
    """Groups data by 'num_images' and calculates statistics for JSON output."""
    if not data:
        return {}
        
    grouped_times = defaultdict(list)
    for item in data:
        num_imgs = item['num_images']
        entry = {'duration': item['elapsed_time']}
        if include_sizes:
            entry['sizes'] = item.get('sizes', [0])
        grouped_times[num_imgs].append(entry)

    analysis_results = {}
    for num_images in sorted(grouped_times.keys(), key=lambda x: int(x)):
        group_data = grouped_times[num_images]
        if len(group_data) < 2: 
            continue

        times_list = [e['duration'] for e in group_data]
        times_array = np.array(times_list)
        
        min_val = np.min(times_array)
        max_val = np.max(times_array)
        mean_val = np.mean(times_array)
        median_val = np.median(times_array)
        std_val = np.std(times_array)

        emd_val = 0.0
        if std_val > 0:
            N = len(times_array) * 10 
            normal_sample = np.random.normal(loc=mean_val, scale=std_val, size=N)
            emd_val = wasserstein_distance(times_array, normal_sample)

        res = {
            'count': len(times_list),
            'min': float(min_val),
            'max': float(max_val),
            'mean': float(mean_val),
            'median': float(median_val),
            'std': float(std_val),
            'emd_vs_normal': float(emd_val),
            'elapsed_times': times_list
        }
        
        if include_sizes:
            res['sizes'] = [e['sizes'] for e in group_data]
            
        analysis_results[str(num_images)] = res
        
    return analysis_results

# --- Specific Parsing Logic ---

def parse_tgen_posting(log_file):
    lines = execute_shell_command(TGEN_POSTING_CMD, log_file)
    parsed_data = []
    for line in lines:
        try:
            clean_line = line.strip().strip('"')
            if not clean_line: continue
            data = json.loads(clean_line)
            num_imgs = data.pop('num_to_post', data.get('num_images', 0))
            parsed_data.append({
                'num_images': num_imgs,
                'elapsed_time': data['elapsed_time'],
                'sizes': [0] * num_imgs
            })
        except Exception as e:
            print(f"⚠️ ERROR (tgenPosting): {e} on line: {line[:60]}")
    return parsed_data

def parse_tgen_fetching(log_file):
    parsed_data = []
    for json_str in execute_shell_command(MONITOR_STATS_CMD, log_file):
        try:
            json_payload = json_str.split('STATS=')[1].strip()
            data = json.loads(json_payload)
            parsed_data.append({
                'num_images': int(data['total_requests']) - 1,
                'elapsed_time': data['elapsed_time']
            })
        except Exception as e:
            print(f"⚠️ ERROR (tgenFetching): {e} on string: {json_str[:60]}")
    return parsed_data

def parse_raceboat_posting(log_file):
    enqueue_lines = execute_shell_command(RACEBOAT_POSTING_IMAGES_CMD, log_file)
    start_lines = execute_shell_command(RACEBOAT_POSTING_START_CMD, log_file)
    stop_lines = execute_shell_command(RACEBOAT_POSTING_STOP_CMD, log_file)

    if not enqueue_lines or not start_lines or not stop_lines:
        return []

    action_data = {}
    for line in enqueue_lines:
        try:
            aid = int(re.search(r'action\.actionId=(\d+)', line).group(1))
            size = int(re.search(r'content\.size\(\)=(\d+)', line).group(1))
            meta = json.loads(re.search(r'action\.json=({.*}),', line).group(1))
            if aid not in action_data:
                action_data[aid] = {'num_images': meta['numImages'], 'sizes': []}
            action_data[aid]['sizes'].append(size)
        except Exception as e: print(f"⚠️ ERROR (rbPost/Images): {e}")

    start_times = {}
    for line in start_lines:
        try:
            parts = line.split(': id:')
            ts = datetime.strptime(parts[0].strip(), TIME_FORMAT)
            aid = int(parts[1].strip().strip('}'))
            start_times[aid] = ts
        except Exception as e: print(f"⚠️ ERROR (rbPost/Start): {e}")

    stop_times = []
    for line in stop_lines:
        try:
            ts = datetime.strptime(line.strip().strip(':'), TIME_FORMAT)
            stop_times.append(ts)
        except Exception as e: print(f"⚠️ ERROR (rbPost/Stop): {e}")

    final_data = []
    correlated_events = []
    for aid, meta in action_data.items():
        if aid in start_times:
            correlated_events.append({**meta, 'start': start_times[aid]})
    
    correlated_events.sort(key=lambda x: x['start'])
    for event, stop in zip(correlated_events, stop_times):
        duration = (stop - event['start']).total_seconds()
        if duration > 0:
            final_data.append({
                'num_images': event['num_images'],
                'elapsed_time': duration,
                'sizes': event['sizes']
            })
    return final_data

def parse_raceboat_fetching(log_file):
    starts = execute_shell_command(RACEBOAT_FETCHING_START_CMD, log_file)
    ends = execute_shell_command(RACEBOAT_FETCHING_END_CMD, log_file)
    
    if not starts or not ends:
        return []
        
    start_times = []
    for s in starts:
        try: start_times.append(datetime.strptime(s.strip().strip(':'), TIME_FORMAT))
        except Exception as e: print(f"⚠️ ERROR (rbFetch/Start): {e}")
            
    parsed_ends = []
    for e in ends:
        try:
            parts = e.split()
            ts = datetime.strptime(f"{parts[0]} {parts[1].strip(':')}", TIME_FORMAT)
            count = int(parts[2])
            parsed_ends.append({'end': ts, 'count': count})
        except Exception as ex: print(f"⚠️ ERROR (rbFetch/End): {ex}")
    
    final_data = []
    for start, end_obj in zip(start_times, parsed_ends):
        duration = (end_obj['end'] - start).total_seconds()
        if duration > 0:
            final_data.append({'num_images': end_obj['count'], 'elapsed_time': duration})
    return final_data

def parse_iodine_duration(send_cmd, recv_cmd, send_log, recv_log):
    """Calculates duration between sending from send_log and receiving in recv_log."""
    if not os.path.exists(send_log) or not os.path.exists(recv_log):
        return []
        
    sends = execute_shell_command(send_cmd, send_log)
    recvs = execute_shell_command(recv_cmd, recv_log)
    
    send_times = []
    for s in sends:
        try: send_times.append(datetime.strptime(s.strip(), TIME_FORMAT))
        except Exception as e: print(f"⚠️ ERROR (iodine/Send): {e}")
            
    recv_times = []
    for r in recvs:
        try: recv_times.append(datetime.strptime(r.strip(), TIME_FORMAT))
        except Exception as e: print(f"⚠️ ERROR (iodine/Recv): {e}")
            
    final_data = []
    for s_time, r_time in zip(send_times, recv_times):
        duration = (r_time - s_time).total_seconds()
        if duration > 0:
            final_data.append({'num_images': 1, 'elapsed_time': duration})
    return final_data

# --- Main Execution ---

if __name__ == "__main__":
    if len(sys.argv) != 7:
        print("Usage: python monitor_parse.py <tgen_log> <rb_post_log> <rb_fetch_log> <app_client_log> <app_server_log> <results_json>")
        sys.exit(1)

    TGEN_LOG = sys.argv[1]
    RB_POST_LOG = sys.argv[2]
    RB_FETCH_LOG = sys.argv[3]
    APP_CLIENT_LOG = sys.argv[4]
    APP_SERVER_LOG = sys.argv[5]
    RESULTS_FILE = sys.argv[6]

    log_files = {
        "Tgen Log": TGEN_LOG,
        "Raceboat Post Log": RB_POST_LOG,
        "Raceboat Fetch Log": RB_FETCH_LOG,
        "App Client Log": APP_CLIENT_LOG,
        "App Server Log": APP_SERVER_LOG
    }

    # Pre-flight check: Issue warnings for missing files instead of exiting
    for name, path in log_files.items():
        if not os.path.exists(path):
            print(f"⚠️ WARNING: {name} not found at '{path}'. Related analyses will be skipped.")

    output = {}

    # 1. tgenPosting & tgenFetching
    if os.path.exists(TGEN_LOG):
        print(f"Analyzing {TGEN_LOG} for tgenPosting/Fetching...")
        output['tgenPosting'] = process_and_analyze_data(parse_tgen_posting(TGEN_LOG))
        output['tgenFetching'] = process_and_analyze_data(parse_tgen_fetching(TGEN_LOG))
    else:
        output['tgenPosting'] = {}
        output['tgenFetching'] = {}
    
    # 2. raceboatPosting
    if os.path.exists(RB_POST_LOG):
        print(f"Analyzing {RB_POST_LOG} for raceboatPosting...")
        output['raceboatPosting'] = process_and_analyze_data(parse_raceboat_posting(RB_POST_LOG))
    else:
        output['raceboatPosting'] = {}
    
    # 3. raceboatFetching
    if os.path.exists(RB_FETCH_LOG):
        print(f"Analyzing {RB_FETCH_LOG} for raceboatFetching...")
        output['raceboatFetching'] = process_and_analyze_data(parse_raceboat_fetching(RB_FETCH_LOG))
    else:
        output['raceboatFetching'] = {}

    # 4. iodineUpstream (Client -> Server)
    if os.path.exists(APP_CLIENT_LOG) and os.path.exists(APP_SERVER_LOG):
        print(f"Analyzing iodineUpstream (Client: {APP_CLIENT_LOG} -> Server: {APP_SERVER_LOG})...")
        output['iodineUpstream'] = process_and_analyze_data(
            parse_iodine_duration(IODINE_UPSTREAM_SEND_CMD, IODINE_UPSTREAM_RECV_CMD, APP_CLIENT_LOG, APP_SERVER_LOG),
            include_sizes=False
        )
    else:
        output['iodineUpstream'] = {}

    # 5. iodineDownstream (Server -> Client)
    if os.path.exists(APP_SERVER_LOG) and os.path.exists(APP_CLIENT_LOG):
        print(f"Analyzing iodineDownstream (Server: {APP_SERVER_LOG} -> Client: {APP_CLIENT_LOG})...")
        output['iodineDownstream'] = process_and_analyze_data(
            parse_iodine_duration(IODINE_DOWNSTREAM_SEND_CMD, IODINE_DOWNSTREAM_RECV_CMD, APP_SERVER_LOG, APP_CLIENT_LOG),
            include_sizes=False
        )
    else:
        output['iodineDownstream'] = {}

    # Save to JSON
    try:
        with open(RESULTS_FILE, 'w') as f:
            json.dump(output, f, indent=4)
        print(f"\n✨ Analysis complete. Consolidated results written to: {RESULTS_FILE}")
    except Exception as e:
        print(f"❌ Failed to write JSON results: {e}")
