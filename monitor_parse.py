import subprocess
import json
from collections import defaultdict
import numpy as np
from scipy.stats import wasserstein_distance
from datetime import datetime, timezone
import re
import os
import sys
import glob
try:
    import yaml
except ImportError:
    yaml = None

# --- Command Definitions ---

TGEN_POSTING_CMD = "grep \"STATS.*num_to_post\" {log_file} | cut -d'=' -f2"
MONITOR_STATS_CMD = "grep 'STATS.*download' {log_file} | cut -d' ' -f4-"

RACEBOAT_POSTING_IMAGES_CMD = "grep \"PluginMastodon::enqueueContent: called with params.linkId\" {log_file} | cut -d' ' -f10,11,12"
RACEBOAT_POSTING_START_CMD = "grep \"Raceboat::TransportComponentWrapper::doAction: called with handlesJson\" {log_file} | cut -d' ' -f1,2,11"
RACEBOAT_POSTING_STOP_CMD = "grep \"PluginCommsTwoSixStubUserModelReactiveFile::onTransportEvent: called with event.json\" {log_file} | cut -d' ' -f1,2"

RACEBOAT_FETCHING_START_CMD = "grep \"PluginMastodon::doAction: Fetching from single link\" {log_file} | cut -d' ' -f1,2"
RACEBOAT_FETCHING_END_CMD = "grep \"Link::fetch: .*items for hashtag\" {log_file} | cut -d' ' -f1,2,8"

IODINE_UPSTREAM_SEND_CMD = "grep \"Sending .*via Iodine\" {log_file} | cut -d' ' -f1,2"
IODINE_UPSTREAM_RECV_CMD = "grep \"Received Iodine Control Message Type:\" {log_file} | cut -d' ' -f1,2"

IODINE_DOWNSTREAM_SEND_CMD = "grep \"Sending .*via Iodine\" {log_file} | cut -d' ' -f1,2"
IODINE_DOWNSTREAM_RECV_CMD = "grep \"Recieved Iodine Message for File\" {log_file} | cut -d' ' -f1,2"

TGEN_DNS_CMD = "grep \"STATS=\" {log_file} | cut -d'=' -f2"

# Timestamp formats - treating as UTC for alignment
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

def get_utc_timestamp(ts_str):
    """Helper to convert log timestamp strings to UTC epoch floats."""
    try:
        dt = datetime.strptime(ts_str.strip(), TIME_FORMAT)
        return dt.replace(tzinfo=timezone.utc).timestamp()
    except Exception:
        return None

def process_and_analyze_data(data, include_sizes=True):
    """Groups data by 'num_images' and calculates statistics for JSON output."""
    if not data:
        return {}
        
    grouped_times = defaultdict(list)
    for item in data:
        num_imgs = item['num_images']
        entry = {
            'duration': item['elapsed_time'], 
            'start_ts': item.get('start_ts'), 
            'stop_ts': item.get('stop_ts')
        }
        if include_sizes:
            entry['sizes'] = item.get('sizes', [0])
        
        if 'zeekSizes' in item:
            entry['zeekSizes'] = item['zeekSizes']
            
        grouped_times[num_imgs].append(entry)

    analysis_results = {}
    for num_images in sorted(grouped_times.keys(), key=lambda x: int(x)):
        group_data = grouped_times[num_images]
        if len(group_data) < 2: 
            continue

        times_list = [e['duration'] for e in group_data]
        times_array = np.array(times_list)
        
        analysis_results[str(num_images)] = {
            'count': len(times_list),
            'min': float(np.min(times_array)),
            'max': float(np.max(times_array)),
            'mean': float(np.mean(times_array)),
            'median': float(np.median(times_array)),
            'std': float(np.std(times_array)),
            'emd_vs_normal': float(wasserstein_distance(times_array, np.random.normal(np.mean(times_array), np.std(times_array), len(times_array)*10)) if np.std(times_array) > 0 else 0),
            'data': group_data
        }
        
    return analysis_results

# --- Zeek Logic ---

def parse_zeek_logs(glob_pattern):
    """Parses Zeek JSON logs and groups events with differential logic."""
    files = glob.glob(glob_pattern)
    events_nested = defaultdict(lambda: defaultdict(list))
    last_val = defaultdict(lambda: defaultdict(float))
    
    for f_path in files:
        with open(f_path, 'r') as f:
            for line in f:
                try:
                    data = json.loads(line)
                    script = data.get('script', 'Unknown')
                    msg = data.get('msg', '')
                    
                    if script == "HTTPS_Upload_Bytes":
                        if "metric=https_upload_bytes_update" not in msg:
                            continue

                    src = '0.0.0.0'
                    src_match = re.search(r'src=([0-9\.]+)', msg)
                    if src_match: src = src_match.group(1)
                    
                    val_match = re.search(r'(total_bytes|resp_bytes|bytes|total|added_len|added_bytes|added_count|req_count|total_requests)=([0-9\.]+)', msg)
                    if not val_match: continue
                        
                    raw_val = float(val_match.group(2))
                    field_name = val_match.group(1)
                    
                    if field_name.startswith('total') or field_name in ['bytes', 'resp_bytes', 'total', 'total_bytes', 'req_count']:
                        diff = max(0.0, raw_val - last_val[script][src])
                        last_val[script][src] = raw_val
                        actual_value = diff
                    else:
                        actual_value = raw_val
                    
                    if actual_value > 0:
                        # Assign a unique ID to each zeek event to track assignment
                        events_nested[script][src].append({
                            'ts': float(data.get('ts')), 
                            'value': actual_value,
                            'event_id': f"{script}_{src}_{data.get('ts')}"
                        })
                except Exception: continue
    return events_nested

def correlate_zeek_to_events(events, zeek_data_nested, assigned_tracker, target_ip="10.20.1.5", required_prefix=None):
    """
    Aligns Zeek events to timed actions using epoch-to-epoch comparison.
    Updates assigned_tracker set with IDs of assigned Zeek events.
    """
    for event in events:
        start = event.get('start_ts')
        stop = event.get('stop_ts')
        if start is None or stop is None: continue
        
        zeek_sizes = []
        for script, ips in zeek_data_nested.items():
            if required_prefix and not script.startswith(required_prefix):
                continue
                
            if target_ip in ips:
                logs = ips[target_ip]
                for entry in logs:
                    if start <= entry['ts'] <= stop:
                        zeek_sizes.append(entry['value'])
                        assigned_tracker.add(entry['event_id'])
        
        event['zeekSizes'] = zeek_sizes
            
    return events

def get_unassigned_zeek_stats(zeek_data_nested, assigned_tracker, target_ip="10.20.1.5"):
    """
    Counts how many events in the nested structure were never assigned.
    Filters by target_ip so only unassigned events for that IP are counted.
    """
    unassigned_counts = defaultdict(int)
    total_unassigned = 0
    
    for script, ips in zeek_data_nested.items():
        if target_ip in ips:
            for entry in ips[target_ip]:
                if entry['event_id'] not in assigned_tracker:
                    unassigned_counts[script] += 1
                    total_unassigned += 1
                    
    return {
        'total_unassigned': total_unassigned,
        'by_script': dict(unassigned_counts),
        'target_ip': target_ip
    }

# --- Metadata Parsing ---

def parse_scenario_metadata(root_dir):
    metadata = {}
    yml_files = glob.glob(os.path.join(root_dir, "*.yml"))
    if not yml_files: return metadata
    yml_path = yml_files[0]
    if yaml is None: return metadata
    try:
        with open(yml_path, 'r') as f:
            cfg = yaml.safe_load(f)
        net_metadata = {}
        for entry in cfg.get('weird_network_section', []):
            src, dst = entry.get('src'), entry.get('dst')
            params = entry.get('net_params', {})
            if src and dst:
                net_metadata[f"{src}_to_{dst}"] = {'latency': params.get('latency'), 'loss': params.get('loss')}
        metadata['network_params'] = net_metadata
        app_cfg = cfg.get('application', {})
        metadata['iodine_config'] = app_cfg.get('iodine', {})
        metadata['raceboat_config'] = {
            'alice_prof_config': app_cfg.get('alice', {}).get('raceboat_prof_config'),
            'bob_prof_config': app_cfg.get('bob', {}).get('raceboat_prof_config')
        }
    except Exception: pass
    return metadata

# --- Parsing Logic ---

def parse_tgen_dns(log_files):
    all_data = []
    for log_file in log_files:
        lines = execute_shell_command(TGEN_DNS_CMD, log_file)
        for line in lines:
            try:
                data = json.loads(line.strip().strip('"'))
                if data.get("type") == "wait": continue
                num = data.get("num_to_resolve", 1) if data.get("type") == "resolve_a_batch" else 1
                if 'elapsed_time' in data:
                    all_data.append({'num_images': num, 'elapsed_time': data['elapsed_time']})
            except Exception: continue
    return all_data

def parse_raceboat_posting(log_file):
    enqueue_lines = execute_shell_command(RACEBOAT_POSTING_IMAGES_CMD, log_file)
    start_lines = execute_shell_command(RACEBOAT_POSTING_START_CMD, log_file)
    stop_lines = execute_shell_command(RACEBOAT_POSTING_STOP_CMD, log_file)

    action_data = {}
    for line in enqueue_lines:
        try:
            aid = int(re.search(r'action\.actionId=(\d+)', line).group(1))
            size = int(re.search(r'content\.size\(\)=(\d+)', line).group(1))
            meta = json.loads(re.search(r'action\.json=({.*}),', line).group(1))
            if aid not in action_data: action_data[aid] = {'num_images': meta['numImages'], 'sizes': []}
            action_data[aid]['sizes'].append(size)
        except Exception: continue

    start_times = {}
    for line in start_lines:
        try:
            parts = line.split(': id:')
            start_times[int(parts[1].strip().strip('}'))] = get_utc_timestamp(parts[0].strip())
        except Exception: continue

    stop_times = []
    for line in stop_lines:
        try: stop_times.append(get_utc_timestamp(line.strip().strip(':')))
        except Exception: continue

    correlated = sorted([{**m, 'start_ts': start_times[aid]} for aid, m in action_data.items() if aid in start_times], key=lambda x: x['start_ts'])
    final_data = []
    for event, stop in zip(correlated, stop_times):
        if stop and event['start_ts'] and stop > event['start_ts']:
            final_data.append({**event, 'stop_ts': stop, 'elapsed_time': stop - event['start_ts']})
    return final_data

def parse_iodine_duration(send_cmd, recv_cmd, send_log, recv_log):
    sends = execute_shell_command(send_cmd, send_log)
    recvs = execute_shell_command(recv_cmd, recv_log)
    send_times = [t for t in [get_utc_timestamp(s) for s in sends] if t]
    recv_times = [t for t in [get_utc_timestamp(r) for r in recvs] if t]
    final_data = []
    for s_time, r_time in zip(send_times, recv_times):
        if r_time > s_time:
            final_data.append({'num_images': 1, 'elapsed_time': r_time - s_time, 'start_ts': s_time, 'stop_ts': r_time})
    return final_data

# --- Main Execution ---

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python monitor_parse.py <root_dir>")
        sys.exit(1)

    ROOT_DIR = sys.argv[1]
    RESULTS_FILE = "analysis_results.json"
    PRE_NAT_GLOB = os.path.join(ROOT_DIR, "zeek", "logs", "worker-*pre-nat.log")
    POST_NAT_GLOB = os.path.join(ROOT_DIR, "zeek", "logs", "worker-*post-nat.log")
    RB_POST_LOG = os.path.join(ROOT_DIR, "raceboat_client.log")
    APP_CLIENT_LOG = os.path.join(ROOT_DIR, "app_client.log")
    APP_SERVER_LOG = os.path.join(ROOT_DIR, "app_server.log")
    
    print(f"🔍 Analyzing logs in {ROOT_DIR}...")
    output = {'scenario_metadata': parse_scenario_metadata(ROOT_DIR)}
    zeek_pre = parse_zeek_logs(PRE_NAT_GLOB)
    zeek_post = parse_zeek_logs(POST_NAT_GLOB)
    output['zeek_metrics'] = {'pre_nat': zeek_pre, 'post_nat': zeek_post}

    # Tracking sets for assigned events
    assigned_pre = set()
    assigned_post = set()

    # Upstream and Downstream Iodine
    output['iodineUpstream'] = process_and_analyze_data(
        correlate_zeek_to_events(
            parse_iodine_duration(IODINE_UPSTREAM_SEND_CMD, IODINE_UPSTREAM_RECV_CMD, APP_CLIENT_LOG, APP_SERVER_LOG), 
            zeek_pre, assigned_pre, target_ip="10.20.1.5", required_prefix="DNS_"
        ), include_sizes=False
    )
    
    output['iodineDownstream'] = process_and_analyze_data(
        correlate_zeek_to_events(
            parse_iodine_duration(IODINE_DOWNSTREAM_SEND_CMD, IODINE_DOWNSTREAM_RECV_CMD, APP_SERVER_LOG, APP_CLIENT_LOG), 
            zeek_post, assigned_post, target_ip="10.20.0.3", required_prefix="DNS_"
        ), include_sizes=False
    )

    # Raceboat
    output['raceboatPosting'] = process_and_analyze_data(
        correlate_zeek_to_events(
            parse_raceboat_posting(RB_POST_LOG), 
            zeek_pre, assigned_pre, target_ip="10.20.1.5", required_prefix="HTTPS_"
        )
    )

    # Calculate and store unassigned counts for the target IPs
    output['unassigned_zeek_metrics'] = {
        'pre_nat': get_unassigned_zeek_stats(zeek_pre, assigned_pre, target_ip="10.20.1.5"),
        'post_nat': get_unassigned_zeek_stats(zeek_post, assigned_post, target_ip="10.20.0.3")
    }
    
    dns_files = glob.glob(os.path.join(ROOT_DIR, "tgen_logs", "dns_client_group_*", "logs", "user*.log"))
    output['tgenDns'] = process_and_analyze_data(parse_tgen_dns(dns_files), include_sizes=False)

    with open(RESULTS_FILE, 'w') as f:
        # Use default=str to handle any remaining non-serializable objects gracefully
        json.dump(output, f, indent=4, default=str)
    
    print(f"✨ Analysis complete. Consolidated results written to: {RESULTS_FILE}")
