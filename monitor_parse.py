import subprocess
import json
from collections import defaultdict
import numpy as np
from scipy.stats import norm, wasserstein_distance
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
TGEN_FETCHING_CMD = "grep \"STATS.*monitor_download\" {log_file} | cut -d'=' -f2"
MONITOR_STATS_CMD = "grep 'STATS.*download' {log_file} | cut -d' ' -f4-"

RACEBOAT_POSTING_IMAGES_CMD = "grep \"PluginMastodon::enqueueContent: called with params.linkId\" {log_file} | cut -d' ' -f10,11,12"
RACEBOAT_POSTING_START_CMD = "grep \"Raceboat::TransportComponentWrapper::doAction: called with handlesJson\" {log_file} | cut -d' ' -f1,2,11"
RACEBOAT_POSTING_STOP_CMD = "grep \"PluginCommsTwoSixStubUserModelReactiveFile::onTransportEvent: called with event.json\" {log_file} | cut -d' ' -f1,2"

# Detailed Raceboat Posting Commands
RACEBOAT_DETAILED_IMAGE_CMD = "grep \"MastodonClient::postStatus: posting image\" {log_file}"
RACEBOAT_DETAILED_STATUS_CMD = "grep \"MastodonClient::postStatus: status URL\" {log_file}"
RACEBOAT_DETAILED_END_CMD = "grep \"Raceboat::ComponentManager::onEvent: called with event=Event{{}}\" {log_file}"

# Reverted to multiple grep commands for fetching
RACEBOAT_FETCHING_START_CMD = "grep \"PluginMastodon::doAction: Fetching from single link\" {log_file} | cut -d' ' -f1,2"
RACEBOAT_FETCHING_END_CMD = "grep \"Link::fetch: Fetched [0-9]\\+ items\" {log_file} | cut -d' ' -f1,2,7,8,9"
RACEBOAT_FETCHING_EACH_CMD = "grep \"Link::fetch: Fetched image content\" {log_file} | cut -d' ' -f1,2,10,11,12"

# Detailed decode bytes commands
RACEBOAT_DETAILED_DECODE_START_CMD = "grep \"Raceboat::EncodingComponentWrapper::decodeBytes: called with handle\" {log_file}"
RACEBOAT_DETAILED_DECODE_END_CMD = "grep \"Raceboat::ComponentReceivePackageManager::onBytesDecoded: called with postId\" {log_file}"

# Decode bytes commands
RACEBOAT_DECODE_START_CMD = "grep \"Link::fetch: Fetched [0-9]\\+ items for hashtag\" {log_file}"
RACEBOAT_DECODE_END_CMD = "grep \"Raceboat::ApiManager::receiveEncPkg: Calling postId:\" {log_file}"

# Iodine logs use spaces to separate date/time
IODINE_UPSTREAM_SEND_CMD = "grep \"Sending .*via Iodine\" {log_file} | cut -d' ' -f1,2"
IODINE_UPSTREAM_RECV_CMD = "grep \"Received Iodine Control Message Type:\" {log_file} | cut -d' ' -f1,2"

IODINE_DOWNSTREAM_SEND_CMD = "grep \"Sending .*via Iodine\" {log_file} | cut -d' ' -f1,2"
IODINE_DOWNSTREAM_RECV_CMD = "grep \"Recieved Iodine Message for File\" {log_file} | cut -d' ' -f1,2"

TGEN_DNS_CMD = "grep \"STATS=\" {log_file} | cut -d'=' -f2"

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
        return [l.strip() for l in result.stdout.strip().split('\n') if l.strip()]
    except subprocess.CalledProcessError as e:
        if e.returncode == 1: 
            return []
        print(f"❌ ERROR: Shell command failed: {full_command}. Stderr: {e.stderr.strip()}")
        return []

def get_utc_timestamp(ts_str):
    """Helper to convert log timestamp strings to UTC epoch floats, handling T and space separators."""
    if not ts_str: return None
    clean_ts = ts_str.strip().rstrip(':')
    
    formats = [
        '%Y-%m-%d %H:%M:%S.%f',
        '%Y-%m-%dT%H:%M:%S.%f',
        '%Y-%m-%d %H:%M:%S',
        '%Y-%m-%dT%H:%M:%S'
    ]
    
    for fmt in formats:
        try:
            dt = datetime.strptime(clean_ts, fmt)
            return dt.replace(tzinfo=timezone.utc).timestamp()
        except ValueError:
            continue
            
    if ' ' in clean_ts:
        first_word = clean_ts.split()[0]
        return get_utc_timestamp(first_word)
        
    return None

def extract_ts_and_last_int(line):
    """Flexible helper to extract a timestamp (1 or 2 parts) and the last integer from a line."""
    parts = line.split()
    if len(parts) < 2: return None, None
    
    # Try 2-part timestamp (Date Space Time)
    ts = get_utc_timestamp(" ".join(parts[:2]))
    val_idx = 2
    
    # If 2nd part wasn't time, try 1-part timestamp
    if ts is None:
        ts = get_utc_timestamp(parts[0])
        val_idx = 1
        
    if ts is None: return None, None
    
    # Search for the last integer in the remaining parts
    val = None
    for p in reversed(parts[val_idx:]):
        try:
            clean_p = re.sub(r'[^0-9]', '', p)
            if clean_p:
                val = int(clean_p)
                break
        except ValueError: continue
            
    return ts, val

def process_and_analyze_data(data, include_sizes=True):
    """Groups data by 'num_images' and calculates statistics for JSON output."""
    if not data: return {}
        
    grouped_times = defaultdict(list)
    for item in data:
        num_imgs = item['num_images']
        entry = {
            'duration': item['elapsed_time'], 
            'start_ts': item.get('start_ts'), 
            'stop_ts': item.get('stop_ts')
        }
        if 'direction' in item: entry['direction'] = item['direction']
        if 'operations' in item: entry['operations'] = item['operations']
        if include_sizes: entry['sizes'] = item.get('sizes', [0])
        if 'zeekSizes' in item: entry['zeekSizes'] = item['zeekSizes']
        grouped_times[num_imgs].append(entry)

    analysis_results = {}
    for num_images in sorted(grouped_times.keys(), key=lambda x: int(x)):
        group_data = grouped_times[num_images]
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

def generate_event_models(output_data):
    """
    Fits Gaussian models to aggregated latencies for each event type.
    For raceboatPosting, fits separate models for image counts 1-4.
    """
    fitted_models = {}

    # 1. Raceboat Posting (Specific 1-4 requirement)
    if 'raceboatPosting' in output_data:
        rp_fits = {}
        for n in ["1", "2", "3", "4"]:
            if n in output_data['raceboatPosting']:
                durations = [item['duration'] for item in output_data['raceboatPosting'][n]['data']]
                if len(durations) >= 2:
                    mu, std = norm.fit(durations)
                    rp_fits[n] = {'loc': float(mu), 'scale': float(std)}
        if rp_fits:
            fitted_models['raceboatPosting'] = rp_fits

    # 2. Other Event Types (Aggregate across all groups)
    event_categories = [
        'iodineUpstream', 'iodineDownstream', 'raceboatFetching', 
        'detailedDecodeBytes', 'decodeBytes',
        'tgenPosting', 'tgenFetching', 'tgenDns'
    ]
    
    for cat in event_categories:
        if cat not in output_data:
            continue
        
        all_durations = []
        for subgroup in output_data[cat].values():
            all_durations.extend([item['duration'] for item in subgroup['data']])
        
        if len(all_durations) >= 2:
            mu, std = norm.fit(all_durations)
            fitted_models[cat] = {'loc': float(mu), 'scale': float(std)}

    return fitted_models

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
                    if script == "HTTPS_Upload_Bytes" and "metric=https_upload_bytes_update" not in msg:
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
                        events_nested[script][src].append({
                            'ts': float(data.get('ts')), 
                            'value': actual_value,
                            'event_id': f"{script}_{src}_{data.get('ts')}"
                        })
                except Exception: continue
    return events_nested

def correlate_zeek_to_events(events, zeek_data_nested, assigned_tracker, target_ip="10.20.1.5", required_prefix=None, continuous=False):
    """Aligns Zeek events to timed actions with safety checks for late-starting logs."""
    earliest_zeek_ts = float('inf')

    for script, ips in zeek_data_nested.items():
        if required_prefix and not script.startswith(required_prefix): continue
        if target_ip in ips:
            for entry in ips[target_ip]:
                if entry['ts'] < earliest_zeek_ts: earliest_zeek_ts = entry['ts']

    sorted_events = sorted(events, key=lambda x: x.get('start_ts', 0))

    # for i, event in enumerate(sorted_events):
    #     start = event.get('start_ts')
    #     stop = sorted_events[i+1].get('start_ts') if continuous and i + 1 < len(sorted_events) else (event.get('stop_ts', float('inf')) if continuous else event.get('stop_ts'))

    #     if start is None or stop is None: continue
    #     if start < earliest_zeek_ts:
    #         event['zeekSizes'] = []
    #         continue
        
    #     zeek_sizes = []
    #     for script, ips in zeek_data_nested.items():
    #         if required_prefix and not script.startswith(required_prefix): continue
    #         if target_ip in ips:
    #             for entry in ips[target_ip]:
    #                 if start <= entry['ts'] < stop:
    #                     zeek_sizes.append(entry['value'])
    #                     assigned_tracker.add(entry['event_id'])
    #     event['zeekSizes'] = zeek_sizes
    return sorted_events

def get_unassigned_zeek_stats(zeek_data_nested, assigned_tracker, target_ip="10.20.1.5"):
    unassigned_counts = defaultdict(int)
    total_unassigned = 0
    for script, ips in zeek_data_nested.items():
        if target_ip in ips:
            for entry in ips[target_ip]:
                if entry['event_id'] not in assigned_tracker:
                    unassigned_counts[script] += 1
                    total_unassigned += 1
    return {'total_unassigned': total_unassigned, 'by_script': dict(unassigned_counts), 'target_ip': target_ip}

def analyze_iodine_dns_activity(iodine_up_data, iodine_down_data, zeek_dns_data_nested, target_ip="10.20.1.5"):
    active_periods = []
    for event in iodine_up_data + iodine_down_data:
        start, stop, direction = event.get('start_ts'), event.get('stop_ts'), event.get('direction', 'unknown')
        if start is not None and stop is not None:
            active_periods.append({'type': 'active', 'direction': direction, 'start_ts': start, 'stop_ts': stop, 'zeek_dns_events': []})
    active_periods.sort(key=lambda x: x['start_ts'])
    
    merged = []
    if active_periods:
        curr = active_periods[0]
        for nxt in active_periods[1:]:
            if nxt['start_ts'] <= curr['stop_ts']:
                curr['stop_ts'] = max(curr['stop_ts'], nxt['stop_ts'])
                if curr['direction'] != nxt['direction']: curr['direction'] = 'mixed'
            else:
                merged.append(curr)
                curr = nxt
        merged.append(curr)

    dns_events = []
    for script, ips in zeek_dns_data_nested.items():
        if script.startswith("DNS_") and target_ip in ips: dns_events.extend(ips[target_ip])
    dns_events.sort(key=lambda x: x['ts'])
    if not dns_events: return {'timeline': []}

    timeline = []
    last_stop = dns_events[0]['ts']
    for p in merged:
        if p['start_ts'] > last_stop:
            timeline.append({'type': 'inactive', 'start_ts': last_stop, 'stop_ts': p['start_ts'], 'zeek_dns_events': []})
        timeline.append(p)
        last_stop = p['stop_ts']
    if dns_events[-1]['ts'] > last_stop:
        timeline.append({'type': 'inactive', 'start_ts': last_stop, 'stop_ts': dns_events[-1]['ts'], 'zeek_dns_events': []})

    for zeek_event in dns_events:
        ts = zeek_event['ts']
        for session in timeline:
            if session['start_ts'] <= ts < session['stop_ts']:
                session['zeek_dns_events'].append(zeek_event)
                break

    summary = defaultdict(lambda: {'count': 0, 'total_size': 0.0, 'total_duration': 0.0})
    for s in timeline:
        t = s['type']
        summary[t]['count'] += len(s['zeek_dns_events'])
        summary[t]['total_size'] += sum(e['value'] for e in s['zeek_dns_events'])
        summary[t]['total_duration'] += s['stop_ts'] - s['start_ts']

    stats = {t: {'event_count': d['count'], 'total_size': d['total_size'], 'avg_size': d['total_size']/d['count'] if d['count']>0 else 0, 'frequency_per_sec': d['count']/d['total_duration'] if d['total_duration']>0 else 0} for t, d in summary.items()}
    return {'statistics': stats, 'timeline': timeline}

# --- Metadata Parsing ---

def parse_scenario_metadata(root_dir):
    metadata = {}
    yml_files = glob.glob(os.path.join(root_dir, "*.yml"))
    if not yml_files: return metadata
    try:
        with open(yml_files[0], 'r') as f:
            cfg = yaml.safe_load(f)
        net_metadata = {f"{e['src']}_to_{e['dst']}": {'latency': e['net_params'].get('latency'), 'loss': e['net_params'].get('loss')} for e in cfg.get('weird_network_section', []) if e.get('src') and e.get('dst')}
        metadata['network_params'] = net_metadata
        app_cfg = cfg.get('application', {})
        metadata['iodine_config'] = app_cfg.get('iodine', {})
        metadata['raceboat_config'] = {'alice_prof_config': app_cfg.get('alice', {}).get('raceboat_prof_config'), 'bob_prof_config': app_cfg.get('bob', {}).get('raceboat_prof_config')}
        metadata['test_id'] = cfg.get('testing', {}).get('test_id', '')
    except Exception: pass
    return metadata

# --- Parsing Logic ---

def parse_tgen_dns(log_files):
    all_data = []
    for log_file in log_files:
        for line in execute_shell_command(TGEN_DNS_CMD, log_file):
            try:
                data = json.loads(line.strip().strip('"'))
                if data.get("type") == "wait": continue
                num = data.get("num_to_resolve", 1) if data.get("type") == "resolve_a_batch" else 1
                if 'elapsed_time' in data:
                    stop_ts = data.get('timestamp')
                    elapsed = data.get('elapsed_time', 0)
                    start_ts = stop_ts - elapsed if stop_ts else None
                    all_data.append({
                        'num_images': num, 
                        'elapsed_time': elapsed,
                        'start_ts': start_ts,
                        'stop_ts': stop_ts
                    })
            except Exception: continue
    return all_data

def parse_tgen_posting(log_files):
    all_data = []
    for log_file in log_files:
        for line in execute_shell_command(TGEN_POSTING_CMD, log_file):
            try:
                data = json.loads(line.strip().strip('"'))
                sizes = [e["request_est_size"] for e in data.get("media_post", []) if "request_est_size" in e]
                num_imgs = data.get('num_to_post', data.get('num_images', len(sizes)))
                if not sizes and num_imgs > 0: sizes = [0] * num_imgs
                
                stop_ts = data.get('timestamp')
                elapsed = data.get('elapsed_time', 0)
                start_ts = stop_ts - elapsed if stop_ts else None
                
                all_data.append({
                    'num_images': num_imgs, 
                    'elapsed_time': elapsed, 
                    'sizes': sizes,
                    'start_ts': start_ts,
                    'stop_ts': stop_ts
                })
            except Exception: continue
    return all_data

def parse_tgen_fetching(log_files):
    all_data = []
    for log_file in log_files:
        for line in execute_shell_command(TGEN_FETCHING_CMD, log_file):
            try:
                data = json.loads(line.strip().strip('"'))
                sizes = [e["content_len"] for e in data.get("downloaded_images_response", []) if "content_len" in e]
                
                stop_ts = data.get('timestamp')
                elapsed = data.get('elapsed_time', 0)
                start_ts = stop_ts - elapsed if stop_ts else None
                
                all_data.append({
                    'num_images': len(sizes), 
                    'elapsed_time': elapsed, 
                    'sizes': sizes,
                    'start_ts': start_ts,
                    'stop_ts': stop_ts
                })
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
            ts = get_utc_timestamp(parts[0])
            if ts: start_times[int(parts[1].strip().strip('}'))] = ts
        except Exception: continue
    stop_times = [t for t in [get_utc_timestamp(l) for l in stop_lines] if t]
    correlated = sorted([{**m, 'start_ts': start_times[aid]} for aid, m in action_data.items() if aid in start_times], key=lambda x: x['start_ts'])
    final_data = []
    for event, stop in zip(correlated, stop_times):
        if stop > event['start_ts']: final_data.append({**event, 'stop_ts': stop, 'elapsed_time': stop - event['start_ts']})
    return final_data

def parse_detailed_raceboat_posting(log_file, base_events):
    """
    Parses detailed posting events and tracks Sizes for operations.
    Matches image sizes from standard base_events and sets status size to 165.
    """
    image_lines = execute_shell_command(RACEBOAT_DETAILED_IMAGE_CMD, log_file)
    status_lines = execute_shell_command(RACEBOAT_DETAILED_STATUS_CMD, log_file)
    end_lines = execute_shell_command(RACEBOAT_DETAILED_END_CMD, log_file)

    all_ops = []
    for label, lines in [('image', image_lines), ('status', status_lines), ('end', end_lines)]:
        for line in lines:
            parts = line.split()
            if len(parts) < 3: continue
            ts_raw = " ".join(parts[:2])
            ts = get_utc_timestamp(ts_raw)
            thread_match = re.search(r'thread=([0-9a-f]+)', line)
            if ts and thread_match:
                all_ops.append({'ts': ts, 'thread': thread_match.group(1), 'type': label})

    all_ops.sort(key=lambda x: x['ts'])
    thread_groups = defaultdict(list)
    for op in all_ops: thread_groups[op['thread']].append(op)

    final_events = []
    for thread, ops in thread_groups.items():
        event = None
        for i, op in enumerate(ops):
            if op['type'] == 'image':
                if event is None:
                    event = {'start_ts': op['ts'], 'ops_queue': [op]}
                else:
                    event['ops_queue'].append(op)
            elif op['type'] == 'status' and event:
                event['ops_queue'].append(op)
            elif op['type'] == 'end' and event:
                start, stop, q = event['start_ts'], op['ts'], event['ops_queue']
                
                # Find matching non-detailed event to pull sizes
                base_match = min(base_events, key=lambda x: abs(x['start_ts'] - start))
                is_valid_match = abs(base_match['start_ts'] - start) < 1.0
                
                detailed_ops = []
                image_idx = 0
                image_count = 0
                sizes_captured = []
                
                for j in range(len(q)):
                    seg_start = q[j]['ts']
                    seg_stop = q[j+1]['ts'] if j+1 < len(q) else stop
                    op_type = q[j]['type']
                    
                    # Size logic
                    op_size = 0
                    if op_type == 'image':
                        image_count += 1
                        if is_valid_match and image_idx < len(base_match['sizes']):
                            op_size = base_match['sizes'][image_idx]
                            image_idx += 1
                    elif op_type == 'status':
                        op_size = 165
                    
                    sizes_captured.append(op_size)
                    detailed_ops.append({
                        'type': op_type,
                        'duration': seg_stop - seg_start,
                        'size': op_size,
                        'order': j
                    })

                final_events.append({
                    'num_images': image_count,
                    'start_ts': start,
                    'stop_ts': stop,
                    'elapsed_time': stop - start,
                    'sizes': sizes_captured,
                    'operations': detailed_ops
                })
                event = None
    return final_events

def parse_raceboat_fetching(log_file):
    """
    Parses Raceboat fetching events using separate greps.
    Fix: FETCHING_EACH statements often occur after FETCHING_END. 
    We match each start with the next occurring start to define the collection window for 'each' sizes.
    """
    starts = execute_shell_command(RACEBOAT_FETCHING_START_CMD, log_file)
    ends = execute_shell_command(RACEBOAT_FETCHING_END_CMD, log_file)
    each_entries = execute_shell_command(RACEBOAT_FETCHING_EACH_CMD, log_file)

    parsed_starts = sorted([t for t in [get_utc_timestamp(s) for s in starts] if t])
    parsed_ends = []
    for line in ends:
        ts, count = extract_ts_and_last_int(line)
        if ts is not None and count is not None:
            parsed_ends.append({'ts': ts, 'count': count})
    parsed_ends.sort(key=lambda x: x['ts'])
    
    parsed_each = []
    for line in each_entries:
        ts, size = extract_ts_and_last_int(line)
        if ts is not None and size is not None:
            parsed_each.append({'ts': ts, 'size': size})
    parsed_each.sort(key=lambda x: x['ts'])

    final_data = []
    for i, start in enumerate(parsed_starts):
        matching_end = next((e for e in parsed_ends if e['ts'] > start), None)
        next_start_limit = parsed_starts[i+1] if i + 1 < len(parsed_starts) else float('inf')
        
        if matching_end:
            stop = matching_end['ts']
            sizes = [e['size'] for e in parsed_each if start <= e['ts'] < next_start_limit]
            final_data.append({
                'num_images': matching_end['count'],
                'elapsed_time': stop - start,
                'start_ts': start,
                'stop_ts': stop,
                'sizes': sizes
            })

    return final_data

def parse_detailed_decode_bytes(log_file):
    """
    Parses detailedDecodeBytes events: tracks from decodeBytes call to onBytesDecoded callback.
    Groups events by handle ID and matches start/stop pairs.
    """
    start_lines = execute_shell_command(RACEBOAT_DETAILED_DECODE_START_CMD, log_file)
    end_lines = execute_shell_command(RACEBOAT_DETAILED_DECODE_END_CMD, log_file)
    
    # Parse start events with handle and size
    start_events = []
    for line in start_lines:
        try:
            parts = line.split()
            if len(parts) < 2: continue
            ts = get_utc_timestamp(" ".join(parts[:2]))
            
            # Extract handle number
            handle_match = re.search(r'handle=(\d+)', line)
            # Extract bytes.size() from the decodeBytes call
            size_match = re.search(r'bytes\.size\(\)=(\d+)', line)
            
            if ts and handle_match:
                start_events.append({
                    'ts': ts,
                    'handle': int(handle_match.group(1)),
                    'input_size': int(size_match.group(1)) if size_match else 0
                })
        except Exception:
            continue
    
    # Parse end events with handle and output size
    end_events = []
    for line in end_lines:
        try:
            parts = line.split()
            if len(parts) < 2: continue
            ts = get_utc_timestamp(" ".join(parts[:2]))
            
            # Extract handle and postId
            handle_match = re.search(r'handle=(\d+)', line)
            post_id_match = re.search(r'postId=(\d+)', line)
            # Extract output bytes.size()
            size_match = re.search(r'bytes\.size\(\)=(\d+)', line)
            
            if ts and handle_match:
                end_events.append({
                    'ts': ts,
                    'handle': int(handle_match.group(1)),
                    'post_id': int(post_id_match.group(1)) if post_id_match else None,
                    'output_size': int(size_match.group(1)) if size_match else 0
                })
        except Exception:
            continue
    
    # Match start and end events by handle
    start_events.sort(key=lambda x: (x['handle'], x['ts']))
    end_events.sort(key=lambda x: (x['handle'], x['ts']))
    
    final_data = []
    handle_groups = defaultdict(list)
    for event in start_events:
        handle_groups[event['handle']].append(event)
    
    for end in end_events:
        handle = end['handle']
        if handle in handle_groups and handle_groups[handle]:
            # Match with the first available start event for this handle
            start = handle_groups[handle].pop(0)
            if end['ts'] > start['ts']:
                final_data.append({
                    'num_images': 1,
                    'elapsed_time': end['ts'] - start['ts'],
                    'start_ts': start['ts'],
                    'stop_ts': end['ts'],
                    'handle': handle,
                    'post_id': end['post_id'],
                    'sizes': [start['input_size'], end['output_size']]
                })
    
    return final_data

def parse_decode_bytes(log_file):
    """
    Parses decodeBytes events: tracks from Link::fetch to receiveEncPkg.
    Matches based on temporal proximity.
    """
    start_lines = execute_shell_command(RACEBOAT_DECODE_START_CMD, log_file)
    end_lines = execute_shell_command(RACEBOAT_DECODE_END_CMD, log_file)
    
    # Parse start events (Link::fetch)
    start_events = []
    for line in start_lines:
        try:
            parts = line.split()
            if len(parts) < 2: continue
            ts = get_utc_timestamp(" ".join(parts[:2]))
            
            # Extract number of items fetched
            count_match = re.search(r'Fetched (\d+) items', line)
            
            if ts and count_match:
                start_events.append({
                    'ts': ts,
                    'count': int(count_match.group(1))
                })
        except Exception:
            continue
    
    # Parse end events (receiveEncPkg)
    end_events = []
    for line in end_lines:
        try:
            parts = line.split()
            if len(parts) < 2: continue
            ts = get_utc_timestamp(" ".join(parts[:2]))
            
            # Extract postId
            post_id_match = re.search(r'postId: (\d+)', line)
            
            if ts:
                end_events.append({
                    'ts': ts,
                    'post_id': int(post_id_match.group(1)) if post_id_match else None
                })
        except Exception:
            continue
    
    # Match start and end events by temporal order
    start_events.sort(key=lambda x: x['ts'])
    end_events.sort(key=lambda x: x['ts'])
    
    final_data = []
    for start in start_events:
        # Find the next end event after this start
        matching_end = next((e for e in end_events if e['ts'] > start['ts']), None)
        if matching_end:
            final_data.append({
                'num_images': start['count'],
                'elapsed_time': matching_end['ts'] - start['ts'],
                'start_ts': start['ts'],
                'stop_ts': matching_end['ts'],
                'post_id': matching_end['post_id'],
                'sizes': [0]  # No size information available in these logs
            })
            # Remove the matched end event to avoid reusing it
            end_events.remove(matching_end)
    
    return final_data

def parse_iodine_duration(send_cmd, recv_cmd, send_log, recv_log, direction):
    sends, recvs = execute_shell_command(send_cmd, send_log), execute_shell_command(recv_cmd, recv_log)
    st = [t for t in [get_utc_timestamp(s) for s in sends] if t]
    rt = [t for t in [get_utc_timestamp(r) for r in recvs] if t]
    return [{'num_images': 1, 'elapsed_time': r - s, 'start_ts': s, 'stop_ts': r, 'direction': direction} for s, r in zip(st, rt) if r > s]

# --- Main Execution ---

if __name__ == "__main__":
    ROOT_DIR = sys.argv[1] if len(sys.argv) == 2 else "."
    RESULTS_FILE = "analysis_results.json"
    PRE_NAT_GLOB, POST_NAT_GLOB = os.path.join(ROOT_DIR, "zeek", "logs", "worker-*pre-nat.log"), os.path.join(ROOT_DIR, "zeek", "logs", "worker-*post-nat.log")
    RB_POST_LOG, RB_FETCH_LOG = os.path.join(ROOT_DIR, "raceboat_client.log"), os.path.join(ROOT_DIR, "raceboat_server.log")
    APP_CLIENT_LOG, APP_SERVER_LOG = os.path.join(ROOT_DIR, "app_client.log"), os.path.join(ROOT_DIR, "app_server.log")
    
    TGEN_MASTODON_FILES = glob.glob(os.path.join(ROOT_DIR, "tgen_logs", "mastodon*client_group_*", "logs", "user*.log"))

    print(f"🔍 Analyzing logs in {ROOT_DIR}...")
    output = {'scenario_metadata': parse_scenario_metadata(ROOT_DIR)}
    zeek_pre, zeek_post = parse_zeek_logs(PRE_NAT_GLOB), parse_zeek_logs(POST_NAT_GLOB)
    output['zeek_metrics'] = {'pre_nat': zeek_pre, 'post_nat': zeek_post}
    apre, apost = set(), set()

    # --- Data Collection for Analysis and Timeline ---
    
    # Iodine Analyses
    up_data = parse_iodine_duration(IODINE_UPSTREAM_SEND_CMD, IODINE_UPSTREAM_RECV_CMD, APP_CLIENT_LOG, APP_SERVER_LOG, "upstream")
    output['iodineUpstream'] = process_and_analyze_data(correlate_zeek_to_events(up_data, zeek_pre, apre, "10.20.1.5", "DNS_"), False)
    
    down_data = parse_iodine_duration(IODINE_DOWNSTREAM_SEND_CMD, IODINE_DOWNSTREAM_RECV_CMD, APP_SERVER_LOG, APP_CLIENT_LOG, "downstream")
    output['iodineDownstream'] = process_and_analyze_data(correlate_zeek_to_events(down_data, zeek_post, apost, "10.20.0.3", "DNS_"), False)

    # Raceboat Analyses
    rb_post_base = parse_raceboat_posting(RB_POST_LOG)
    output['raceboatPosting'] = process_and_analyze_data(correlate_zeek_to_events(rb_post_base, zeek_pre, apre, "10.20.1.5", "HTTPS_", True))
    
    rb_fetch_data = parse_raceboat_fetching(RB_FETCH_LOG)
    output['raceboatFetching'] = process_and_analyze_data(correlate_zeek_to_events(rb_fetch_data, zeek_post, apost, "10.20.0.3", "HTTPS_", True))

    # Detailed Raceboat Posting Analysis
    detailed_rb_post = parse_detailed_raceboat_posting(RB_POST_LOG, rb_post_base)
    output['detailedRaceboatPosting'] = process_and_analyze_data(correlate_zeek_to_events(detailed_rb_post, zeek_pre, apre, "10.20.1.5", "HTTPS_", True))

    # Detailed Decode Bytes Analysis
    detailed_decode_data = parse_detailed_decode_bytes(RB_FETCH_LOG)
    output['detailedDecodeBytes'] = process_and_analyze_data(correlate_zeek_to_events(detailed_decode_data, zeek_post, apost, "10.20.0.3", "HTTPS_", True))

    # Decode Bytes Analysis
    decode_data = parse_decode_bytes(RB_FETCH_LOG)
    output['decodeBytes'] = process_and_analyze_data(correlate_zeek_to_events(decode_data, zeek_post, apost, "10.20.0.3", "HTTPS_", True))

    # Tgen Metrics
    tgen_dns_data = parse_tgen_dns(glob.glob(os.path.join(ROOT_DIR, "tgen_logs", "dns_client_group_*", "logs", "user*.log")))
    output['tgenDns'] = process_and_analyze_data(tgen_dns_data, False)
    
    tgen_post_data = parse_tgen_posting(TGEN_MASTODON_FILES)
    output['tgenPosting'] = process_and_analyze_data(tgen_post_data)
    
    tgen_fetch_data = parse_tgen_fetching(TGEN_MASTODON_FILES)
    output['tgenFetching'] = process_and_analyze_data(tgen_fetch_data)

    # --- Chronological Event Timeline Generation ---
    
    raw_timeline = []
    event_sources = [
        (up_data, 'iodineUpstream'),
        (down_data, 'iodineDownstream'),
        (rb_post_base, 'raceboatPosting'),
        (rb_fetch_data, 'raceboatFetching'),
        (detailed_rb_post, 'detailedRaceboatPosting'),
        (detailed_decode_data, 'detailedDecodeBytes'),
        (decode_data, 'decodeBytes'),
        (tgen_dns_data, 'tgenDns'),
        (tgen_post_data, 'tgenPosting'),
        (tgen_fetch_data, 'tgenFetching')
    ]
    
    for source_list, event_type in event_sources:
        for event in source_list:
            if 'start_ts' in event and 'stop_ts' in event:
                raw_timeline.append({
                    'type': event_type,
                    'start_ts': event['start_ts'],
                    'stop_ts': event['stop_ts']
                })
    
    # Trim logic: start at first iodineUpstream, end at last iodineDownstream
    upstream_starts = [e['start_ts'] for e in up_data if 'start_ts' in e]
    downstream_stops = [e['stop_ts'] for e in down_data if 'stop_ts' in e]
    
    if upstream_starts and downstream_stops:
        ref_start = min(upstream_starts)
        ref_stop = max(downstream_stops)
        
        trimmed_timeline = []
        for event in raw_timeline:
            # Keep events that occur (even partially) within the ref window
            # but standard interpretation is usually based on start_ts being within window
            if event['start_ts'] >= ref_start and event['stop_ts'] <= ref_stop:
                event['relative_start_ts'] = event['start_ts'] - ref_start
                event['relative_stop_ts'] = event['stop_ts'] - ref_start
                trimmed_timeline.append(event)
        
        trimmed_timeline.sort(key=lambda x: x['start_ts'])
        output['event_timeline'] = trimmed_timeline
    else:
        output['event_timeline'] = []

    # --- Remaining Metrics ---
    output['unassigned_zeek_metrics'] = {'pre_nat': get_unassigned_zeek_stats(zeek_pre, apre, "10.20.1.5"), 'post_nat': get_unassigned_zeek_stats(zeek_post, apost, "10.20.0.3")}
    output['dns_activity_comparison'] = analyze_iodine_dns_activity(up_data, down_data, zeek_pre, "10.20.1.5")

    # Final Summary Gaussian Models
    output['event_gaussian_models'] = generate_event_models(output)

    with open(RESULTS_FILE, 'w') as f:
        json.dump(output, f, indent=4, default=str)
    print(f"✨ Analysis complete. Consolidated results written to: {RESULTS_FILE}")
