import subprocess
import json
import logging
import argparse
from pathlib import Path

# Configure Logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def parse_event_log(json_path):
    """
    Parses the nested log format and flattens it into a list of event objects.
    """
    with open(json_path, 'r') as f:
        raw_log = json.load(f)

    flat_events = []

    # Iterate over top-level keys (e.g., tgenPosting, tgenFetching)
    for activity_type, batches in raw_log.items():
        if activity_type not in ['tgenPosting', 'tgenFetching']:
            continue
        # Iterate over batch IDs (e.g., "1", "2")
        for batch_id, metrics in batches.items():
            # Ensure this is a valid batch dict
            if not isinstance(metrics, dict) or 'data' not in metrics:
                continue

            for entry in metrics['data']:
                # Extract the list of file sizes
                sizes = entry.get('sizes', [])
                expected_size = sum(sizes)

                flat_events.append({
                    'activity': activity_type,
                    # Convert batch key "1" to int 1
                    'batch_id': int(batch_id) if batch_id.isdigit() else 0,
                    'start_ts': float(entry['start_ts']),
                    'end_ts': float(entry['stop_ts']),
                    'duration': float(entry['duration']),
                    'sizes': sizes,
                    'expected_bytes': int(expected_size)
                })

    # Sort events by start time for linear correlation
    flat_events.sort(key=lambda x: x['start_ts'])
    logging.info(f"Parsed {len(flat_events)} events from log.")
    return flat_events

def get_packets_from_pcaps(pcap_files, display_filter="tcp"):
    """
    Runs tshark on all provided PCAPs and returns a merged, sorted list of packet dicts.
    """
    all_packets = []

    for pcap in pcap_files:
        if not Path(pcap).exists():
            logging.warning(f"PCAP file not found: {pcap}")
            continue

        cmd = [
            'tshark', '-r', pcap,
            '-Y', display_filter,
            '-T', 'json',
            '-e', 'frame.time_epoch',
            '-e', 'ip.src', '-e', 'tcp.srcport',
            '-e', 'ip.dst', '-e', 'tcp.dstport',
            '-e', 'tcp.len'  # We only need Payload length to compare against 'expected_bytes'
        ]

        logging.info(f"Processing {pcap}...")
        try:
            # Run tshark
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            raw_data = json.loads(result.stdout)
            
            for p in raw_data:
                layers = p['_source']['layers']
                
                # Default to 0 if tcp.len is missing (e.g. syn/ack packets often have len 0)
                tcp_len = int(layers.get('tcp.len', ['0'])[0])
                
                all_packets.append({
                    'ts': float(layers['frame.time_epoch'][0]),
                    'len': tcp_len,
                    'upstream': '10.20.1.' in layers['ip.src'][0]
                })

        except subprocess.CalledProcessError as e:
            logging.error(f"Error reading {pcap}: {e.stderr}")
        except json.JSONDecodeError:
            logging.warning(f"File {pcap} produced no valid JSON output (possibly empty).")

    # Sort packets by timestamp (crucial when merging multiple files)
    all_packets.sort(key=lambda x: x['ts'])
    logging.info(f"Loaded {len(all_packets)} packets total.")
    return all_packets

def correlate(events, packets):
    """
    Correlates events with packets and builds the requested output structure.
    """
    output_list = []
    
    # Cursor for optimization
    pkt_idx = 0
    total_packets = len(packets)

    for event in events:
        start = event['start_ts']
        end = event['end_ts']
        
        # 1. Move cursor to start of window
        while pkt_idx < total_packets and packets[pkt_idx]['ts'] < start:
            pkt_idx += 1
            
        # 2. Sum packets within window
        temp_idx = pkt_idx
        current_actual_bytes = 0
        current_pkt_count = 0
        current_upstream_bytes = 0
        
        while temp_idx < total_packets and packets[temp_idx]['ts'] <= end:
            current_actual_bytes += packets[temp_idx]['len']
            current_pkt_count += 1
            if packets[temp_idx]['upstream']:
                current_upstream_bytes += packets[temp_idx]['len']

            temp_idx += 1

           
        # 3. Build Result Object
        # Note: We cast duration to int as requested in prompt, though it loses precision.
        result_entry = {
            'event': event['activity'],
            'start': event['start_ts'],
            'stop': event['end_ts'],
            'duration': event['duration'],
            'expected_bytes': event['expected_bytes'],
            'actual_bytes': current_actual_bytes,
            'upstream_bytes': current_upstream_bytes,
            'pkts': current_pkt_count,
            'batch': event['batch_id'],
            'sizes': event['sizes']
        }
        
        output_list.append(result_entry)

    return output_list

def main():
    parser = argparse.ArgumentParser(description="Correlate Event Log with PCAP to JSON.")
    parser.add_argument('--log', required=True, help="Path to input event log JSON")
    parser.add_argument('--pcaps', nargs='+', required=True, help="List of PCAP files")
    parser.add_argument('--output', default='correlated_results.json', help="Output JSON file path")
    
    args = parser.parse_args()

    # 1. Parse
    events = parse_event_log(args.log)
    
    # 2. Extract
    packets = get_packets_from_pcaps(args.pcaps)
    
    if not packets:
        logging.error("No packets extracted. Exiting.")
        return

    # 3. Correlate
    results = correlate(events, packets)

    # 4. Save
    with open(args.output, 'w') as f:
        json.dump(results, f, indent=4)
        
    logging.info(f"Successfully wrote {len(results)} events to {args.output}")

if __name__ == "__main__":
    main()
