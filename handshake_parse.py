import subprocess
import csv
import io
import json
import os
import glob

def analyze_pcaps(file_list, output_json):
    all_results = []

    for pcap_file in file_list:
        if not os.path.exists(pcap_file):
            print(f"File not found: {pcap_file}")
            continue

        # Tshark command to get time, flow info, SYN/ACK flags, TLS type, and IP length
        cmd = [
            'tshark', '-r', pcap_file,
            '-Y', 'tcp || tls.record.content_type==20',
            '-T', 'fields',
            '-e', 'frame.time_epoch',
            '-e', 'ip.src', '-e', 'tcp.srcport',
            '-e', 'ip.dst', '-e', 'tcp.dstport',
            '-e', 'tcp.flags.syn',
            '-e', 'tcp.flags.ack',
            '-e', 'ip.len',
            '-e', 'tls.record.content_type',
            '-E', 'separator=,',
        ]

        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        
        tracker = {}  # {(client_ip, client_port, server_ip, server_port): {'start': float, 'bytes': int}}
        file_entries = []

        # Read the tshark output stream
        reader = csv.reader(io.StringIO(process.stdout.read()))

        for row in reader:
            ts = float(row[0])
            src_ip, src_port = row[1], row[2]
            dst_ip, dst_port = row[3], row[4]
            is_syn = row[5] == 'True'
            is_ack = row[6] == 'True'
            ip_len = int(row[7]) if row[7] else 0
            tls_type = [e.replace('\\', '') for e in row[8:]]

            flow_key = (src_ip, src_port, dst_ip, dst_port)
            rev_key = (dst_ip, dst_port, src_ip, src_port)

            # 1. Start: Client -> Server SYN (no ACK)
            if is_syn and not is_ack:
                tracker[flow_key] = {
                    'start': ts,
                    'bytes': ip_len
                }
            
            # 2. Accumulate: If flow is active, add Upstream bytes
            elif flow_key in tracker:
                tracker[flow_key]['bytes'] += ip_len

            # 3. Stop: Server -> Client Change Cipher Spec (TLS Type 20)
            if '20' in tls_type and rev_key in tracker:
                data = tracker.pop(rev_key)
                duration = ts - data['start']
                
                file_entries.append({
                    'start': data['start'],
                    'stop': ts,
                    'duration': round(duration, 6),
                    'bytes': data['bytes']
                })

        all_results.append({pcap_file: file_entries})

    # Write to the single result file
    with open(output_json, 'w') as f:
        json.dump(all_results, f, indent=4)
    
    print(f"Analysis complete. Results written to {output_json}")

# Example Usage
if __name__ == "__main__":
    pcaps = glob.glob("./pcaps/pcaps/*.pcap")
    analyze_pcaps(pcaps, "handshake_analysis.json")
