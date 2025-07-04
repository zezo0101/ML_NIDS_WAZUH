import re
from datetime import datetime
import time
import json

def parse_log(log):
    """Parses a single log entry and returns a dictionary."""
    current_year = datetime.now().year
    timestamp_match = re.search(r'\d{2}/\d{2}-\d{2}:\d{2}:\d{2}\.\d+', log)
    formatted_timestamp = (
        f"{current_year} {datetime.strptime(timestamp_match.group(), '%m/%d-%H:%M:%S.%f').strftime('%b %d %H:%M:%S.%f')[:-3]}"
        if timestamp_match
        else 'UnknownTime'
    )    
    sid_match = re.search(r'\[1:(\d+):\d+\]', log)
    sid = sid_match.group(1) if sid_match else 'UnknownSID'
    msg_match = re.search(r'\] (.*?) \[', log)
    msg = msg_match.group(1) if msg_match else 'No message'
    
    mac_match = re.search(r'(\S{2}:\S{2}:\S{2}:\S{2}:\S{2}:\S{2}) -> (\S{2}:\S{2}:\S{2}:\S{2}:\S{2}:\S{2})', log)
    src_mac, dst_mac = mac_match.groups() if mac_match else ('UnknownSrcMAC', 'UnknownDstMAC')
    
    ip_match = re.search(r'(\d{1,3}(?:\.\d{1,3}){3}|\[[\da-fA-F:]+\])(?::(\d+))? -> (\d{1,3}(?:\.\d{1,3}){3}|\[[\da-fA-F:]+\])(?::(\d+))?', log)
    src_ip, src_port, dst_ip, dst_port = ip_match.groups() if ip_match else ('UnknownSrcIP', 'UnknownSrcPort', 'UnknownDstIP', 'UnknownDstPort')
    
    ttl_match = re.search(r'TTL:(\d+)', log)
    ttl = ttl_match.group(1) if ttl_match else 'Unknown'
    
    tos_match = re.search(r'TOS:(\S+)', log)
    tos = tos_match.group(1) if tos_match else 'Unknown'
    
    id_match = re.search(r'ID:(\d+)', log)
    id = id_match.group(1) if id_match else 'Unknown'
    
    ip_len_match = re.search(r'IpLen:(\d+)', log)
    ip_len = ip_len_match.group(1) if ip_len_match else 'Unknown'
    
    dgm_len_match = re.search(r'DgmLen:(\d+)', log)
    dgm_len = dgm_len_match.group(1) if dgm_len_match else 'Unknown'
    
    proto_match = re.search(r'\] (TCP|UDP|ICMP) ', log)
    protocol = proto_match.group(1) if proto_match else 'UnknownProtocol'
    
    extra_info = {}
    
    if protocol == "TCP":
        tcp_extra_match = re.search(r'Seq: (0x[0-9A-Fa-f]+)  Ack: (0x[0-9A-Fa-f]+)  Win: (0x[0-9A-Fa-f]+)  TcpLen: (\d+)', log)
        flags_match = re.search(r'(\*{8}|[\*A-Z]{8})', log)  # Match 8-character flag sequence
        if tcp_extra_match:
            extra_info.update({
                "Seq": tcp_extra_match.group(1),
                "Ack": tcp_extra_match.group(2),
                "Win": tcp_extra_match.group(3),
                "TcpLen": tcp_extra_match.group(4)
            })
        if flags_match:
            flags = flags_match.group(1)
            # Map each position to its corresponding flag
            flag_mapping = {
                0: "C",  # Position 1
                1: "E",  # Position 2
                2: "U",  # Position 3
                3: "A",  # Position 4
                4: "P",  # Position 5
                5: "R",  # Position 6
                6: "S",  # Position 7
                7: "F"   # Position 8
            }
            detected_flags = []
            for i, char in enumerate(flags):
                if char != '*':
                    detected_flags.append(flag_mapping[i])
            extra_info["Flags"] = "".join(detected_flags)
    elif protocol == "ICMP":
        icmp_extra_match = re.search(r'Type:(\d+)  Code:(\d+)  ID:(\d+)  Seq:(\d+)', log)
        if icmp_extra_match:
            extra_info.update({
                "Type": icmp_extra_match.group(1),
                "Code": icmp_extra_match.group(2),
                "ID": icmp_extra_match.group(3),
                "Seq": icmp_extra_match.group(4)
            })
        if extra_info.get("Type") == "0":
            extra_info["TypeDescription"] = "ECHO REPLY"
    elif protocol == "UDP":
        udp_extra_match = re.search(r'Len: (\d+)', log)
        if udp_extra_match:
            extra_info["Len"] = udp_extra_match.group(1)
    
    log_entry = {
        "time": formatted_timestamp,
        "source_mac": src_mac,
        "destination_mac": dst_mac,
        "source_ip": src_ip,
        "source_port": src_port,
        "destination_ip": dst_ip,
        "destination_port": dst_port,
        "protocol": protocol,
        "ttl": ttl,
        "tos": tos,
        "id": id,
        "ip_len": ip_len,
        "dgm_len": dgm_len
    }
    
    log_entry.update(extra_info)
    return log_entry

def count_logs(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            return len(file.read().strip().split('\n\n'))
    except FileNotFoundError:
        return 0

def process_logs(input_file, output_file):
    last_log_count = count_logs(input_file)
    
    while True:
        time.sleep(2)
        current_log_count = count_logs(input_file)
        
        if current_log_count > last_log_count:
            print(f"New logs detected: Processing {current_log_count - last_log_count} new entries...")
            with open(input_file, 'r', encoding='utf-8') as infile:
                log_entries = infile.read().strip().split('\n\n')
            
            new_logs = log_entries[last_log_count:]
            if new_logs:
                with open(output_file, 'a', encoding='utf-8') as outfile:
                    for log in new_logs:
                        outfile.write(json.dumps(parse_log(log)) + "\n")
            
            last_log_count = current_log_count
        else:
            print("No new logs detected.")

process_logs('alert.ids', 'snort_logs.json')