import re
import json
import time
import os
import uuid
import numpy as np
import pandas as pd
from ipaddress import ip_address
import joblib
from collections import deque

encoder = {0:"DoS",1:"MetarPretar",2:"Normal",3:"PortScaning"}

from telegram import Bot
from telegram.error import TelegramError
import asyncio
# Replace these with your actual values
BOT_TOKEN = '7693390312:AAGw3UV3jqkYifcByuBfyTrDiey0wfdc5ag' #https://api.telegram.org/bot7693390312:AAGw3UV3jqkYifcByuBfyTrDiey0wfdc5ag/getUpdates
GROUP_CHAT_ID = '-4757872043'  # Can be the group's username (with @) or ID
async def send_message_to_group(message):
    bot = Bot(token=BOT_TOKEN)
    
    try:
        # Send a simple text message
        await bot.send_message(chat_id=GROUP_CHAT_ID, text=message)
        
        print("Message sent successfully!")
    except TelegramError as e:
        print(f"Error sending message: {e}")

def get_unique_folder_name(base_name):
    """Generates a unique folder name by appending a number if the folder already exists."""
    folder_name = base_name
    counter = 1
    while os.path.exists(folder_name):
        folder_name = f"{base_name}_{counter}"
        counter += 1
    return folder_name

def get_unique_mapping_file_name(base_name):
    """Generates a unique mapping file name by appending a number if the file already exists."""
    file_name = base_name
    counter = 1
    while os.path.exists(file_name):
        file_name = f"{base_name.split('.')[0]}_{counter}.txt"
        counter += 1
    return file_name

# Create a unique connections folder
connections_folder = get_unique_folder_name('connections')
os.makedirs(connections_folder)

# Create a unique mapping file
mapping_file = get_unique_mapping_file_name('mapping.txt')

def parse_log(log):
    """Parses a single log entry and returns a dictionary."""
    json_match = re.search(r'\{.*\}', log)
    if json_match:
        return json.loads(json_match.group())
    return None

def count_logs(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            log_entries = file.read().strip().split('\n\n')
            return (len(log_entries), log_entries)
    except FileNotFoundError:
        return (0, 0)

def get_connection_key(log):
    """Generates a unique key for a connection based on the log entry, ignoring ports."""
    return (
        log.get("source_ip", "N/A"),
        log.get("destination_ip", "N/A"),
        log.get("protocol", "Unknown")
    )

def load_mapping(mapping_file):
    """Loads the connection key to ID mapping from the mapping file."""
    if not os.path.exists(mapping_file):
        return {}
    
    with open(mapping_file, 'r', encoding='utf-8') as file:
        mapping = {}
        for line in file:
            key, conn_id = line.strip().split(':', 1)
            mapping[tuple(key.split(','))] = conn_id
        return mapping

def save_mapping(mapping_file, mapping):
    """Saves the connection key to ID mapping to the mapping file."""
    with open(mapping_file, 'w', encoding='utf-8') as file:
        for key, conn_id in mapping.items():
            file.write(f"{','.join(key)}:{conn_id}\n")

def is_private_ip(ip):
    """Check if an IP address is private."""
    try:
        return ip_address(ip).is_private
    except ValueError:
        return False

def extract_features(logs):
    """Extract features from a list of logs for a single connection."""
    flag_types = ["F", "S", "R", "P", "A", "U", "E", "C"]
    
    flag_counts = {flag: 0 for flag in flag_types}
    total_size = 0
    packet_sizes = []
    win_sizes = []
    seq_nums = []
    ack_nums = []
    timestamps = []
    
    # Track unique source and destination ports
    source_ports = set()
    destination_ports = set()
    
    # Initialize new features
    zero_flgs = 0
    more_than_2_flags = 0
    
    for log in logs:
        flags = log.get("Flags", "")
        if flags:
            
            # Count flags
            flag_count = 0
            for flag in flag_types:
                if flag in flags:
                    flag_counts[flag] += 1
                    flag_count += 1
            
            # Count more than 2 flags
            if flag_count > 2:
                more_than_2_flags += 1
        else:
            zero_flgs += 1
            
            
        total_size += int(log.get("dgm_len", 0))
        packet_sizes.append(int(log.get("dgm_len", 0)))
        win_sizes.append(int(log.get("Win", "0"), 16))
        seq_nums.append(int(log.get("Seq", "0"), 16))
        ack_nums.append(int(log.get("Ack", "0"), 16))
        timestamps.append(pd.to_datetime(log.get("time", "1970-01-01 00:00:00")))
        
        # Collect source and destination ports
        if "source_port" in log:
            source_ports.add(log["source_port"])
        if "destination_port" in log:
            destination_ports.add(log["destination_port"])
    
    timestamps.sort()
    time_diffs = np.diff(timestamps).astype('timedelta64[ms]').astype(int) if len(timestamps) > 1 else [0]
    
    # Calculate packet_rate and other new features
    duration = (timestamps[-1] - timestamps[0]).total_seconds() if len(timestamps) > 1 else 0
    packet_rate = len(logs) / duration if duration > 0 else 0
    inter_arrival_time_std = np.std(time_diffs) if len(time_diffs) > 1 else 0
    packet_size_std = np.std(packet_sizes) if len(packet_sizes) > 1 else 0
    packet_size_avg = np.mean(packet_sizes) if len(packet_sizes) > 1 else 0
    syn_ack_ratio = flag_counts["S"] / flag_counts["A"] if flag_counts["A"] > 0 else 0
    is_syn_flood = 1 if syn_ack_ratio > 2 else 0

    # Features dictionary
    features = {
        "source_ip": logs[0]["source_ip"],
        "destination_ip": logs[0]["destination_ip"],
        "protocol": logs[0].get("protocol", "Unknown"),
        "duration": duration,
        "ttl_average": sum(int(log.get("ttl", 0)) for log in logs) / len(logs),
        "seq_variance": np.var(seq_nums) if len(seq_nums) > 1 else 0,
        "ack_variance": np.var(ack_nums) if len(ack_nums) > 1 else 0,
        "win_min": min(win_sizes) if win_sizes else 0,
        "win_max": max(win_sizes) if win_sizes else 0,
        "packet_size_min": min(packet_sizes) if packet_sizes else 0,
        "packet_size_max": max(packet_sizes) if packet_sizes else 0,
        "size": total_size,
        "syn_ack_ratio": syn_ack_ratio,
        "time_between_packets_avg": np.mean(time_diffs) if len(time_diffs) > 1 else 0,
        "packet_rate": packet_rate,
        "inter_arrival_time_std": inter_arrival_time_std,
        "packet_size_std": packet_size_std,
        "packet_size_avg": packet_size_avg,
        "is_tcp": 1 if logs[0].get("protocol") == "TCP" else 0,
        "is_udp": 1 if logs[0].get("protocol") == "UDP" else 0,
        "is_icmp": 1 if logs[0].get("protocol") == "ICMP" else 0,
        "is_private_ip": is_private_ip(logs[0]["source_ip"]) or is_private_ip(logs[0]["destination_ip"]),
        "is_well_known_port": 1 if isinstance(logs[0].get("destination_port", "N/A"), int) and 0 <= logs[0].get("destination_port", 0) <= 1023 else 0,
        "is_syn_flood": is_syn_flood,
        "source_ports_count": len(source_ports),
        "destination_ports_count": len(destination_ports),
        "log_count": len(logs),
        "zero_flgs": zero_flgs,
        "more_than_2_flags": more_than_2_flags,
    }
    
    features.update(flag_counts)
    return features

# Define file paths (no label encoder)
model_path = 'svc_model.pkl'
scaler_path = 'scaler.pkl'

# Load the model and scaler
log_reg = joblib.load(model_path)
scaler = joblib.load(scaler_path)

def update_connections_json(connections_folder, mapping, max_log_length=250):
    global file_sizes
    """Update the connections.json file with features for each connection.
    
    Args:
        connections_folder: Path to the folder containing connection files
        mapping: Dictionary mapping connection keys to connection IDs
        max_log_length: Maximum number of logs to keep in each connection file.
                       If 0, keeps all logs (no clearing).
                       note: if N > 0 don't make the value less than 50 for correct prediction
    """
    connections_json_path = os.path.join(connections_folder, "connections.json")
    file_sizes = {}
    
    if os.path.exists(connections_json_path):
        with open(connections_json_path, "r", encoding="utf-8") as file:
            existing_data = [json.loads(line) for line in file]
    else:
        existing_data = []
    
    for key, conn_id in mapping.items():
        conn_file = os.path.join(connections_folder, f"{conn_id}.json")
        if not os.path.exists(conn_file):
            continue
        
        current_size = os.path.getsize(conn_file)
        if conn_id in file_sizes and file_sizes[conn_id] == current_size:
            continue # Skip if file size hasn't changed
        
        file_sizes[conn_id] = current_size
        
        # Read the connection file
        with open(conn_file, "r", encoding="utf-8") as file:
            logs = [json.loads(line) for line in file]
        
        # If we're limiting log length and need to truncate the file
        if max_log_length > 0 and len(logs) > max_log_length:
            logs = logs[-max_log_length:]
            # print(f"I WILL Write {len(logs)} !!!")
            # Rewrite the file with only the last N logs
            with open(conn_file, "w", encoding="utf-8") as file:
                for log in logs:
                    file.write(json.dumps(log) + "\n")

        features = extract_features(logs[-50:]) # pass last 50 only for prediction
        features["connection_id"] = conn_id
        
        # Update or append to existing_data
        updated = False
        for i, entry in enumerate(existing_data):
            if entry["connection_id"] == conn_id:
                existing_data[i] = features
                updated = True
                break
        if not updated:
            existing_data.append(features)
        
        if features["log_count"] >= 50: # do not predicit for less than 50
            predicting_data = pd.DataFrame({
                'duration': [features['duration']],
                'ttl_average': [features['ttl_average']],
                'seq_variance': [features['seq_variance']],
                'ack_variance': [features['ack_variance']],
                'win_min': [features['win_min']],
                'win_max': [features['win_max']],
                'packet_size_min': [features['packet_size_min']],
                'packet_size_max': [features['packet_size_max']],
                'size': [features['size']],
                'syn_ack_ratio': [features['syn_ack_ratio']],
                'time_between_packets_avg': [features['time_between_packets_avg']],
                'packet_rate': [features['packet_rate']],
                'inter_arrival_time_std': [features['inter_arrival_time_std']],
                'packet_size_std': [features['packet_size_std']],
                'packet_size_avg': [features['packet_size_avg']],
                'is_tcp': [features['is_tcp']],
                'is_udp': [features['is_udp']],
                'is_icmp': [features['is_icmp']],
                'is_well_known_port': [features['is_well_known_port']],
                'is_syn_flood': [features['is_syn_flood']],
                'source_ports_count': [features['source_ports_count']],
                'destination_ports_count': [features['destination_ports_count']],
                'log_count': [features['log_count']],
                'zero_flgs': [features['zero_flgs']],
                'more_than_2_flags': [features['more_than_2_flags']],
                'F': [features['F']],
                'S': [features['S']],
                'R': [features['R']],
                'P': [features['P']],
                'A': [features['A']],
                'U': [features['U']],
                'E': [features['E']],
                'C': [features['C']]
                })
            
            predicting_data_scaled = scaler.transform(predicting_data)
            predictions = log_reg.predict(predicting_data_scaled)
            predicted_label = predictions[0]
            
            if encoder[predicted_label] != "Normal": #noraml
                # Run the async function
                message = f"!! ALERT !! Connection file with key < {key} > : Predicted as {encoder[predicted_label]}."
                print(message)
                asyncio.run(send_message_to_group(message))
    
    # Save updated data to connections.json
    with open(connections_json_path, "w", encoding="utf-8") as file:
        for entry in existing_data:
            file.write(json.dumps(entry) + "\n")

def process_logs(input_file):
    last_log_count, log_entries = count_logs(input_file)
    mapping = load_mapping(mapping_file)
    
    while True:
        time.sleep(2)
        current_log_count, log_entries = count_logs(input_file)
        
        if current_log_count > last_log_count:
            print(f"New logs detected: Processing {current_log_count - last_log_count} new entries...")
            
            new_logs = log_entries[last_log_count:]
            if new_logs:
                for log in new_logs:
                    parsed_log = parse_log(log)
                    if parsed_log:
                        key = get_connection_key(parsed_log)
                        if key in mapping:
                            conn_id = mapping[key]
                        else:
                            conn_id = str(uuid.uuid4())
                            mapping[key] = conn_id
                            save_mapping(mapping_file, mapping)
                        
                        conn_file = os.path.join(connections_folder, f'{conn_id}.json')
                        with open(conn_file, 'a', encoding='utf-8') as outfile:
                            outfile.write(json.dumps(parsed_log) + "\n")
                            
                update_connections_json(connections_folder, mapping)
                
            last_log_count = current_log_count
        else:
            print("No new logs detected.")

process_logs('alerts.log')
