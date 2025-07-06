from flask import Flask, render_template, request, jsonify
import pandas as pd
import numpy as np
import joblib
import os

# Define file paths (no label encoder)
model_path = 'svm_model.pkl'
scaler_path = 'scaler.pkl'

app = Flask(__name__)

# Load the model and preprocessing objects
model = joblib.load(model_path)
scaler = joblib.load(scaler_path)

# Required features for the model in correct order (updated to match training data)
REQUIRED_FEATURES = [
    'duration', 'ttl_average', 'seq_variance', 'ack_variance', 'win_min', 'win_max',
    'packet_size_min', 'packet_size_max', 'size', 'syn_ack_ratio', 'time_between_packets_avg',
    'packet_rate', 'inter_arrival_time_std', 'packet_size_std', 'packet_size_avg',
    'is_tcp', 'is_udp', 'is_icmp', 'is_private_ip', 'is_syn_flood',
    'source_ports_count', 'destination_ports_count', 'log_count', 'zero_flgs',
    'more_than_2_flags', 'F', 'S', 'R', 'P', 'A', 'U', 'E', 'C'
]

# Label mapping
LABEL_MAP = {
    0: 'DoS',
    1: 'MetarPretar',
    2: 'Normal',
    3: 'PortScanning'
}

def extract_features(raw_data):
    """Extract required features from raw log data"""
    # Initialize features dictionary
    features = {}
    
    # Direct mapping features
    for feature in REQUIRED_FEATURES:
        if feature in raw_data:
            features[feature] = raw_data[feature]
        else:
            # Handle missing features
            if feature == 'is_private_ip' and 'source_ip' in raw_data:
                # Calculate is_private_ip based on source_ip
                ip = raw_data['source_ip']
                is_private = (
                    ip.startswith('10.') or
                    ip.startswith('172.16.') or
                    ip.startswith('192.168.')
                )
                features[feature] = 1 if is_private else 0
            else:
                features[feature] = 0  # Default value for missing features
    
    return features

def process_log_entries(log_entries):
    """Process multiple log entries and return predictions"""
    results = []
    
    for entry in log_entries:
        # Extract features from raw data
        features = extract_features(entry)
        
        # Skip entries with insufficient log count
        if features['log_count'] < 50:
            results.append({
                'connection_id': entry.get('connection_id', 'unknown'),
                'status': 'skipped',
                'message': 'Insufficient log count (minimum 50 required)',
                'source_ip': entry.get('source_ip', 'unknown'),
                'destination_ip': entry.get('destination_ip', 'unknown'),
                'log_count': features['log_count']
            })
            continue
            
        # Create DataFrame with features in correct order
        df = pd.DataFrame({feature: [features[feature]] for feature in REQUIRED_FEATURES})
        
        # Scale the features
        scaled_features = scaler.transform(df)
        
        # Make prediction
        prediction = model.predict(scaled_features)
        
        # Get prediction probability if available
        probabilities = model.predict_proba(scaled_features)[0] if hasattr(model, 'predict_proba') else None
        
        result = {
            'connection_id': entry.get('connection_id', 'unknown'),
            'status': 'success',
            'prediction': LABEL_MAP.get(prediction[0], 'Unknown'),
            'source_ip': entry.get('source_ip', 'unknown'),
            'destination_ip': entry.get('destination_ip', 'unknown'),
            'log_count': features['log_count']
        }
        
        if probabilities is not None:
            result['confidence'] = f'{np.max(probabilities) * 100:.2f}%'
            
        results.append(result)
    
    return results

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/predict', methods=['POST'])
def predict():
    try:
        # Get data from request
        data = request.get_json()
        
        # Handle both single entry and multiple entries
        log_entries = data if isinstance(data, list) else [data]
        
        # Process all log entries
        results = process_log_entries(log_entries)
        
        # If it was a single entry request, return just that result
        if not isinstance(data, list):
            if results and results[0]['status'] == 'success':
                return jsonify({
                    'status': 'success',
                    'prediction': results[0]['prediction'],
                    'confidence': results[0].get('confidence')
                })
            else:
                return jsonify({
                    'status': 'error',
                    'message': results[0].get('message', 'Processing failed')
                }), 400
        
        # For multiple entries, return all results
        return jsonify({
            'status': 'success',
            'results': results
        })
        
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 400

if __name__ == '__main__':
    app.run(debug=True) 