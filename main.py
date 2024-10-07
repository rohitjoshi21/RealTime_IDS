import threading
import pyshark
import pandas as pd
import subprocess
import os
import joblib
import time
from termcolor import colored  # Importing termcolor
from preprocessor import preprocess
import xgboost as xgb

MODELPATH = 'xgboost3.joblib'
CICFLOWMETERPATH = '/home/riemann/.cache/pypoetry/virtualenvs/'
NETWORKINTERFACE = 'wlp1s0'


model = joblib.load(MODELPATH)
labels = {0: "Benign", 1: "BruteForce", 2: "DDoS", 3: "DoS", 4: "Other", 5: "PortScan", 6: "WebAttack"}

# Directories for storing packets and features
packet_dir = 'packets'
feature_dir = 'features'

# Ensure directories exist
os.makedirs(packet_dir, exist_ok=True)
os.makedirs(feature_dir, exist_ok=True)

pcap_lock = threading.Lock()

# Simulated packet capture function that saves to PCAP
def capture_packet():
    print(colored("[Producer]   Starting continuous packet capturing...", "cyan"))
    while True:
        # Create a new filename with the current timestamp
        timestamp = time.strftime("%Y%m%d-%H%M%S")
        pcap_file = os.path.join(packet_dir, f'capture_{timestamp}.pcap')
        
        capture = pyshark.LiveCapture(interface=NETWORKINTERFACE, output_file=pcap_file)
        capture.sniff(timeout=5)  # Capture for 5 seconds (adjust as needed)
        
        with pcap_lock:
            print(colored("[Producer]   Packet capture completed.", "green"))

# Function to extract features using CICFlowMeter and return a dataframe
def extract_features(pcap_file):
    timestamp = time.strftime("%Y%m%d-%H%M%S")
    feature_file = os.path.join(feature_dir, f'output_{timestamp}.csv')
    
    # Activate virtual environment and run CICFlowMeter
    activate_env = 'source {CICFLOWMETERPATH}cicflowmeter-J2zf1J8o-py3.11/bin/activate && '
    cmd = f'{activate_env} cicflowmeter -f {pcap_file} -c {feature_file} &>logs.txt'

    subprocess.run(cmd, shell=True, executable='/bin/bash')  # Ensure using bash to run the command
    
    # Load the generated CSV into a dataframe
    processeddf = preprocess(feature_file)
    return processeddf, feature_file

# Inference function using the trained model
def infer_result(df):
    if df.empty:
        print(colored("[Infer]      No Attack Detected.", "yellow"))
        return
    print(colored("[Infer]      Running inference...", "cyan"))
    x_pred = xgb.DMatrix(df)
    predictions = model.predict(x_pred)
    
    if sum(predictions) == 0:
        print(colored("[Infer]      No Attack Detected.", "yellow"))
    else:
        for p in predictions:
            if p != 0:
                print(colored("[Infer]      Attack Detected.", "red"))

# Thread for reading PCAP file and inferring using the model
def pcap_reader():
    while True:
        with pcap_lock:
            # List all pcap files in the packet directory
            pcap_files = [f for f in os.listdir(packet_dir) if f.endswith('.pcap')]
            for pcap_file in pcap_files:
                pcap_path = os.path.join(packet_dir, pcap_file)
                try:
                    df, feature_file = extract_features(pcap_path)
                except:
                    print(colored("[Reader]     No packet captured or error in feature extraction!", "red"))
                    continue

                # Pass the extracted features to the model for inference
                infer_result(df)

                # Clean up the generated files after processing
                if os.path.exists(pcap_path):
                    os.remove(pcap_path)
                if os.path.exists(feature_file):
                    os.remove(feature_file)

                print(colored("[Reader]     Processing and cleanup completed.", "green"))

if __name__ == "__main__":
    # Create threads for capturing packets and reading PCAP files
    producer_thread = threading.Thread(target=capture_packet)
    reader_thread = threading.Thread(target=pcap_reader)

    # Start threads
    producer_thread.start()
    reader_thread.start()

    # Ensure threads keep running
    producer_thread.join()
    reader_thread.join()

