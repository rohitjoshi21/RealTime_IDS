import pac
import joblib
import xgboost as xgb
import pandas as pd
import tensorflow as tf
import numpy as np

selected_columns = [
    'Flow Duration', 'Total Fwd Packets', 'Total Length of Fwd Packets', 'Fwd Packet Length Max', 
    'Fwd Packet Length Min', 'Fwd Packet Length Mean', 'Bwd Packet Length Max', 'Bwd Packet Length Min', 
    'Flow Bytes/s', 'Flow Packets/s', 'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Min', 'Fwd IAT Mean', 
    'Fwd IAT Min', 'Bwd IAT Total', 'Bwd IAT Mean', 'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min', 
    'Fwd PSH Flags', 'Fwd URG Flags', 'Fwd Header Length', 'Fwd Packets/s', 'Bwd Packets/s', 
    'Min Packet Length', 'Packet Length Variance', 'FIN Flag Count', 'RST Flag Count', 'PSH Flag Count', 
    'ACK Flag Count', 'URG Flag Count', 'Down/Up Ratio', 'Init_Win_bytes_forward', 'Init_Win_bytes_backward', 
    'Active Mean', 'Active Std', 'Active Max', 'Active Min', 'Idle Std'
]

pcap_file = r'D:\Project\Automated-Intrusion-Detection-System-\packet_capture\nirajattack.pcap'
df = pac.extract_features_from_pcap(pcap_file=pcap_file)

df = pd.DataFrame(df, columns=selected_columns)
df.to_csv('test.csv', encoding='utf-8', index=False, header=True)