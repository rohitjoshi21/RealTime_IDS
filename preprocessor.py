import pandas as pd
import joblib
import os

config = [0,0,3,0,0,0,0,0,0,0,3,3,3,3,0,3,3,3,0,3,3,0,0,0,0]

def preprocess(inputcsv):

    if os.stat(inputcsv).st_size == 0:
        df = pd.DataFrame()
        return df
    else:
        df = pd.read_csv(inputcsv)

    # Dictionary mapping old column names to new ones
    column_mapping = {
        'flow_duration': 'Flow Duration',
        'tot_fwd_pkts': 'Total Fwd Packets',
        'totlen_fwd_pkts': 'Total Length of Fwd Packets',
        'fwd_pkt_len_max': 'Fwd Packet Length Max',
        'fwd_pkt_len_min': 'Fwd Packet Length Min',
        'fwd_pkt_len_mean': 'Fwd Packet Length Mean',
        'bwd_pkt_len_max': 'Bwd Packet Length Max',
        'bwd_pkt_len_min': 'Bwd Packet Length Min',
        'flow_byts_s': 'Flow Bytes/s',
        'flow_pkts_s': 'Flow Packets/s',
        'flow_iat_mean': 'Flow IAT Mean',
        'flow_iat_std': 'Flow IAT Std',
        'flow_iat_min': 'Flow IAT Min',
        'fwd_iat_mean': 'Fwd IAT Mean',
        'fwd_iat_min': 'Fwd IAT Min',
        'bwd_iat_tot': 'Bwd IAT Total',
        'bwd_iat_mean': 'Bwd IAT Mean',
        'bwd_iat_std': 'Bwd IAT Std',
        'bwd_iat_max': 'Bwd IAT Max',
        'bwd_iat_min': 'Bwd IAT Min',
        'fwd_psh_flags': 'Fwd PSH Flags',
        'fwd_urg_flags': 'Fwd URG Flags',
        'fwd_header_len': 'Fwd Header Length',
        'fwd_pkts_s': 'Fwd Packets/s',
        'bwd_pkts_s': 'Bwd Packets/s',
        'pkt_len_min': 'Min Packet Length',
        'pkt_len_var': 'Packet Length Variance',
        'fin_flag_cnt': 'FIN Flag Count',
        'rst_flag_cnt': 'RST Flag Count',
        'psh_flag_cnt': 'PSH Flag Count',
        'ack_flag_cnt': 'ACK Flag Count',
        'urg_flag_cnt': 'URG Flag Count',
        'down_up_ratio': 'Down/Up Ratio',
        'init_fwd_win_byts': 'Init_Win_bytes_forward',
        'init_bwd_win_byts': 'Init_Win_bytes_backward',
        'active_mean': 'Active Mean',
        'active_std': 'Active Std',
        'active_max': 'Active Max',
        'active_min': 'Active Min',
        'idle_std': 'Idle Std'
    }

    # Rename columns
    df.rename(columns=column_mapping, inplace=True)

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

    df = df[selected_columns]

    scaler = joblib.load("scaler.joblib")
    df = pd.DataFrame(scaler.transform(df),columns = selected_columns)
    
    return df 
