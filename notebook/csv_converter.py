import pandas as pd
import re
from fuzzywuzzy import process

# Install fuzzywuzzy and python-Levenshtein for better performance
# pip install fuzzywuzzy[speedup]

# Read the full dataset CSV file
input_csv = 'output.csv'
df = pd.read_csv(input_csv)

# List of required columns
required_columns = [
    'Destination Port', 'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets',
    'Total Length of Fwd Packets', 'Total Length of Bwd Packets', 'Fwd Packet Length Max',
    'Fwd Packet Length Min', 'Fwd Packet Length Mean', 'Fwd Packet Length Std',
    'Bwd Packet Length Max', 'Bwd Packet Length Min', 'Bwd Packet Length Mean',
    'Bwd Packet Length Std', 'Flow Bytes/s', 'Flow Packets/s', 'Flow IAT Mean',
    'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min', 'Fwd IAT Total', 'Fwd IAT Mean',
    'Fwd IAT Std', 'Fwd IAT Max', 'Fwd IAT Min', 'Bwd IAT Total', 'Bwd IAT Mean',
    'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min', 'Fwd PSH Flags', 'Fwd URG Flags',
    'Fwd Header Length', 'Bwd Header Length', 'Fwd Packets/s', 'Bwd Packets/s',
    'Min Packet Length', 'Max Packet Length', 'Packet Length Mean', 'Packet Length Std',
    'Packet Length Variance', 'FIN Flag Count', 'SYN Flag Count', 'RST Flag Count',
    'PSH Flag Count', 'ACK Flag Count', 'URG Flag Count', 'CWE Flag Count',
    'ECE Flag Count', 'Down/Up Ratio', 'Average Packet Size', 'Avg Fwd Segment Size',
    'Avg Bwd Segment Size', 'Fwd Header Length.1', 'Subflow Fwd Packets',
    'Subflow Fwd Bytes', 'Subflow Bwd Packets', 'Subflow Bwd Bytes',
    'Init_Win_bytes_forward', 'Init_Win_bytes_backward', 'act_data_pkt_fwd',
    'min_seg_size_forward', 'Active Mean', 'Active Std', 'Active Max', 'Active Min',
    'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min', 'Label'
]

# Normalize column names by stripping spaces and converting to lowercase
def normalize_column_name(col):
    col = re.sub(r'\s+', ' ', col.strip())  # Replace multiple spaces with single space
    return col.lower()

df.columns = [normalize_column_name(col) for col in df.columns]
normalized_required_columns = [normalize_column_name(col) for col in required_columns]

# Match columns in the dataset with required columns using fuzzy matching
def match_columns(df_cols, req_cols):
    col_mapping = {}
    for req_col in req_cols:
        match, score = process.extractOne(req_col, df_cols)
        if score >= 90:  # Set a threshold for matching similarity
            col_mapping[match] = req_col
    return col_mapping

# Get the column mapping
column_mapping = match_columns(df.columns, normalized_required_columns)

# Rename the columns in the dataframe
df = df.rename(columns=column_mapping)

# Check if all required columns are present after renaming
missing_columns = set(normalized_required_columns) - set(df.columns)

if missing_columns:
    print(f"Missing columns after renaming: {missing_columns}")
else:
    # Save the filtered dataset with the required columns
    df_filtered = df[normalized_required_columns]
    output_csv = 'filtered_dataset.csv'
