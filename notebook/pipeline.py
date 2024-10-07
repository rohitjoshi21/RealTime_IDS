import pandas as pd
import joblib
import os
import time

# Load the trained model
model = joblib.load('rf_model.joblib')

# Define the folder to monitor
folder_path = 'packetcsvs'

# Keep track of visited files
visited_files = set()

df = pd.read_csv("dataset.csv")
df2 = pd.read_csv('output.csv')

to_infer = df2.columns.values
trained = df.columns.values

merged = intersect(to_infer, trained)

def intersect(col1, col2):
  result = [value for value in col1 if value in col2]
  return result

def attacked(attackType):
  print(f"YOU ARE ATTACKED  with {attackType} !!! BE ALERT !!!")


# Function to format DataFrame and predict
def process_file(file_path):
    print(f"Processing {file_path}")
    try:
        df = pd.read_csv(file_path)
        # Keep only the columns that are common between df2 (output.csv) and df (dataset.csv)
        df_formatted = df[merged]

        # Make predictions
        y_pred = model.predict(df_formatted)
        
        # Check predictions
        for prediction in y_pred:
            if prediction != 0:
                attacked(prediction)
                return True
    except Exception as e:
        print(f"Error processing {file_path}: {e}")


while True:
    # Get list of CSV files in the folder
    files_in_folder = [f for f in os.listdir(folder_path) if f.endswith('.csv')]

    # Process new files
    for file_name in files_in_folder:
        if file_name not in visited_files:
            file_path = os.path.join(folder_path, file_name)
            attack = process_file(file_path)
            visited_files.add(file_name)
            if not attack:
                print("All good till now !!")
    # Wait for 20 seconds before checking again
    time.sleep(20)
