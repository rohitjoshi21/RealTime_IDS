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

model = joblib.load('neural.joblib')
#pcap_file = r'D:\Project\Automated-Intrusion-Detection-System-\packet_capture\gitattack.pcapng'
scaler = joblib.load('scaler.joblib')
#df = pac.extract_features_from_pcap(pcap_file=pcap_file)

#df.to_csv("gitnew.csv")
df = pd.read_csv("normal.csv")
arr = scaler.transform(df)
df = pd.DataFrame(arr, columns=selected_columns)
#df.to_csv('test.csv', encoding='utf-8', index=False, header=True)

#x_pred = xgb.DMatrix(df)
prediction = model.predict(df)
print(list(prediction))
print(prediction.sum())
#model = tf.keras.models.load_model('new.keras')

'''def return_max(y):
  dim = y.shape[0]
  y_ret = np.zeros(shape=(dim, 7))
  for i in range(y.shape[0]):
    max = np.max(y[i])
    y_ret[i] = np.where(y[i] == max, 1, 0)
  return y_ret

prediction = model.predict(df)
prediction = return_max(prediction)
print(prediction)'''