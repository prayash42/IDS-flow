import schedule
import time
import pandas as pd
from capture.capture_packets import capture_packets
from extract.extract_features import extract_all_features
from model.predict import load_model, make_predictions
from sklearn.preprocessing import MinMaxScale

def preprocess_features(features):
    # Convert the features list of dicts into a DataFrame
    df = pd.DataFrame(features)

    # Preprocess the DataFrame
    # Convert 'Timestamp' column to datetime
    if 'Timestamp' in df.columns:
        df['Timestamp'] = pd.to_datetime(df['Timestamp'], format='%d/%m/%Y %H:%M:%S', errors='coerce')

    # Print descriptive statistics for each numeric column
    for column in df.columns:
        if df[column].dtype in [np.int64, np.float64]:
            print(f"Descriptive statistics for column '{column}':\n")
            print(df[column].describe())
    
    # Normalize numeric columns
    numeric_columns = df.select_dtypes(include=[np.int64, np.float64]).columns
    if len(numeric_columns) > 0:
        scaler = MinMaxScaler()
        df[numeric_columns] = scaler.fit_transform(df[numeric_columns])
    
    # Drop the 'Timestamp' column if it's not needed
    if 'Timestamp' in df.columns:
        df = df.drop(columns=['Timestamp'])

    # Convert the DataFrame back to a list of dictionaries
    return df.to_dict(orient='records')

def job():
    print("Starting scheduled job...")
    packets = capture_packets()
    features = extract_all_features(packets)
    
    # Preprocess the features
    preprocessed_features = preprocess_features(features)
    
    model = load_model()
    predictions = make_predictions(preprocessed_features, model)
    print("Predictions:", predictions)

def schedule_scans(interval_minutes=2):
    print("Scheduling scans...")
    schedule.every(interval_minutes).minutes.do(job)
    while True:
        schedule.run_pending()
        time.sleep(1)
