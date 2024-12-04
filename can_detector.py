import threading
import queue
import can
import numpy as np
from tensorflow.keras.models import load_model
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report
import tensorflow as tf
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense, Dropout
from tensorflow.keras.optimizers import Adam

# Load the trained model
model = load_model("can_model.h5")
print("Model loaded successfully!")
model.summary()

import joblib
# Load the fitted scaler
scaler = joblib.load("scaler.pkl")
print("Scaler loaded successfully!")

#Assuming NORMAL_IDS.txt contains one CAN ID per line
def read_can_data(file_path):
    # Read CAN IDs from the file
    with open(file_path, 'r') as file:
        can_ids = file.readlines()

    # Chop the first character from each CAN ID
    can_ids = [can_id.strip()[1:] for can_id in can_ids]  # strip() removes newline characters, [1:] removes first character
    return can_ids
# Function to preprocess the window and convert CAN IDs to numeric
def preprocess_window(window, window_size=64):
    """
    Preprocess the window data into the shape (1, window_size).
    :param window: List of CAN IDs (e.g., hexadecimal strings)
    :param window_size: The size of the sliding window (input length)
    :return: A preprocessed feature vector reshaped to (1, window_size)
    """
    # Convert hexadecimal CAN IDs (strings) to integers
    window_data = [int(can_id, 16) for can_id in window]

    # Ensure the window is fixed size
    window_data = extract_features(window_data, window_size)

    # Reshape to (1, window_size) for the model
    window_data = window_data.reshape(1, window_size)  # Reshape to (1, window_size)

    # Normalize the data (assuming scaler is already fitted)
    window_data = scaler.transform(window_data)  # Normalize using the same scaler used during training

    return window_data

def create_windows(can_ids, window_size=64):
    # Create sliding windows of data from the can_ids list
    windows = []
    for i in range(len(can_ids) - window_size + 1):
        windows.append(can_ids[i:i + window_size])
    return windows

# Function to convert a sequence of CAN IDs into a fixed-size vector
def extract_features(can_data, window_size=64):
    """
    Converts a sequence of CAN IDs into a fixed-size vector.
    :param can_data: List of CAN IDs (e.g., integers or strings)
    :param window_size: The size of the sliding window (input length)
    :return: A feature vector of length `window_size`
    """
    # Ensure that we have a fixed window size by padding the sequence if it's smaller
    # or truncating it if it's larger
    if len(can_data) < window_size:
        # Padding with 0 (assuming CAN IDs range from 0 to 255)
        can_data = [0] * (window_size - len(can_data)) + can_data
    elif len(can_data) > window_size:
        # Truncating if the sequence is longer than the window size
        can_data = can_data[:window_size]

    return np.array(can_data)
# Create a dataset of normal and intrusion data
def create_dataset(normal_can_data, intrusion_can_data, window_size=64):
    """
    Create a dataset for training.
    :param normal_can_data: List of CAN IDs for normal traffic
    :param intrusion_can_data: List of CAN IDs for intrusion traffic
    :param window_size: The size of the sliding window for feature extraction
    :return: Tuple of feature array X and label array y
    """
    features = []
    labels = []

    # Extract features for normal data
    for i in range(len(normal_can_data) - window_size + 1):
        window_data = normal_can_data[i:i+window_size]
        features.append(extract_features(window_data, window_size))
        labels.append(0)  # 0 for normal

    # Extract features for intrusion data
    for i in range(len(intrusion_can_data) - window_size + 1):
        window_data = intrusion_can_data[i:i+window_size]
        features.append(extract_features(window_data, window_size))
        labels.append(1)  # 1 for intrusion

    return np.array(features), np.array(labels)

# Function to load CAN ID data from a file and remove the first character
def load_can_ids_from_file(file_path):
    """
    Loads CAN IDs from a file, removes the first character, and returns them as a list of integers.
    :param file_path: Path to the file containing CAN IDs (one per line)
    :return: List of CAN IDs as integers
    """
    with open(file_path, 'r') as file:
        # For each line, strip it, remove the first character, and convert to integer
        can_ids = [int(line.strip()[1:], 16) for line in file.readlines() if line.strip()]
    return can_ids

# Function to listen to CAN messages and store them in the queue
def listen_to_can(channel='vcan0'):
    bus = can.interface.Bus(channel=channel, bustype='socketcan')
    print("Listening to CAN messages...")
    while True:
        message = bus.recv()  # Receive CAN message
        if message is not None:
            can_queue.put(message.arbitration_id)  # Store only the arbitration ID


def process_can_data(window_size=64):
    can_ids = []

    while True:
        try:
            # Get CAN ID from the queue
            can_id = can_queue.get(timeout=1)  # Wait for data with a timeout
            can_ids.append(can_id)

            # If we have a full window of CAN IDs, process them
            if len(can_ids) >= window_size:

                can_ids_window = can_ids[-window_size:]  # Get the last 64 IDs
                can_ids_window = [id_ & 0x7FF for id_ in can_ids_window]  # Mask to 11-bit SFF format
                 # Ensure all can_ids in the window are hexadecimal strings
                can_ids_window = [hex(can_id) if not isinstance(can_id, str) else can_id for can_id in can_ids_window]
                #print("[1] window: ")
                #print(can_ids_window)
                # Preprocess it
                processed_window = preprocess_window(can_ids_window)
                #print("[2] Input to classifier")
                #print(processed_window)
                # Make a prediction
                prediction = model.predict(processed_window)
                label = 'Intrusion' if prediction[0][0] > 0.5 else 'Normal'
                # Print the prediction
                print(f"Prediction: {label}")

        except queue.Empty:
            # If no data is received in the timeout, continue listening
            continue
       

intrusion=0
normal = 0

# Example usage
file_path = 'NORMAL_IDS.txt'
can_ids = read_can_data(file_path)  # Read and process CAN IDs
input_data = create_windows(can_ids, window_size=64)  # Create windows of size 64

# Optionally, print a few windows
for window in input_data[:5]:
    print(window)

for i in range(0,1):
   #print("Get a prediciton")
    window = input_data[i]  # Get the first window (replace with the desired window)
    print("[1] pre- preprocess:")
    print(window)
    processed_window = preprocess_window(window)  # Preprocess it
    print("[2] input to classifier") 
    print(processed_window) 
    # Get the prediction from the model
    prediction = model.predict(processed_window)
    #print(f"Prediction: {prediction}")
    # Interpret the prediction (output is between 0 and 1, where 0 means normal and 1 means intrusion)
    if prediction < 0.5:
 #       print("Prediction: Normal traffic")
        normal+=1
    else:
#        print("Prediction: Intrusion detected")
        intrusion+=1

print("normal: "+str(normal))
print("Intrusion: "+str(intrusion))

# Shared queue for CAN IDs
can_queue = queue.Queue()

# Main function to start the threads
if __name__ == '__main__':
    print("Starting CAN ID detection with threading...")

    # Create threads
    listener_thread = threading.Thread(target=listen_to_can, args=('vcan0',), daemon=True)
    processor_thread = threading.Thread(target=process_can_data, args=(64,), daemon=True)

    # Start threads
    listener_thread.start()
    processor_thread.start()

    # Keep the main thread alive
    listener_thread.join()
    processor_thread.join()
