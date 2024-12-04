import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report
import tensorflow as tf
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense, Dropout
from tensorflow.keras.optimizers import Adam

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

# Load normal and intrusion CAN ID data
normal_can_data = load_can_ids_from_file('NORMAL_IDS.txt')  # File containing normal CAN IDs
intrusion_can_data = load_can_ids_from_file('DOS_IDS.txt')  # File containing intrusion CAN IDs

# Create dataset
X, y = create_dataset(normal_can_data, intrusion_can_data)

# Split into train and test sets
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Normalize the features (CAN IDs in range 0-255, so normalization is optional but can help)
scaler = StandardScaler()
X_train = scaler.fit_transform(X_train)
X_test = scaler.transform(X_test)

# Define a simple neural network model
model = Sequential([
    Dense(128, input_dim=X_train.shape[1], activation='relu'),
    Dropout(0.2),
    Dense(64, activation='relu'),
    Dropout(0.2),
    Dense(1, activation='sigmoid')  # Binary output (normal or intrusion)
])

# Compile the model
model.compile(optimizer=Adam(learning_rate=0.001), loss='binary_crossentropy', metrics=['accuracy'])

# Train the model
history = model.fit(X_train, y_train, epochs=5, batch_size=32, validation_data=(X_test, y_test))

# Evaluate the model
y_pred = (model.predict(X_test) > 0.5).astype("int32")  # Convert probabilities to binary predictions

# Print classification report
print(classification_report(y_test, y_pred))

# Save the model for future use
model.save('can_intrusion_detection_model.h5')

# Optionally, you can load the model later with:
# model = tf.keras.models.load_model('can_intrusion_detection_model.h5')





 # Assuming NORMAL_IDS.txt contains one CAN ID per line
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

# Example usage
file_path = 'NORMAL_IDS.txt'
can_ids = read_can_data(file_path)  # Read and process CAN IDs
input_data = create_windows(can_ids, window_size=64)  # Create windows of size 64

# Optionally, print a few windows
for window in input_data[:5]:
    print(window)



intrusion=0
normal = 0

# Example usage
file_path = 'NORMAL_IDS.txt'
can_ids = read_can_data(file_path)  # Read and process CAN IDs
input_data = create_windows(can_ids[44000:], window_size=64)  # Create windows of size 64

# Optionally, print a few windows
for window in input_data[:5]:
    print(window)

for i in range(0,100):
   #print("Get a prediciton")
    window = input_data[i]  # Get the first window (replace with the desired window)
    processed_window = preprocess_window(window)  # Preprocess it

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


