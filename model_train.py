import pandas as pd
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.naive_bayes import GaussianNB
from sklearn.metrics import accuracy_score, confusion_matrix
import joblib
from prettytable import PrettyTable

# 1. The 41 features + the attack label and difficulty level
columns = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
    "land", "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in",
    "num_compromised", "root_shell", "su_attempted", "num_root", "num_file_creations",
    "num_shells", "num_access_files", "num_outbound_cmds", "is_host_login",
    "is_guest_login", "count", "srv_count", "serror_rate", "srv_serror_rate",
    "rerror_rate", "srv_rerror_rate", "same_srv_rate", "diff_srv_rate",
    "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count",
    "dst_host_same_srv_rate", "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate", "dst_host_serror_rate", "dst_host_srv_serror_rate",
    "dst_host_rerror_rate", "dst_host_srv_rerror_rate", "attack_type", "difficulty_level"
]

# 2. Load the files (Ensure these .txt files are in your project folder)
train_df = pd.read_csv('KDD/KDDTrain+.txt', names=columns)
test_df = pd.read_csv('KDD/KDDTest+.txt', names=columns)

# 3. CLEAN: Simplify the Attack Labels
# We change specific attacks like "neptune" or "satan" to just "attack"
train_df['attack_type'] = train_df['attack_type'].apply(lambda x: 'normal' if x == 'normal' else 'attack')
test_df['attack_type'] = test_df['attack_type'].apply(lambda x: 'normal' if x == 'normal' else 'attack')

# 4. ENCODE: Turn Words into Numbers (The Teacher/Student Method)
# We save the encoders in a dictionary, so we can save them to a file later
encoders = {}
categorical_cols = ['protocol_type', 'service', 'flag']

for col in categorical_cols:
    le = LabelEncoder()

    # Learns from the training data (Fit) and change it (Transform)
    train_df[col] = le.fit_transform(train_df[col])

    # Uses what was learned to change the test data
    test_df[col] = le.transform(test_df[col])

    # Save the teacher for later
    encoders[col] = le

# For a table output
table = PrettyTable(categorical_cols)

# We loop through the .head() of the DataFrame and add each row to the table
for index, row in train_df[['protocol_type', 'service', 'flag']].head(5).iterrows():
    table.add_row([row['protocol_type'], row['service'], row['flag']])

# Checking for right output
print("Chunk 1 Success! Text columns are now numbers.")
print(table)

# # View the mappings to understand what they are
# print("Flag Mapping:", encoders['flag'].classes_)
# print("Service Mapping (First 10):", encoders['service'].classes_[:10])


# 5. SPLIT: Separate the Evidence (X) from the Answers (y)
# We drop the target column and the useless columns
X_train = train_df.drop(['attack_type', 'difficulty_level', 'num_outbound_cmds'], axis=1)
y_train = train_df['attack_type']

X_test = test_df.drop(['attack_type', 'difficulty_level', 'num_outbound_cmds'], axis=1)
y_test = test_df['attack_type']

# 6. SCALE: The Equalizer
# Fit on train, transform both.
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

print("\nChunk 2 Success! Data split and scaled.")

# 7. TRAIN: The Learning Phase
model = GaussianNB()
print("'\nTraining the model...")
model.fit(X_train_scaled, y_train)

# 8. TEST: The Final Exam
print("\nTesting the model...")
y_pred = model.predict(X_test_scaled)

# 9. RESULTS: The Grade
accuracy = accuracy_score(y_test, y_pred)
print(f"\n--- FINAL REPORT ---")
print(f"Model Accuracy: {accuracy:.2%}")

# 10. DETAILED BREAKDOWN (The Matrix)
cm = confusion_matrix(y_test, y_pred)

cm_table = PrettyTable()
cm_table.field_names = ["", "Predicted Attack (0)", "Predicted Normal (1)"]

# Row 1: The Truth was Attack
cm_table.add_row(["Actual Attack", cm[0][0], cm[0][1]])

# Row 2: The Truth was Normal
cm_table.add_row(["Actual Normal", cm[1][0], cm[1][1]])

print("\nConfusion Matrix:")
print(cm_table)


print("\nSaving the model and tools...")

# 11. FREEZE: Save the 'Brain' and the 'Translators'
# We need the model to predict, the scaler to squash numbers,
# and the encoders to translate "TCP" to "1".
joblib.dump(model, 'ids_model.pkl')
joblib.dump(scaler, 'scaler.pkl')
joblib.dump(encoders, 'encoders.pkl')

print("Success! Files saved: 'ids_model.pkl', 'scaler.pkl', 'encoders.pkl'")
