import pandas as pd

# 1. The Headers (Labels)
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

# 2. Read the FULL Test Data (All 22,000+ rows)
df = pd.read_csv('KDD/KDDTest+.txt', names=columns)

# --- SCENARIO 1: The "Mixed Bag" (Random 50 rows) ---
# Good for general testing
mixed_df = df.sample(150)
mixed_df.to_csv('./test_inputs/test_mixed.csv', index=False)
print("Created 'test_mixed.csv' (150 random rows)")

# --- SCENARIO 2: The "Pure Attack" (Only Hackers) ---
# Useful to see if your AI catches ALL of them or misses some
attack_df = df[df['attack_type'] != 'normal'].sample(100)
attack_df.to_csv('./test_inputs/test_attacks_only.csv', index=False)
print("Created 'test_attacks_only.csv' (100 attacks)")

# --- SCENARIO 3: The "Normal Day" (Clean Traffic) ---
# Useful to check for False Alarms (Burnt Toast)
normal_df = df[df['attack_type'] == 'normal'].sample(100)
normal_df.to_csv('./test_inputs/test_normal_only.csv', index=False)
print("Created 'test_normal_only.csv' (100 normal rows)")
