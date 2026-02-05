# AI-Based Network Intrusion Detection System (Group 35)

## 1. Project Overview
This project (BayesianGuard) is a simple, real-time network security tool designed to detect and classify network anomalies. It utilizes a Hybrid Architecture combining a Gaussian Naive Bayes classifier for probabilistic prediction and Heuristic Logic for specific threat categorization (DoS, Reconnaissance, Data Exfiltration). The system is deployed via a Streamlit web interface for accessible forensic analysis.

## 2. System Requirements
To run the system efficiently, the host machine must meet the following specifications:
- OS: Windows 10/11, macOS, or Linux.
- Python: Version 3.11+ (Strict Requirement).
   - Note: While older versions (3.9/3.10) may function, the system utilizes performance optimizations specific to Python 3.11. Compatibility with older versions is not guaranteed.
- Dependencies: streamlit, pandas, scikit-learn, plotly, joblib, numpy.
- Files must include trained model files (ids_model.pkl, scaler.pkl, encoders.pkl) in the root directory.

## 3. Installation & Setup
**Step 1**: Clone the repo:
```bash
git clone [https://github.com/Lwrencee/IDS-w-Bayes-GROUP-35-.git](https://github.com/Lwrencee/IDS-w-Bayes-GROUP-35-.git)
```


**Step 2**: Install Dependencies. Ensure you are in the project root directory, then run:
```
pip install -r requirements.txt
```


**Step 3**: Generate Model Files (Critical) The system requires three specific .pkl files to function. If these are missing from your directory (or if you wish to retrain the model from scratch), simply run the training script:
```
python model_train.py
```
This script reads the raw data from the KDD/ folder and compiles ids_model.pkl, scaler.pkl, and encoders.pkl.


**Step 4**: Generate Test Data (Optional) If you do not have ready-made CSV logs to test the dashboard, you can generate standardized test files using the included utility script:
```
python create_input_data.py
```
This will create three distinct CSV files in the test_inputs/ folder (test_mixed.csv, test_attacks_only.csv, test_normal_only.csv) for immediate use.


**Step 5**: Launch the application:
```
streamlit run app.py
```

## 4. User Guide (Dashboard Navigation)
**1. Upload & Scan**
* Launch the app and drag-and-drop your network log (**CSV**) into the upload box.
* The system automatically validates the file structure and switches to the Analysis Dashboard.

**2. Dashboard Analysis**
* **Risk Assessment:** Instantly flags traffic risk levels:
    * 🔴 **High Risk:** >70% Malicious
    * 🟠 **Medium Risk:** >30% Malicious
    * 🟡 **Low Risk:** <30% Malicious
    * 🟢 **Safe:** 0 Threats
* **Visual Forensics:**
    * **Scatter Plot:** Logarithmic view of traffic volume. **Red dots** indicate anomalies.
    * **Pattern Insights:** Heuristic logic explains *why* traffic was flagged (e.g., High Volume = **Exfiltration/DoS**, Low Volume = **Reconnaissance**).

**3. Reporting**
* Click **"📄 Download Scan Report"** in the sidebar to export the fully labeled dataset (including the new `Verdict` column) for further analysis.

## 6. Troubleshooting
| Error Message | Solution |
| :--- | :--- |
| **🚨 Critical Error: Model files missing** | Run `python model_train.py` to generate the required `.pkl` files. |
| **⚠️ Error: Your scaler is too old...** | Delete all `.pkl` files and re-run `python model_train.py`. |
| **Upload Error / No Data to Test** | Run `python create_input_data.py` to generate valid test CSVs in `test_inputs/`. |
| **Missing columns in input data** | Ensure your CSV matches the **NSL-KDD** schema (headers like `src_bytes`, `dst_bytes`). |
