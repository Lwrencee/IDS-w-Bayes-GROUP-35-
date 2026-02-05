import streamlit as st
import pandas as pd
import joblib
import plotly.express as px
import time

# --- PAGE CONFIGURATION ---
st.set_page_config(
    page_title="IDS with Bayes Reasoning",
    page_icon="🛡️",
    layout="wide"
)

# --- SESSION STATE INITIALIZATION ---
# This helps us toggle between "Upload Mode" and "Dashboard Mode"
if 'dashboard_data' not in st.session_state:
    st.session_state.dashboard_data = None
if 'scan_history' not in st.session_state:
    st.session_state.scan_history = []

# ADD THIS: Initialize a key for the uploader
if 'uploader_key' not in st.session_state:
    st.session_state.uploader_key = 0


# --- LOAD TOOLS ---
@st.cache_resource
def load_tools():
    try:
        loaded_model = joblib.load('ids_model.pkl')
        loaded_scaler = joblib.load('scaler.pkl')
        loaded_encoders = joblib.load('encoders.pkl')
        return loaded_model, loaded_scaler, loaded_encoders
    except FileNotFoundError:
        return None, None, None


model, scaler, encoders = load_tools()

# --- SIDEBAR UI ---
with st.sidebar:
    # 1. New Professional Logo (Shield Icon)
    st.image("https://cdn-icons-png.flaticon.com/512/2438/2438078.png", width=100)

    st.title("IDS Using Bayes Reasoning")
    st.caption("CSC411 Project - Group 35")
    st.markdown("---")

    if st.session_state.dashboard_data is not None:
        # 2. Action Menu (Only shows if data is loaded)
        # order of columns in downloaded file
        desired_order = ['protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes', 'Verdict']

        # Check if 'Verdict' exists (it's added after processing)
        if 'Verdict' in st.session_state.dashboard_data.columns:
            # Filter the dataframe to only these columns
            download_df = st.session_state.dashboard_data[desired_order]

            # Convert filtered data to CSV
            csv = download_df.to_csv(index=False).encode('utf-8')

            st.download_button(
                label="📄 Download Scan Report",
                data=csv,
                file_name=f"scan_report_for_{st.session_state.current_filename}",
                mime="text/csv",
                use_container_width=True
            )

        st.markdown("---")

    # 3. History Section (Placeholder for "Previous Reports")
    with st.expander("🕒 Scan History"):
        if not st.session_state.scan_history:
            st.info("No recent scans.")
        else:
            for scan in st.session_state.scan_history:
                st.text(f"• {scan}")

    # 4. About Section
    with st.expander("ℹ️ About System"):
        st.write("""
        **BayesianGuard** employs a **Gaussian Naive Bayes classifier** to evaluate network traffic patterns 
        in real-time. By analyzing key behavioral features—such as protocol type, service duration, and byte 
        volume—the system calculates the probabilistic likelihood of malicious activity. This statistical 
        approach allows for rapid anomaly detection with high computational efficiency, suitable for live 
        network monitoring.
        """)

    st.markdown("---")
    st.caption("v1.0.0 | System Status: **ONLINE** 🟢")

# --- MAIN CONTENT LOGIC ---

# CHECK MODEL STATUS
if model is None:
    st.error("🚨 Critical Error: Model files missing. Please run 'model_train.py' first.")
    st.stop()

# LOGIC: If no data is loaded, show the Uploader. If data is loaded, show Dashboard.
if st.session_state.dashboard_data is None:
    # --- UPLOAD MODE ---

    # Centered Header
    st.markdown("""
            <div style='text-align: center; margin-top: 5px;'>
                <h1 style='font-size: 3rem;'>🛡️ BayesianGuard</h1>
                <p style='font-size: 1.5rem; opacity: 1.9;'>Monitors network traffic and detects potential 
                intrusions.</p>
            </div>
            <style>
                .stApp {
                    background-image: linear-gradient(to top left, #000000, #0047AB);
                    background-attachment: fixed;
                    background-size: cover;
                }
                
                header[data-testid="stHeader"] {
                    background-color: transparent;
                }
                
                header[data-testid="stHeader"] * {
                    color: white !important;
                }
                
                [data-testid="stSidebarCollapsedControl"] {
                    color: white !important;
                }
            </style>
    """, unsafe_allow_html=True)

    # Vertical Spacer (pushes the content down slightly)
    st.markdown("<br>", unsafe_allow_html=True)

    # 2. CENTERED UPLOADER BOX
    # We use columns [1, 2, 1] to create empty space on left/right
    col1, col2, col3 = st.columns([1, 2, 1])

    with col2:
        uploaded_file = st.file_uploader(
            "📂 Drag & Drop Network Log (CSV)",
            type="csv",
            # 👇 THIS IS THE NEW PART
            key=f"uploader_{st.session_state.uploader_key}"
        )

    # 3. PROCESSING LOGIC
    if uploaded_file is not None:
        with st.spinner('🔄 Analyzing Network Traffic...'):
            time.sleep(3)  # Simulate processing for effect

            try:
                # Read Data
                df = pd.read_csv(uploaded_file)

                # Save to Session State (This switches the View to Dashboard)
                st.session_state.dashboard_data = df
                st.session_state.current_filename = uploaded_file.name

                # Add to history
                timestamp = time.strftime("%H:%M:%S")
                st.session_state.scan_history.append(f"Scan at {timestamp}")

                # Rerun to refresh page
                st.rerun()
            except Exception as e:
                st.error(f"Error reading file: {e}")

else:
    # --- DASHBOARD MODE ---

    # 1. Top Navigation
    c1, c2 = st.columns([1, 6])
    with c1:
        if st.button("⬅️ New Scan"):
            st.session_state.dashboard_data = None
            st.session_state.uploader_key += 1
            st.rerun()
    with c2:
        st.title("📊 Analysis Results")
        if 'current_filename' in st.session_state:
            st.caption(f"Source File: **{st.session_state.current_filename}**")

    # Load data from state
    input_df = st.session_state.dashboard_data

    if input_df is None:
        st.stop()  # This halts the script if data is missing.
    # --------------------------------------

    # 2. PREPROCESS & PREDICT
    processed_df = input_df.copy()

    drop_cols = ['difficulty_level', 'num_outbound_cmds', 'attack_type']
    processed_df = processed_df.drop([c for c in drop_cols if c in processed_df.columns], axis=1)

    categorical_cols = ['protocol_type', 'service', 'flag']
    for col in categorical_cols:
        if col in processed_df.columns:
            # Check if we have the encoder for this column
            if col in encoders:
                le = encoders[col]
                # Handle unknown labels (like we discussed earlier)
                processed_df[col] = processed_df[col].apply(lambda x: x if x in le.classes_ else le.classes_[0])
                processed_df[col] = le.transform(processed_df[col])
            else:
                st.error(f"Error: No encoder found for column '{col}'.")
                st.stop()

    try:
        expected_order = scaler.feature_names_in_
    except AttributeError:
        st.error("⚠️ Error: Your scaler is too old or wasn't fitted with column names.")
        st.stop()

        # 2. Check if we are missing any columns
    missing_cols = set(expected_order) - set(processed_df.columns)
    if missing_cols:
        st.error(f"🚨 Missing columns in input data: {missing_cols}")
        st.stop()

    processed_df = processed_df[expected_order]

    input_scaled = scaler.transform(processed_df)
    prediction = model.predict(input_scaled)

    results = ["Malicious" if p == 'attack' else "Normal" for p in prediction]
    input_df['Verdict'] = results

    # 3. METRICS ROW
    total_packets = len(input_df)
    total_attacks = results.count("Malicious")
    total_normal = results.count("Normal")

    m1, m2, m3 = st.columns(3)
    m1.metric("Total Packets Scanned", total_packets, delta="100% Complete", delta_color="blue")

    # defining color and risk level based on percentage of attacks
    if (int(total_attacks) / int(total_packets)) * 100 > 70:
        risk_level = 'High Risk'
        risk_color = 'red'
    elif (int(total_attacks) / int(total_packets)) * 100 > 30:
        risk_level = 'Medium Risk'
        risk_color = 'orange'
    else:
        risk_level = 'Low Risk'
        risk_color = 'yellow'
    m2.metric("Threats Detected", total_attacks, delta=risk_level if total_attacks > 0 else "Safe",
              delta_color=risk_color if total_attacks > 0 else "green")

    m3.metric("Normal Traffic", total_normal)

    st.divider()

    # 4. VISUALIZATION AREA
    col_left, col_right = st.columns([2, 1])

    with col_left:
        st.subheader("📝 Traffic Log Details")

        display_cols = ['protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes', 'Verdict']

        final_view = input_df[[c for c in display_cols if c in input_df.columns]]
        final_view.index = final_view.index + 1  # stops index from start at 0

        column_mapping = {
            'protocol_type': 'Protocol',
            'service': 'Service',
            'flag': 'Status Flag',
            'src_bytes': 'Bytes Sent',
            'dst_bytes': 'Bytes Received'
        }
        final_view = final_view.rename(columns=column_mapping)

        # Helper to color rows
        def highlight_threat(val):
            color = '#ff4b4b' if val == 'Malicious' else '#28a745'
            return f'background-color: {color}; color: white; font-weight: bold'

        st.dataframe(
            final_view.style.map(highlight_threat, subset=['Verdict']),
            use_container_width=True,
            height=400
        )

        st.divider()
        st.subheader("📈 Traffic Pattern Analysis")

        if 'src_bytes' in input_df.columns and 'dst_bytes' in input_df.columns:
            # Create a copy for plotting to avoid messing up the main data
            plot_df = input_df.copy()
            # Add 1 to values to avoid log(0) errors
            plot_df['src_bytes'] = plot_df['src_bytes'] + 1
            plot_df['dst_bytes'] = plot_df['dst_bytes'] + 1

            fig_scatter = px.scatter(
                plot_df,
                x='src_bytes',
                y='dst_bytes',
                color='Verdict',
                # Green for Normal, Red for Malicious
                color_discrete_map={'Normal': '#28a745', 'Malicious': '#ff4b4b'},
                hover_data=['service', 'protocol_type'],
                log_x=True,
                log_y=True,
                title="Bytes Received vs. Sent (Log Scale)"
            )

            # change text on axis
            fig_scatter.update_yaxes(
                title_text="Destination Bytes"
            )

            fig_scatter.update_xaxes(
                title_text="Source Bytes"
            )

            # Remove margins so it fits snugly
            fig_scatter.update_layout(margin=dict(l=0, r=0, t=30, b=0), height=350)
            st.plotly_chart(fig_scatter, use_container_width=True)

            # 3. 🧠 DYNAMIC INTERPRETATION LOGIC
            malicious_traffic = input_df[input_df['Verdict'] == 'Malicious']

            st.markdown("### 🔍 Pattern Insight")

            if malicious_traffic.empty:
                st.success(
                    "**Analysis:** Traffic patterns appear normal. "
                    "The ratio of bytes sent vs. received falls within expected baselines."
                )
            else:
                avg_malicious_bytes_sent = malicious_traffic['src_bytes'].mean()
                # We clarify that we are analyzing the specific SUBSET of flagged traffic
                explanation = f"##### **Analysis:** While {len(malicious_traffic)} packets were flagged as " \
                              f"anomalous, the specific data patterns suggest:\n\n"

                if avg_malicious_bytes_sent > 10000:
                    explanation += (
                        "🔴 **High Volume Outbound:** The average connection size (i.e., average source bytes) "
                        "of the malicious packets is notably large. This is a strong indicator of "
                        "**Data Exfiltration** or a **Volumetric DoS Attack**."
                    )
                elif avg_malicious_bytes_sent < 100:
                    explanation += (
                        "🟠 **Low Volume / Headers Only:** The average connection size (i.e., average source bytes) "
                        "of the malicious packets is very small. This typically indicates **Reconnaissance** "
                        "(Port Scanning) or **Botnet 'Heartbeats'**."
                    )
                else:
                    # 👇 UPDATED: Softened language for the "Middle Ground"
                    explanation += (
                        "🟡 **Medium Volume / Irregular Structure:** The connection size (i.e., average source bytes) "
                        "of the malicious packets falls in the mid-range. While this can indicate "
                        "**Exploit Attempts**, it is also commonly caused by **Network Misconfigurations**, "
                        "**Policy Violations**, or **Corrupted Packets** that deviate from the standard protocol.")

                st.warning(explanation)
                st.divider()

            # 👇 NEW: IMPROVED "HOW TO READ" SECTION
            with st.expander("ℹ️ How to interpret this graph"):
                st.markdown("""
                            * **X-Axis (Source Bytes):** Represents data sent **OUT** from the computer.
                            * **Y-Axis (Destination Bytes):** Represents data received **IN**.
                            * **The Diagonal:** Normal web browsing usually follows a diagonal pattern 
                            (Request $\leftrightarrow$ Response).
                            * **Bottom-Right Corner:** High risk area. Sending large data (High X) but receiving 
                            little (Low Y) can indicate **Malware uploading data**.
                            * **Top-Left Corner:** Usually safe. Receiving large files (High Y) with small requests 
                            (Low X), typical of **Downloads/Streaming**.
                            """)

    with col_right:
        st.subheader("🚨 Threat Distribution")

        # --- 1. PIE CHART SECTION ---
        if total_attacks > 0:
            # Donut Chart
            fig = px.pie(
                values=[total_normal, total_attacks],
                names=['Normal', 'Malicious'],
                color=['Normal', 'Malicious'],
                color_discrete_map={'Normal': '#28a745', 'Malicious': '#ff4b4b'},
                hole=0.5
            )

            # 👇 THIS CONTROLS THE TEXT INSIDE THE SLICE
            fig.update_traces(
                textinfo='percent',  # Show percentage
                textfont_size=14,
                textfont_color='white',  # 🎨 FORCE TEXT TO WHITE
                marker=dict(line=dict(color='#000000', width=2))  # Add thin black border
            )

            fig.update_layout(showlegend=False, margin=dict(t=0, b=0, l=0, r=0))
            st.plotly_chart(fig, use_container_width=True)

            st.error(f"⚠️ **ACTION REQUIRED**\n\n{total_attacks} Malicious packets detected in this batch.")
        else:
            # All Clear Chart
            fig = px.pie(
                values=[1],
                names=['Normal'],
                color=['Normal'],
                color_discrete_map={'Normal': '#28a745'},
                hole=0.5
            )
            fig.update_layout(showlegend=False, margin=dict(t=0, b=0, l=0, r=0))
            st.plotly_chart(fig, use_container_width=True)

            st.success("✅ **SYSTEM SECURE**\n\nNo threats detected.")

        # --- 2. NEW GLOSSARY SECTION ---
        st.divider()

        # We use an expander to keep the UI clean
        with st.expander("📖 Quick Reference Guide", expanded=False):
            st.markdown("""
            #### 🔌 Protocols
            * **TCP:** Reliable connection (Web, Email).
            * **UDP:** Fast, connectionless (Streaming, DNS).
            * **ICMP:** Diagnostics (Ping, Traceroute).

            #### 🚩 Status Flags
            * **SF:** Normal, successful connection.
            * **S0:** Connection attempted, no reply (e.g., Scanning).
            * **REJ:** Connection rejected/blocked.
            * **RSTR:** Connection established then reset.
            """)
