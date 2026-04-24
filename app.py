import streamlit as st
import pandas as pd
import plotly.express as px

from core.pe_extractor import PEExtractor
from core.yara_engine import YaraEngine
from core.ml_predictor import MLPredictor
from core.strings_engine import StringsEngine

st.set_page_config(
    page_title="Aegis Anlyzer",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

st.markdown("""
    <style>
    .verdict-safe { background-color: #1e4620; padding: 20px; border-radius: 10px; color: #a5d6a7; text-align: center;}
    .verdict-malware { background-color: #4a1414; padding: 20px; border-radius: 10px; color: #ffab91; text-align: center;}
    .verdict-critical { background-color: #ff0000; padding: 20px; border-radius: 10px; color: white; text-align: center; font-weight: bold; font-size: 24px;}
    </style>
""", unsafe_allow_html=True)

@st.cache_resource
def load_ml_predictor():
    ###Loading the ML predictor and caches it in the memory.
    return MLPredictor()

@st.cache_resource
def load_yara_engine():
    return YaraEngine()

ml_engine = load_ml_predictor()
yara_engine = load_yara_engine()

#the main Ui
st.title("Aegis Static Malware Analyzer")
st.markdown("Advanced pe Analysis | YARA Engine | Machine Learning | MITRE ATT&CK")

with st.sidebar:
    st.header("File Upload")
    uploaded_file = st.file_uploader("Upload an Executable (.exe, .dll)", type=['exe', 'dll', 'bin', 'txt'])
    st.info("**Memory  Rule Enforeced: Files are never written to disk. Analysis is done purely in RAM.")

if uploaded_file is not None:
    raw_bytes = uploaded_file.getbuffer().tobytes()
    file_name = uploaded_file.name

    with st.spinner(f"Analyzing {file_name} in memory...."):
        #start Engines
        pe_extractor = PEExtractor(raw_bytes)
        ml_features, ui_metadata = pe_extractor.analyze_and_extract_fearures()

        yara_results = yara_engine.scan_memory(raw_bytes)

        strings_engine = StringsEngine(raw_bytes)

        strings_engine = StringsEngine(raw_bytes)
        iocs = strings_engine.extract_icos()

        ml_prediction = {"status": "error"}
        if pe_extractor.is_valid_pe and ml_features:
            ml_prediction = ml_engine.predict(ml_features)

        #the master vedict logic
        #if yara macthes a high rule : Final verdict: critical malware.
        #else, rely on the ML probability.

        final_verdict = "SAFE"
        verdictic_class = "verdict-safe"
        probability = ml_prediction.get('malware_probability', 0.0)

        if yara_results.get('is_critical'):
            final_verdict = "Critical MAlware (Yara Match)"
            verdictic_class = "verdict-malware"

        st.markdown(f'<div class="{verdictic_class}"><h2>VERDICT: {final_verdict}</h2></div><br>', unsafe_allow_html=True)

        tab1, tab2, tab3, tab4, = st.tabs(["OverVeiw & Mitre", "ML Features", "🧬 YARA Result", "Extracted IoCs"])

        with tab1:
            st.subheader("File Fingerprint")
            if "error" in ui_metadata:
                st.warning(ui_metadata["error"])
            else:
                col1, col2 = st.columns(2)
                col1.metric("MD5", ui_metadata['hashes']['MD5'])
                col2.metric("SHA256", ui_metadata['hashes']['SHA256'])

                st.markdown("---")
                col3, col4 = st.columns(2)

                with col3:
                    st.subheader("Threat Intel metadata")
                    st.write(f"*is packed Heuristic: {ui_metadata['is_packed']}")
                    if ui_metadata.get('detected_packers'):
                        st.write(f"**Detected Packers:** {', '.join(ui_metadata['detected_packers'])}")

                    if ml_prediction.get('status') == 'succes':
                        st.metric("ML Malware Probability", f"{probability}%")

                with col4:
                    st.subheader("MITRE ATT&CK Map")
                    if ui_metadata.get('mitre_hits'):
                        for tactic, apis in ui_metadata.get('mitre_hits', {}).items():
                            with st.expander(f"🚩 {tactic}"):
                                st.write(apis)
                    else:
                        st.success("No suspicious APIs mapped to MITRE ATT&CK.")

                with tab2:
                    st.subheader("Machine Learning Vector")
                    if not pe_extractor.is_valid_pe:
                        st.error("Cannot display ML features. File is not a valid PE.")
                    elif ml_features:
                        df_features = pd.DataFrame([ml_features]).T.reset_index()
                        df_features.columns = ['Feature Name', 'Value']
                    
                        col_a, col_b = st.columns([1, 2])
                        with col_a:
                            st.dataframe(df_features, width='stretch')
                        with col_b:
                            fig = px.bar(df_features.head(7), x='Feature Name', y='Value', title="Structural Features Overview")
                            st.plotly_chart(fig, width='stretch')
                        
                        with tab4:
                            st.subheader("Actionable Indicators of Compromise (IoCs)")
                            col_x, col_y = st.columns(2)
            
                            with col_x:
                                st.write("**IPv4 Addresses**")
                                st.code("\n".join(iocs.get('IPv4', [])) if iocs.get('IPv4') else "None found")
                
                                st.write("**URLs**")
                                st.code("\n".join(iocs.get('URLs', [])) if iocs.get('URLs') else "None found")
                
                            with col_y:
                                st.write("**Registry Keys**")
                                st.code("\n".join(iocs.get('Registry_Keys', [])) if iocs.get('Registry_Keys') else "None found")
                
                                st.write("**Possible Crypto Wallets**")
                                st.code("\n".join(iocs.get('Bitcoin_Wallets', [])) if iocs.get('Bitcoin_Wallets') else "None found")

else:
    st.info("Awating file upload...")