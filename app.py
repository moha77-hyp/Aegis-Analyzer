import streamlit as st
import os
from core.pe_extractor import PEExtractor
from core.yara_engine import YaraEngine
from core.ml_predictor import MLPredictor

st.set_page_config(page_title="Aegis Malware Analyzer", page_icon="🛡️", layout="wide")

st.title("🛡️ Aegis Static Malware Analyzer")
st.markdown("---")

uploaded_file = st.file_uploader("Upload a file for analysis (EXE, DILL, etc....)", type=None)

if uploaded_file is not None:
    file_path = os.path.join("temp", uploaded_file.name)
    os.makedirs("temp", exist_ok=True)
    with open(file_path, "wb") as f:
        f.write(uploaded_file.getbuffer())

    st.success(f"File uploaded: {uploaded_file.name}")

    col1, col2 = st.columns(2)

    #PE Extractor
    with col1:
        st.header("🔍 PE Structural Analysis")
        try:
        
            analyzer = PEExtractor(file_path)
            info = analyzer.get_basic_info()

            st.subheader("Basic Info")
            st.json(info)

            st.subheader("Sections Analysis")
            sections = analyzer.analyze_sections()
            st.table(sections)

        except Exception as e:
            st.error(f"PE Engine Erroe: {e}")

#YARA and AI
    with col2:
        st.header("🐕 YARA Signature Scan")
        try:
            yara_scanner = YaraEngine(rules_dir="rules")
            yara_results = yara_scanner.scan_file(file_path)
            if yara_results:
                for res in yara_results:
                    st.warning(f"Match: {res['rule_name']} (Severity: {res['severity']})")
                    st.info(f"Description: {res['description']}")
            else:
                st.success("Clean: No Yara signature matched.")
        except Exception as e:
            st.error(f"YARA Error: {e}")

        st.markdown("---")

        st.header("AI Descition Engine")
        try:
            total_entropy = sum(s['entropy'] for s in sections) if sections else 0
            avg_entropy = total_entropy / len(sections) if sections else 0

            ml_engine = MLPredictor()
            prediction = ml_engine.predict({
                'avg_entropy': avg_entropy,
                'num_sections': info.get('number_of_sections',0),
                'num_imports': len(analyzer.get_imports()),
                'file_size': os.path.getsize(file_path)
            })

            if prediction['is_malware']:
                st.error(f"AI VERDICT: MALICIOUS ({prediction['malware_probability']}%)")
            else:
                st.success(f"✅AI VERDICT: SAFE ({prediction['safe_probability']}%)")

            st.progress(prediction['malware_probability'] / 100)

        except Exception as e:
            st.error(f"AI Engine Error: {e}")

    try:
        import gc
        gc.collect()
        os.remove(file_path)
    except PermissionError:
        pass