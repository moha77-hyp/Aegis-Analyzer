import streamlit as st
import os
import tempfile
import gc
from core.pe_extractor import PEExtractor
from core.yara_engine import YaraEngine
from core.ml_predictor import MLPredictor

st.set_page_config(page_title="Aegis Malware Analyzer", page_icon="🛡️", layout="wide")

st.title("🛡️ Aegis Static Malware Analyzer")
st.markdown("---")

uploaded_file = st.file_uploader("Upload a file for analysis (EXE, DLL, etc....)", type=None)

if uploaded_file is not None:
    # حفظ الملف بشكل آمن جداً في الذاكرة المؤقتة للويندوز
    with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as tmp_file:
        tmp_file.write(uploaded_file.getbuffer())
        file_path = tmp_file.name

    st.success(f"File uploaded: {uploaded_file.name}")

    col1, col2 = st.columns(2)

    # --- PE Extractor ---
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
            st.error(f"PE Engine Error: {e}")

    # --- YARA and AI ---
    with col2:
        st.header("🐕 YARA Signature Scan")
        try:
            current_dir = os.path.dirname(os.path.abspath(__file__))
            absolute_rules_dir = os.path.join(current_dir, "rules")
            
            yara_scanner = YaraEngine(rules_dir=absolute_rules_dir)
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

        st.header("🤖 AI Decision Engine")
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
                st.error(f"🚨 AI VERDICT: MALICIOUS ({prediction['malware_probability']}%)")
            else:
                st.success(f"✅ AI VERDICT: SAFE ({prediction['safe_probability']}%)")

            st.progress(prediction['malware_probability'] / 100)

        except Exception as e:
            st.error(f"AI Engine Error: {e}")

    # --- تنظيف آمن بعد انتهاء الفحص ---
    try:
        del analyzer
        gc.collect()
        if os.path.exists(file_path):
            os.remove(file_path)
    except Exception:
        pass