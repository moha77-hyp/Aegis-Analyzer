# Aegis Static Malware Analyzer

A static malware analysis pipeline and triage dashboard built with Python and Streamlit. 

The primary goal of Aegis is to perform rapid, initial triage of Windows executables (PE files) securely. To prevent accidental execution or host compromise, the analyzer is strictly memory-resident—uploaded files are read directly into byte buffers and are never written to the host filesystem.

## Architecture & Core Modules

Aegis evaluates potential threats using a hybrid approach (Deterministic + Heuristic):

1. **In-Memory PE Parser (`pe_extractor.py`)**: 
   Parses the PE header directly from the byte stream. It extracts 15+ structural features including section entropy, import/export counts, and packing heuristics (e.g., raw vs. virtual size discrepancies).
2. **YARA Scanning Engine (`yara_engine.py`)**: 
   Compiles and matches YARA rules against the raw byte buffer. Used for deterministic signature matching (e.g., identifying standard EICAR strings or specific APT signatures).
3. **Machine Learning Predictor (`ml_predictor.py`)**: 
   A Random Forest classifier that evaluates the features extracted by the PE Parser to flag zero-day or heavily obfuscated anomalies based on structural deviations.
4. **Behavioral & IoC Extraction**:
   - Maps identified suspicious Windows APIs (e.g., `VirtualAllocEx`) to MITRE ATT&CK tactics.
   - Regex-based engine to decode and extract basic Indicators of Compromise (IPv4, URLs, Registry Keys) from ASCII and UTF-16 strings.

## Installation & Triage Setup

### Prerequisites
- Python 3.8+
- Required packages: `pefile`, `yara-python`, `scikit-learn`, `pandas`, `streamlit`, `plotly`.

### Setup
1. Clone the repository:
   ```bash
   git clone [https://github.com/moha77-hyp/Aegis-Analyzer.git](https://github.com/moha77-hyp/Aegis-Analyzer.git)
   cd Aegis-Analyzer
Install dependencies:

Bash
pip install -r requirements.txt
Generate the baseline ML models:
(Note: The current repository uses a synthetic dataset generator to build the initial .pkl files for the Proof of Concept).

Bash
python train_model.py
Spin up the Streamlit dashboard:

Bash
streamlit run app.py
Verdict Logic
The system uses a fallback logic for its final verdict:

If the YARA engine triggers a 'High' severity rule match -> Critical Malware.

If YARA is clean, but the Random Forest probability exceeds the configured threshold -> Malicious (Heuristics).

Otherwise -> Safe.

Current Limitations & Future Work (TODO)
As this is currently a Proof of Concept (PoC) for my evaluation:

ML Dataset: The Random Forest model is trained on synthetic data to demonstrate the pipeline functionality. For a production environment, this needs to be retrained on a real-world dataset (e.g., EMBER dataset).

YARA Ruleset: The current rules/ directory contains basic testing rules (like EICAR). It requires integration with updated threat intel feeds (like Neo23x0/signature-base) for actual threat hunting.

Dynamic Analysis: Aegis is strictly a static analyzer. It cannot observe runtime behavior or unpack highly sophisticated multi-stage loaders dynamically.

Disclaimer
This project was developed for educational purposes and academic evaluation. Always perform malware triage in an isolated, secure environment (e.g., a disconnected virtual machine).