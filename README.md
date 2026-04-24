Aegis - Static Malware Analyzer
I built this tool to help with fast triage for Windows PE files. The main idea behind Aegis is to analyze suspicious files safely without any risk to the host machine.

To make it very secure, I designed the analyzer to be "memory-resident". This means when you upload a file, it goes directly to the byte buffer and the code never write it to the hard drive. This prevents any accidental execution of the malware during analysis.

How it works?
The project is divided into few core modules that work together:

PE Parser (pe_extractor.py): This part read the PE header from the memory directly. I made it extract more than 15 features like section entropy and raw/virtual size to find if the file is packed or not.

YARA Scanner: I used yara-python to check the file against known signatures. It's very fast because it scan the raw bytes in the RAM.

ML Prediction: There is a Random Forest model inside ml_predictor.py. It looks at the features from the PE parser to flag any strange things that don't match standard signatures (Zero-days).

IoC & Behavior: The tool also look for suspicious Windows APIs like VirtualAllocEx and try to map them to MITRE ATT&CK tactics. Also it uses Regex to find IPs and URLs hidden in the strings.

Instaltion & Setup
Requirements:
You need Python 3.8 and some libaries: pefile, yara-python, scikit-learn, streamlit.

Steps:
Clone the repo:
git clone https://github.com/moha77-hyp/Aegis-Analyzer.git

Install the requirements:
pip install -r requirements.txt

Train the PoC model:
python train_model.py
(Note: right now it uses synthetic data just to show how the pipeline works).

Run the dashboard:
streamlit run app.py

My "Verdict" Logic
The system decide if the file is dangerous using this flow:

If YARA find a match -> It's a Malware.

If YARA is clean but the ML model probability is high -> It's suspicious (Heuristics).

Anything else -> Safe.

Current Problems & To-Do list
Since this is a Proof of Concept for my graduation/evaluation, there are some limits:

The Dataset: The Random Forest is trained on fake data for now. I need to retrain it on a real dataset like EMBER later.

YARA Rules: I only put basic rules (EICAR) for testing. You need to add real threat intel rules to use it for real hunting.

Static only: This tool can't see what the malware does when it runs (Dynamic analysis). It only looks at the code and headers.

Disclaimer: This is for educational use only! Always use a Virtual Machine when dealing with malware.