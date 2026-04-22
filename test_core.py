from core.pe_extractor import PEExtractor
from core.yara_engine import YaraEngine
from core.ml_predictor import MLPredictor

def run_test(file_path: str):
    print(f"[*] Analyzing Target: {file_path}")
    print("-" * 40)

    try:
        analyzer = PEExtractor(file_path)

        print("[+] Basic PE Information:")
        info = analyzer.get_basic_info()
        for key, value in info.items():
            print(f" -{key}: {value}")

        print("\n[+] Sections Analysis (Entropy & Suspicion):")
        sections = analyzer.analyze_sections()

        print(f" {'Name': <10} | {'V.Size': <10} | {'R.Size':<10} | {'Entropy':<8} | {'Status'}")
        print(" " + "-" * 55)

        for sec in sections:
            status = "SUSPICIOUS" if sec['is_suspicious'] else "✅Ok!"
            print(f" {sec['name']:<10} | {sec['virtual_size']:<10} | {sec['raw_size']:<10} | {sec['entropy']:<8} | {status}")

        print("\n[+] Imported Functions (Showing first 5 for brevity:)")
        imports = analyzer.get_imports()
        for imp in imports[:5]:
            print(f" - DLL: {imp['dll']} | Function: {imp['function']}")
        print(f" ... and {len(imports) - 5} more functions.")

    except Exception as e:
        print(f"PE Analysis Error: {e}")

    print("\n[+] YARA Signature Scan:")
    try:
        yara_scanner = YaraEngine(rules_dir="rules")
        yara_results = yara_scanner.scan_file(file_path)

        if yara_results:
            print(f"Warning: {len(yara_results)} rule(s) matched!")
            for res in yara_results:
                print(f" - Rule:{res['rule_name']} | Severity: {res['severity']}")
                print(f"  Desc: {res['description']}")
        else:
            print(" CLEAN: No malicious signature found.")

    except Exception as yara_error:
        print(f" YARA Scanner Error: {yara_error}")

    ##Machine Learning
    print("\n[+] AI Model Prediction:")
    try:
        total_entropy = sum(sec['entropy'] for sec in sections) if sections else 0
        avg_entropy = total_entropy / len(sections) if sections else 0

        fearures = {
            'avg_entropy': avg_entropy,
            'num_sections': info.get('number_of_sections', 0),
            'num_imports': len(imports) if imports else 0,
            'file_size': sum(sec['raw_size'] for sec in sections) if sections else 0
        } 

        ml_engine = MLPredictor()
        prediction = ml_engine.predict(fearures)

        if prediction['is_malware']:
            print(f" AI VERDICT: MALICIOUS({prediction['malware_probabilty']}% confidence)")
        else:
            print(f" AI VERDICT: SAFE ({prediction['safe_probability']}% confidence)")

    except Exception as ml_error:
        print(f" AI predictor Error: {ml_error}")

if __name__ == "__main__" :
    run_test("calc.exe")