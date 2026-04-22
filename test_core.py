from core.pe_extractor import PEExtractor

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
        print(f"Error: {e}")

if __name__ == "__main__" :
    run_test("calc.exe")