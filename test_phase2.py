import os
from core.pe_extractor import PEExtractor
from core.yara_engine import YaraEngine

def run_test():
    print("=== 🚀 بدء اختبار Phase 2 ===")
    
    # هنجرب على الآلة الحاسبة بتاعة الويندوز كملف سليم (Benign)
    # بما إنك شغال على بيئة ويندوز (من مسار الـ PS اللي بعته)، ده هيشتغل معاك طلقة
    test_file_path = r"C:\Windows\System32\calc.exe"
    
    if not os.path.exists(test_file_path):
        print(f"❌ مش لاقي الملف: {test_file_path}. حط مسار أي ملف .exe تاني.")
        return

    print(f"📂 بنقرأ الملف في الميموري (Memory Rule): {test_file_path}")
    # هنا بنقرأ الملف كـ Raw Bytes زي ما الـ Streamlit هيعمل بالظبط
    with open(test_file_path, 'rb') as f:
        raw_bytes = f.read()

    # ---------------------------------------------------------
    print("\n--- 1. اختبار PE Extractor ---")
    extractor = PEExtractor(raw_bytes)
    ml_features, ui_metadata = extractor.analyze_and_extract_fearures()
    
    if extractor.is_valid_pe:
        print("✅ استخراج الـ ML Features (15+ features) تم بنجاح:")
        for key, value in ml_features.items():
            print(f"   🔹 {key}: {value}")
            
        print("\n✅ استخراج الـ UI Metadata تم بنجاح:")
        print(f"   🔹 MD5: {ui_metadata['hashes']['MD5']}")
        print(f"   🔹 MITRE Hits: {ui_metadata['mitre_hits']}")
        print(f"   🔹 Is Packed?: {ui_metadata['is_packed']}")
    else:
        print(f"❌ الملف مش PE صحيح أو حصل مشكلة: {ui_metadata.get('error')}")

    # ---------------------------------------------------------
    print("\n--- 2. اختبار YARA Engine ---")
    scanner = YaraEngine()
    yara_results = scanner.scan_memory(raw_bytes)
    
    print("✅ الفحص تم بنجاح. النتيجة:")
    print(f"   🔹 Status: {yara_results['status']}")
    print(f"   🔹 Is Critical Malware?: {yara_results['is_critical']}")
    print(f"   🔹 Matches: {yara_results['matches']}")
    
    print("\n=== 🎉 الاختبار خلص بنجاح يا هندسة! ===")

if __name__ == "__main__":
    run_test()