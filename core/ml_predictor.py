import os
import joblib
import pandas as pd
import numpy as np

class MLPrediction:
    def __init__(self):
        ####
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.model_path = os.path.join(base_dir, "assets", "models", "aegis_rf_model.pkl")
        self.scaler_path = os.path.join(base_dir, "assets", "models", "aegis_scaler.pkl")

        self.model = None
        self.scaler = None

        self._load_assets()

    def _load_assets(self):
        try:
            if os.path.exists(self.model_path) and os.path.exists(self.scaler_path):
                self.model = joblib.load(self.model_path)
                self.scaler = joblib.load(self.scaler_path)

            else:
                print(f"[!] Warining: ML assets not found at {self.model_path}. Please run train_model.py first.")
        
        except Exception as e:
            print(f"[!] Critical error loading ML models: {e}")

    def predict(self, features_dict):
        if not self.model or not self.scaler:
            return {"error": "Ml model not loaded", "malware_probability": 0.0, "is_malicious": False}
        
        expected_features = [
            'entropy_mean', 'entropy_max', 'size_of_code', 'size_of_image',
           'virtual_size_diff_mean' , 'imports_count', 'exports_count',
            'suspicious_imports_count', 'number_of_sections',
            'number_of_executable_sections', 'has_debug_info',
            'is_packed_heuristic', 'machine_type', 'dll_characteristics',
            'major_linker_version', 'resources_count'
        ]
    
        safe_features = {k: features_dict.get(k, 0) for k in expected_features}

        try:
            df = pd.DataFrame([safe_features])

            scaled_features = self.scaler.transform(df)

            prob = self.model.predict_proba(scaled_features)[0][1]

            is_malicious = bool(prob >= 0.60)

            return{
                "malware_probability": round(prob * 100, 2),
                "is_malicious": is_malicious,
                "status": "success"
            }
        except Exception as e:
            print(f"[- Eroor during ML prediction: {e}]")
            return {"error": str(e), "malware_probability": 0.0, "is_malicious": False}