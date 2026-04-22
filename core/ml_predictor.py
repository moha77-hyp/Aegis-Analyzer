import joblib
import numpy as np
import os

class MLPredictor:
    def __init__(self, model_path: str = "assets/models/malware_rf_model.pkl"):
        if not os.path.exists(model_path):
            raise FileExistsError(f"AI Model not found at {model_path}. Did you run train_model.py??!")
        
        self.model = joblib.load(model_path)

    def predict(self, features: dict) -> dict:
        try:
            avg_entropy = features.get('avg_entropy', 0.0)
            num_section = features.get('num_sections', 0)
            num_imports = features.get('num_imports', 0)
            file_size = features.get('file_size', 0)

            feature_vector = np.array([[avg_entropy, num_section, num_imports, file_size]])

            is_malware = self.model.predict(feature_vector)[0]
            probability = self.model.predict_proba(feature_vector)[0]

            return {
                "is_malware": bool(is_malware == 1),
                "malware_probability": round(probability[1] * 100, 2),
                "safe_probability": round(probability[0] * 100, 2)
            }
        except Exception as e:
            raise Exception(f"AI Prediction faild: {str(e)}")