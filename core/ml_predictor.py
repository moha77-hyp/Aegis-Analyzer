import os
import logging
import joblib
import pandas as pd

logger = logging.getLogger(__name__)

class MLPredictor:
    def __init__(self):
       current_dir = os.path.dirname(os.path.abspath(__file__))
       models_dir = os.path.join(current_dir, '..', 'assets', 'models')

       model_path = os.path.join(models_dir, 'aegis_rf_model.pkl')
       scaler_path = os.path.join(models_dir, 'aegis_scaler.pkl')

       self.model = None
       self.scaler = None
       try:
           #
           self.model = joblib.load(model_path)
           self.scaler = joblib.load(scaler_path)
           logger.debug("Ml Predictor initialized. artifacts loaded successfully.")
       except FileNotFoundError as e:
            logger.error(f"Faild to load the ML: {e}. Did you train_model.py first?")
       except Exception as e:
            logger.critical(f"Unexpected error loading models: {e}")

    def predict(self, features_dict: dict) -> dict:
        ####
        if not self.model or not self.scaler:
            return {
                "status": "error",
                "message": "ML Model not loaded.",
                "malware_probability": 0.0,
                "is_malicious": False
            }
        
        try:
            df = pd.DataFrame([features_dict])

            X_scaled = self.scaler.transform(df)

            prob = self.model.predict_proba(X_scaled)[0][1]

            threshold  = 0.65
            is_malicious = bool(prob >= threshold)

            return{
                "status": "success",
                "malware_probability": round(prob * 100, 2),
                "is_malicious": is_malicious,
                "threshold_used": threshold
            }
        except ValueError as ve:
            logger.error(f"Feature mismacth error during prediction: {ve}")
            return {"status": "error", "message": "Feature mismatch", "malware_probability": 0.0, "is_malicious": False}
        except Exception as e:
            logger.error(f"Prediction failed: {e}")
            return {"status": "error", "message": str(e), "malware_probability": 0.0, "is_malicious": False}