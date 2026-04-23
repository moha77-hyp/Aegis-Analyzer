import os
import logging
import joblib
import pandas as pd
from sklearn.datasets import make_classification
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

Feature_names = [
    'entropy_mean',
    'entropy_max',
    'imports_count',
    'suspicious_imports_count',
    'exports_count',
    'sections_count',
    'suspicious_sections_count',
    'opt_header_size',
    'has_debug_data',
    'has_relocations',
    'has_tls',
    'is_packed_heuristic',
    'dll_characteristics_anomalies',
    'file_size_bytes',
    'overlay_size'
]

def generate_synthetic_malware_data(n_samples=10000):
    logger.info(f"Generating synthetic dataset with {n_samples} samples...")
    X, Y = make_classification(
        n_samples=n_samples,
        n_features=len(Feature_names),
        n_informative=10,
        n_redundant=3,
        n_repeated=0,
        n_classes=2,
        weights=[0.6, 0.4],
        flip_y=0.05,
        random_state=42
    )

    df = pd.DataFrame(X, columns=Feature_names)

    binary_cols = ['has_debug_data', 'has_relocations', 'has_tls', 'is_packed_heuristic']
    for col in binary_cols:
        df[col] = (df[col] > 0).astype(int)
    return df, Y

def train_and_export_model():
    X, y = generate_synthetic_malware_data(n_samples=15000)

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    
    logger.info("Scaling features...")
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    logger.info("Trainig RndomForsetClassifier..")

    clf = RandomForestClassifier(n_estimators=150, max_depth=15, n_jobs=1, random_state=42)
    clf.fit(X_train_scaled, y_train)

    accuracy = clf.score(X_test_scaled, y_test)
    logger.info(f"Model validation accuracy: {accuracy: .4f}")

    current_dir = os.path.dirname(os.path.abspath(__file__))
    models_dir = os.path.join(current_dir, 'assets', 'models')

    os.makedirs(models_dir, exist_ok=True)

    model_path = os.path.join(models_dir, 'aegis_rf_model.pkl')
    scaler_path = os.path.join(models_dir, 'aegis_scaler.pkl')

    logger.info("Exporting model and scaler artifatc to the disk...")
    joblib.dump(clf, model_path)
    joblib.dump(scaler, scaler_path)

    logger.info("Traning pipline complected successfully.")

if __name__ == "__main__":
    train_and_export_model()