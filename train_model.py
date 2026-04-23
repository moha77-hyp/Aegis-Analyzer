import os
import numpy as np
import pandas as pd
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score

BASE_dir = os.path.dirname(os.path.abspath(__file__))
MODELS_dir = os.path.join(BASE_dir, "assets", "models")

def generate_synthetic_pe_data(n_samples=5000):
    np.random.seed(42)

    labels = np.random.randint(0, 2, n_samples)

    entropy_mean = np.where(labels == 1, np.random.uniform(5.5, 7.9, n_samples), np.random.uniform(3.0, 6.2, n_samples))
    entropy_max = np.clip(entropy_mean + np.random.uniform(0.5, 1.5, n_samples), 0, 8.0)

    size_of_code = np.random.randint(1024, 1024000, n_samples)
    size_of_image = size_of_code + np.random.randint(4096, 512000, n_samples)

    virtual_size_diff_mean = np.where(labels == 1, np.random.exponential(15000, n_samples), np.random.exponential(2000, n_samples))

    import_count = np.random.randint(10, 300, n_samples)
    export_count = np.random.choice([0, 0, 0, 1, 5, 10], n_samples)

    suspicious_imports_count = np.where(labels == 1, np.random.randint(2, 15, n_samples), np.random.randint(0, 3, n_samples))

    number_of_sections = np.random.randint(3, 10, n_samples)
    number_of_executable_sections = np.where(labels == 1, np.random.randint(1, 4, n_samples), 1)

    has_debug_info = np.where(labels == 1, np.random.choice([0, 1], p=[0.9, 0.1], size=n_samples), np.random.choice([0, 1], p=[0.4, 0.6], size=n_samples))
    is_packed_heuristic = np.where(entropy_max > 7.2, 1, 0)
    machine_type = np.random.choice([332, 34404], n_samples)
    dll_characteristics = np.random.randint(0, 65535, n_samples)
    major_linker_version = np.random.randint(6, 14, n_samples)
    resources_count = np.random.randint(1, 50, n_samples)

    df = pd.DataFrame({
       'entropy_mean': entropy_mean,
       'entropy_max': entropy_max,
       'size_of_code': size_of_code,
       'size_of_image': size_of_image,
       'virtual_size_diff_mean': virtual_size_diff_mean,
       'imports_count': import_count,
       'exports_count': export_count,
       'suspicious_imports_count': suspicious_imports_count,
       'number_of_sections': number_of_sections,
       'number_of_executable_sections': number_of_executable_sections,
       'has_debug_info': has_debug_info,
       'is_packed_heuristic': is_packed_heuristic,
       'machine_type': machine_type,
       'dll_characteristics': dll_characteristics,
       'major_linker_version': major_linker_version,
       'resources_count': resources_count,
       'label': labels
    })

    return df

def main():
    print("[*Generating highly correlated synthetic dataset for aegis ML...]")
    data = generate_synthetic_pe_data(10000)

    X = data.drop('label', axis=1)
    y = data['label']

    print(f"[*] Dataset generated. Shape: {X.shape}. Splitting data...")
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

    print("[*] Scaling features...")
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    print("[*] Training RandomForest Classifier...")
    model = RandomForestClassifier(
        n_estimators=150,
        max_depth=15,
        random_state=42,
        class_weight='balanced',
        n_jobs=-1
    )

    model.fit(X_train_scaled, y_train)

    print("[*] Evaluating Model...")
    y_pred = model.predict(X_test_scaled)
    print(classification_report(y_test, y_pred))
    print(f"Accuracy: {accuracy_score(y_test, y_pred):.4f}")

    if not os.path.exists(MODELS_dir):
        os.makedirs(MODELS_dir)

    model_path = os.path.join(MODELS_dir, 'aegis_rf_model.pkl')
    scaler_path = os.path.join(MODELS_dir, 'aegis_scaler.pkl')

    print(f"[*] Saving model and scaler to {MODELS_dir}...")
    joblib.dump(model, model_path)
    joblib.dump(scaler, scaler_path)
    print("[*] Model training and export complete. aegis AI is ready.")

if __name__ == "__main__":
    main()