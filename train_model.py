import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
import joblib
import os

print("[*] Generating tranning data!")

clean_data = np.array([
    [np.random.uniform(3.0, 5.9), np.random.randint(4, 8), np.random.randint(20, 100), np.random.uniform(1000, 50000)]
    for _ in range(1000)
])
clean_labels = np.zeros(1000)

malware_data = np.array([
    [np.random.uniform(6.5, 8.0), np.random.randint(2, 5), np.random.randint(1, 10), np.random.uniform(500, 20000)]
    for _ in range(1000)
])
malware_labels = np.ones(1000)

X = np.vstack((clean_data, malware_data))
y = np.concatenate((clean_labels, malware_labels))

X_train, x_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

print("[*] Traning Random Forest AI Model..")

model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

accuracy = model.score(x_test, y_test)
print(f"[+] Model Trained successsfully with accuracy: {accuracy * 100:.2f}%")

os.makedirs("assets/models", exist_ok=True)
model_path = "assets/models/malware_rf_model.pkl"
joblib.dump(model, model_path)

print(f"[+] Brain saved to: {model_path}")