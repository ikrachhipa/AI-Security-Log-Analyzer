import pandas as pd
from sklearn.ensemble import IsolationForest

def detect_anomalies(file_path):

    # Load extracted security features
    df = pd.read_csv(file_path)

    # Select numerical features
    features = df[
        [
            "total_events",
            "failed_logins",
            "successful_logins",
            "unique_users",
            "unique_endpoints",
            "failed_login_ratio"
        ]
    ]

    # Initialize Isolation Forest
    model = IsolationForest(
        contamination=0.2,
        random_state=42
    )

    # Train model and predict anomalies
    df["anomaly"] = model.fit_predict(features)

    # Convert predictions into readable labels
    df["threat_status"] = df["anomaly"].map({
        1: "Normal",
        -1: "Suspicious"
    })

    print("\nMachine Learning Detection Results:")
    print(df[["ip_address", "threat_status"]])

    # Save results
    df.to_csv("data/anomaly_results.csv", index=False)

    print("\nAnomaly detection completed!")
    print("Results saved successfully!")

if __name__ == "__main__":
    detect_anomalies("data/security_features.csv")