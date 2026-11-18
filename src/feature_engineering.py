import pandas as pd

def extract_features(file_path):

    df = pd.read_csv(file_path)

    # Convert status into uppercase
    df["status"] = df["status"].str.upper()

    # Group activities by IP address
    features = df.groupby("ip_address").agg(

        total_events=("ip_address", "count"),

        failed_logins=("status", lambda x: (x == "FAILED").sum()),

        successful_logins=("status", lambda x: (x == "SUCCESS").sum()),

        unique_users=("username", "nunique"),

        unique_endpoints=("endpoint", "nunique")

    ).reset_index()

    # Calculate failed login ratio
    features["failed_login_ratio"] = (
        features["failed_logins"] / features["total_events"]
    )

    # Flag IPs with 5 or more failed logins
    features["suspicious"] = (
        features["failed_logins"] >= 5
    )

    print("\nExtracted Security Features:")
    print(features)

    # Save extracted features
    features.to_csv("data/security_features.csv", index=False)

    print("\nSecurity features saved successfully!")

    return features


if __name__ == "__main__":

    data = extract_features("data/security_logs.csv")