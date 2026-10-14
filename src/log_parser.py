import pandas as pd

#Loading the security log dataset
file_path = "data/security_logs.csv"

logs = pd.read_csv(file_path)
logs["timestamp"] = pd.to_datetime(logs["timestamp"])

#Display the project title
print("=" * 40)
print("       AI SECURITY LOG ANALYZER")
print("=" * 40)

#Display logs
print("\nSecurity Logs:")
print(logs.to_string(index=False))

#Display the total number of events 
print("\nTotal log entries:", len(logs))

#FIlter failed login attempts
failed_logins = logs[
    (logs["event_type"]== "LOGIN")&
    (logs["status"] == "FAILED")
]

#Display failed login attempts
print("\nFailed login Attempts: ")
print(failed_logins.to_string(index=False))

#Count failed logins by IP address
print("\nFailed Logins by IP Adress:")
print(failed_logins["ip_address"].value_counts())

#Flag IP Adresses with repeated failed logins
login_counts = failed_logins["ip_address"].value_counts()

print("\nSuspicious Activity Alerts:")

suspicious_ips = login_counts[login_counts >= 5]

if suspicious_ips.empty:
    print("No suspicious login activity detected. ")

else: 
    for ip, count in suspicious_ips.items():

        print(
            f"ALERT: {ip} has {count} failed login attempts!"
        )

print("\nTimestamp Data Type:")
print(logs["timestamp"].dtype)

print("\nFirst 3 Timestamps:")
print(logs["timestamp"].head(3))

#Calculate time between consecutive failed logins per IP
failed_logins = failed_logins.sort_values("timestamp")

failed_logins["time_difference"] = (
    failed_logins.groupby("ip_address")["timestamp"]
    .diff()
    .dt.total_seconds()
)

print("\nTime between Failed logins (seconds) : ")
print(
    failed_logins[
        ["ip_address", "timestamp", "time_difference"]
    ].to_string(index=False)
)


 # Detect five failed logins within 60 seconds
print("\nBrute-Force Detection:")

threshold = 5
window_seconds = 60
found_attack = False

for ip, group in failed_logins.groupby("ip_address"):
    timestamps = group["timestamp"].sort_values().tolist()

    for i in range(len(timestamps)):
        window_end = timestamps[i] + pd.Timedelta(
            seconds=window_seconds
        )

        attempts = sum(
            timestamps[i] <= ts <= window_end
            for ts in timestamps
        )

        if attempts >= threshold:
            print(
                f"ALERT: {ip} had {attempts} failed login "
                f"attempts within {window_seconds} seconds."
            )
            found_attack = True
            break

if not found_attack:
    print("No brute-force pattern detected.")