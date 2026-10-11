import pandas as pd

#Loading the security log dataset
file_path = "data/security_logs.csv"

logs = pd.read_csv(file_path)

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
