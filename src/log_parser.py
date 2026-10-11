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