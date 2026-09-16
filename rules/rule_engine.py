import json
import re


RULES = [
    {
        "rule": "SYSTEM_RECON",
        "severity": "LOW",
        "description": "System reconnaissance detected",
        "pattern": r"^uname(\s+-a)?$"
    },
    {
        "rule": "USER_RECON",
        "severity": "LOW",
        "description": "User/account discovery detected",
        "pattern": r"^whoami$"
    },
    {
        "rule": "DIRECTORY_RECON",
        "severity": "LOW",
        "description": "Directory discovery detected",
        "pattern": r"^pwd$"
    },
    {
        "rule": "FILE_RECON",
        "severity": "LOW",
        "description": "File and directory enumeration detected",
        "pattern": r"^ls(\s.*)?$"
    },
    {
        "rule": "ACCOUNT_ENUMERATION",
        "severity": "MEDIUM",
        "description": "Attempt to access the system account database detected",
        "pattern": r"cat\s+/etc/passwd"
    },
    {
        "rule": "DOWNLOAD_ACTIVITY",
        "severity": "MEDIUM",
        "description": "Possible file download activity detected",
        "pattern": r"(^|\s)(wget|curl)(\s|$)"
    },
    {
        "rule": "NETWORK_RECON",
        "severity": "LOW",
        "description": "Network reconnaissance detected",
        "pattern": r"(^|\s)(ifconfig|ip\s+addr)(\s|$)"
    }
]


def check_event(event):
    command = event.get("input", "").strip()

    for rule in RULES:
        if re.search(rule["pattern"], command):
            return {
                "rule": rule["rule"],
                "severity": rule["severity"],
                "description": rule["description"],
                "command": command,
                "src_ip": event.get("src_ip"),
                "session": event.get("session"),
                "timestamp": event.get("timestamp")
            }

    return None


def process_log(log_file):
    with open(log_file, "r") as file:

        for line in file:
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue

            if event.get("eventid") != "cowrie.command.input":
                continue

            alert = check_event(event)

            if alert:
                print(json.dumps(alert, indent=4))


if __name__ == "__main__":
    process_log("cowrie/var/log/cowrie/cowrie.json")
