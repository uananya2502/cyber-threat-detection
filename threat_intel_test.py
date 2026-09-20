import json
from pathlib import Path
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

# Read the Auth-Key from the local .env file.
env_path = Path(".env")

if not env_path.exists():
    raise SystemExit("ERROR: .env file not found.")

auth_key = None

for line in env_path.read_text().splitlines():
    if line.startswith("THREATFOX_AUTH_KEY="):
        auth_key = line.split("=", 1)[1].strip()
        break

if not auth_key:
    raise SystemExit("ERROR: ThreatFox Auth-Key not found in .env.")

# ThreatFox request: indicators reported in the last day.
url = "https://threatfox-api.abuse.ch/api/v1/"

payload = {
    "query": "get_iocs",
    "days": 1
}

request = Request(
    url,
    data=json.dumps(payload).encode("utf-8"),
    headers={
        "Auth-Key": auth_key,
        "Content-Type": "application/json"
    },
    method="POST"
)

try:
    with urlopen(request, timeout=30) as response:
        response_body = response.read().decode("utf-8")

except HTTPError as error:
    raise SystemExit(
        f"HTTP error: {error.code}. "
        "Check the API key and request details."
    )

except URLError as error:
    raise SystemExit(f"Connection error: {error.reason}")

# Parse the response.
try:
    result = json.loads(response_body)
except json.JSONDecodeError:
    raise SystemExit("ERROR: ThreatFox returned invalid JSON.")

# Save the raw response for later processing.
output_path = Path("data/threat_intel/threatfox_raw.json")
output_path.write_text(json.dumps(result, indent=2))

print("ThreatFox API request completed.")
print("Response saved to:", output_path)
print("Query status:", result.get("query_status"))

data = result.get("data")

if isinstance(data, list):
    print("Number of returned indicators:", len(data))

    if data:
        print("\nExample indicator metadata:")

        example = data[0]

        # Do not print the Auth-Key.
        # Show only a few fields to inspect the response structure.
        for field in [
            "id",
            "ioc_type",
            "threat_type",
            "threat_type_desc",
            "confidence_level",
            "first_seen"
        ]:
            print(f"{field}: {example.get(field)}")

elif data is None:
    print("No data list was returned.")
    print("API response message:", result.get("query_status"))

else:
    print("The response data is not a list.")
    print("Response data type:", type(data).__name__)
