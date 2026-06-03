import os
import sys
import requests

def load_env_file(env_path=".env"):
    if not os.path.exists(env_path):
        return
    with open(env_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" in line:
                key, val = line.split("=", 1)
                key = key.strip()
                val = val.strip()
                if (val.startswith('"') and val.endswith('"')) or (val.startswith("'") and val.endswith("'")):
                    val = val[1:-1]
                os.environ[key] = val

def main():
    load_env_file()
    host = os.environ.get('ISE_HOST')
    user = os.environ.get('ISE_USER')
    password = os.environ.get('ISE_PASSWORD')
    
    headers = {"Accept": "application/json", "Content-Type": "application/json"}
    verify = False
    requests.packages.urllib3.disable_warnings()
    
    trust_url = f"https://{host}/api/v1/certs/trusted-certificate"
    r = requests.get(f"{trust_url}?size=100", auth=(user, password), headers=headers, verify=verify, timeout=15)
    certs = r.json().get('response', [])
    
    print("INTERNAL CAs in Trust Store:")
    internal_cas = [c for c in certs if 'Certificate Services' in c.get('friendlyName', '')]
    for idx, c in enumerate(internal_cas):
        print(f"[{idx+1}] FriendlyName: {c.get('friendlyName')}")
        print(f"    ID: {c.get('id')}")
        print(f"    Subject: {c.get('subject')}")
        print(f"    IssuedTo: '{c.get('issuedTo')}'")
        print(f"    IssuedBy: '{c.get('issuedBy')}'")
        print(f"    Status: {c.get('status')}")
        print("-" * 50)
        
if __name__ == "__main__":
    main()
