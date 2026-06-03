import os
import sys
import requests
import json

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
    
    if not host or not user or not password:
        print("Error: Missing credentials.")
        sys.exit(1)
        
    headers = {"Accept": "application/json", "Content-Type": "application/json"}
    verify = False
    requests.packages.urllib3.disable_warnings()
    
    # 1. Get first node name
    nodes_url = f"https://{host}/api/v1/deployment/node"
    r = requests.get(nodes_url, auth=(user, password), headers=headers, verify=verify, timeout=10)
    nodes = r.json().get('response', [])
    node_name = nodes[0].get('hostname')
    
    # 2. Get system certificates
    sys_url = f"https://{host}/api/v1/certs/system-certificate/{node_name}"
    r_sys = requests.get(sys_url, auth=(user, password), headers=headers, verify=verify, timeout=10)
    sys_certs = r_sys.json().get('response', [])
    if sys_certs:
        print("FULL SYSTEM CERTIFICATE:")
        print(json.dumps(sys_certs[0], indent=2))
        print("=" * 60)
        # Find one that has usages if possible
        for c in sys_certs:
            used_by = c.get('usedBy')
            if used_by and used_by != "Not in use":
                print("FULL IN-USE SYSTEM CERTIFICATE:")
                print(json.dumps(c, indent=2))
                break
    
    # 3. Get trusted certificates
    trust_url = f"https://{host}/api/v1/certs/trusted-certificate"
    r_trust = requests.get(f"{trust_url}?size=5", auth=(user, password), headers=headers, verify=verify, timeout=10)
    trust_certs = r_trust.json().get('response', [])
    if trust_certs:
        print("=" * 60)
        print("FULL TRUSTED CERTIFICATE:")
        print(json.dumps(trust_certs[0], indent=2))

if __name__ == "__main__":
    main()
