#!/usr/bin/env python3
"""Deploy updated backend to VPS"""
import paramiko
from pathlib import Path
import time

host = "cloud.jagadeesh.site"
username = "riru"
password = "riru@1228"
local_main = Path("d:/My Projects/DNS Detc/backend/main.py").resolve()
remote_tmp = "/tmp/main_updated.py"
remote_path = "/opt/dns-monitor-backend/main.py"

print(f"Local file: {local_main}")
print(f"Exists: {local_main.exists()}")
print(f"Size: {local_main.stat().st_size}")

with open(local_main) as f:
    content = f.read()
    if "port=9000" in content:
        print("[OK] File contains port=9000")
    else:
        print("[ERROR] File does NOT contain port=9000")

client = paramiko.SSHClient()
client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

try:
    client.connect(host, username=username, password=password)
    sftp = client.open_sftp()

    print(f"\n[1/5] Uploading {local_main}...")
    sftp.put(str(local_main), remote_tmp)

    print(f"[2/5] Verifying upload...")
    remote_size = sftp.stat(remote_tmp).st_size
    print(f"  Remote size: {remote_size}, Local size: {local_main.stat().st_size}")

    print(f"[3/5] Checking remote content...")
    with sftp.open(remote_tmp) as f:
        remote_content = f.read().decode()
        if "port=9000" in remote_content:
            print("[OK] Remote file has port=9000")
        else:
            print("[ERROR] Remote file doesn't have port=9000")

    print("[4/5] Copying to target and restarting...")
    stdin, stdout, stderr = client.exec_command(f'cp {remote_tmp} {remote_path}')
    stdout.read()

    stdin, stdout, stderr = client.exec_command('pkill -9 -f "python.*main" || true')
    stdout.read()
    time.sleep(1)

    stdin, stdout, stderr = client.exec_command(f'cd /opt/dns-monitor-backend && python3 main.py > /tmp/backend.log 2>&1 &')
    stdout.read()
    time.sleep(3)

    print("[5/5] Checking backend health...")
    stdin, stdout, stderr = client.exec_command('curl -s http://localhost:9000/health')
    result = stdout.read().decode('utf-8', errors='ignore')
    if "ok" in result.lower() or "200" in result:
        print(f"[SUCCESS] Backend responding: {result[:100]}")
    else:
        print(f"[INFO] Backend response: {result[:100] if result else '(no response yet)'}")

    sftp.close()

except Exception as e:
    print(f"Error: {e}")
    import traceback
    traceback.print_exc()
finally:
    client.close()

