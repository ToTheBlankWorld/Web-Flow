#!/usr/bin/env python3
"""Deploy backend to VPS via SSH"""
import paramiko
import os
import sys
from pathlib import Path

def run_command(client, cmd):
    """Run a command and return output"""
    stdin, stdout, stderr = client.exec_command(f'echo "riru@1228" | sudo -S {cmd}')
    output = stdout.read().decode()
    errors = stderr.read().decode()
    return output, errors

def deploy_backend():
    """Deploy backend files to VPS"""
    host = "cloud.jagadeesh.site"
    username = "riru"
    password = "riru@1228"
    local_backend = Path("d:/My Projects/DNS Detc/backend").resolve()
    remote_path = "/opt/dns-monitor-backend"

    print(f"Local backend path: {local_backend}")
    print(f"main.py exists: {(local_backend / 'main.py').exists()}")
    print(f"requirements.txt exists: {(local_backend / 'requirements.txt').exists()}")
    print()

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        print(f"Connecting to {username}@{host}...")
        client.connect(host, username=username, password=password, timeout=10)
        print("[OK] Connected!\n")

        # Create remote directory
        print("Creating backend directory...")
        stdin, stdout, stderr = client.exec_command(f'echo "{password}" | sudo -S mkdir -p {remote_path}')
        stdout.read()

        print("Setting permissions...")
        stdin, stdout, stderr = client.exec_command(f'echo "{password}" | sudo -S chown -R root:root {remote_path}')
        stdout.read()

        # Use SFTP to copy files
        sftp = client.open_sftp()

        # Copy main.py
        main_py_local = local_backend / "main.py"
        main_py_remote = f"{remote_path}/main.py"

        print(f"Copying main.py... ({main_py_local})")
        sftp.put(str(main_py_local), "/tmp/main.py")

        # Copy to final location with sudo
        stdin, stdout, stderr = client.exec_command(f'echo "{password}" | sudo -S cp /tmp/main.py {main_py_remote}')
        stdout.read()

        # Copy requirements.txt
        req_local = local_backend / "requirements.txt"
        req_remote = f"{remote_path}/requirements.txt"

        print(f"Copying requirements.txt...")
        sftp.put(str(req_local), "/tmp/requirements.txt")
        stdin, stdout, stderr = client.exec_command(f'echo "{password}" | sudo -S cp /tmp/requirements.txt {req_remote}')
        stdout.read()

        sftp.close()

        # Install Python dependencies
        print("Installing Python dependencies...")
        stdin, stdout, stderr = client.exec_command(f'echo "{password}" | sudo -S pip3 install -q -r {req_remote}')
        result = stdout.read().decode('utf-8', errors='ignore')
        errors = stderr.read().decode('utf-8', errors='ignore')
        if errors and 'notice' not in errors.lower():
            print(f"Info: Installation output received")

        # Start backend service
        print("Starting backend service...")
        cmd = f'cd {remote_path} && nohup python3 main.py > /var/log/dns-backend.log 2>&1 &'
        stdin, stdout, stderr = client.exec_command(f'echo "{password}" | sudo -S bash -c "{cmd}"')
        stdout.read()

        # Verify it started
        import time
        time.sleep(2)
        stdin, stdout, stderr = client.exec_command(f'ps aux | grep "main.py" | grep -v grep')
        result = stdout.read().decode()

        if "main.py" in result:
            print("[OK] Backend started successfully!")
            print(f"\nBackend location: {remote_path}")
            print(f"Logs: /var/log/dns-backend.log")
        else:
            print("[ERROR] Backend failed to start")
            print("Check logs with: ssh riru@cloud.jagadeesh.site 'sudo tail /var/log/dns-backend.log'")

    except Exception as e:
        print(f"Failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
    finally:
        client.close()

if __name__ == "__main__":
    deploy_backend()
