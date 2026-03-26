#!/usr/bin/env python3
"""SSH into VPS and run commands"""
import paramiko
import sys

def run_ssh_commands(host, username, password, commands):
    """Connect via SSH and run commands"""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        print(f"Connecting to {username}@{host}...")
        client.connect(host, username=username, password=password, timeout=10)
        print("[OK] Connected!")
        print()

        for cmd in commands:
            print(f"$ {cmd}")
            # Pass password to sudo via stdin with -S flag
            if cmd.startswith('sudo'):
                cmd_with_password = f'echo "{password}" | sudo -S {cmd[5:].strip()}'
                stdin, stdout, stderr = client.exec_command(cmd_with_password)
            else:
                stdin, stdout, stderr = client.exec_command(cmd)
            output = stdout.read().decode('utf-8', errors='ignore')
            errors = stderr.read().decode('utf-8', errors='ignore')

            if output:
                print(output, end='')
            if errors and 'no tty present' not in errors.lower():
                if 'password' not in errors.lower():
                    print(f"[INFO] {errors[:100]}" , file=sys.stderr, end='')
            print()

    except Exception as e:
        print(f"Failed: {e}")
        sys.exit(1)
    finally:
        client.close()

if __name__ == "__main__":
    host = "cloud.jagadeesh.site"
    username = "riru"
    password = "riru@1228"

    commands = [
        "sudo cp /tmp/main_updated.py /opt/dns-monitor-backend/main.py",
        "tail -1 /opt/dns-monitor-backend/main.py",
        "pkill -9 -f 'python.*main' || true",
        "sleep 2",
        "cd /opt/dns-monitor-backend && python3 main.py > /tmp/backend.log 2>&1 &",
        "sleep 4",
        "cat /tmp/backend.log | grep -E 'startup|port|Watching'",
    ]

    run_ssh_commands(host, username, password, commands)
