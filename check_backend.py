#!/usr/bin/env python3
import paramiko

client = paramiko.SSHClient()
client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
client.connect("cloud.jagadeesh.site", username="riru", password="riru@1228")

stdin, stdout, stderr = client.exec_command("curl -s http://localhost:9000/health && echo 'OK' || ( ps aux | grep main.py | grep -v grep && echo 'Running' || echo 'Not running' )")
print(stdout.read().decode('utf-8', errors='ignore'))

client.close()
