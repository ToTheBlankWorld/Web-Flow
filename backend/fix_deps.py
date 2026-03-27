"""
Run this script to fix Python dependency conflicts and install all required packages.
Usage: python fix_deps.py
"""
import subprocess
import sys
import os

print("=" * 50)
print("  DNS Guardian - Dependency Fixer")
print("=" * 50)
print(f"\nPython: {sys.executable}")
print(f"Version: {sys.version}\n")

# Packages to install with exact compatible versions
PACKAGES = [
    # Keep pydantic at whatever is installed but fix pydantic-core to match
    "pydantic-core==2.41.5",  # required by pydantic 2.12.x on your system
    "fastapi==0.104.1",
    "uvicorn==0.24.0",
    "websockets==12.0",
    "aiofiles==23.2.1",
    "dnspython==2.4.2",
    "httptools",
    "python-dotenv",
]

def run(cmd):
    print(f"Running: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=False, text=True)
    return result.returncode == 0

# First upgrade pip itself
print("[1/3] Upgrading pip...")
run([sys.executable, "-m", "pip", "install", "--upgrade", "pip"])

# Force reinstall pydantic and pydantic-core to matching versions
print("\n[2/3] Fixing pydantic version conflict...")
run([
    sys.executable, "-m", "pip", "install",
    "--force-reinstall",
    "--no-deps",
    "pydantic==2.5.0",
    "pydantic-core==2.14.6",
])

# Install all other packages
print("\n[3/3] Installing all packages...")
run([sys.executable, "-m", "pip", "install"] + PACKAGES)

# Verify
print("\n[Verify] Testing imports...")
test_code = """
import fastapi, uvicorn, pydantic, aiofiles, dns.resolver
print(f"  fastapi:   {fastapi.__version__}")
print(f"  uvicorn:   {uvicorn.__version__}")
print(f"  pydantic:  {pydantic.__version__}")
print(f"  dnspython: {dns.__version__}")
print("All OK!")
"""
result = subprocess.run([sys.executable, "-c", test_code], capture_output=False)

if result.returncode == 0:
    print("\n✓ Setup complete! Run: python main.py")
else:
    print("\n✗ Some packages still have issues. Try running as Administrator.")

input("\nPress Enter to exit...")
