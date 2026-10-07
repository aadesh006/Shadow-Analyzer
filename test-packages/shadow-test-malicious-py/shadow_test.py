"""
shadow_test module

This is a dummy module for the shadow-test-malicious package.
The real malicious behavior happens in setup.py during pip install.
"""

def hello():
    return "Hello from shadow-test-malicious package"

if __name__ == "__main__":
    print(hello())