# shadow-test-malicious-py

Test package for Shadow Analyzer pip support.

Contains a setup.py with malicious install hooks that trigger all Shadow detection paths:

- Credential file reads (LSM blocking)
- C2 connections (network monitoring)  
- Suspicious process spawning
- File system writes outside expected paths

Safe for testing — all actions are sandboxed and cause no real harm.