# Testing Guide: Registry Security Monitor

This document outlines how to verify the functionality and security logic of the Registry Monitor.

## 📋 Prerequisites
- Python 3.x installed.
- Administrative privileges (required to modify certain registry keys).
- The `pandas` library installed (`pip install pandas`).

## 🧪 Manual Testing Scenarios

### Test 1: Standard Persistence (MEDIUM Risk)
* **Goal:** Verify detection of a normal application adding itself to startup.
* **Action:** 1. Open CMD as Admin.
    2. Run: `reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "DemoApp" /t REG_SZ /d "calc.exe"`
* **Expected Result:** The monitor detects an `ADDED` event with a `MEDIUM` risk level.

### Test 2: Malicious Script (HIGH Risk)
* **Goal:** Detect dangerous file extensions in startup paths.
* **Action:**
    1. Run: `reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "BadScript" /t REG_SZ /d "C:\Users\Public\malware.vbs"`
* **Expected Result:** Monitor detects `HIGH` risk due to the `.vbs` extension.

### Test 3: Security Policy Tampering (CRITICAL Risk)
* **Goal:** Detect attempts to disable system security features.
* **Action:**
    1. Run: `reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d 1`
* **Expected Result:** Monitor detects `CRITICAL` risk due to the path and "Disable" keyword.

## 📊 Report Generation Test
1. Run the tests above.
2. Stop the monitor (Ctrl+C).
3. Run `python generate_report.py`.
4. **Verification:** Check the `logs/` folder for `Security_Audit_Report.txt`. Ensure all test events are listed.

## 🧹 Cleanup
After testing, remove the keys:
- `reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "DemoApp" /f`
- `reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "BadScript" /f`
- `reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /f`