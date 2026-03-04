import winreg
import json
import os

class RegistryAnalyzer:
    def __init__(self, config):
        self.config = config
        self.hives = {
            "HKEY_CURRENT_USER": winreg.HKEY_CURRENT_USER,
            "HKEY_LOCAL_MACHINE": winreg.HKEY_LOCAL_MACHINE
        }

    def get_risk_level(self, path, value):
        """
        Automated Risk Categorization Logic
        Categorizes changes based on path sensitivity and payload patterns.
        """
        path_upper = path.upper()
        value_string = str(value).lower()
        
        # 1. CRITICAL: Security tool tampering (Defender, UAC, Policies)
        # Directly addresses Objective 2: Detect malware-like changes
        security_paths = ["WINDOWS DEFENDER", "POLICIES\\SYSTEM", "SECURITY CENTER"]
        if any(sp in path_upper for sp in security_paths):
            if "DISABLE" in value_string or "1" in value_string or "0" in value_string:
                return "CRITICAL"
            return "HIGH"
        
        # 2. HIGH: Suspicious Payload Patterns
        # Detects scripts or executables in non-standard/temporary locations
        suspicious_exts = ['.vbs', '.ps1', '.bat', '.tmp', '.scr', '.js', '.hta']
        suspicious_keywords = ['powershell', 'cmd.exe', 'temp', 'appdata\\local\\temp', 'curl', 'wget']
        
        is_startup_path = "CURRENTVERSION\\RUN" in path_upper
        
        if is_startup_path:
            # Check for dangerous extensions
            if any(ext in value_string for ext in suspicious_exts):
                return "HIGH"
            # Check for suspicious execution keywords (e.g., encoded powershell)
            if any(kw in value_string for kw in suspicious_keywords):
                return "HIGH"
            
            # Standard executable in startup is Medium (Persistence detection)
            return "MEDIUM"
        
        # 3. LOW: General modifications
        return "LOW"

    def fetch_current_state(self):
        """Reads the registry with 64-bit view support to prevent redirection."""
        current_data = {}
        for entry in self.config['monitor_keys']:
            hive_name = entry['hive']
            path = entry['path']
            
            try:
                # KEY_WOW64_64KEY ensures we see the true registry on 64-bit systems
                access_flags = winreg.KEY_READ | winreg.KEY_WOW64_64KEY
                with winreg.OpenKey(self.hives[hive_name], path, 0, access_flags) as key:
                    num_values = winreg.QueryInfoKey(key)[1]
                    for i in range(num_values):
                        name, value, _ = winreg.EnumValue(key, i)
                        full_path = f"{hive_name}\\{path}\\{name}"
                        current_data[full_path] = str(value)
            except Exception as e:
                # Log error but continue to next key
                print(f"[!] Access Denied or Path Missing: {hive_name}\\{path}")
        return current_data

    def compare(self, baseline, live):
        """
        Registry Integrity Checker
        Compares live state against baseline to detect drift.
        """
        changes = []
        
        # Check for additions and modifications
        for path, value in live.items():
            severity = self.get_risk_level(path, value)
            
            if path not in baseline:
                changes.append({
                    "type": "ADDED", 
                    "path": path, 
                    "value": value, 
                    "risk": severity
                })
            elif baseline[path] != value:
                changes.append({
                    "type": "MODIFIED", 
                    "path": path, 
                    "old": baseline[path], 
                    "new": value, 
                    "risk": severity
                })
        
        # Check for deletions
        for path in baseline:
            if path not in live:
                changes.append({
                    "type": "DELETED", 
                    "path": path,
                    "risk": "INFO"
                })
                
        return changes