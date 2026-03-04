import json
import time
import os
import yaml
from datetime import datetime
from src.analyzer import RegistryAnalyzer

def main():
    # 1. Load Configuration
    try:
        with open('config/settings.yaml', 'r') as f:
            config = yaml.safe_load(f)
    except FileNotFoundError:
        print("[!] Error: config/settings.yaml not found.")
        return

    analyzer = RegistryAnalyzer(config)
    baseline_path = config['baseline_file']

    # 2. Check for Baseline; if missing or empty, create one
    if not os.path.exists(baseline_path) or os.path.getsize(baseline_path) == 0:
        print("[+] No valid baseline found. Capturing current state as 'Clean'...")
        initial_state = analyzer.fetch_current_state()
        os.makedirs(os.path.dirname(baseline_path), exist_ok=True) # Ensure data folder exists
        with open(baseline_path, 'w') as f:
            json.dump(initial_state, f, indent=4)
        print(f"[+] Baseline saved to {baseline_path}. Restart script to monitor.")
        return

    # 3. Load existing Baseline
    with open(baseline_path, 'r') as f:
        baseline = json.load(f)

    print(f"[*] Monitoring started. Interval: {config['scan_interval_seconds']}s")
    print(f"[*] Monitoring {len(config['monitor_keys'])} registry paths...")

    # 4. Continuous Monitoring Loop
    try:
        while True:
            live_state = analyzer.fetch_current_state()
            detected_changes = analyzer.compare(baseline, live_state)

            if detected_changes:
                for change in detected_changes:
                    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    risk = change.get('risk', 'INFO')
                    change_type = change['type']
                    path = change['path']

                    # Visually distinct alerts based on risk
                    if risk in ["CRITICAL", "HIGH"]:
                        alert_prefix = f"!!! [ALERT - {risk}] !!!"
                    else:
                        alert_prefix = f"[{risk}]"

                    print(f"{alert_prefix} {timestamp} - {change_type}: {path}")
                    
                    # Log to CSV (Now including the Risk Level column)
                    os.makedirs(os.path.dirname(config['log_file']), exist_ok=True)
                    with open(config['log_file'], 'a') as log:
                        # Format: Timestamp, Risk, Action, Path
                        log.write(f"{timestamp},{risk},{change_type},{path}\n")
            
            # Note: We do NOT update the baseline here so that alerts persist 
            # until the user removes the registry key (as you requested).
            
            time.sleep(config['scan_interval_seconds'])
            
    except KeyboardInterrupt:
        print("\n[*] Monitoring stopped by user. Exiting safely...")

if __name__ == "__main__":
    main()