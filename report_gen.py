import pandas as pd
import os
from datetime import datetime

def generate_professional_report(csv_file='logs/alerts.csv', output_file='logs/Security_Audit_Report.txt'):
    # Check if the log directory exists, create it if not
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    
    if not os.path.exists(csv_file):
        print(f"[!] No alerts found at {csv_file}")
        return

    try:
        # Load the CSV
        df = pd.read_csv(csv_file, names=['Timestamp', 'Risk', 'Action', 'Path'])
        
        # Summary Calculations
        total_events = len(df)
        risk_summary = df['Risk'].value_counts()
        action_summary = df['Action'].value_counts()
        threats = df[df['Risk'].isin(['CRITICAL', 'HIGH'])]

        # Start writing to the file
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write("█" * 65 + "\n")
            f.write("         SYSTEM REGISTRY SECURITY AUDIT REPORT\n")
            f.write("█" * 65 + "\n")
            f.write(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Total Events Tracked: {total_events}\n")
            f.write("-" * 65 + "\n\n")

            # 1. Severity Breakdown
            f.write("[!] ALERT SEVERITY BREAKDOWN:\n")
            for risk, count in risk_summary.items():
                f.write(f" - {risk:<10}: {count} events\n")

            # 2. Critical Threats Highlight
            f.write("\n[!] TOP SECURITY THREATS (CRITICAL/HIGH):\n")
            if not threats.empty:
                top_threats = threats['Path'].value_counts().head(5)
                for path, count in top_threats.items():
                    f.write(f" ALERT: {path} ({count} occurrences)\n")
            else:
                f.write(" No critical or high-risk threats detected.\n")

            # 3. Full Event Log (Table Format)
            f.write("\n" + "=" * 65 + "\n")
            f.write("### FULL DETAILED EVENT LOG ###\n")
            f.write("-" * 65 + "\n")
            
            # Using to_string to format the dataframe as a readable table in the text file
            f.write(df.to_string(index=False))
            
            f.write("\n" + "█" * 65 + "\n")
            f.write("                   END OF REPORT\n")

        print(f"[+] Success! Report generated and saved to: {output_file}")

    except Exception as e:
        print(f"[!] Error processing report: {e}")

if __name__ == "__main__":
    generate_professional_report()