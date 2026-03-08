import requests
import csv
import io

FILENAME = "ja3_fingerprints.csv"

# gets malicious JA3 fingerprints from abuse.ch
def get_threat_database():
    print(f"[*] Loading threat data from: {FILENAME}")
    
    threat_dict = {}
    
    with open(FILENAME, mode='r', encoding='utf-8') as f:
        reader = csv.reader(f)
        
        for row in reader:
            # ignore comments in csv. 
            if not row or row[0].startswith('#'):
                continue
            
            if len(row) >= 4:
                ja3_hash = row[0]
                malware_type = row[3]
                threat_dict[ja3_hash] = malware_type
                        
    return threat_dict

# checks if hash is in database
def analyze_fingerprint(ja3_hash, database):
    print(f"[*] Analyzing JA3 hash: {ja3_hash}")
    
    if ja3_hash in database:
        print("")
        print(f"[!] JA3 fingerprint match found.")
        print(f"[!] Threat: {database[ja3_hash]}")
        return True
    else:
        print(f"[+] No known threats associated with this fingerprint.")
        return False
