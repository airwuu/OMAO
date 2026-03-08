#!/bin/bash

echo "[*] Searching for MAC isolation rules in the FORWARD chain..."

# 1. Use iptables -S to list rules exactly as they were written (e.g., "-A FORWARD ...")
# 2. Use grep to filter only the rules that match the MAC drop pattern
RULES=$(sudo iptables -S FORWARD | grep "\-m mac \-\-mac-source .* \-j DROP")

# Check if we found any matching rules
if [ -z "$RULES" ]; then
    echo "[+] No MAC isolation rules found. Nothing to do."
    exit 0
fi

# Loop through each matching rule line by line
echo "$RULES" | while read -r rule; do
    
    # 3. Use sed to swap the "-A" (Append) at the start of the rule with "-D" (Delete)
    delete_cmd=$(echo "$rule" | sed 's/^-A/-D/')
    
    # Extract the MAC address just for the print output (optional, but looks nice)
    mac_addr=$(echo "$rule" | grep -o -E '([[:xdigit:]]{1,2}:){5}[[:xdigit:]]{1,2}')
    echo "[*] Removing isolation for MAC: $mac_addr"
    
    # 4. Execute the new delete command
    # We don't need quotes around $delete_cmd here because we want bash to read it as separate arguments
    sudo iptables $delete_cmd

done

echo "[+] Cleanup complete. All isolated MAC addresses have been restored."
