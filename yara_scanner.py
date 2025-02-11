import yara
import os

def load_yara_rules():
    """Loads YARA rules from the file, ensuring it exists."""
    rule_file = './yara_rules/malware_rules.yar'

    if not os.path.exists(rule_file):
        raise FileNotFoundError(f"YARA rule file not found: {rule_file}")

    try:
        rules = yara.compile(filepath=rule_file)
        return rules
    except yara.SyntaxError as e:
        raise RuntimeError(f"YARA syntax error: {e}")

def scan_with_yara(packet_hashes):
    """Scans MD5 hashes using YARA rules and returns JSON-serializable matches."""
    if not packet_hashes:
        print("No packet hashes provided for scanning.")
        return []

    try:
        rules = load_yara_rules()
        matches = []
        
        for packet_hash in packet_hashes:
            match_results = rules.match(data=packet_hash.encode())

            if match_results:
                # Convert YARA Match objects to JSON-serializable format
                match_info = [
                    {
                        "rule": match.rule,
                        "tags": match.tags,
                        "meta": match.meta
                    }
                    for match in match_results
                ]
                matches.append({'hash': packet_hash, 'result': match_info})

        return matches

    except Exception as e:
        print(f"Error scanning with YARA: {e}")
        return []