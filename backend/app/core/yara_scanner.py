import json
import re
import logging
from functools import lru_cache
from pathlib import Path

from .config import settings

logger = logging.getLogger(__name__)

# Try to import yara-python
try:
    import yara
    HAS_YARA = True
except ImportError:
    HAS_YARA = False
    logger.warning("yara-python is not installed. Using pure Python fallback scanner.")


@lru_cache(maxsize=1)
def get_compiled_rules():
    if not HAS_YARA:
        return None
    rule_file = settings.YARA_RULES_PATH
    if not rule_file.exists():
        raise FileNotFoundError(f'YARA rule file not found: {rule_file}')
    try:
        return yara.compile(filepath=str(rule_file))
    except Exception as e:
        logger.error(f"Failed to compile YARA rules using yara-python: {e}. Falling back to custom parser.")
        return None


@lru_cache(maxsize=1)
def load_yara_rules_fallback():
    rule_file = settings.YARA_RULES_PATH
    if not rule_file.exists():
        raise FileNotFoundError(f'YARA rule file not found: {rule_file}')

    rule_text = rule_file.read_text(encoding='utf-8')

    rule_name_match = re.search(r'^\s*rule\s+([A-Za-z0-9_]+)\s*{', rule_text, re.MULTILINE)
    rule_name = rule_name_match.group(1) if rule_name_match else rule_file.stem

    meta_section_match = re.search(r'\bmeta:\s*(.*?)\bstrings:', rule_text, re.DOTALL | re.MULTILINE)
    strings_section_match = re.search(r'\bstrings:\s*(.*?)\bcondition:', rule_text, re.DOTALL | re.MULTILINE)

    meta: dict[str, str] = {}
    if meta_section_match:
        for key, value in re.findall(r'^\s*([A-Za-z0-9_]+)\s*=\s*"([^"]*)"\s*$', meta_section_match.group(1), re.MULTILINE):
            meta[key] = value

    hash_values: set[str] = set()
    if strings_section_match:
        for hash_value in re.findall(r'\$h\d+\s*=\s*"([0-9a-fA-F]{32})"', strings_section_match.group(1), re.MULTILINE):
            hash_values.add(hash_value.lower())

    return {
        'rule_name': rule_name,
        'meta': meta,
        'hash_values': hash_values,
    }


def scan_with_yara(packet_records: list[dict]) -> list[dict]:
    if not packet_records:
        return []

    detections: list[dict] = []
    rules = get_compiled_rules()

    if HAS_YARA and rules is not None:
        for packet in packet_records:
            payload_hash = packet.get('payload_hash')
            if not payload_hash:
                continue

            # Check if payload_hash matches compiled rules
            matches = rules.match(data=payload_hash.encode('utf-8'))
            if not matches:
                continue

            for match in matches:
                meta = match.meta
                detections.append(
                    {
                        'packet_index': packet['packet_index'],
                        'md5_hash': payload_hash,
                        'rule_name': match.rule,
                        'description': meta.get('description') or '',
                        'author': meta.get('author') or 'Unknown',
                        'tags': json.dumps(match.tags),
                        'severity': meta.get('severity') or 'medium',
                        'vt_positives': int(meta.get('vt_positives') or 0),
                        'vt_total': int(meta.get('vt_total') or 72),
                        'raw_payload': packet.get('raw_payload'),
                    }
                )
    else:
        # Fallback pure-python regex scanner
        rule_bundle = load_yara_rules_fallback()
        hash_values = rule_bundle['hash_values']
        meta = rule_bundle['meta']
        rule_name = rule_bundle['rule_name']

        for packet in packet_records:
            payload_hash = packet.get('payload_hash')
            if not payload_hash or payload_hash.lower() not in hash_values:
                continue

            detections.append(
                {
                    'packet_index': packet['packet_index'],
                    'md5_hash': payload_hash,
                    'rule_name': rule_name,
                    'description': meta.get('description') or '',
                    'author': meta.get('author') or 'Unknown',
                    'tags': json.dumps([]),
                    'severity': meta.get('severity') or 'medium',
                    'vt_positives': int(meta.get('vt_positives') or 0),
                    'vt_total': int(meta.get('vt_total') or 72),
                    'raw_payload': packet.get('raw_payload'),
                }
            )

    return detections