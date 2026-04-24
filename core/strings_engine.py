import re
import logging

logger = logging.getLogger(__name__)

class StringsEngine:
    def __init__(self, raw_bytes: bytes):
        self.raw_bytes = raw_bytes
        self.decode_text = self._extract_readable_strings()

        self.patterns = {
            "IPv4": r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
            "URLs": r'(?i)\b((?:https?://|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,4}/)(?:[^\s()<>]+|\(([^\s()<>]+|(\([^\s()<>]+\)))*\))+(?:\(([^\s()<>]+|(\([^\s()<>]+\)))*\)|[^\s`!()\[\]{};:\'".,<>?«»“”‘’]))',
            "Registry_keys": r'(?i)(HKLM|HKCU|HKCR|HKU|HKCC|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER)\\[a-zA-Z0-9_\\]+',
            "Bitcoin_wallets": r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b' #Basic BTC regex heuristic
        }

    def _extract_readable_strings(self) -> str:
        try:
            ascii_strings = re.findall(b'[\x20-\x7e]{4,}', self.raw_bytes)
            utf16_strings = re.findall(b'(?:[\x20-\x7e]\x00){4,}', self.raw_bytes) #Trying to cath utf-16LE strings because its coomon in windows PE

            combind = b" ".join(ascii_strings + utf16_strings)
            return combind.decode('ascii', errors='ignore')
        except Exception as e:
            logger.error(f"Error decoding strings from memory: {e}")
            return ""
        
    def extract_icos(self) -> dict:
        ###
        results = {
            "IPv4": [],
            "URLs": [],
            "Registry_keys": [],
            "Bitcoin_wallets": []
        }

        if not self.decode_text:
            return results
        
        try:
            for key, pattern in self.patterns.items():
                matches = re.findall(pattern, self.decode_text)

            if key == "URLs":
                cleaned_matches = [m[0] for m in matches if isinstance(m, tuple)]
                results[key] = list(set(cleaned_matches))

            else:
                results[key] = list(set(matches))

        except Exception as e:
            logger.error(f"Regex matching failed: {e}")

        return results