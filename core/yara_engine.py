import os
import logging
import yara

logger = logging.getLogger(__name__)

class YaraEngine:
    def __init__(self):
        current_dir = os.path.dirname(os.path.abspath(__file__))
        rules_path = os.path.join(current_dir, '..', 'rules', 'eicar.yar')

        self.rules = None
        try:
            if not os.path.exists(rules_path):
                logger.warning(f"YARA rules file not found at {rules_path}. Generating dummy rule.")
                self._create_dummy_rule(rules_path)

            self.rules = yara.compile(filepath=rules_path)
            logger.info("YARA Engine intilized and rules compiled successfully.")
        except yara.SynatxErroe as e:
            logger.error(f"YARA Synatx Error in rules file: {e}")
        except Exception as e:
            logger.error(f"Failed to Load Yara rules: {e}")

    def _create_dummy_rule(self, filepath: str):
        ###
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        dummy_rule = '''
        rule EICAR_Test_File {
            meta:
                author = "Aegis Architect"
                description = "Standard EICAR Anti-Virus Test File"
                severity = "High"
            strings:
                $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
            condition:
                $eicar
        }
        '''
        with open(filepath, 'W') as f:
            f.write(dummy_rule)

    def scan_memory(self, raw_bytes: bytes) -> dict:
        ###
        if not self.rules:
            return {"status": "error", "message": "YARA rules not loaded.", "matches": [], "is_critical": False}
        try:
            yara_matches = self.rules.match(data=raw_bytes)

            matches_info = []
            is_critical = False

            for match in yara_matches:
                severity = match.meta.get('severity', 'Low')

                if severity == 'High':
                    is_critical = True

                matches_info.append({
                    "rule_name": match.rule,
                    "description": match.meta.get('description', 'No description provided.'),
                    "severity": severity
                })

            return {
                "status": "success",
                "matches": matches_info,
                "is_critical": is_critical
            }
        except yara.Error as ye:
            logger.error(f"YARA scanning engine erroe {ye}")
            return {"status": "error", "message": "Engine error during scan", "matches": [], "is_critical": False}
        except Exception as e:
            logger.error(f"Unexpected erroe during YARA scan: {e}")
            return {"status": "error", "message": str(e), "matches": [], "is_critical": False}