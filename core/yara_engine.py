import yara
import os

class YaraEngine:
    def __init__(self, rules_dir: str = "rules"):
        self.rules_dir = rules_dir
        self.rules = self._compile_rules()

    def _compile_rules(self):
        rule_filepaths = {}

        if os.path.exists(self.rules_dir):
            for filename in os.listdir(self.rules_dir):
                if filename.endswith('.yar'):
                    rule_filepaths[filename] = os.path.join(self.rules_dir, filename)

        if not rule_filepaths:
            print("Warning: No YARA rules found in the rules directory.!")
            return None
        
        try:
            return yara.compile(filepaths=rule_filepaths)
        except yara.SyntaxError as e:
            raise Exception(f"Syntax Error in YARA rules: {e}")
        
    def scan_file(self, file_path: str) -> list:
        ####
        if not self.rules:
            return []
        try:
            matches = self.rules.match(file_path)

            results = []
            for match in matches:
                results.append({
                    "rule_name": match.rule,
                    "description": match.meta.get('description', 'No descriptipn'),
                    "severity": match.meta.get('severity', 'Unknown')
                })
            return results
        except Exception as e:
            raise Exception(f"Faild to scan file with YARA: {str(e)}")