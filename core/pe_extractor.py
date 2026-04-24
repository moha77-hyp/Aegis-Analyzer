import hashlib
import math
import logging
import pefile

logger = logging.getLogger(__name__)

Suspicous_Apis = {
    b'VirtualAlloc': 'T1055 (Process Injection)',
    b'VirtualAllocEx': 'T1055 (Process Injection)',
    b'WriteProcessMemory': 'T1055 (Process Injection)',
    b'CreateRemoteThread': 'T1055 (Process Injection)',
    b'LoadLibraryA': 'T1129 (Shared Modules)',
    b'GetProcAddress': 'T1129 (Shared Modules)',
    b'URLDownloadToFileA': 'T1105 (Ingress Tool Transfer)',
    b'InternetOpenA': 'T1071 (Application Layer Protocol)',
    b'CryptAcquireContextA': 'T1486 (Data Encrypted for Impact)',
    b'IsDebuggerPresent': 'T1497 (Virtualization/Sandbox Evasion)'
}

Packer_sections = [b'.upx', b'.aspack', b'nspack', b'.themida', b'.vmp']

class PEExtractor:
    def __init__(self, raw_bytes: bytes):
        self.raw_bytes = raw_bytes
        self.pe = None
        self.is_valid_pe = ""

        try:
            self.pe = pefile.PE(data=raw_bytes, fast_load=True)
            self.pe.parse_data_directories()
            self.is_valid_pe = True
        except pefile.PEFormatError:
            self.error_msg = "Not a valid PE file, skiping structural analysis."

        except Exception as e :
            self.error_msg = f"Unexpeected error during PE parsing: {str(e)}"
            logger.error(self.error_msg)

    def _calculate_entropy(self, data: bytes) -> float:
        if not data:
            return 0.0
        entropy = 0
        for x in range(256):
            p_x = float(data.count(x)) / len(data)
            if p_x > 0:
                entropy += - p_x * math.log(p_x, 2)
        return entropy
    
    def get_hashes(self) -> dict:
        ###
        return{
            "MD5": hashlib.md5(self.raw_bytes).hexdigest(),
            "SHA256": hashlib.sha256(self.raw_bytes).hexdigest()
        }
    
    def analyze_and_extract_fearures(self) -> dict:
        if not self.is_valid_pe:
            return None, {"error": self.error_msg}

        entropy_list = []
        imports_count = 0
        suspicous_imports_count = 0
        sections_count = self.pe.FILE_HEADER.NumberOfSections
        suspicious_sections_count = 0
        has_tls = 0
        has_debug = 0
        has_reloc = 0
        dll_characteristics_anomalies = 0

        mitre_hits = {}
        detected_packers = []

        for section in self.pe.sections:
            sec_name = section.Name.rstrip(b'\x00').lower()
            sec_data = section.get_data()
            ent = self._calculate_entropy(sec_data)
            entropy_list.append(ent)

            if ent > 7.0 or sec_name in Packer_sections:
                suspicious_sections_count += 1
                if sec_name in Packer_sections:
                    detected_packers.append(sec_name.decode('utf-8', errors='ignore'))
            
            if section.Characteristics & 0xE0000000 == 0xE0000000:
                suspicious_sections_count += 1

        entropy_mean = sum(entropy_list) / len(entropy_list) if entropy_list else 0.0
        entropy_max  =max(entropy_list) if entropy_list else 0.0

        is_packed_heuristic = 1 if entropy_max > 7.2 or suspicious_sections_count > 0 else 0

        if hasattr(self.pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    imports_count += 1
                    if imp.name and imp.name in Suspicous_Apis:
                        suspicous_imports_count += 1
                        tactic = Suspicous_Apis[imp.name]
                        api_name =imp.name.decode('utf-8', errors='ignore')
                        if tactic not in mitre_hits:
                            mitre_hits[tactic] = []
                        mitre_hits[tactic].append(api_name)
        
        exports_count = len(self.pe.DIRECTORY_ENTRY_EXPORT.symbols) if hasattr(self.pe, 'DIRECTORY_ENTRY_EXPORT') else 0
        opt_header_size = self.pe.FILE_HEADER.SizeOfOptionalHeader
        file_size_bytes = len(self.raw_bytes)
        overlay_size = self.pe.get_overlay_data_start_offset()
        overlay_size = file_size_bytes - overlay_size if overlay_size else 0

        if hasattr(self.pe, 'Optional_Header'):
            has_debug = 1 if self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[6].Size > 0 else 0
            has_tls = 1 if self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[9].Size > 0 else 0 
            has_reloc = 1 if self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[5].Size > 0 else 0

            if self.pe.OPTIONAL_HEADER.DllCharacteristics == 0:
                dll_characteristics_anomalies = 1

        
        ml_features = {
            'entropy_mean': entropy_mean,
            'entropy_max': entropy_max,
            'imports_count': imports_count,
            'suspicious_imports_count': suspicous_imports_count,
            'exports_count': exports_count,
            'sections_count': sections_count,
            'suspicious_sections_count': suspicious_sections_count,
            'opt_header_size': opt_header_size,
            'has_debug_data': has_debug,
            'has_relocations': has_reloc,
            'has_tls': has_tls,
            'is_packed_heuristic': is_packed_heuristic,
            'dll_characteristics_anomalies': dll_characteristics_anomalies,
            'file_size_bytes': file_size_bytes,
            'overlay_size': overlay_size
        }

        ui_metadata = {
            "hashes": self.get_hashes(),
            "mitre_hits": mitre_hits,
            "detected_packers": list(set(detected_packers)),
            "is_packed": bool(is_packed_heuristic)
        }
        return ml_features, ui_metadata