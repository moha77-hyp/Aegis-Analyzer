import pefile
from core.math_engine import MathEngine

class PEExtractor:
    def __init__(self, file_path: str):
        self.file_path = file_path
        try:
            self.pe = pefile.PE(file_path)
        except pefile.PEFormatError:
            raise ValueError(f"Invalid format: the file '{file_path}' is not a valid Windows PE file.")
        except Exception as e:
            raise Exception(f"Failed to parse file: {str(e)}")
        
    
    def get_basic_info(self) -> dict:
        ####
        return {
            "machine_type": hex(self.pe.FILE_HEADER.Machine),
            "number_of_sections": self.pe.FILE_HEADER.NumberOfSections,
            "timesstamp": self.pe.FILE_HEADER.TimeDateStamp,
        }
    
    def analyze_sections(self) -> list:
        ####
        sections_info = []

        for section in self.pe.sections:
            ####
            section_name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
            section_data = section.get_data()

            entropy = MathEngine.calculate_shannon_entropy(section_data)

            is_suspicious = entropy > 7.2

            sections_info.append({
                "name": section_name,
                "virtual_size": section.Misc_VirtualSize,
                "raw_size": section.SizeOfRawData,
                "entropy": round(entropy, 2),
                "is_suspicious": is_suspicious
            })

        return sections_info
    
    def get_imports(self) -> list:
        ####
        imports_list = []

        if hasattr(self.pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode('utf-8', errors='ignore')

                for imp in entry.imports:
                    if imp.name:
                        if imp.name:
                            func_name = imp.name.decode('utf-8', errors='ignore')
                            imports_list.append({
                                "dll": dll_name,
                                "function": func_name
                            })
        return imports_list