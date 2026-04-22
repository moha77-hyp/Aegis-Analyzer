import math
from collections import Counter

class MathEngine:
    @staticmethod
    def calculate_shannon_entropy(data: bytes) -> float:
        ####
        if not data:
            return 0.0
        
        entropy = 0.0
        length = len(data)

        occurrences = Counter(data)

        occurrences = Counter(data)

        for count in occurrences.values():
            probaility = count / length
            entropy -= probaility * math.log2(probaility)
        
        return entropy