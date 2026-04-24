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