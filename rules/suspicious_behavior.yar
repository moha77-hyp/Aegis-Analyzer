rule Suspicious_Process_Injection {
    meta:
        description = "Detects classic Process Injection API calls"
        author = "Aegis Analyzer"
        severity = "High"

    strings:
        $api1 = "VirtualAllocEx" ascii wide
        $api2 = "WriteProcessMemory" ascii wide
        $api3 = "CreateRemoteThread" ascii wide

    condition:
        2 of them
}

rule Crypto_Wallet_Hunter {
    meta:
        description = "Detects files looking for crypto wallets"
        severity = "Medium"

    strings:
        $wallet1 = "wallet.dat" ascii wide
        $str1 = "bitcoin" nocase ascii wide

    condition:
        any of them
}