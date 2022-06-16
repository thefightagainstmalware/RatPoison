rule LowRisk
{
    meta:
        author = "PandaNinjas & Golden Doge"
        date="2022/05/23"
    
    strings:
        $hwid = "HWID"
        $appdata = "\"APPDATA\""

    condition:
        any of them
}