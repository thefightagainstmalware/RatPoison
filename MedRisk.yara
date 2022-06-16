rule MedRisk
{
    meta:
        author = "PandaNinjas & Golden Doge"
        date="2022/05/23"

    strings:
        $anonfiles = "https://api.anonfiles.com/upload"
        $check_ip = /https?:\/\/checkip\.amazonaws\.com/
        $java_webhook = "Java-DiscordWebhook-BY-Gelox_"
        $branchlock_watermark = "Branchlock Demo"
        $branchlock_decomp_crasher = "Branchlock"
        $launch_blackboard_attempt = " ey"
        $another_breadcat_string = "SmolPeePeeEnergy"
        $guilded_gg = "media.guilded.gg"
        $heroku = "herokuapp.com"
        $custom_payload = "SKID DOWN"
        $lI_nonsense = /(l|I){8,}/ ascii

    condition:
        any of them
}
