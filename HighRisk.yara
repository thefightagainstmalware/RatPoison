rule HighRisk 
{
    meta:
        author = "PandaNinjas & Golden Doge"
        date="2022/05/24"
    
    strings:
        $webhook_url = /(https?):\/\/((ptb\.|canary\.)?discord(app)?\.com)\/api(\/)?(v\d{1,2})?\/webhooks\/(\d{17,19})\/([\w\-]{68})/ ascii wide nocase
        $breadcat_url = "http://api.breadcat.cc:80"
        $pizza_session_protection = "qolskyblockmod.pizzaclient.features.misc.SessionProtection"
        $session_id = "func_148254_d"
        $session_id_2 = "func_111286_b"
        $breadcat = "BreadOS/69.420"
        $breadcat_2 = "Forge Mod Handler"
        $stealing_discord_info = /https:\/\/discordapp.com\/api\/v\d\/users\/@me/ ascii wide nocase
        $chrome = "\\Google\\Chrome\\User Data\\Default"
        $opera = "\\Opera Software\\Opera Stable"
        $brave = "\\BraveSoftware\\Brave-Browser\\User Data\\Default"
        $yandex = "\\Yandex\\YandexBrowser\\User Data\\Default"
        $hibp = "https://haveibeenpwned.com/unifiedsearch/"

    condition:
        any of them
}
