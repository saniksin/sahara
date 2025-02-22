import re
import requests
import base64
import json


def compute_version():
    res = requests.get(
        "https://updates.discord.com/distributions/app/manifests/latest",
        params={"install_id": "0", "channel": "stable", "platform": "win", "arch": "x86"},
        headers={"user-agent": "Discord-Updater/1", "accept-encoding": "gzip"},
        timeout=10
    ).json()
    return int(res["metadata_version"])


def assemble_build():
    pg = requests.get("https://discord.com/app", timeout=10).text
    found = re.findall(r'src="/assets/([^"]+)"', pg)
    for f in reversed(found):
        jsn = requests.get(f"https://discord.com/assets/{f}", timeout=10).text
        if "buildNumber:" in jsn:
            return int(jsn.split('buildNumber:"')[1].split('"')[0])
    return -1


def create_x_super_properties(
        user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
        client_build_number=359425,
        native_build_number=1
    ) -> str:

    return base64.b64encode(json.dumps({
        "os": "Windows",
        "browser": "Chrome",
        "device": "",
        "system_locale": "en-US",
        "browser_user_agent": user_agent,
        "browser_version": "131.0.0.0",
        "os_version": "10",
        "referrer": "",
        "referring_domain": "",
        "referrer_current": "https://discord.com/",
        "referring_domain_current": "discord.com",
        "release_channel": "stable",
        "client_build_number": client_build_number,
        "native_build_number": native_build_number,
        "client_event_source": None
    }, separators=(',', ':')).encode('utf-8')).decode('utf-8')


def create_x_context_properties(location_guild_id: str, location_channel_id: str) -> str:
    return base64.b64encode(json.dumps({
        "location": "Join Guild",
        "location_guild_id": location_guild_id,
        "location_channel_id": location_channel_id,
        "location_channel_type": 0
    }, separators=(',', ':')).encode('utf-8')).decode('utf-8')
