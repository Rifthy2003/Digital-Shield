import re
from fastapi import Request


def parse_device_name(user_agent: str | None) -> str:
    """Derive a friendly, safe device and browser name from User-Agent without fingerprinting."""
    if not user_agent:
        return "Unknown Device"

    ua = user_agent.lower()

    # Detect Operating System
    os_name = "Unknown OS"
    if "windows nt 10.0" in ua or "windows nt 11.0" in ua or "windows" in ua:
        os_name = "Windows"
    elif "macintosh" in ua or "mac os x" in ua:
        os_name = "macOS"
    elif "android" in ua:
        os_name = "Android"
    elif "iphone" in ua or "ipad" in ua:
        os_name = "iOS"
    elif "linux" in ua:
        os_name = "Linux"

    # Detect Browser or Client
    client_name = "Web Browser"
    if "edg/" in ua:
        client_name = "Edge"
    elif "chrome/" in ua and "chromium" not in ua and "edg/" not in ua:
        client_name = "Chrome"
    elif "firefox/" in ua:
        client_name = "Firefox"
    elif "safari/" in ua and "chrome/" not in ua:
        client_name = "Safari"
    elif "inforashield" in ua:
        client_name = "Infora App"

    if os_name != "Unknown OS":
        return f"{client_name} on {os_name}"[:128]
    return client_name[:128]


def extract_client_metadata(request: Request) -> dict[str, str | None]:
    """
    Safely extract client metadata from request headers.
    Ensures safe bounded string lengths and prevents malicious header payload storage.
    """
    headers = request.headers

    # 1. User Agent (capped at 512 characters)
    raw_ua = headers.get("user-agent")
    user_agent = raw_ua.strip()[:512] if raw_ua else None

    # 2. Client Type (web / mobile / tablet)
    header_client_type = headers.get("x-client-type")
    if header_client_type and header_client_type.lower() in {"web", "mobile", "tablet"}:
        client_type = header_client_type.lower()[:32]
    elif user_agent and any(m in user_agent.lower() for m in ["mobile", "android", "iphone", "ipad"]):
        client_type = "mobile"
    else:
        client_type = "web"

    # 3. Device Name (capped at 128 characters)
    header_device_name = headers.get("x-device-name")
    if header_device_name:
        # Sanitize non-standard characters from client-provided device names
        sanitized = re.sub(r"[^\w\s\.\-\(\)]", "", header_device_name).strip()
        device_name = (sanitized[:128] if sanitized else "Mobile Device")
    else:
        device_name = parse_device_name(user_agent)

    # 4. IP Address (capped at 64 characters)
    ip_address = None
    forwarded = headers.get("x-forwarded-for")
    if forwarded:
        first_ip = forwarded.split(",")[0].strip()
        ip_address = first_ip[:64] if first_ip else None
    elif request.client and request.client.host:
        ip_address = request.client.host[:64]

    return {
        "user_agent": user_agent,
        "client_type": client_type,
        "device_name": device_name,
        "ip_address": ip_address,
    }
