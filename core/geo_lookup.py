"""
Geo Lookup Module
-----------------
Resolves IP addresses to geographic locations using the free ip-api.com service.

Features:
    - LRU cache (max 1024 entries) to avoid redundant API calls
    - Skips private / reserved IPs (192.168.x, 10.x, 127.x, etc.)
    - Graceful fallback: returns "Unknown" on any failure
    - Lightweight — no database downloads needed (great for RPi)

Rate limit: ip-api.com allows 45 req/min on free tier.
The cache ensures we rarely hit that in practice.
"""

import ipaddress
from functools import lru_cache

import requests

# Timeout for geo API calls (seconds) — keep short so pipeline isn't stalled
_API_TIMEOUT = 2


def is_private_ip(ip: str) -> bool:
    """Check if an IP is private / reserved (not geolocatable)."""
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return True  # malformed → treat as private


@lru_cache(maxsize=1024)
def _lookup_ip(ip: str) -> dict:
    """
    Query ip-api.com for geolocation data. Cached via LRU.

    Returns a dict with keys:
        country, city, region, lat, lon, isp, org
    All values default to "Unknown" / 0.0 on failure.
    """
    fallback = {
        "country": "Unknown",
        "city": "Unknown",
        "region": "Unknown",
        "lat": 0.0,
        "lon": 0.0,
        "isp": "Unknown",
        "org": "Unknown",
    }

    if is_private_ip(ip):
        fallback["country"] = "Local Network"
        fallback["city"] = "Local"
        return fallback

    try:
        resp = requests.get(
            f"http://ip-api.com/json/{ip}",
            params={"fields": "status,country,city,regionName,lat,lon,isp,org"},
            timeout=_API_TIMEOUT,
        )
        data = resp.json()

        if data.get("status") != "success":
            return fallback

        return {
            "country": data.get("country", "Unknown"),
            "city": data.get("city", "Unknown"),
            "region": data.get("regionName", "Unknown"),
            "lat": float(data.get("lat", 0.0)),
            "lon": float(data.get("lon", 0.0)),
            "isp": data.get("isp", "Unknown"),
            "org": data.get("org", "Unknown"),
        }

    except Exception:
        return fallback


def geolocate_ip(ip: str) -> dict:
    """
    Public API — resolve an IP to its geographic location.

    Returns:
        {
            "ip": "203.0.113.5",
            "country": "China",
            "city": "Beijing",
            "region": "Beijing",
            "lat": 39.9042,
            "lon": 116.4074,
            "isp": "China Telecom",
            "org": "China Telecom",
            "is_private": False
        }
    """
    geo = _lookup_ip(ip)
    return {
        "ip": ip,
        **geo,
        "is_private": is_private_ip(ip),
    }


def geolocate_top_sources(packets: list[dict], top_n: int = 3) -> list[dict]:
    """
    Find the top N source IPs by packet count and geolocate them.

    Parameters
    ----------
    packets : list[dict]
        Raw packet metadata with 'src_ip' key.
    top_n : int
        Number of top sources to geolocate.

    Returns
    -------
    List of geo dicts, one per top source IP, sorted by packet count (desc).
    Each dict includes an extra 'packet_count_from_ip' key.
    """
    if not packets:
        return []

    # Count packets per source IP
    ip_counts: dict[str, int] = {}
    for p in packets:
        src = p.get("src_ip", "")
        if src:
            ip_counts[src] = ip_counts.get(src, 0) + 1

    # Sort by count descending, take top N
    sorted_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:top_n]

    results = []
    for ip, count in sorted_ips:
        geo = geolocate_ip(ip)
        geo["packet_count_from_ip"] = count
        results.append(geo)

    return results
