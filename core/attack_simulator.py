"""
Attack Simulator
----------------
Generates synthetic "attack" traffic to test the pipeline + geo tracking
WITHOUT needing sudo or actual network floods.

Sends crafted feature payloads directly to the backend /predict endpoint,
simulating what the real pipeline would send during:
    1. Normal traffic      (domestic IPs)
    2. Flood / DDoS attack (high packet_count, foreign IPs)
    3. Port scan           (many unique IPs, foreign IPs)

Now includes threat source geolocation data for each attack.

Usage:
    uv run python attack_simulator.py [--api http://127.0.0.1:8000/predict]
"""

import argparse
import random
import time

import requests
from geo_lookup import geolocate_ip

# ── colours ──────────────────────────────────────────────────────
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
MAGENTA = "\033[95m"
RESET = "\033[0m"
BOLD = "\033[1m"

# ── realistic IPs for simulation ─────────────────────────────────
# These are well-known public IPs from various countries
NORMAL_IPS = [
    "8.8.8.8",          # Google DNS — US
    "1.1.1.1",          # Cloudflare — US
    "208.67.222.222",   # OpenDNS — US
]

ATTACK_IPS = [
    "203.0.113.50",     # TEST-NET-3 (documentation range)
    "185.220.101.1",    # Known Tor exit node (Germany)
    "45.33.32.156",     # Scanme.nmap.org (US)
    "91.189.88.142",    # Canonical (UK)
    "5.255.255.50",     # Yandex (Russia)
    "104.16.132.229",   # Cloudflare (US)
    "220.181.38.148",   # Baidu (China)
    "93.184.216.34",    # Example.com (EU)
]


# ── traffic profiles ─────────────────────────────────────────────

def _add_geo(payload: dict, ip: str) -> dict:
    """Attach geolocation data for the given IP to the payload."""
    geo = geolocate_ip(ip)
    payload["threat_source_ip"] = ip
    payload["threat_source_country"] = geo["country"]
    payload["threat_source_city"] = geo["city"]
    payload["threat_source_lat"] = geo["lat"]
    payload["threat_source_lon"] = geo["lon"]
    payload["threat_source_isp"] = geo["isp"]
    return payload


def normal_traffic() -> dict:
    """Simulate a typical 1-second window of benign traffic."""
    payload = {
        "packet_count": random.randint(80, 150),
        "avg_packet_size": round(random.uniform(400, 600), 2),
        "unique_ips": random.randint(3, 8),
        "protocol": random.choice(["TCP", "UDP"]),
    }
    return _add_geo(payload, random.choice(NORMAL_IPS))


def flood_attack() -> dict:
    """Simulate a DDoS / ping flood — huge packet count, foreign sources."""
    payload = {
        "packet_count": random.randint(2000, 8000),
        "avg_packet_size": round(random.uniform(60, 128), 2),
        "unique_ips": random.randint(1, 3),
        "protocol": "ICMP",
    }
    return _add_geo(payload, random.choice(ATTACK_IPS))


def port_scan() -> dict:
    """Simulate a port scan — many unique IPs, small packets."""
    payload = {
        "packet_count": random.randint(300, 600),
        "avg_packet_size": round(random.uniform(40, 80), 2),
        "unique_ips": random.randint(30, 100),
        "protocol": "TCP",
    }
    return _add_geo(payload, random.choice(ATTACK_IPS))


PROFILES = {
    "normal": normal_traffic,
    "flood": flood_attack,
    "scan": port_scan,
}


def send_payload(payload: dict, api_url: str):
    """Send a feature payload and print the response with location."""
    try:
        resp = requests.post(api_url, json=payload, timeout=5)
        result = resp.json()

        anomaly = result.get("anomaly", False)
        score = result.get("confidence", result.get("score", "?"))
        message = result.get("message", "")

        if anomaly:
            tag = f"{RED}{BOLD}🚨 ANOMALY{RESET}"
        else:
            tag = f"{GREEN}✅ NORMAL{RESET}"

        # Location info
        loc = f"{payload.get('threat_source_city', '?')}, {payload.get('threat_source_country', '?')}"
        ip = payload.get("threat_source_ip", "?")

        print(
            f"  packets={payload['packet_count']:>5}  "
            f"avg_size={payload['avg_packet_size']:>7}  "
            f"ips={payload['unique_ips']:>3}  "
            f"proto={payload['protocol']:<5}  "
            f"→ {tag}  score={score}"
        )
        print(
            f"    {MAGENTA}📍 {ip} → {loc}{RESET}  "
            f"{message}"
        )
    except Exception as e:
        print(f"{RED}  Error: {e}{RESET}")


def run_simulation(api_url: str):
    """Run through attack scenarios with geolocation."""
    print(f"\n{BOLD}{CYAN}{'=' * 65}{RESET}")
    print(f"{BOLD}{CYAN}  Attack Simulator — Predictions + Geo Tracking{RESET}")
    print(f"{BOLD}{CYAN}{'=' * 65}{RESET}")
    print(f"  Backend: {api_url}")
    print(f"  Geo:     ip-api.com (live lookups)\n")

    # Phase 1: Normal traffic
    print(f"{BOLD}▸ Phase 1: Normal Traffic (5 windows){RESET}")
    for _ in range(5):
        send_payload(normal_traffic(), api_url)
        time.sleep(0.3)

    print()

    # Phase 2: Flood attack from foreign IPs
    print(f"{BOLD}▸ Phase 2: Flood / DDoS Attack from Foreign IPs (5 windows){RESET}")
    for _ in range(5):
        send_payload(flood_attack(), api_url)
        time.sleep(0.3)

    print()

    # Phase 3: Port scan from foreign IPs
    print(f"{BOLD}▸ Phase 3: Port Scan from Foreign IPs (5 windows){RESET}")
    for _ in range(5):
        send_payload(port_scan(), api_url)
        time.sleep(0.3)

    print()

    # Phase 4: Mixed (random)
    print(f"{BOLD}▸ Phase 4: Mixed Traffic (10 windows){RESET}")
    for _ in range(10):
        profile = random.choice(list(PROFILES.values()))
        send_payload(profile(), api_url)
        time.sleep(0.3)

    print(f"\n{CYAN}{'=' * 65}{RESET}")
    print(f"{GREEN}  Simulation complete!{RESET}\n")


def main():
    parser = argparse.ArgumentParser(description="Simulate network attacks with geo tracking")
    parser.add_argument(
        "--api",
        default="http://127.0.0.1:8000/predict",
        help="Backend prediction endpoint URL.",
    )
    args = parser.parse_args()
    run_simulation(api_url=args.api)


if __name__ == "__main__":
    main()
