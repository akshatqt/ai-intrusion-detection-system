"""
Attack Simulator
----------------
Generates synthetic "attack" traffic to test the pipeline
WITHOUT needing sudo or actual network floods.

Sends crafted feature payloads directly to the backend /predict endpoint,
simulating what the real pipeline would send during:
    1. Normal traffic
    2. Flood / DDoS attack  (high packet_count, few unique IPs)
    3. Port scan            (many unique IPs, low packet counts)

Usage:
    uv run python attack_simulator.py [--api http://127.0.0.1:8000/predict]
"""

import argparse
import random
import time

import requests

# ── colours ──────────────────────────────────────────────────────
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
RESET = "\033[0m"
BOLD = "\033[1m"

# ── traffic profiles ─────────────────────────────────────────────

def normal_traffic() -> dict:
    """Simulate a typical 1-second window of benign traffic."""
    return {
        "packet_count": random.randint(80, 150),
        "avg_packet_size": round(random.uniform(400, 600), 2),
        "unique_ips": random.randint(3, 8),
        "protocol": random.choice(["TCP", "UDP"]),
    }


def flood_attack() -> dict:
    """Simulate a DDoS / ping flood — huge packet count, few sources."""
    return {
        "packet_count": random.randint(2000, 8000),
        "avg_packet_size": round(random.uniform(60, 128), 2),
        "unique_ips": random.randint(1, 3),
        "protocol": "ICMP",
    }


def port_scan() -> dict:
    """Simulate a port scan — many unique IPs, small packets."""
    return {
        "packet_count": random.randint(300, 600),
        "avg_packet_size": round(random.uniform(40, 80), 2),
        "unique_ips": random.randint(30, 100),
        "protocol": "TCP",
    }


PROFILES = {
    "normal": normal_traffic,
    "flood": flood_attack,
    "scan": port_scan,
}


def send_payload(payload: dict, api_url: str):
    """Send a feature payload and print the response."""
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

        threat = result.get("threat_level", "UNKNOWN")
        reason = result.get("reason", "")

        print(
            f"  packets={payload['packet_count']:>5}  "
            f"avg_size={payload['avg_packet_size']:>7}  "
            f"ips={payload['unique_ips']:>3}  "
            f"proto={payload['protocol']:<5}  "
            f"→ {tag}  score={score}  threat={threat}  {message}\n"
            f"     reason: {reason}"
        )

    except Exception as e:
        print(f"{RED}  Error: {e}{RESET}")


def run_simulation(api_url: str):
    """Run through attack scenarios."""
    print(f"\n{BOLD}{CYAN}{'=' * 60}{RESET}")
    print(f"{BOLD}{CYAN}  Attack Simulator — Testing Backend Predictions{RESET}")
    print(f"{BOLD}{CYAN}{'=' * 60}{RESET}")
    print(f"  Backend: {api_url}\n")

    # Phase 1: Normal traffic (5 seconds)
    print(f"{BOLD}▸ Phase 1: Normal Traffic (5 windows){RESET}")
    for _ in range(5):
        send_payload(normal_traffic(), api_url)
        time.sleep(0.3)

    print()

    # Phase 2: Flood attack (5 seconds)
    print(f"{BOLD}▸ Phase 2: Flood / DDoS Attack (5 windows){RESET}")
    for _ in range(5):
        send_payload(flood_attack(), api_url)
        time.sleep(0.3)

    print()

    # Phase 3: Port scan (5 seconds)
    print(f"{BOLD}▸ Phase 3: Port Scan (5 windows){RESET}")
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

    print(f"\n{CYAN}{'=' * 60}{RESET}")
    print(f"{GREEN}  Simulation complete!{RESET}\n")


def main():
    parser = argparse.ArgumentParser(description="Simulate network attacks against the IDS backend")
    parser.add_argument(
        "--api",
        default="http://127.0.0.1:8000/predict",
        help="Backend prediction endpoint URL.",
    )
    args = parser.parse_args()
    run_simulation(api_url=args.api)


if __name__ == "__main__":
    main()
