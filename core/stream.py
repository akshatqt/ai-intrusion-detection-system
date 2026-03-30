"""
Stream — Main Pipeline
----------------------
Ties together packet capture → feature extraction → backend API.

Usage:
    sudo uv run python stream.py [--iface en0] [--api http://127.0.0.1:8000/predict]

Runs an infinite loop:
    1. Wait 1 second  (time window)
    2. Drain captured packets
    3. Extract features
    4. POST features to backend /predict
    5. Print prediction result
"""

import argparse
import sys
import time

import requests

from packet_capture import PacketCapture
from feature_engineering import extract_features

# ── colours for terminal output ──────────────────────────────────
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
RESET = "\033[0m"
BOLD = "\033[1m"


def send_to_backend(features: dict, api_url: str) -> dict | None:
    """POST features JSON to the backend and return the response."""
    try:
        resp = requests.post(api_url, json=features, timeout=5)
        resp.raise_for_status()
        return resp.json()
    except requests.ConnectionError:
        print(f"{RED}[Stream] Backend unreachable at {api_url}{RESET}")
    except requests.Timeout:
        print(f"{YELLOW}[Stream] Backend timed out{RESET}")
    except Exception as e:
        print(f"{RED}[Stream] Request error: {e}{RESET}")
    return None


def run_pipeline(iface: str | None, api_url: str):
    """Main loop: capture → extract → send → print, every 1 second."""
    capture = PacketCapture()
    capture.start(iface=iface)

    print(f"{BOLD}{CYAN}{'=' * 55}{RESET}")
    print(f"{BOLD}{CYAN}  AI Intrusion Detection — Packet Pipeline{RESET}")
    print(f"{BOLD}{CYAN}{'=' * 55}{RESET}")
    print(f"  Interface : {iface or 'default'}")
    print(f"  Backend   : {api_url}")
    print(f"  Window    : 1 second")
    print(f"{CYAN}{'=' * 55}{RESET}\n")

    try:
        while True:
            time.sleep(1)  # 1-second time window

            packets = capture.drain()
            features = extract_features(packets)

            if features is None:
                print(f"{YELLOW}[Window] No IP packets captured{RESET}")
                continue

            # Pretty-print features
            print(
                f"{CYAN}[Features]{RESET}  "
                f"packets={features['packet_count']}  "
                f"avg_size={features['avg_packet_size']}  "
                f"ips={features['unique_ips']}  "
                f"proto={features['protocol']}"
            )

            # Send to backend
            result = send_to_backend(features, api_url)
            if result is None:
                continue

            # Colour-coded prediction
            anomaly = result.get("anomaly", False)
            score = result.get("confidence", result.get("score", "?"))
            message = result.get("message", "")

            if anomaly:
                tag = f"{RED}{BOLD}🚨 ANOMALY{RESET}"
            else:
                tag = f"{GREEN}✅ NORMAL{RESET}"

            print(f"  → {tag}  score={score}  {message}\n")

    except KeyboardInterrupt:
        print(f"\n{YELLOW}[Stream] Shutting down…{RESET}")
    finally:
        capture.stop()


def main():
    parser = argparse.ArgumentParser(
        description="Packet capture → feature extraction → anomaly detection pipeline"
    )
    parser.add_argument(
        "--iface",
        default=None,
        help="Network interface to sniff (e.g. en0, eth0). Default: all.",
    )
    parser.add_argument(
        "--api",
        default="http://127.0.0.1:8000/predict",
        help="Backend prediction endpoint URL.",
    )
    args = parser.parse_args()

    run_pipeline(iface=args.iface, api_url=args.api)


if __name__ == "__main__":
    main()
