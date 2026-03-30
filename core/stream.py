"""
Stream — Main Pipeline
----------------------
Ties together packet capture → feature extraction → geo lookup → backend API.

Usage:
    sudo uv run python stream.py [--iface en0] [--api http://127.0.0.1:8000/predict]

Runs an infinite loop:
    1. Wait 1 second  (time window)
    2. Drain captured packets
    3. Extract features + identify top source IP
    4. Geolocate the threat source
    5. POST features + geo data to backend /predict
    6. Print prediction result with location
"""

import argparse
import sys
import time

import requests

from packet_capture import PacketCapture
from feature_engineering import extract_features
from geo_lookup import geolocate_ip, geolocate_top_sources

# ── colours for terminal output ──────────────────────────────────
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
MAGENTA = "\033[95m"
RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"


def send_to_backend(payload: dict, api_url: str) -> dict | None:
    """POST features JSON to the backend and return the response."""
    try:
        resp = requests.post(api_url, json=payload, timeout=5)
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
    """Main loop: capture → extract → geolocate → send → print, every 1 second."""
    capture = PacketCapture()
    capture.start(iface=iface)

    print(f"{BOLD}{CYAN}{'=' * 60}{RESET}")
    print(f"{BOLD}{CYAN}  AI Intrusion Detection — Packet Pipeline + Geo Tracking{RESET}")
    print(f"{BOLD}{CYAN}{'=' * 60}{RESET}")
    print(f"  Interface : {iface or 'default'}")
    print(f"  Backend   : {api_url}")
    print(f"  Window    : 1 second")
    print(f"  Geo       : ip-api.com (cached)")
    print(f"{CYAN}{'=' * 60}{RESET}\n")

    try:
        while True:
            time.sleep(1)  # 1-second time window

            packets = capture.drain()
            features = extract_features(packets)

            if features is None:
                print(f"{YELLOW}[Window] No IP packets captured{RESET}")
                continue

            # ── Geolocate the top source IP ──────────────────────
            top_ip = features.pop("top_source_ip", None)
            geo_data = {}
            if top_ip:
                geo = geolocate_ip(top_ip)
                geo_data = {
                    "threat_source_ip": top_ip,
                    "threat_source_country": geo["country"],
                    "threat_source_city": geo["city"],
                    "threat_source_lat": geo["lat"],
                    "threat_source_lon": geo["lon"],
                    "threat_source_isp": geo["isp"],
                }

            # ── Build full payload (features + geo) ──────────────
            payload = {**features, **geo_data}

            # ── Pretty-print features ────────────────────────────
            print(
                f"{CYAN}[Features]{RESET}  "
                f"packets={features['packet_count']}  "
                f"avg_size={features['avg_packet_size']}  "
                f"ips={features['unique_ips']}  "
                f"proto={features['protocol']}"
            )

            if geo_data:
                loc = f"{geo_data['threat_source_city']}, {geo_data['threat_source_country']}"
                print(
                    f"{MAGENTA}[GeoTrace]{RESET}  "
                    f"ip={top_ip}  "
                    f"loc={loc}  "
                    f"coords=({geo_data['threat_source_lat']}, {geo_data['threat_source_lon']})  "
                    f"isp={geo_data['threat_source_isp']}"
                )

            # ── Send to backend ──────────────────────────────────
            result = send_to_backend(payload, api_url)
            if result is None:
                continue

            # ── Colour-coded prediction ──────────────────────────
            anomaly = result.get("anomaly", False)
            score = result.get("confidence", result.get("score", "?"))
            message = result.get("message", "")

            if anomaly:
                tag = f"{RED}{BOLD}🚨 ANOMALY{RESET}"
                # Extra emphasis on anomaly location
                if geo_data and geo_data["threat_source_country"] != "Local Network":
                    print(
                        f"  {RED}⚠  THREAT SOURCE: {geo_data['threat_source_city']}, "
                        f"{geo_data['threat_source_country']} "
                        f"({geo_data['threat_source_ip']}){RESET}"
                    )
            else:
                tag = f"{GREEN}✅ NORMAL{RESET}"

            print(f"  → {tag}  score={score}  {message}\n")

    except KeyboardInterrupt:
        print(f"\n{YELLOW}[Stream] Shutting down…{RESET}")
    finally:
        capture.stop()


def main():
    parser = argparse.ArgumentParser(
        description="Packet capture → feature extraction → geo tracking → anomaly detection pipeline"
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
