"""
Packet Capture Module
---------------------
Uses Scapy to sniff network packets and store raw metadata
(source IP, destination IP, protocol number, packet length)
into a thread-safe buffer that the feature extractor reads.
"""

import threading
import time
from collections import deque

from scapy.all import sniff, IP, TCP, UDP, ICMP


class PacketCapture:
    """Continuously captures packets in a background thread."""

    def __init__(self):
        # Thread-safe buffer — bounded to prevent memory bloat on RPi
        self._buffer: deque = deque(maxlen=10_000)
        self._lock = threading.Lock()
        self._running = False
        self._thread: threading.Thread | None = None

    # ── public API ───────────────────────────────────────────────

    def start(self, iface: str | None = None):
        """Start sniffing in a daemon thread."""
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(
            target=self._sniff_loop,
            args=(iface,),
            daemon=True,
        )
        self._thread.start()
        print(f"[PacketCapture] Started on interface={iface or 'default'}")

    def stop(self):
        """Signal the sniffer to stop."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=3)
        print("[PacketCapture] Stopped")

    def drain(self) -> list[dict]:
        """
        Atomically drain all buffered packets and return them.
        This is called once per time-window by the feature extractor.
        """
        with self._lock:
            packets = list(self._buffer)
            self._buffer.clear()
        return packets

    # ── internals ────────────────────────────────────────────────

    def _sniff_loop(self, iface: str | None):
        """Blocking sniff loop — runs inside a daemon thread."""
        while self._running:
            try:
                sniff(
                    iface=iface,
                    prn=self._process_packet,
                    store=False,
                    timeout=1,          # yields control every 1 s
                    count=0,            # unlimited within timeout
                )
            except PermissionError:
                print("[PacketCapture] ⚠  Need root / sudo to capture packets!")
                self._running = False
            except Exception as e:
                print(f"[PacketCapture] Error: {e}")
                time.sleep(0.5)

    def _process_packet(self, pkt):
        """Extract lightweight metadata from a single packet."""
        if not pkt.haslayer(IP):
            return

        ip_layer = pkt[IP]

        # Determine protocol name
        if pkt.haslayer(TCP):
            proto = "TCP"
        elif pkt.haslayer(UDP):
            proto = "UDP"
        elif pkt.haslayer(ICMP):
            proto = "ICMP"
        else:
            proto = "OTHER"

        meta = {
            "src_ip": ip_layer.src,
            "dst_ip": ip_layer.dst,
            "protocol": proto,
            "length": len(pkt),
        }

        with self._lock:
            self._buffer.append(meta)
