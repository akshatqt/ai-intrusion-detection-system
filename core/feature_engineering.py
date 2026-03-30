"""
Feature Engineering Module
--------------------------
Takes a batch of raw packet metadata (from PacketCapture.drain())
and computes the exact features the backend /predict endpoint expects:

    packet_count   : int   – total packets in the window
    avg_packet_size: float – mean packet length
    unique_ips     : int   – number of distinct source IPs
    protocol       : str   – most frequent protocol ("TCP"/"UDP"/"ICMP")
"""

from collections import Counter


def extract_features(packets: list[dict]) -> dict | None:
    """
    Compute features from a 1-second window of packet metadata.

    Parameters
    ----------
    packets : list[dict]
        Each dict has keys: src_ip, dst_ip, protocol, length

    Returns
    -------
    dict with keys packet_count, avg_packet_size, unique_ips, protocol
    or None if the window was empty (nothing to report).
    """
    if not packets:
        return None

    packet_count = len(packets)

    # Average packet size
    total_size = sum(p["length"] for p in packets)
    avg_packet_size = round(total_size / packet_count, 2)

    # Unique source IPs
    unique_ips = len({p["src_ip"] for p in packets})

    # Most frequent protocol
    proto_counts = Counter(p["protocol"] for p in packets)
    protocol = proto_counts.most_common(1)[0][0]

    if protocol not in ["TCP", "UDP", "ICMP"]:
        protocol = "TCP"


    return {
        "packet_count": packet_count,
        "avg_packet_size": avg_packet_size,
        "unique_ips": unique_ips,
        "protocol": protocol,
    }
