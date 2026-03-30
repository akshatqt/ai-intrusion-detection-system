from fastapi import APIRouter
from app.model import predict_anomaly
from datetime import datetime
import time

logs=[]
probe_active = False
probe_data = []
recent_activity=[]

router = APIRouter()

@router.post("/predict")
def predict(data: dict):
    global probe_active, probe_data
    result = predict_anomaly(data)

    if result["anomaly"] and not probe_active:
        probe_active=True
        probe_data=[]
        time.sleep(1) #giving delay to differentiate between bots and actual human traffic

    if probe_active:
        probe_data.append({
            "packet_count": data["packet_count"],
            "unique_ips": data["unique_ips"]
        })

    if probe_active and len(probe_data) >= 3:
        first = probe_data[0]
        last = probe_data[-1]

        if abs(first["packet_count"] - last["packet_count"]) < 100:
            result["reason"] += " | Probe result: No adaptation → likely bot"
            result["threat_level"] = "CRITICAL"
        else:
            result["reason"] += " | Probe result: Behavior changed → likely human"

        probe_active = False
        probe_data=[]

    log_entry = {
        "timestamp": datetime.now().isoformat(),
        "packet_count": data["packet_count"],
        "avg_packet_size": data["avg_packet_size"],
        "unique_ips": data["unique_ips"],
        "protocol": data["protocol"],
        "anomaly": result["anomaly"],
        "confidence": result["score"],
        "message": result["message"],
        "probe_active": probe_active
    }

    logs.append(log_entry)
    recent_activity.append(log_entry)

    if (len(recent_activity) > 5):
        recent_activity.pop(0)
    anomaly_count = sum(1 for item in recent_activity if item["anomaly"])

    if anomaly_count >= 3:
        threat_level = "CRITICAL"
    elif anomaly_count == 2:
        threat_level = "HIGH"
    elif anomaly_count == 1:
        threat_level = "MEDIUM"
    else:
        threat_level = "LOW"

    
    if "Probe result" in result["reason"]:
        threat_level = "CRITICAL"

    log_entry["threat_level"] = threat_level
    log_entry["reason"] = result["reason"]
    return log_entry

@router.get("/logs")
def get_logs():
    return logs
