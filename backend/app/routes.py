from fastapi import APIRouter
from app.model import predict_anomaly
from datetime import datetime

logs=[]
recent_activity=[]

router = APIRouter()

@router.post("/predict")
def predict(data: dict):
    result = predict_anomaly(data)

    log_entry = {
        "timestamp": datetime.now().isoformat(),
        "packet_count": data["packet_count"],
        "avg_packet_size": data["avg_packet_size"],
        "unique_ips": data["unique_ips"],
        "protocol": data["protocol"],
        "anomaly": result["anomaly"],
        "confidence": result["score"]
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

    log_entry["threat_level"] = threat_level
    log_entry["reason"] = result["reason"]
    return log_entry

@router.get("/logs")
def get_logs():
    return logs
