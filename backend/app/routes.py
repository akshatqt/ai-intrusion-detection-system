from fastapi import APIRouter
from app.model import predict_anomaly
from datetime import datetime

logs=[]

router = APIRouter()

@router.post("/post")
def predict(data:dict):
    result = predict_anomaly(data)

    return{
        "input":data,
        "result":result
    }

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

    # Attach geolocation data if provided by the core pipeline
    if "threat_source_ip" in data:
        log_entry["threat_source_ip"] = data["threat_source_ip"]
        log_entry["threat_source_country"] = data.get("threat_source_country", "Unknown")
        log_entry["threat_source_city"] = data.get("threat_source_city", "Unknown")
        log_entry["threat_source_lat"] = data.get("threat_source_lat", 0.0)
        log_entry["threat_source_lon"] = data.get("threat_source_lon", 0.0)
        log_entry["threat_source_isp"] = data.get("threat_source_isp", "Unknown")

    logs.append(log_entry)

    return log_entry

@router.get("/logs")
def get_logs():
    return logs
