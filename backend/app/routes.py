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

    logs.append(log_entry)

    return log_entry

@router.get("/logs")
def get_logs():
    return logs
