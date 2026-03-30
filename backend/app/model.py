from sklearn.ensemble import IsolationForest
import random

model = IsolationForest(contamination=0.01)

training_data=[]
for i in range(100):
    packet_count = random.randint(80, 150)
    avg_packet_size = random.randint(450, 550)
    unique_ips = random.randint(3, 8)
    protocol = random.choice([1, 2]) 

    training_data.append([
        packet_count,
        avg_packet_size,
        unique_ips,
        protocol
    ])

model.fit(training_data)

def  predict_anomaly(data):
    features = [
        data["packet_count"],
        data["avg_packet_size"],
        data["unique_ips"],
        1 if data["protocol"] == "TCP" else 2 if data["protocol"] == "UDP" else 3
    ]

    prediction = model.predict([features])[0]
    score = model.decision_function([features])[0]
    print("DEBUG:", data["packet_count"], data["unique_ips"])


    #hardcoded values , incase of overnight hype
    if data["packet_count"] > 800 :
        print("HIGH TRAFFIC DETECTED")
        if data["unique_ips"] > 20:
            print("RULE: FEW IPS → ATTACK")
            return{
                "anomaly":False,
                "score":round(score,3),
                "message": "normal traffic",
                "reason": "High packet_count with high unique_ips (many users)"
            }
        
        else:
            print("RULE: MANY IPS → NORMAL")
            return{
                "anomaly":True,
                "score":round(abs(score),3),
                "message": "suspicious traffic detected",
                "reason": "High packet_count with very low unique_ips (possible DDoS)"
            } 

    if prediction == - 1:
        return {
            "anomaly":True,
            "score":round(abs(score),3),
            "message":"suspicious traffic detected",
            "reason": "Pattern deviates significantly from learned normal behavior"
        }
    
    else:
        return {
            "anomaly":False,
            "score":round(score,3),
            "message":"normal traffic",
            "reason": "Traffic pattern matches learned baseline"
        }
