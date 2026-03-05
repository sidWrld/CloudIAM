from flask import Flask, request, jsonify
import datetime

app = Flask(__name__)

@app.route("/analyze", methods=["POST"])
def analyze_traffic():
    data = request.get_json()
    traffic_summary = data.get("traffic_summary", {})

    total_packets = traffic_summary.get("total_packets", 0)

    mock_response = {
        "timestamp": datetime.datetime.utcnow().isoformat(),
        "anomaly_detected": total_packets > 50,
        "risk_score": 0.85 if total_packets > 50 else 0.2,
        "anomaly_type": "High Traffic Volume",
        "recommended_action": "Investigate network activity"
    }

    return jsonify(mock_response)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)