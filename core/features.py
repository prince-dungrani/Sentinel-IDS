import time

def parse_http(payload):
    try:
        lines = payload.split("\r\n")
        request_line = lines[0].split(" ")

        method = request_line[0]
        uri = request_line[1]

        headers = {}
        for line in lines[1:]:
            if ":" in line:
                key, value = line.split(":", 1)
                headers[key.strip().lower()] = value.strip()

        return {
            "method": method,
            "uri": uri,
            "user_agent": headers.get("user-agent", "")
        }
    except:
        return {}


def extract_features(packet):
    features = {}

    features["src_ip"] = packet.get("src_ip")
    features["dst_ip"] = packet.get("dst_ip")
    features["protocol"] = packet.get("protocol")
    features["dst_port"] = packet.get("dst_port")
    features["timestamp"] = time.time()
    features["payload"] = packet.get("payload", "")
    features["flags"] = packet.get("flags", "")

    # 🔥 HTTP Parsing
    if features["dst_port"] == 80:
        http_data = parse_http(features["payload"])
        features.update(http_data)

    # 🔥 DNS detection (basic)
    if features["dst_port"] == 53:
        features["dns_query"] = features["payload"]

    return features