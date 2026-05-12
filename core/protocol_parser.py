import struct
import socket
import urllib.parse

class ProtocolParser:

    def parse(self, packet_tuple):
        
        timestamp, raw_bytes = packet_tuple
        features = {"timestamp": timestamp}
        
        try:
            # Determine if this is an Ethernet frame (14 bytes) or Loopback/Null frame (4 bytes)
            ip_offset = None
            
            if len(raw_bytes) >= 34:
                eth_header = struct.unpack('!6s6sH', raw_bytes[:14])
                eth_protocol = socket.ntohs(eth_header[2])
                if eth_protocol == 8: # 8 = IPv4
                    ip_offset = 14
                    
            if ip_offset is None and len(raw_bytes) >= 24:
                # Check for Npcap Loopback/Null header (4 bytes)
                # IPv4 starts at byte 4, version nibble is 4
                if (raw_bytes[4] >> 4) == 4:
                    ip_offset = 4
                    
            if ip_offset is None:
                return None
            
            # Parse IPv4 (20 bytes)
            # !BBHHHBBH4s4s
            ip_header = struct.unpack('!BBHHHBBH4s4s', raw_bytes[ip_offset:ip_offset+20])
            
            version_ihl = ip_header[0]
            ihl = version_ihl & 0xF
            ip_header_length = ihl * 4
            
            ttl = ip_header[5]
            protocol = ip_header[6]
            src_ip = socket.inet_ntoa(ip_header[8])
            dst_ip = socket.inet_ntoa(ip_header[9])
            
            features["src_ip"] = src_ip
            features["dst_ip"] = dst_ip
            
            payload_offset = ip_offset + ip_header_length
            
            # TCP
            if protocol == 6:
                features["protocol"] = "TCP"
                tcp_header = struct.unpack('!HHLLBBHHH', raw_bytes[payload_offset:payload_offset+20])
                features["src_port"] = tcp_header[0]
                features["dst_port"] = tcp_header[1]
                features["seq"] = tcp_header[2]
                features["ack"] = tcp_header[3]
                
                # TCP Flags
                flags = tcp_header[5]
                features["flags"] = ""
                if flags & 0x02: features["flags"] += "S"
                if flags & 0x10: features["flags"] += "A"
                if flags & 0x01: features["flags"] += "F"
                if flags & 0x04: features["flags"] += "R"
                if flags & 0x08: features["flags"] += "P"
                
                data_offset = (tcp_header[4] >> 4) * 4
                payload = raw_bytes[payload_offset + data_offset:]
                self._parse_payload(features, payload)
                
            # UDP
            elif protocol == 17:
                features["protocol"] = "UDP"
                udp_header = struct.unpack('!HHHH', raw_bytes[payload_offset:payload_offset+8])
                features["src_port"] = udp_header[0]
                features["dst_port"] = udp_header[1]
                
                payload = raw_bytes[payload_offset + 8:]
                self._parse_payload(features, payload)
                
                # Basic DNS extraction if port 53
                if udp_header[1] == 53 or udp_header[0] == 53:
                    if len(payload) > 12:
                        # Skip DNS header (12 bytes), read QNAME roughly
                        # A true DNS parser is complex, this is a basic heuristic for length
                        qname_len = 0
                        idx = 12
                        while idx < len(payload) and payload[idx] != 0:
                            idx += payload[idx] + 1
                        qname = payload[13:idx].replace(b'\x03', b'.').decode(errors='ignore')
                        features["dns_query"] = qname
                
            # ICMP
            elif protocol == 1:
                features["protocol"] = "ICMP"
                
            return features
            
        except Exception:
            return None

    def _parse_payload(self, features, payload):
        
        if not payload:
            return
            
        decoded = payload.decode(errors="ignore")
        features["payload"] = decoded
        
        if "HTTP" in decoded:
            lines = decoded.split("\r\n")
            if len(lines) > 0:
                request = lines[0].split()
                if len(request) >= 2:
                    features["method"] = request[0]
                    # URL Decode the URI to prevent evasion (e.g. %63%6d%64 -> cmd)
                    features["uri"] = urllib.parse.unquote(request[1])
                    
            for line in lines:
                if line.lower().startswith("host:"):
                    features["host"] = line.split(":",1)[1].strip()
                if line.lower().startswith("user-agent:"):
                    features["user_agent"] = line.split(":",1)[1].strip()