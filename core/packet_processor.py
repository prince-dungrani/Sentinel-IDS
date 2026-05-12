from core.protocol_parser import ProtocolParser
from core.flow_manager import FlowManager
from core.tcp_tracker import TCPTracker
from core.detector import detect
from core.logger import log_alert
from core.alert_manager import AlertManager

parser = ProtocolParser()
flow_manager = FlowManager()
tcp_tracker = TCPTracker()
alert_manager = AlertManager()


class PacketProcessor:

    def process(self, pkt):

        # =========================
        # Parse packet
        # =========================

        features = parser.parse(pkt)

        if not features:
            return

        # =========================
        # Flow tracking
        # =========================

        flow_data = flow_manager.update_flow(features)

        features.update(flow_data)

        # =========================
        # TCP state tracking
        # =========================

        tcp_state = tcp_tracker.update_state(features)

        features["tcp_state"] = tcp_state

        # =========================
        # Detection engine
        # =========================

        alerts = detect(features)

        # =========================
        # Alert management
        # =========================

        for alert in alerts:

            if alert_manager.should_alert(alert):

                log_alert(alert)