import time
from collections import defaultdict

class AlertManager:

    def __init__(self):

        self.alert_history = defaultdict(list)

        # seconds
        self.rate_limit_window = 10

        # max same alerts
        self.max_alerts = 5

    def should_alert(self, alert):

        key = (
            alert.get("message"),
            alert.get("src_ip")
        )

        now = time.time()

        # remove old alerts
        self.alert_history[key] = [
            t for t in self.alert_history[key]
            if now - t < self.rate_limit_window
        ]

        # rate limit
        if len(self.alert_history[key]) >= self.max_alerts:
            return False

        self.alert_history[key].append(now)

        return True