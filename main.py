import multiprocessing
import sys
import signal
from core.sniffer import PacketSniffer
from core.protocol_parser import ProtocolParser
from core.flow_manager import FlowManager
from core import detector
from core.logger import IDSLogger
from core.tcp_tracker import TCPTracker

def process_packets(queue):
    """Worker process to analyze packets in parallel."""
    # Ignore CTRL+C in worker processes to avoid messy stack traces.
    # The main process will handle shutting them down.
    signal.signal(signal.SIGINT, signal.SIG_IGN)

    # Instantiate objects per-process to avoid pickling issues
    parser = ProtocolParser()
    flow_manager = FlowManager()
    tcp_tracker = TCPTracker()
    logger = IDSLogger()

    print(f"[Worker] Started process: {multiprocessing.current_process().name}")

    while True:
        try:
            packet_tuple = queue.get()
            
            # features will be None if the packet is not IPv4
            features = parser.parse(packet_tuple)
            
            if not features:
                continue

            flow = flow_manager.update_flow(features)
            features.update(flow)
            
            tcp_state = tcp_tracker.update_state(features)
            if tcp_state:
                features["tcp_state"] = tcp_state

            # DEBUG: See if we are catching HTTP URIs
            if "uri" in features:
                print(f"[*] Worker detected HTTP {features['method']}: {features['uri']}")

            alerts = detector.detect(features)

            for alert in alerts:
                logger.log(alert)
                print(f"[ALERT] {alert['severity']}: {alert['message']} ({alert.get('src_ip', 'Unknown')})")
                
        except Exception as e:
            # Silently drop failed packets to maintain speed
            pass

if __name__ == "__main__":
    
    # Use spawn for cross-platform compatibility (required on Windows)
    multiprocessing.set_start_method('spawn')
    
    print("[*] Starting High-Performance IDS Engine...")
    
    # Create a high-performance multiprocessing queue
    packet_queue = multiprocessing.Queue()

    sniffer = PacketSniffer(packet_queue)

    # Number of worker processes (leave 1 core for the sniffer)
    num_workers = max(1, multiprocessing.cpu_count() - 1)
    
    workers = []
    for i in range(num_workers):
        p = multiprocessing.Process(target=process_packets, args=(packet_queue,))
        p.daemon = True
        p.start()
        workers.append(p)

    print(f"[*] Started {num_workers} packet inspection worker processes.")
    print(f"[*] Capturing on interface: {sniffer.interface}")

    try:
        # Sniffer runs in the main process
        sniffer.start_live_capture()
    except KeyboardInterrupt:
        print("\n[*] Shutting down IDS...")
        for p in workers:
            p.terminate()
            p.join()
        print("[*] All workers stopped safely.")
        sys.exit(0)