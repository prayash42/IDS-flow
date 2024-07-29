import pyshark

def capture_packets(interface='eth0', duration=60):
    capture = pyshark.LiveCapture(interface=interface)
    capture.sniff(timeout=duration)
    return capture
