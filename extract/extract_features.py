import pandas as pd
import numpy as np
from collections import defaultdict

class Flow:
    def __init__(self):
        self.timestamps = []
        self.packet_lengths = []
        self.fwd_packet_lengths = []
        self.bwd_packet_lengths = []
        self.flags = defaultdict(int)
        self.forward_packets = 0
        self.backward_packets = 0
        self.forward_bytes = 0
        self.backward_bytes = 0
    
    def add_packet(self, packet, direction):
        self.timestamps.append(packet.sniff_time.timestamp())
        self.packet_lengths.append(int(packet.length))
        
        if direction == 'forward':
            self.forward_packets += 1
            self.forward_bytes += int(packet.length)
            self.fwd_packet_lengths.append(int(packet.length))
            if hasattr(packet.tcp, 'flags_psh'):
                self.flags['PSH'] += int(packet.tcp.flags_psh)
        else:
            self.backward_packets += 1
            self.backward_bytes += int(packet.length)
            self.bwd_packet_lengths.append(int(packet.length))
        
        if hasattr(packet.tcp, 'flags_fin'):
            self.flags['FIN'] += int(packet.tcp.flags_fin)
        if hasattr(packet.tcp, 'flags_syn'):
            self.flags['SYN'] += int(packet.tcp.flags_syn)
        if hasattr(packet.tcp, 'flags_rst'):
            self.flags['RST'] += int(packet.tcp.flags_rst)
        if hasattr(packet.tcp, 'flags_ack'):
            self.flags['ACK'] += int(packet.tcp.flags_ack)
        if hasattr(packet.tcp, 'flags_urg'):
            self.flags['URG'] += int(packet.tcp.flags_urg)
        if hasattr(packet.tcp, 'flags_ece'):
            self.flags['ECE'] += int(packet.tcp.flags_ece)

def calculate_features(flow):
    features = {}
    features['Dst Port'] = flow.dst_port
    features['Protocol'] = flow.protocol
    features['Timestamp'] = flow.timestamps[0]
    
    features['Flow Duration'] = flow.timestamps[-1] - flow.timestamps[0]
    features['Tot Fwd Pkts'] = flow.forward_packets
    features['Tot Bwd Pkts'] = flow.backward_packets
    features['TotLen Fwd Pkts'] = flow.forward_bytes
    features['TotLen Bwd Pkts'] = flow.backward_bytes
    
    features['Fwd Pkt Len Max'] = max(flow.fwd_packet_lengths, default=0)
    features['Fwd Pkt Len Min'] = min(flow.fwd_packet_lengths, default=0)
    features['Fwd Pkt Len Mean'] = np.mean(flow.fwd_packet_lengths) if flow.fwd_packet_lengths else 0
    features['Fwd Pkt Len Std'] = np.std(flow.fwd_packet_lengths) if flow.fwd_packet_lengths else 0
    
    features['Bwd Pkt Len Max'] = max(flow.bwd_packet_lengths, default=0)
    features['Bwd Pkt Len Min'] = min(flow.bwd_packet_lengths, default=0)
    features['Bwd Pkt Len Mean'] = np.mean(flow.bwd_packet_lengths) if flow.bwd_packet_lengths else 0
    features['Bwd Pkt Len Std'] = np.std(flow.bwd_packet_lengths) if flow.bwd_packet_lengths else 0
    
    features['Flow Byts/s'] = (flow.forward_bytes + flow.backward_bytes) / features['Flow Duration'] if features['Flow Duration'] else 0
    features['Flow Pkts/s'] = (flow.forward_packets + flow.backward_packets) / features['Flow Duration'] if features['Flow Duration'] else 0
    
    iat = np.diff(flow.timestamps)
    features['Flow IAT Mean'] = np.mean(iat) if len(iat) > 0 else 0
    features['Flow IAT Std'] = np.std(iat) if len(iat) > 0 else 0
    features['Flow IAT Max'] = np.max(iat) if len(iat) > 0 else 0
    features['Flow IAT Min'] = np.min(iat) if len(iat) > 0 else 0
    
    fwd_iat = np.diff([flow.timestamps[i] for i in range(len(flow.timestamps)) if i in flow.fwd_packet_lengths])
    features['Fwd IAT Tot'] = np.sum(fwd_iat) if len(fwd_iat) > 0 else 0
    features['Fwd IAT Mean'] = np.mean(fwd_iat) if len(fwd_iat) > 0 else 0
    features['Fwd IAT Std'] = np.std(fwd_iat) if len(fwd_iat) > 0 else 0
    features['Fwd IAT Max'] = np.max(fwd_iat) if len(fwd_iat) > 0 else 0
    features['Fwd IAT Min'] = np.min(fwd_iat) if len(fwd_iat) > 0 else 0
    
    bwd_iat = np.diff([flow.timestamps[i] for i in range(len(flow.timestamps)) if i in flow.bwd_packet_lengths])
    features['Bwd IAT Tot'] = np.sum(bwd_iat) if len(bwd_iat) > 0 else 0
    features['Bwd IAT Mean'] = np.mean(bwd_iat) if len(bwd_iat) > 0 else 0
    features['Bwd IAT Std'] = np.std(bwd_iat) if len(bwd_iat) > 0 else 0
    features['Bwd IAT Max'] = np.max(bwd_iat) if len(bwd_iat) > 0 else 0
    features['Bwd IAT Min'] = np.min(bwd_iat) if len(bwd_iat) > 0 else 0
    
    features['Fwd PSH Flags'] = flow.flags['PSH']
    features['Fwd Header Len'] = sum(flow.fwd_packet_lengths) if flow.fwd_packet_lengths else 0
    features['Bwd Header Len'] = sum(flow.bwd_packet_lengths) if flow.bwd_packet_lengths else 0
    
    features['Fwd Pkts/s'] = flow.forward_packets / features['Flow Duration'] if features['Flow Duration'] else 0
    features['Bwd Pkts/s'] = flow.backward_packets / features['Flow Duration'] if features['Flow Duration'] else 0
    
    features['Pkt Len Min'] = min(flow.packet_lengths, default=0)
    features['Pkt Len Max'] = max(flow.packet_lengths, default=0)
    features['Pkt Len Mean'] = np.mean(flow.packet_lengths) if flow.packet_lengths else 0
    features['Pkt Len Std'] = np.std(flow.packet_lengths) if flow.packet_lengths else 0
    features['Pkt Len Var'] = np.var(flow.packet_lengths) if flow.packet_lengths else 0
    
    features['FIN Flag Cnt'] = flow.flags['FIN']
    features['SYN Flag Cnt'] = flow.flags['SYN']
    features['RST Flag Cnt'] = flow.flags['RST']
    features['PSH Flag Cnt'] = flow.flags['PSH']
    features['ACK Flag Cnt'] = flow.flags['ACK']
    features['URG Flag Cnt'] = flow.flags['URG']
    features['ECE Flag Cnt'] = flow.flags['ECE']
    
    features['Down/Up Ratio'] = (flow.backward_bytes / flow.forward_bytes) if flow.forward_bytes else 0
    
    features['Pkt Size Avg'] = np.mean(flow.packet_lengths) if flow.packet_lengths else 0
    features['Fwd Seg Size Avg'] = np.mean(flow.fwd_packet_lengths) if flow.fwd_packet_lengths else 0
    features['Bwd Seg Size Avg'] = np.mean(flow.bwd_packet_lengths) if flow.bwd_packet_lengths else 0
    
    features['Subflow Fwd Pkts'] = flow.forward_packets
    features['Subflow Fwd Byts'] = flow.forward_bytes
    features['Subflow Bwd Pkts'] = flow.backward_packets
    features['Subflow Bwd Byts'] = flow.backward_bytes
    
    features['Init Fwd Win Byts'] = 0  # Placeholder, not directly extractable
    features['Init Bwd Win Byts'] = 0  # Placeholder, not directly extractable
    features['Fwd Act Data Pkts'] = flow.forward_packets
    features['Fwd Seg Size Min'] = min(flow.fwd_packet_lengths, default=0)
    
    active = [flow.timestamps[i+1] - flow.timestamps[i] for i in range(len(flow.timestamps)-1)]
    features['Active Mean'] = np.mean(active) if active else 0
    features['Active Std'] = np.std(active) if active else 0
    features['Active Max'] = max(active, default=0)
    features['Active Min'] = min(active, default=0)
    
    idle = [flow.timestamps[i+1] - flow.timestamps[i] for i in range(len(flow.timestamps)-1)]
    features['Idle Mean'] = np.mean(idle) if idle else 0
    features['Idle Std'] = np.std(idle) if idle else 0
    features['Idle Max'] = max(idle, default=0)
    features['Idle Min'] = min(idle, default=0)
    
    return features

def extract_all_features(packets):
    flow = Flow()
    for packet in packets:
        direction = 'forward' if packet.direction == 'f' else 'backward'
        flow.add_packet(packet, direction)
    features = calculate_features(flow)
    return features
