import pyshark
import pandas as pd
import statistics

my_ip = '100.101.144.183'

class PacketProcessor:
    def process_packet(self, packet):
        try:
            # Extract basic features
            src_ip = packet.ip.src
            dst_ip = packet.ip.dst
            protocol = packet.transport_layer
            packet_len = int(packet.length)
            sniff_time = float(packet.sniff_timestamp)

            # Extract TCP flags if present
            tcp_flags = {
                'FIN': int(packet.tcp.flags_fin) if hasattr(packet, 'tcp') and packet.tcp.flags_fin.isnumeric() else 0,
                'SYN': int(packet.tcp.flags_syn) if hasattr(packet, 'tcp') and packet.tcp.flags_fin.isnumeric() else 0,
                'RST': int(packet.tcp.flags_rst) if hasattr(packet, 'tcp') and packet.tcp.flags_fin.isnumeric() else 0,
                'PSH': int(packet.tcp.flags_psh) if hasattr(packet, 'tcp') and packet.tcp.flags_fin.isnumeric() else 0,
                'ACK': int(packet.tcp.flags_ack) if hasattr(packet, 'tcp') and packet.tcp.flags_fin.isnumeric() else 0,
                'URG': int(packet.tcp.flags_urg) if hasattr(packet, 'tcp') and packet.tcp.flags_fin.isnumeric() else 0,
                'CWE': int(packet.tcp.flags_cwr) if hasattr(packet, 'tcp') and packet.tcp.flags_fin.isnumeric() else 0,
                'ECE': int(packet.tcp.flags_ecn) if hasattr(packet, 'tcp') and packet.tcp.flags_fin.isnumeric() else 0
            }
            total_header_length = 0

            # Access the Ethernet layer
            if hasattr(packet, 'eth'):
                eth_header_len = 14  # Ethernet header is typically 14 bytes
                total_header_length += eth_header_len

            # Access the IP layer
            if hasattr(packet, 'ip'):
                ip_header_len = int(packet.ip.hdr_len) * 4  # IP header length is in 32-bit words, so multiply by 4
                total_header_length += ip_header_len

            # Access the TCP/UDP layer (if applicable)
            if hasattr(packet, 'tcp'):
                tcp_header_len = int(packet.tcp.hdr_len) * 4  # TCP header length is in 32-bit words, so multiply by 4
                total_header_length += tcp_header_len
            elif hasattr(packet, 'udp'):
                udp_header_len = 8  # UDP header is typically 8 bytes
                total_header_length += udp_header_len

            return {
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'src_port': packet[packet.transport_layer].srcport if hasattr(packet, 'tcp') or hasattr(packet, 'udp') else None,
                'dst_port': packet[packet.transport_layer].dstport if hasattr(packet, 'tcp') or hasattr(packet, 'udp') else None,
                'protocol': protocol,
                'packet_length': packet_len,
                'sniff_time': sniff_time,
                'tcp_flags': tcp_flags,
                'header_length': total_header_length}
        except Exception as e:
            print(e)
            return None

class FlowAnalyzer:
    def __init__(self):
        self.flows = {}

    def extract_flow_features(self, packets):
        flow_features_list = []
        for i,packet in enumerate(packets):
            processor = PacketProcessor()
            features = processor.process_packet(packet)
            if features is None:
                continue
            # elif features['src_ip'] != my_ip and features['dst_ip'] != my_ip:
            #     continue

            # Flow key to track the flows (based on 4-tuple)
            s = features['src_ip']
            d = features['dst_ip']
            flow_key =(min(s,d),max(s,d), features['src_port'], features['dst_port'])

            if flow_key not in self.flows:
                self.flows[flow_key] = {
                    'src_ip':features['src_ip'],
                    'dst_ip':features['dst_ip'],
                    'packets': [],
                    'fwd_packet_lengths': [],
                    'bwd_packet_lengths': [],
                    'timestamps': [],
                    'fwd_timestamps': [],
                    'bwd_timestamps': [],
                    'total_fwd_packets': 0,
                    'total_bwd_packets': 0,
                    'total_length_fwd': 0,
                    'total_length_bwd': 0,
                    'tcp_flags_count': {'FIN': 0, 'SYN': 0, 'RST': 0, 'PSH': 0, 'ACK': 0, 'URG': 0, 'CWE': 0, 'ECE': 0},
                    'fwd_psh_flags': 0,
                    'fwd_urg_flags': 0,
                    'fwd_header_lengths': [],
                    'bwd_header_lengths': [],
                    'act_data_pkt_fwd': 0,
                    'init_win_bytes_fwd': 0,
                    'init_win_bytes_bwd': 0,
                }

            flow = self.flows[flow_key]
            flow['packets'].append(features)

            # Timestamp
            timestamp = float(features.get('sniff_time', 0))
            flow['timestamps'].append(timestamp)


            #init_win_bytes_fwd calculation
            forward_bytes = flow['init_win_bytes_fwd']
            initial_window_size = 1024

            if 'TCP' in packet:

                options = getattr(packet.tcp, 'options', None)
                if options is not None:
                    if hasattr(options, 'window_size'):
                        length = int(options.window_size)
                        forward_bytes += length
                # Check if the packet is from client to server
                #if features['src_ip'] == flow['src_ip']:
                #    print(forward_bytes)
                #    tcp_payload_length = int(packet.tcp.len)
                #    forward_bytes += tcp_payload_length
                   # if forward_bytes >= initial_window_size:
                    #    break
                        
            backward_bytes = 0
            initial_window_size = 1024
            if 'TCP' in packet:
                # Check if the packet is from client to server
                if features['dst_ip'] == flow['src_ip']:
                    tcp_payload_length = int(packet.tcp.len)
                    backward_bytes += tcp_payload_length
                    #if backward_bytes >= initial_window_size:
                    #    break

            flow['init_win_bytes_fwd']= forward_bytes
            flow['init_win_bytes_bwd']= backward_bytes
       



            # Update flow based on direction
            if features['src_ip'] == flow['src_ip']:  # Forward packets
                flow['fwd_packet_lengths'].append(features['packet_length'])
                flow['fwd_timestamps'].append(timestamp)
                flow['total_fwd_packets'] += 1
                flow['total_length_fwd'] += features['packet_length']
                flow['fwd_psh_flags'] += features['tcp_flags'].get('PSH', 0)
                flow['fwd_urg_flags'] += features['tcp_flags'].get('URG', 0)
                flow['fwd_header_lengths'].append(features.get('header_length', 0))
            else:  # Backward packets
                flow['bwd_packet_lengths'].append(features['packet_length'])
                flow['bwd_timestamps'].append(timestamp)
                flow['total_bwd_packets'] += 1
                flow['total_length_bwd'] += features['packet_length']
                flow['bwd_header_lengths'].append(features.get('header_length', 0))

            # Update TCP flags counts
            for flag in flow['tcp_flags_count']:
                flow['tcp_flags_count'][flag] += features['tcp_flags'][flag]

        # Processing flows
        for flow_key, flow in self.flows.items():
            if len(flow['packets']) <= 1:
                continue
            first_packet_time = flow['timestamps'][0] if flow['timestamps'] else 0
            last_packet_time = flow['timestamps'][-1] if flow['timestamps'] else 0
            flow_duration = (last_packet_time - first_packet_time)

            # Flow Bytes/s and Packets/s
            flow_bytes_per_sec = (flow['total_length_fwd'] + flow['total_length_bwd']) / flow_duration
            flow_packets_per_sec = (flow['total_fwd_packets'] + flow['total_bwd_packets']) / flow_duration
            
            # Inter-arrival times (IAT)
            def compute_iat(timestamps):
                if len(timestamps) < 2:
                    return 0, 0, 0, 0  # Return 0 for mean, std, max, and min if not enough data points
                iats = [t2 - t1 for t1, t2 in zip(timestamps[:-1], timestamps[1:])]
                mean_iat = statistics.mean(iats)
                std_iat = statistics.stdev(iats) if len(iats) > 1 else 0  # Only calculate stdev if more than 1 value
                max_iat = max(iats)
                min_iat = min(iats)
                return mean_iat, std_iat, max_iat, min_iat

            flow_iat_mean, flow_iat_std, flow_iat_max, flow_iat_min = compute_iat(flow['timestamps'])
            fwd_iat_mean, fwd_iat_std, fwd_iat_max, fwd_iat_min = compute_iat(flow['fwd_timestamps'])
            bwd_iat_mean, bwd_iat_std, bwd_iat_max, bwd_iat_min = compute_iat(flow['bwd_timestamps'])

            # Header length and packet statistics
            fwd_header_len = sum(flow['fwd_header_lengths'])
            #bwd_header_len = sum(flow['bwd_header_lengths'])

            if flow['fwd_packet_lengths']:
                fwd_pkt_len_max = max(flow['fwd_packet_lengths'])
                fwd_pkt_len_min = min(flow['fwd_packet_lengths'])
                fwd_pkt_len_mean = statistics.mean(flow['fwd_packet_lengths'])
                #fwd_pkt_len_std = statistics.stdev(flow['fwd_packet_lengths']) if len(flow['fwd_packet_lengths']) > 1 else 0
            else:
                fwd_pkt_len_max = fwd_pkt_len_min = fwd_pkt_len_mean = fwd_pkt_len_std = 0

            if flow['bwd_packet_lengths']:
                bwd_pkt_len_max = max(flow['bwd_packet_lengths'])
                bwd_pkt_len_min = min(flow['bwd_packet_lengths'])
                #bwd_pkt_len_mean = statistics.mean(flow['bwd_packet_lengths'])
                #bwd_pkt_len_std = statistics.stdev(flow['bwd_packet_lengths']) if len(flow['bwd_packet_lengths']) > 1 else 0
            else:
                bwd_pkt_len_max = bwd_pkt_len_min = bwd_pkt_len_mean = bwd_pkt_len_std = 0

            # Additional metrics
            total_packets = flow['total_fwd_packets'] + flow['total_bwd_packets']
            if total_packets > 0:
                min_packet_length = min(flow['fwd_packet_lengths'] + flow['bwd_packet_lengths'])
                #max_packet_length = max(flow['fwd_packet_lengths'] + flow['bwd_packet_lengths'])
                #packet_length_mean = (flow['total_length_fwd'] + flow['total_length_bwd']) / total_packets
                packet_length_std = statistics.stdev(flow['fwd_packet_lengths'] + flow['bwd_packet_lengths']) if total_packets > 1 else 0
                packet_length_variance = packet_length_std ** 2
            else:
                min_packet_length = max_packet_length = packet_length_mean = packet_length_std = packet_length_variance = 0
            # Calculate Idle Times
            idle_times = []
            for i in range(1, len(flow['timestamps'])):
                # Calculate idle time between consecutive packets
                idle_time = flow['timestamps'][i] - flow['timestamps'][i - 1]
                # Only consider times above a threshold (e.g., 1 second) as idle
                if idle_time > 1:  
                    idle_times.append(idle_time)

            # Compute Idle Statistics
            if idle_times:
                #idle_mean = statistics.mean(idle_times)
                idle_std = statistics.stdev(idle_times) if len(idle_times) > 1 else 0
                #idle_max = max(idle_times)
                #idle_min = min(idle_times)
            else:
                idle_mean = idle_std = idle_max = idle_min = 0  # No idle times detected

            # Prepare the flow features dictionary
            flow_features = {
                # ... (existing features)
                #'Idle Mean': idle_mean,
                'Idle Std': idle_std,
                #'Idle Max': idle_max,
                #'Idle Min': idle_min
            }
            # Prepare the flow features dictionary
            flow_features = {
                #'Destination Port': flow_key[3],
                'Flow Duration': flow_duration * 10**6,
                'Total Fwd Packets': flow['total_fwd_packets'],
                #'Total Backward Packets': flow['total_bwd_packets'],
                'Total Length of Fwd Packets': flow['total_length_fwd'],
                #'Total Length of Bwd Packets': flow['total_length_bwd'],
                'Fwd Packet Length Max': fwd_pkt_len_max,
                'Fwd Packet Length Min': fwd_pkt_len_min,
                'Fwd Packet Length Mean': fwd_pkt_len_mean,
                #'Fwd Packet Length Std': fwd_pkt_len_std,
                'Bwd Packet Length Max': bwd_pkt_len_max,
                'Bwd Packet Length Min': bwd_pkt_len_min,
                #'Bwd Packet Length Mean': bwd_pkt_len_mean,
                #'Bwd Packet Length Std': bwd_pkt_len_std,
                'Flow Bytes/s': flow_bytes_per_sec,
                'Flow Packets/s': flow_packets_per_sec,
                'Flow IAT Mean': flow_iat_mean * 10**6,
                'Flow IAT Std': flow_iat_std * 10**6,
                #'Flow IAT Max': flow_iat_max,
                'Flow IAT Min': flow_iat_min * 10**6,
                #'Fwd IAT Total': sum(flow['fwd_timestamps'][1:]) - sum(flow['fwd_timestamps'][:-1]) if len(flow['fwd_timestamps']) > 1 else 0,
                'Fwd IAT Mean': fwd_iat_mean * 10**6,
                #'Fwd IAT Std': fwd_iat_std,
                #'Fwd IAT Max': fwd_iat_max,
                'Fwd IAT Min': fwd_iat_min * 10**6,
                'Bwd IAT Total': (sum(flow['bwd_timestamps'][1:]) - sum(flow['bwd_timestamps'][:-1])) * 10**6 if len(flow['bwd_timestamps']) > 1 else 0,
                'Bwd IAT Mean': bwd_iat_mean * 10**6,
                'Bwd IAT Std': bwd_iat_std * 10**6,
                'Bwd IAT Max': bwd_iat_max * 10**6,
                'Bwd IAT Min': bwd_iat_min * 10**6,
                'Fwd PSH Flags': flow['fwd_psh_flags'],
                'Fwd URG Flags': flow['fwd_urg_flags'],
                'Fwd Header Length': fwd_header_len,
                #'Bwd Header Length': bwd_header_len,
                'Fwd Packets/s': flow['total_fwd_packets'] / flow_duration,
                'Bwd Packets/s': flow['total_bwd_packets'] / flow_duration,
                'Min Packet Length': min_packet_length,
                #'Max Packet Length': max_packet_length,
                #'Packet Length Mean': packet_length_mean,
                #'Packet Length Std': packet_length_std,
                'Packet Length Variance': packet_length_variance,
                'FIN Flag Count': flow['tcp_flags_count']['FIN'],
                #'SYN Flag Count': flow['tcp_flags_count']['SYN'],
                'RST Flag Count': flow['tcp_flags_count']['RST'],
                'PSH Flag Count': flow['tcp_flags_count']['PSH'],
                'ACK Flag Count': flow['tcp_flags_count']['ACK'],
                'URG Flag Count': flow['tcp_flags_count']['URG'],
                #'CWE Flag Count': flow['tcp_flags_count']['CWE'],
                #'ECE Flag Count': flow['tcp_flags_count']['ECE'],
                'Down/Up Ratio': flow['total_bwd_packets'] / flow['total_fwd_packets'] if flow['total_fwd_packets'] > 0 else 0,
                #'Average Packet Size': (flow['total_length_fwd'] + flow['total_length_bwd']) / total_packets if total_packets > 0 else 0,
                #'Avg Fwd Segment Size': flow['total_length_fwd'] / flow['total_fwd_packets'] if flow['total_fwd_packets'] > 0 else 0,
                #'Avg Bwd Segment Size': flow['total_length_bwd'] / flow['total_bwd_packets'] if flow['total_bwd_packets'] > 0 else 0,
                'Init_Win_bytes_forward': flow['init_win_bytes_fwd'],
                'Init_Win_bytes_backward': flow['init_win_bytes_bwd'],
                #'act_data_pkt_fwd': flow['act_data_pkt_fwd'],
                #'min_seg_size_forward': min(flow['fwd_packet_lengths']) if flow['fwd_packet_lengths'] else 0,
                'Active Mean': statistics.mean(flow['timestamps']) if flow['timestamps'] else 0,
                'Active Std': statistics.stdev(flow['timestamps']) if len(flow['timestamps']) > 1 else 0,
                'Active Max': max(flow['timestamps']) if flow['timestamps'] else 0,
                'Active Min': min(flow['timestamps']) if flow['timestamps'] else 0,
                #'Idle Mean': idle_mean,
                'Idle Std': idle_std,
                #'Idle Max': idle_max,
                #'Idle Min': idle_min
            }

            flow_features_list.append(flow_features)

        return flow_features_list

def capture_packets():
    capture = pyshark.LiveCapture(interface='\\Device\\NPF_{D9927163-4CF3-4EE0-9B85-B8B257ED5292}')
    capture.sniff(packet_count=5)
    return capture

def capture_from_pcap(pcap_file):
    capture = pyshark.FileCapture(pcap_file)
    return capture

def extract_features():
    packets = capture_packets()
    analyzer = FlowAnalyzer()
    flow_features = analyzer.extract_flow_features(packets)
    return pd.DataFrame(flow_features)

def extract_features_from_pcap(pcap_file):
    packets = capture_from_pcap(pcap_file)
    analyzer = FlowAnalyzer()
    flow_features = analyzer.extract_flow_features(packets)
    return pd.DataFrame(flow_features)

if __name__ == '__main__':
    #pcap_file = 'D:\Project\Automated-Intrusion-Detection-System-\packet_capture\captured_packet.pcap'
    #flow_feature_df = extract_features()
    #print(flow_feature_df.tail())
    #flow_feature_df.to_csv('D:\Project\Automated-Intrusion-Detection-System-\packet_capture\output1.csv', index=False)
    pcap_file = r'D:\Project\Automated-Intrusion-Detection-System-\packet_capture\nirajport.pcapng'
    capture = pyshark.FileCapture(pcap_file)
    for packet in capture:
        if 'ip' in packet:
            print(packet.ip)