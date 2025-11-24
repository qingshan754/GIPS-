# import module
import os
import pickle
import configparser

import decimal

from scapy.all import *
from tqdm.auto import tqdm

def decode_ascii(payload: str):
    arr, cur = [], ''
    for char in payload:
        cur += char
        if len(cur)==2:
            data_hex = int('0x' + cur, 16)
            arr.append(chr(data_hex))
            cur = ''
    
    return ''.join(arr)

def make_flow_dict(flow_path: str):
    
    # iot23 flow 파일 기준 컬럼 정보 등 제거
    reader = open(flow_path, 'r')
    for _ in range(8):
        reader.readline()
    
    flow_dict = dict()

    flow_id = 0 # 한 flow의 index
    while True:
        line_raw = reader.readline()
        if not line_raw:
            break
            
        # 1. 清除行首尾的空白字符（包括换行符）
        line_raw = line_raw.strip()
        
        # 2. 如果行是空的，跳过
        if not line_raw:
            continue

        line = line_raw.split('\t')
        
        # 检查是否是结束标记
        if line[0]=='#close':
            break
        
        # 3. 清除第一个字段的空白字符，并尝试转换
        try:
            st = decimal.Decimal(line[0].strip()) 
        except decimal.InvalidOperation:
            # 如果转换失败，打印信息并跳过当前行，或者直接中断
            print(f"警告：Flow文件中的时间戳数据格式不正确，跳过该行。内容: {line[0]}")
            continue # 跳过当前有问题的行

        sip = line[2]
        sip = line[2]
        sport = int(line[3])
        dip = line[4]
        dport = int(line[5])
        proto = line[6].lower()

        if line[8] == '-':
            line[8] = '0.00000000000000001' # duration이 -인 경우 예외처리
        et = st + decimal.Decimal(line[8])
        label = line[-1]

        key = f'{sip}_{sport}_{dip}_{dport}_{proto}' # 5-tuple 정보를 key로 설정
        if key not in flow_dict.keys():
            flow_dict[key] = []
        flow_dict[key].append((flow_id, st, et, label))

        flow_id += 1

    reader.close()

    return flow_dict

def get_payloads_from_pcap_with_flow(pcap_path: str, flow_dict: dict):
    if os.path.getsize(pcap_path) == 0:
        return []

    pkts = PcapReader(pcap_path)
    processed_pkts = []
    for idx, pkt in enumerate(tqdm(pkts)):
        if pkt.haslayer("IP"):
            sip = pkt["IP"].src
            dip = pkt["IP"].dst

            if pkt.haslayer("TCP"):
                protocol = "TCP"
            elif pkt.haslayer("UDP"):
                protocol = "UDP"
            else:
                continue
            sport = int(pkt[protocol].sport)
            dport = int(pkt[protocol].dport)
            if bool(pkt[protocol].payload):
                if "Padding" in pkt[protocol].payload:
                    if (
                        pkt[protocol].payload["Padding"].load
                        == pkt[protocol].payload.load
                    ):
                        payload = ""
                    else:
                        payload = bytes(pkt[protocol].payload.load).hex()
                else:
                    payload = bytes(pkt[protocol].payload).hex()
            else:
                payload = ""

            payload = decode_ascii(payload)

            if len(payload) >= 4:
                time = pkt.time
                proto = protocol.lower()

                # sip, dip, sport, dport, proto, time
                final_flow_label = 'unknown'
                key = f'{sip}_{sport}_{dip}_{dport}_{proto}'

                if key in flow_dict.keys():
                    for flow_id, st, et, label in flow_dict[key]:
                        if st - decimal.Decimal('0.001') <= time < et + decimal.Decimal('0.001'):
                            if 'benign' in label.lower():
                                final_flow_label = f'BENIGN{flow_id}'
                            else:
                                final_flow_label = f'MALWARE{flow_id}'
                            break

                processed_pkts.append((payload, final_flow_label, (sip, dip, sport, dport, protocol)))

    return processed_pkts

if __name__ == '__main__':

    properties = configparser.ConfigParser()
    properties.read('config.ini')

    pcap_path = properties.get('PATH', 'pcap_path')
    flow_path = properties.get('PATH', 'flow_path')

    payload_path = properties.get('PATH', 'payload_path')
    label_path = properties.get('PATH', 'label_path')

    # read dataset
    flow_dict = make_flow_dict(flow_path)

    packets = []
    for pcap_name in os.listdir(pcap_path):
        if pcap_name.split('.')[-1] in ['pcap', 'done']:
            packets += get_payloads_from_pcap_with_flow(os.path.join(pcap_path, pcap_name), flow_dict)

    # packets 데이터 형태
    # (payload 정보, 플로우 라벨, 5-tuple)
    # 플로우 라벨은 'unknown', 'BENIGN{flow_id}', 'MALWARE{flow_id}' 로 구성
            
    payloads = []
    labels = []

    for payload, flow_label, tuple5 in packets:
        payloads.append(payload)
        labels.append(flow_label)

    with open(payload_path, 'wb') as f:
        pickle.dump(payloads, f)

    with open(label_path, 'wb') as f:
        pickle.dump(labels, f)