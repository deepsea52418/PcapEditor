import os
import json
import copy
import traceback
import io
from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from scapy.all import rdpcap, wrpcap, Raw
from scapy.utils import PcapNgWriter, wrpcap, PcapWriter
import scapy.packet
from scapy.layers.l2 import Ether, Dot1Q
from scapy.layers.inet import IP
from scapy.layers.inet6 import IPv6
from datetime import datetime, timezone
import pytz


# 全局变量来存储会话数据
pcap_data = {
    "original_packets": None,
    "modified_packets": None,
    "filename": None,
    "undo_stack": [],
    "redo_stack": [],
}

app = Flask(__name__)
CORS(app)  # 允许跨域请求

UPLOAD_FOLDER = 'uploads'
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 MB

def packet_to_summary(i, pkt):
    """将 Scapy 报文对象转换为摘要字典"""
    
    # 尝试生成更简洁的 info
    info_layer = pkt.lastlayer()
    # 避免显示原始字节或填充层
    if isinstance(info_layer, (Raw, scapy.packet.Padding)):
        info_layer = info_layer.underlayer
    
    # 如果有IP层，优先显示网络层以上的摘要
    if IP in pkt:
        info_layer = pkt[IP].payload
    elif IPv6 in pkt:
        info_layer = pkt[IPv6].payload

    info = info_layer.summary() if info_layer else pkt.summary()

    summary = {
        "id": i,
        "timestamp": float(pkt.time),
        "len": len(pkt),
        "vlan_id": pkt[Dot1Q].vlan if Dot1Q in pkt else 'N/A' # 提取 VLAN ID
    }
    if 'IP' in pkt:
        summary['src'] = pkt['IP'].src
        summary['dst'] = pkt['IP'].dst
        summary['proto'] = pkt['IP'].get_field('proto').i2s[pkt['IP'].proto]
    elif 'IPv6' in pkt:
        summary['src'] = pkt['IPv6'].src
        summary['dst'] = pkt['IPv6'].dst
        summary['proto'] = pkt['IPv6'].get_field('nh').i2s[pkt['IPv6'].nh]
    elif 'ARP' in pkt:
        summary['src'] = pkt['ARP'].psrc
        summary['dst'] = pkt['ARP'].pdst
        summary['proto'] = 'ARP'
    elif 'Ether' in pkt:
        summary['src'] = pkt['Ether'].src
        summary['dst'] = pkt['Ether'].dst
        summary['proto'] = 'L2'
    else:
        summary['src'] = 'N/A'
        summary['dst'] = 'N/A'
        summary['proto'] = 'L2'


    summary['info'] = info
    return summary

def parse_packet_layers(pkt):
    """
    根据协议规范，使用固定偏移量和长度精确计算字段的字节范围。
    此版本修复了前端高亮时的“差一错误”，通过将 byteRange 的 结束位置+1 来实现。
    同时，此版本新增了对报文时间戳的详细解析。
    """
    layers_data = []
    
    # --- Timestamp Parsing ---
    try:
        ts = float(pkt.time)
        dt_utc = datetime.fromtimestamp(ts, tz=timezone.utc)
        dt_local = dt_utc.astimezone(pytz.timezone('Asia/Shanghai'))

        # Decomposed fields
        seconds = int(ts)
        # Format fractional part to 9 digits and split into ms, us, ns
        fractional_str = f"{ts - seconds:.9f}"[2:]
        ms = fractional_str[0:3]
        us = fractional_str[3:6]
        ns = fractional_str[6:9]
        
        timestamp_info = {
            "key": "timestamp",
            "title": "Timestamp",
            "children": [
                {
                    "key": "timestamp-raw",
                    "title": f"Raw Timestamp: {ts}",
                    "value": ts,
                    "is_editable": True,
                },
                {
                    "key": "timestamp-utc8",
                    "title": f"UTC+8: {dt_local.strftime('%Y-%m-%d %H:%M:%S')}.{fractional_str}",
                    "is_editable": False,
                },
                {
                    "key": "timestamp-decomposed",
                    "title": "Decomposed",
                    "children": [
                        {"key": "timestamp-s", "title": f"s: {seconds}"},
                        {"key": "timestamp-ms", "title": f"ms: {ms}"},
                        {"key": "timestamp-us", "title": f"µs: {us}"},
                        {"key": "timestamp-ns", "title": f"ns: {ns}"},
                    ],
                    "is_editable": False,
                }
            ]
        }
        layers_data.append(timestamp_info)
    except Exception as e:
        print(f"Error parsing timestamp: {e}")

    current_offset = 0

    # 1. 处理 Ethernet 层
    if pkt.haslayer(Ether):
        eth_layer = pkt[Ether]
        eth_header_len = 14
        
        eth_info = {
            "key": f"layer-{current_offset}-Ethernet",
            "title": "Ethernet",
            "byteRange": [current_offset, current_offset + eth_header_len], # 修正
            "children": [
                {
                    "key": f"layer-{current_offset}-Ethernet-dst",
                    "title": f"dst: {repr(eth_layer.dst)}",
                    "byteRange": [current_offset + 0, current_offset + 6] # 修正: 6 bytes
                },
                {
                    "key": f"layer-{current_offset}-Ethernet-src",
                    "title": f"src: {repr(eth_layer.src)}",
                    "byteRange": [current_offset + 6, current_offset + 12] # 修正: 6 bytes
                }
            ]
        }
        layers_data.append(eth_info)
        current_offset += eth_header_len

    # 2. 处理 VLAN 层 (如果存在)
    if pkt.haslayer(Dot1Q):
        vlan_layer = pkt[Dot1Q]
        vlan_header_len = 4
        
        vlan_info = {
            "key": f"layer-{current_offset}-VLAN",
            "title": "VLAN",
            "byteRange": [current_offset, current_offset + vlan_header_len], # 修正
            "children": [
                {
                    "key": f"layer-{current_offset}-VLAN-prio",
                    "title": f"pcp: {repr(vlan_layer.prio)}",
                    "byteRange": [current_offset + 0, current_offset + 2] # 修正: TCI field is 2 bytes
                },
                {
                    "key": f"layer-{current_offset}-VLAN-vlan",
                    "title": f"Vlan ID: {repr(vlan_layer.vlan)}",
                    "byteRange": [current_offset + 0, current_offset + 2] # 修正: TCI field is 2 bytes
                }
            ]
        }
        layers_data.append(vlan_info)
        current_offset += vlan_header_len

    # 3. 处理 IP 层 (IPv4 或 IPv6)
    ip_layer = None
    ip_title = None
    if pkt.haslayer(IP):
        ip_layer = pkt[IP]
        ip_title = "IP"
    elif pkt.haslayer(IPv6):
        ip_layer = pkt[IPv6]
        ip_title = "IPv6"

    if ip_layer:
        ip_header_len = ip_layer.ihl * 4 if hasattr(ip_layer, 'ihl') else 40
        
        ip_info = {
            "key": f"layer-{current_offset}-{ip_title}",
            "title": ip_title,
            "byteRange": [current_offset, current_offset + ip_header_len], # 修正
            "children": []
        }
        
        if pkt.haslayer(IP):
            ip_info["children"].extend([
                {
                    "key": f"layer-{current_offset}-IP-src",
                    "title": f"src: {repr(ip_layer.src)}",
                    "byteRange": [current_offset + 12, current_offset + 16] # 修正: 4 bytes
                },
                {
                    "key": f"layer-{current_offset}-IP-dst",
                    "title": f"dst: {repr(ip_layer.dst)}",
                    "byteRange": [current_offset + 16, current_offset + 20] # 修正: 4 bytes
                }
            ])
        elif pkt.haslayer(IPv6):
             ip_info["children"].extend([
                {
                    "key": f"layer-{current_offset}-IPv6-src",
                    "title": f"src: {repr(ip_layer.src)}",
                    "byteRange": [current_offset + 8, current_offset + 24] # 修正: 16 bytes
                },
                {
                    "key": f"layer-{current_offset}-IPv6-dst",
                    "title": f"dst: {repr(ip_layer.dst)}",
                    "byteRange": [current_offset + 24, current_offset + 40] # 修正: 16 bytes
                }
            ])
        
        layers_data.append(ip_info)

    return layers_data

def _save_undo_state():
    """Saves the current state for undo."""
    pcap_data["undo_stack"].append(copy.deepcopy(pcap_data["modified_packets"]))
    # Limit undo history
    if len(pcap_data["undo_stack"]) > 10:
        pcap_data["undo_stack"].pop(0)
    # A new action clears the redo stack
    pcap_data["redo_stack"] = []

def _save_undo_state_for_redo():
    """Saves the current state to the undo stack without clearing the redo stack."""
    pcap_data["undo_stack"].append(copy.deepcopy(pcap_data["modified_packets"]))
    if len(pcap_data["undo_stack"]) > 10:
        pcap_data["undo_stack"].pop(0)

@app.route('/api/upload', methods=['POST'])
def upload_file():
    """处理 pcap 文件上传"""
    if 'file' not in request.files:
        return jsonify({"error": "No file part"}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400
    if file:
        filename = file.filename
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)

        try:
            packets = rdpcap(filepath)
            pcap_data["original_packets"] = packets
            pcap_data["modified_packets"] = [p.copy() for p in packets]
            pcap_data["filename"] = filename
            pcap_data["undo_stack"] = []
            pcap_data["redo_stack"] = []

            page = 1
            per_page = 50 # Default number of packets per page
            start = (page - 1) * per_page
            end = start + per_page
            
            summaries = [packet_to_summary(i, p) for i, p in enumerate(pcap_data["modified_packets"][start:end])]
            
            return jsonify({
                "filename": filename,
                "total_packets": len(pcap_data["modified_packets"]),
                "packets": summaries
            })
        except Exception as e:
            return jsonify({"error": f"Failed to parse pcap file: {str(e)}"}), 500

    return jsonify({"error": "File upload failed"}), 500

@app.route('/api/packets', methods=['GET'])
def get_packets():
    """获取分页的报文摘要"""
    if pcap_data["modified_packets"] is None:
        return jsonify({"error": "pcap not loaded"}), 404
        
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 50, type=int)
    start = (page - 1) * per_page
    end = start + per_page

    packets_slice = pcap_data["modified_packets"][start:end]
    summaries = [packet_to_summary(start + i, p) for i, p in enumerate(packets_slice)]
    
    return jsonify({
        "total_packets": len(pcap_data["modified_packets"]),
        "packets": summaries
    })

@app.route('/api/packet/<int:packet_id>', methods=['GET'])
def get_packet_detail(packet_id):
    """获取单个报文的详细信息"""
    if pcap_data["modified_packets"] is None or packet_id >= len(pcap_data["modified_packets"]):
        return jsonify({"error": "Packet not found or pcap not loaded"}), 404

    pkt = pcap_data["modified_packets"][packet_id]
    
    try:
        layers = parse_packet_layers(pkt)
        hex_data = pkt.build().hex()

        return jsonify({
            "layers": layers,
            "hex": hex_data
        })
    except Exception as e:
        traceback.print_exc() # 增加日志记录
        return jsonify({"error": f"Failed to parse packet detail: {str(e)}"}), 500

@app.route('/api/packet/<int:packet_id>/update', methods=['POST'])
def update_packet_hex(packet_id):
    """从十六进制数据更新报文"""
    if pcap_data["modified_packets"] is None or packet_id >= len(pcap_data["modified_packets"]):
        return jsonify({"error": "Packet not found or pcap not loaded"}), 404

    data = request.get_json()
    if 'hex' not in data:
        return jsonify({"error": "Missing 'hex' data in request"}), 400

    hex_data = data['hex']
    
    try:
        _save_undo_state()
        
        raw_bytes = bytes.fromhex(hex_data)
        original_pkt = pcap_data["modified_packets"][packet_id]
        
        # 使用原始数据包的类来重新构建，以保留正确的链路层类型
        new_pkt = original_pkt.__class__(raw_bytes)

        # 保留原始时间戳
        new_pkt.time = original_pkt.time

        pcap_data["modified_packets"][packet_id] = new_pkt
        
        layers = parse_packet_layers(new_pkt)
        summary = packet_to_summary(packet_id, new_pkt)
        
        return jsonify({
            "message": "Packet updated successfully",
            "layers": layers,
            "hex": hex_data,
            "summary": summary
        })
    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": f"Failed to update packet from hex: {str(e)}"}), 500

@app.route('/api/packet/<int:packet_id>/update_timestamp', methods=['POST'])
def update_packet_timestamp(packet_id):
    """Updates the timestamp of a specific packet."""
    if pcap_data["modified_packets"] is None or packet_id >= len(pcap_data["modified_packets"]):
        return jsonify({"error": "Packet not found or pcap not loaded"}), 404

    data = request.get_json()
    if 'timestamp' not in data:
        return jsonify({"error": "Missing 'timestamp' data in request"}), 400

    try:
        new_timestamp = float(data['timestamp'])
    except (ValueError, TypeError):
        return jsonify({"error": "Invalid timestamp format"}), 400

    try:
        _save_undo_state()

        original_pkt = pcap_data["modified_packets"][packet_id]
        original_pkt.time = new_timestamp

        # Re-generate details to send back to the client
        layers = parse_packet_layers(original_pkt)
        summary = packet_to_summary(packet_id, original_pkt)
        hex_data = original_pkt.build().hex() # Add hex data to the response

        return jsonify({
            "message": "Timestamp updated successfully",
            "layers": layers,
            "summary": summary,
            "hex": hex_data
        })
    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": f"Failed to update timestamp: {str(e)}"}), 500

def find_changed_packet(packets_before, packets_after):
    """Finds the first changed packet and the byte ranges of differences."""
    if not packets_before or not packets_after or len(packets_before) != len(packets_after):
        return None, None

    for i in range(len(packets_after)):
        bytes_before = packets_before[i].build()
        bytes_after = packets_after[i].build()

        if bytes_before != bytes_after:
            # Found the changed packet, now find the differing bytes
            diff_ranges = []
            in_diff = False
            start_diff = -1
            
            limit = min(len(bytes_before), len(bytes_after))
            for j in range(limit):
                if bytes_before[j] != bytes_after[j] and not in_diff:
                    in_diff = True
                    start_diff = j
                elif bytes_before[j] == bytes_after[j] and in_diff:
                    in_diff = False
                    diff_ranges.append([start_diff, j])
            
            if in_diff:
                diff_ranges.append([start_diff, limit])

            # If one is longer than the other
            if len(bytes_before) != len(bytes_after):
                 diff_ranges.append([limit, max(len(bytes_before), len(bytes_after))])

            # For simplicity, we'll just highlight the first block of changes
            highlight_range = diff_ranges[0] if diff_ranges else None
            
            return i, highlight_range

    return None, None

@app.route('/api/undo', methods=['POST'])
def undo():
    if not pcap_data["undo_stack"]:
        return jsonify({"error": "No actions to undo"}), 400
    
    current_packets = copy.deepcopy(pcap_data["modified_packets"])
    
    # Restore previous state
    pcap_data["modified_packets"] = pcap_data["undo_stack"].pop()
    
    # Find what changed
    changed_packet_id, highlight_range = find_changed_packet(current_packets, pcap_data["modified_packets"])

    # Move current state to redo stack
    pcap_data["redo_stack"].append(current_packets)
    
    # Get new summaries for the frontend
    summaries = [packet_to_summary(i, p) for i, p in enumerate(pcap_data["modified_packets"])]

    return jsonify({
        "message": "Undo successful",
        "packets": summaries,
        "changed_packet_id": changed_packet_id,
        "highlight_range": highlight_range
    })

@app.route('/api/redo', methods=['POST'])
def redo():
    if not pcap_data["redo_stack"]:
        return jsonify({"error": "No actions to redo"}), 400
        
    current_packets = copy.deepcopy(pcap_data["modified_packets"])
    
    # Save current state for a potential undo
    _save_undo_state_for_redo()

    # Restore future state from redo stack
    pcap_data["modified_packets"] = pcap_data["redo_stack"].pop()
    
    # Find what changed to send back for highlighting
    changed_packet_id, highlight_range = find_changed_packet(current_packets, pcap_data["modified_packets"])

    # Get new summaries for the frontend
    summaries = [packet_to_summary(i, p) for i, p in enumerate(pcap_data["modified_packets"])]

    return jsonify({
        "message": "Redo successful",
        "packets": summaries,
        "undo_count": len(pcap_data["undo_stack"]),
        "redo_count": len(pcap_data["redo_stack"]),
        "changed_packet_id": changed_packet_id,
        "highlight_range": highlight_range
    })

@app.route('/api/packet/<int:packet_id>/delete', methods=['POST'])
def delete_packet(packet_id):
    """Deletes a packet."""
    if pcap_data["modified_packets"] is None or packet_id >= len(pcap_data["modified_packets"]):
        return jsonify({"error": "Packet not found or pcap not loaded"}), 404

    try:
        _save_undo_state()

        # Remove the packet
        pcap_data["modified_packets"].pop(packet_id)

        # Re-generate summaries with new IDs
        summaries = [packet_to_summary(i, p) for i, p in enumerate(pcap_data["modified_packets"])]

        return jsonify({
            "message": f"Packet {packet_id} deleted successfully",
            "packets": summaries,
            "total_packets": len(pcap_data["modified_packets"]),
        })
    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": f"Failed to delete packet: {str(e)}"}), 500

@app.route('/api/save', methods=['POST'])
def save_pcap_file():
    """将修改后的报文保存到内存中的 pcap 文件并提供下载"""
    data = request.get_json()
    new_filename = data.get('filename')

    if not new_filename:
        return jsonify({"error": "Filename is required"}), 400
    
    if pcap_data["modified_packets"] is None:
        return jsonify({"error": "No pcap data to save"}), 404

    if '/' in new_filename or '..' in new_filename:
        return jsonify({"error": "Invalid filename"}), 400

    try:
        # 创建一个内存中的二进制流
        mem_file = io.BytesIO()
        
        # 使用 PcapWriter 进行更可控的写入
        writer = PcapWriter(mem_file, sync=True)
        writer.write(pcap_data["modified_packets"])
        writer.flush()
        
        # 获取内存中的字节
        pcap_bytes = mem_file.getvalue()
        mem_file.close() # 清理
        
        # 发送获取到的字节内容
        return send_file(
            io.BytesIO(pcap_bytes),
            as_attachment=True,
            download_name=new_filename,
            mimetype='application/vnd.tcpdump.pcap'
        )
    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": f"Failed to generate file: {str(e)}"}), 500


if __name__ == '__main__':
    app.run(debug=True, port=5001)