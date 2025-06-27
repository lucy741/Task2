import socket
import random
import struct
from threading import Thread
from datetime import datetime

"""
自定义UDP协议头部格式说明：
Type(类型):4 bits,支持16种类型，1=SYN（连接请求），2=SYN-ACK（连接确认），3=DATA（数据），
          4=ACK（确认），5=FIN（断开请求）
Reserved(保留位):4 bits,预留字段
Sequence(序列号):2字节，表示数据包的顺序编号(范围：0~65535)
Ack(确认号):2字节，累积确认号，表示接收方期望接收的下一个数据包序号（范围：0~65535）
Windows(窗口大小):2字节，发送方的接收窗口大小（固定为400字节）
Length(数据长度):1字节，数据长度范围（0~255字节）
"""

class UDPServer:
    def __init__(self, host='127.0.0.1', port=8080, drop_rate=0.3):
        # 初始化服务器套接字并绑定地址
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.server_socket.bind((host, port))
        self.drop_rate = drop_rate  # 客户端→服务器丢包率
        self.connections = {}  # 存储客户端连接状态
        self.stats = {  # 统计信息
            'client_to_server': {'sent': 0, 'dropped': 0},
            'server_to_client': {'sent': 0}
        }
        print(f"UDP服务器启动，监听{host}:{port}")

    def start(self):
        # 服务器主循环，持续接收客户端数据
        while True:
            try:
                data, addr = self.server_socket.recvfrom(1024)
                Thread(target=self.handle_client, args=(data, addr)).start()
            except Exception as e:
                print(f"[服务器错误] {e}")

    def parse_header(self, data):
        # 解析数据包头部信息
        header = struct.unpack('!BHHHB', data[:8])
        ptype = header[0] >> 4  # 提取高4位作为类型
        seq = header[1]  # 序列号
        ack = header[2]  # 确认号
        window = header[3]  # 窗口大小
        length = header[4]  # 数据长度
        return ptype, seq, ack, window, length

    def build_header(self, ptype, seq, ack, window, length):
        # 构建数据包头部
        return struct.pack('!BHHHB', (ptype << 4) | 0x0F, seq, ack, window, length)

    def handle_client(self, data, addr):
        # 处理客户端请求的核心方法
        header = data[:8]  # 头部数据
        payload = data[8:]  # 负载数据
        ptype, seq, ack, window, length = self.parse_header(header)

        # 如果是新连接，初始化连接状态
        if addr not in self.connections:
            self.connections[addr] = {'state': 'CLOSED', 'expected_seq': 0, 'my_seq': 0}

        if ptype == 1:  # SYN（连接请求）
            print(f"[连接请求] 来自{addr}，SYN序列号={seq}")
            my_seq = random.randint(0, 65535)  # 生成随机初始序列号
            syn_ack = self.build_header(2, my_seq, seq + 1, 400, 0)  # 构建SYN-ACK响应
            self.server_socket.sendto(syn_ack, addr)  # 发送响应
            self.stats['server_to_client']['sent'] += 1  # 更新统计
            self.connections[addr] = {'state': 'SYN_RECEIVED', 'expected_seq': 0, 'my_seq': my_seq}

        elif ptype == 4 and addr in self.connections:  # ACK（确认）
            if self.connections[addr]['state'] == 'SYN_RECEIVED':
                print(f"[连接建立] 收到{addr}的ACK，连接已建立")
                self.connections[addr]['state'] = 'ESTABLISHED'  # 更新连接状态
                self.connections[addr]['expected_seq'] = 0

                # 发送丢包率配置给客户端
                config_pkt = self.build_header(6, 0, 0, 400, 1) + struct.pack('!B', int(self.drop_rate * 100))
                self.server_socket.sendto(config_pkt, addr)
                self.stats['server_to_client']['sent'] += 1

        elif ptype == 3 and addr in self.connections:  # DATA（数据）
            if self.connections[addr]['state'] != 'ESTABLISHED':
                print(f"[未建立连接] 来自{addr}的数据包被丢弃")
                return

            self.stats['client_to_server']['sent'] += 1  # 更新接收统计
            expected_seq = self.connections[addr]['expected_seq']

            # 模拟丢包
            if random.random() < self.drop_rate:
                print(f"[模拟丢包] 丢弃第{seq}个数据包")
                self.stats['client_to_server']['dropped'] += 1
                return

            if seq == expected_seq:  # 按序接收
                print(f"[接收] 成功接收第{seq}个数据包")
                self.connections[addr]['expected_seq'] += 1  # 期望序列号递增
            else:  # 乱序包
                print(f"[乱序包] 期望{expected_seq}，实际{seq}")

            # 发送ACK，携带服务器当前时间
            server_time = datetime.now().strftime('%H:%M:%S.%f')
            ack_pkt = self.build_header(4, 0, self.connections[addr]['expected_seq'], 400, len(server_time))
            self.server_socket.sendto(ack_pkt + server_time.encode(), addr)
            self.stats['server_to_client']['sent'] += 1

        elif ptype == 5 and addr in self.connections:  # FIN（断开请求）
            print(f"[断开请求] 收到来自{addr}的FIN，序列号={seq}")
            fin_ack = self.build_header(5, 0, seq + 1, 400, 0)  # 构建FIN-ACK响应
            self.server_socket.sendto(fin_ack, addr)  # 发送响应
            self.stats['server_to_client']['sent'] += 1

            del self.connections[addr]  # 删除连接状态

if __name__ == '__main__':
    server = UDPServer()
    server.start()