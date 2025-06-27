import socket
import struct
import random
import time
from threading import Lock
import pandas as pd

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

class UDPClient:
    def __init__(self, server_ip, server_port, target_packets=30):
        """
        初始化UDP客户端参数
        - 网络连接参数：服务器地址、套接字
        - 滑动窗口参数：窗口大小、当前占用量、数据包大小范围
        - 超时控制参数：初始超时时间、RTT平滑因子
        - 序列号管理：基序号、下一个发送序号、发送缓冲区
        - 统计数据：目标包数、RTT记录、重传计数
        - 计时器状态：是否运行、启动时间
        """
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.server_addr = (server_ip, server_port)

        # 窗口管理参数
        self.window_size_bytes = 400
        self.current_window_usage = 0
        self.min_packet_size = 40
        self.max_packet_size = 80

        # 超时管理参数
        self.initial_timeout = 0.3
        self.timeout = self.initial_timeout
        self.rtt_alpha = 0.125
        self.smoothed_rtt = None
        self.rtt_var = None

        # 序列号管理
        self.base = 0
        self.next_seq = 0
        self.buffer = {}  # 存储已发送未确认的数据包
        self.lock = Lock()  # 线程安全锁

        # 数据与统计
        self.target_packets = target_packets
        self.data = b'TestData' * 1000  # 测试数据（重复1000次"TestData"）
        self.rtt_list = []  # 记录RTT值（毫秒）
        self.retransmit_count = 0  # 重传次数
        self.sent_count = 0  # 总发送包数
        self.initial_sent = 0  # 初始发送包数（不包含重传）

        # 计时器
        self.timer_running = False
        self.timer_start = 0

        # 服务器配置（从服务器CONFIG包获取，此处为初始值）
        self.server_drop_rate = 0.3

    def build_header(self, ptype, seq, ack, window, length):
        """
        构建UDP协议头部
        - 使用struct.pack按大端序打包数据
        - 高4位为类型，低4位为保留位（设为0x0F）
        - 返回二进制头部数据
        """
        return struct.pack('!BHHHB', (ptype << 4) | 0x0F, seq, ack, window, length)

    def parse_header(self, data):
        """
        解析UDP协议头部
        - 从二进制数据中提取头部字段
        - 返回：类型、序列号、确认号、窗口大小、数据长度
        """
        header = struct.unpack('!BHHHB', data[:8])
        return header[0] >> 4, header[1], header[2], header[3], header[4]

    def calculate_data_range(self, seq, packet_size):
        """
        计算数据包在测试数据中的字节范围
        - seq：数据包序列号
        - packet_size：数据包大小
        - 返回：(起始字节位置, 结束字节位置)
        """
        start = seq * self.min_packet_size
        end = start + min(packet_size, len(self.data) - start)
        return start, end

    def connect(self):
        """
        实现三次握手建立连接
        - 发送SYN包并等待SYN-ACK响应
        - 处理超时重传（最多5次）
        - 成功后发送ACK完成握手
        - 返回：连接是否建立成功
        """
        retries = 0
        max_retries = 5
        my_seq = random.randint(0, 65535)
        while retries < max_retries:
            syn = self.build_header(1, my_seq, 0, self.window_size_bytes, 0)
            self.client_socket.sendto(syn, self.server_addr)
            self.client_socket.settimeout(self.timeout)
            try:
                data, _ = self.client_socket.recvfrom(1024)
                ptype, server_seq, ack, _, _ = self.parse_header(data)
                if ptype == 2 and ack == my_seq + 1:  # 验证SYN-ACK合法性
                    ack_pkt = self.build_header(4, my_seq + 1, server_seq + 1,
                                                self.window_size_bytes, 0)
                    self.client_socket.sendto(ack_pkt, self.server_addr)
                    print("[连接] 三次握手成功")
                    self.base = 0
                    self.next_seq = 0
                    return True
            except socket.timeout:
                retries += 1
                print(f"[连接重试] 第{retries}次")
                self.timeout *= 2  # 指数退避
        return False

    def send_data(self):
        """
        主发送循环：持续发送数据直到达到目标包数
        - 流程：发送窗口包 → 接收ACK → 检查超时 → 处理重传
        - 完成后发送FIN包断开连接，并生成统计汇总
        """
        while self.base < self.target_packets:
            self.send_window_packets()
            self.receive_ack()
            if self.check_timer():
                self.handle_timeout()
        fin = self.build_header(5, self.next_seq, 0, self.window_size_bytes, 0)
        self.client_socket.sendto(fin, self.server_addr)
        print("[断开] 发送FIN")
        self.summary()

    def send_window_packets(self):
        """
        发送滑动窗口内的数据包
        - 条件：未达目标包数且窗口未填满
        - 随机生成数据包大小（在最小/最大值之间）
        - 从测试数据中提取对应字节段
        - 构建DATA包并加入发送缓冲区
        - 启动计时器（若未运行）
        """
        while (self.next_seq < self.target_packets and
               self.current_window_usage < self.window_size_bytes):
            remaining_window = self.window_size_bytes - self.current_window_usage
            packet_size = min(random.randint(self.min_packet_size, self.max_packet_size),
                              remaining_window)
            start, end = self.calculate_data_range(self.next_seq, packet_size)
            chunk = self.data[start:end]
            packet = self.build_header(3, self.next_seq, 0,
                                       self.window_size_bytes, len(chunk)) + chunk

            with self.lock:
                self.client_socket.sendto(packet, self.server_addr)
                send_time = time.time()
                self.buffer[self.next_seq] = {
                    'packet': packet,
                    'send_time': send_time,
                    'acked': False,
                    'start': start,
                    'end': end,
                    'retries': 0
                }
                print(f"[发送] 第{self.next_seq}个(第{start}~{end}字节)client端已经发送")
                self.sent_count += 1
                self.initial_sent += 1
                self.next_seq += 1
                self.current_window_usage += len(chunk)

            if not self.timer_running and self.buffer:
                self.start_timer()

    def start_timer(self):
        """启动超时计时器，记录开始时间"""
        self.timer_start = time.time()
        self.timer_running = True

    def stop_timer(self):
        """停止超时计时器"""
        self.timer_running = False

    def check_timer(self):
        """检查是否超时：计时器运行且经过时间超过超时值"""
        return self.timer_running and (time.time() - self.timer_start > self.timeout)

    def handle_timeout(self):
        """
        处理超时重传逻辑
        - 重传所有未确认的数据包
        - 重置计时器
        - 记录重传次数
        """
        print(f"[超时重传] 窗口从{self.base}开始重传")
        self.stop_timer()
        with self.lock:
            for seq in sorted(self.buffer.keys()):
                if not self.buffer[seq]['acked']:
                    packet_info = self.buffer[seq]
                    self.client_socket.sendto(packet_info['packet'], self.server_addr)
                    packet_info['send_time'] = time.time()
                    packet_info['retries'] += 1
                    self.sent_count += 1
                    self.retransmit_count += 1
                    print(f"[超时重传] 第{seq}个(第{packet_info['start']}~{packet_info['end']}字节)数据包")
            if self.buffer:
                self.start_timer()

    def receive_ack(self):
        """
        接收并处理ACK包
        - 解析ACK中的确认号
        - 标记已确认的数据包，释放窗口空间
        - 移动窗口基序号
        - 计算RTT并调整超时时间
        - 处理socket超时异常（非错误，继续循环）
        """
        try:
            self.client_socket.settimeout(0.1)  # 短超时，非阻塞接收
            data, _ = self.client_socket.recvfrom(1024)
            if len(data) < 8:
                return
            ptype, _, ack, _, length = self.parse_header(data)

            if ptype == 4 and ack > 0:  # 仅处理ACK类型包
                with self.lock:
                    old_base = self.base
                    for seq in list(self.buffer.keys()):
                        if seq < ack and not self.buffer[seq]['acked']:
                            send_time = self.buffer[seq]['send_time']
                            rtt = (time.time() - send_time) * 1000  # 转换为毫秒
                            self.rtt_list.append(rtt)
                            start, end = self.buffer[seq]['start'], self.buffer[seq]['end']
                            print(f"[确认] 第{seq}个(第{start}~{end}字节)server端已经收到，RTT是{rtt:.2f}ms")
                            self.buffer[seq]['acked'] = True
                            self.current_window_usage -= (end - start + 1)

                    # 移动窗口基序号，移除已确认的包
                    while self.base in self.buffer and self.buffer[self.base]['acked']:
                        del self.buffer[self.base]
                        self.base += 1

                    if old_base != self.base and self.buffer:
                        self.stop_timer()
                        self.start_timer()

                    self.adjust_timeout()
        except socket.timeout:
            pass  # 超时属于正常现象，继续循环

    def adjust_timeout(self):
        """
        动态调整超时时间（增强稳定性）
        - 当RTT记录≥10条时，使用最近10条RTT的中位数
        - 超时时间=5×中位数/1000（转换为秒）
        - 中位数比平均值更能抵抗异常值影响
        """
        if len(self.rtt_list) >= 10:
            sorted_rtt = sorted(self.rtt_list[-10:])
            median_rtt = sorted_rtt[5]  # 10个数据的中位数（索引5）
            self.timeout = 5 * median_rtt / 1000  # 转换为秒

    def summary(self):
        """
        生成传输统计汇总
        - 计算实际丢包率：目标包数/总发送包数×100%
        - 使用pandas计算RTT统计量（最大、最小、平均、标准差）
        - 打印模拟丢包率与实际丢包率对比
        """
        if not self.rtt_list:
            print("[汇总信息] 未获取到RTT数据")
            return

        # 正确丢包率计算：(总发送-目标包数)/总发送*100% → 此处修正为目标包数/总发送×100%（实际接收率）
        loss_rate = (self.target_packets / self.sent_count * 100
                     if self.sent_count > 0 else 0)

        df = pd.DataFrame(self.rtt_list, columns=["RTT"])
        print("\n[汇总信息]")
        print(f"模拟丢包率: {self.server_drop_rate * 100}%")
        print(f"实际丢包率: {loss_rate:.2f}%")
        print(f"总发送包数: {self.sent_count}")
        print(f"初始发送包数: {self.initial_sent}")
        print(f"重传次数: {self.retransmit_count}")
        print(f"最大RTT: {df['RTT'].max():.2f}ms")
        print(f"最小RTT: {df['RTT'].min():.2f}ms")
        print(f"平均RTT: {df['RTT'].mean():.2f}ms")
        print(f"RTT标准差: {df['RTT'].std():.2f}ms")


if __name__ == '__main__':
    import sys

    if len(sys.argv) != 3:
        print("用法: python udpclient.py <服务器IP> <服务器端口>")
        sys.exit(1)
    ip = sys.argv[1]
    port = int(sys.argv[2])
    client = UDPClient(ip, port)
    if client.connect():
        client.send_data()