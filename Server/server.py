import socket
import struct
import threading
import time
from colorama import Fore, Style
import math

# Server settings
UDP_PORT = 13117
TCP_PORT = 7490
MAGIC_COOKIE = b"\xab\xcd\xdc\xba"  # Magic cookie for packet format
MESSAGE_TYPE_OFFER = 0x2
MESSAGE_TYPE_REQUEST = 0x3
MESSAGE_TYPE_PAYLOAD = 0x4

MESSAGE_SIZE_PAYLOAD = 5


class Server:
    def __init__(self, ip_address="192.168.1.118"):
        self.ip_address = ip_address
        self.udp_port = UDP_PORT
        self.tcp_port = TCP_PORT
        self.debug = True
        self.udp_broadcast_server = None
        # self.tcp_server = None

    def start_server(self):
        print(f"Server started, listening on IP address {self.ip_address}")
        self.udp_broadcast_server = socket.socket(
            socket.AF_INET, socket.SOCK_DGRAM)
        self.udp_broadcast_server.setsockopt(
            socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

        broadcasting_thread = threading.Thread(
            target=self.send_broadcast_offer)

        tcp_thread = threading.Thread(target=self.handle_tcp_request)

        udp_thread = threading.Thread(target=self.handle_udp_request)

        tcp_thread.start()
        udp_thread.start()
        broadcasting_thread.start()

        tcp_thread.join()
        udp_thread.join()
        broadcasting_thread.join()

    def handle_udp_request(self):
        udp_server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp_server.bind((self.ip_address, self.udp_port))
        if self.debug:
            print(
                f"{Fore.LIGHTMAGENTA_EX}DEBUG-----UDP server started on port {self.udp_port} {self.ip_address}{Style.RESET_ALL}")

        while True:
            try:
                data, address = udp_server.recvfrom(1024)
                if data[:4] == MAGIC_COOKIE and data[4] == MESSAGE_TYPE_REQUEST:
                    threading.Thread(target=self.process_udp_request,
                                     args=(data, address), daemon=True).start()
            except Exception as e:
                print(f"An error occurred in UDP handling: {e}")

    def process_udp_request(self, data, address):
        if self.debug:
            print(
                f"{Fore.LIGHTMAGENTA_EX}DEBUG-----UDP Recieved request: {data} {Style.RESET_ALL}")

        # Handle UDP connection
        try:
            file_size = int.from_bytes(data[5:13], 'big')
            self.send_payload(file_size, address)

        except Exception as e:
            print(f"Error handling UDP client: {str(e)}")

    def handle_tcp_request(self):
        tcp_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tcp_server.bind((self.ip_address, self.tcp_port))
        if self.debug:
            print(
                f"{Fore.LIGHTBLUE_EX}DEBUG-----TCP server started on port {self.tcp_port} {self.ip_address}{Style.RESET_ALL}")
        tcp_server.listen(5)
        while True:
            try:
                client_socket, client_address = tcp_server.accept()
                if self.debug:
                    print(
                        f"{Fore.LIGHTBLUE_EX}DEBUG-----TCP Accepted connection from {client_address}{Style.RESET_ALL}")
                threading.Thread(target=self.process_tcp_request,
                                 args=(client_socket,), daemon=True).start()
            except KeyboardInterrupt:
                break
            except Exception as e:
                print(f"An error occurred during TCP handling: {e}")
        tcp_server.close()

    def process_tcp_request(self, client_socket):
        # Handle TCP connection
        try:
            # Example: receive data from the client
            data = client_socket.recv(1024)
            if self.debug:
                print(
                    f"{Fore.LIGHTBLUE_EX}DEBUG-----TCP Recieved request: {data} {Style.RESET_ALL}")

            if data[-1] == '\n':
                print(f"{Fore.RED} Received invalid data {
                      data} {Style.RESET_ALL}")
            # Mock data based on size
            file_size = int(data.decode().strip())

            payload_message = ("a" * file_size).encode()
            client_socket.sendall(payload_message)

            if self.debug:
                print(
                    f"{Fore.LIGHTBLUE_EX}DEBUG-----TCP Sent payload: {payload_message} {Style.RESET_ALL}")

        except Exception as e:
            print(f"Error handling TCP client: {str(e)}")
        finally:
            client_socket.close()  # Close the client connection

    def build_offer_packet(self):
        header = struct.pack('4sB', MAGIC_COOKIE, MESSAGE_TYPE_OFFER)
        message = struct.pack('>HH', self.udp_port, self.tcp_port)
        return header + message

    def send_broadcast_offer(self):
        try:
            offer_packet = self.build_offer_packet()
            print("Broadcasting offer...")
            while True:
                self.udp_broadcast_server.sendto(
                    offer_packet, ('255.255.255.255', 12345))
                time.sleep(1)
        except OSError:
            return
        except KeyboardInterrupt:
            return

    def build_payload_packet(self, total_seg_count: int, curr_seg_count: int, payload):
        header = struct.pack('4sB', MAGIC_COOKIE, MESSAGE_TYPE_PAYLOAD)
        total_seg_count = total_seg_count.to_bytes(8, 'big')
        curr_seg_count = curr_seg_count.to_bytes(8, 'big')
        return header + total_seg_count + curr_seg_count + payload

    def send_payload(self, file_size, address):
        try:
            udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            total_seg_count = math.ceil(file_size / MESSAGE_SIZE_PAYLOAD)
            for i in range(total_seg_count):
                curr_seg_count = i
                offset = curr_seg_count * MESSAGE_SIZE_PAYLOAD
                curr_seg_size = min(MESSAGE_SIZE_PAYLOAD, file_size - offset)
                curr_seg_data = ("a" * curr_seg_size).encode()
                payload_packet = self.build_payload_packet(
                    total_seg_count, i, curr_seg_data)

                try:
                    udp_socket.sendto(payload_packet, address)
                    if self.debug:
                        print(
                            f"{Fore.LIGHTMAGENTA_EX}DEBUG-----Sent payload packet #{i} via UDP: {payload_packet} {Style.RESET_ALL}")
                except Exception as e:
                    print(
                        f"An error occurred while sending payload: {str(e)}")
        except OSError:
            return
        except KeyboardInterrupt:
            return


if __name__ == "__main__":
    ip_address = '192.168.1.118'
    server = Server(ip_address)
    server.start_server()
