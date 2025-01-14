import socket
import threading
import time
import struct
from colorama import Fore, Style
import consts


class Client:
    def __init__(self):
        self.file_size = None
        self.tcp_connections = None
        self.udp_connections = None
        self.udp_socket = None
        self.server_UDP_port = None
        self.server_TCP_port = None
        self.server_IP_address = None
        self.states = {0: "Startup",
                       1: "Looking for a server", 2: "Speed test"}
        self.client_state = 0
        self.debug = True

    def start_client(self):
        self.startup()
        self.create_udp_socket()  # Create the UDP socket before looking for a server
        while True:
            try:
                if self.client_state == 1:
                    self.looking_for_server()
            except KeyboardInterrupt:
                if self.debug:
                    print("DEBUG-----Exiting...")
                self.udp_socket.close()
                return

    def startup(self):
        self.client_state = 0
        if self.debug:
            print(
                f"{Fore.GREEN}DEBUG-----state: {self.states[self.client_state]} {Style.RESET_ALL}")

        while True:
            try:
                self.file_size = int(input("Enter file size: "))
                self.tcp_connections = int(
                    input("Enter number of TCP connections: "))
                self.udp_connections = int(
                    input("Enter number of UDP connections: "))

                if self.file_size <= 0 or self.tcp_connections <= 0 or self.udp_connections <= 0:
                    raise ValueError("Please enter positive values.")

                self.client_state = 1
                break  # Exit the loop if everything is correct

            except ValueError as e:
                print(f"Invalid input: {e}. Please try again.")

    def looking_for_server(self):
        if self.debug:
            print(
                f"{Fore.GREEN}DEBUG-----state: {self.states[self.client_state]} {Style.RESET_ALL}")

        while self.client_state == 1:
            try:
                print(f"Client started, listening for offer requests...")
                data, address = self.udp_socket.recvfrom(1024)
                self.handle_offer_packet(data, address)

            except KeyboardInterrupt:
                print("Exiting...")
                self.server_running = False
                self.udp_socket.close()
                return

    def handle_payload_packet(self, data):
        if data[:4] == consts.MAGIC_COOKIE and data[4] == consts.MESSAGE_TYPE_PAYLOAD:
            total_seg_count = int.from_bytes(data[5:13], 'big')
            curr_seg_count = int.from_bytes(data[13:21], 'big')
            payload = data[21:].decode()
            print(total_seg_count, curr_seg_count, payload)
            return total_seg_count, curr_seg_count, payload

    def handle_offer_packet(self, data, address):
        if self.debug:
            print(
                f"{Fore.GREEN}DEBUG-----Received offer: {data[:10]} From: {address[0]} {Style.RESET_ALL}")
        if data[:4] == consts.MAGIC_COOKIE and data[4] == consts.MESSAGE_TYPE_OFFER:
            self.server_UDP_port = int.from_bytes(data[5:7], 'big')
            self.server_TCP_port = int.from_bytes(data[7:9], 'big')
            self.server_IP_address = address[0]
            print(f"Received offer from {self.server_IP_address}")
            self.client_state = 2
            if self.debug:
                print(
                    f"{Fore.GREEN}DEBUG-----state: {self.states[self.client_state]} {Style.RESET_ALL}")

            self.request_file()  # Proceed to request file

    def request_file(self):
        request_packet = consts.MAGIC_COOKIE + \
            bytes([consts.MESSAGE_TYPE_REQUEST]) + \
            self.file_size.to_bytes(8, 'big')

        # Start the requests in separate threads
        for i in range(self.tcp_connections):
            threading.Thread(target=self.request_tcp).start()
            if self.debug:
                print(
                    f"{Fore.CYAN}DEBUG-----Sent request packet (TCP #{i}) {Style.RESET_ALL}")

        for i in range(self.udp_connections):
            threading.Thread(target=self.request_udp,
                             args=(request_packet,)).start()
            if self.debug:
                print(
                    f"{Fore.MAGENTA}DEBUG-----Sent request packet (UDP #{i}) {Style.RESET_ALL}")

    def request_tcp(self):
        try:
            # Create a new TCP socket per thread
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as tcp_socket:
                tcp_socket.connect(
                    (self.server_IP_address, self.server_TCP_port))
                tcp_socket.sendall(f"{self.file_size}\n".encode())
                start_time = time.time()

                data_received = tcp_socket.recv(self.file_size)
                finish_time = time.time()

                total_time = finish_time - start_time
                return len(data_received), total_time

        except ConnectionRefusedError:
            print("Connection refused, server may not be available")
        except Exception as e:
            print(f"Error during TCP transfer: {e}")

    def request_udp(self, request_packet):
        try:
            # Create a new UDP socket for sending
            udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            udp_socket.bind(("", 0))  # Bind to any available port
            # udp_socket.settimeout(1.0)  # Set a timeout for receiving data
            udp_socket.sendto(
                request_packet, (self.server_IP_address, self.server_UDP_port))

            start_time = time.time()

            total_bytes_received = 0
            recieved_seg_count = 0

            while True:
                try:
                    packet, _ = udp_socket.recvfrom(1024)
                    if self.debug:
                        print(
                            f"{Fore.LIGHTCYAN_EX}DEBUG-----UDP Received payload packet\n   packet: {packet} {Style.RESET_ALL}")
                    total_seg_count, curr_seg_count, payload = self.handle_payload_packet(
                        packet)
                    print(f"{Fore.LIGHTCYAN_EX} Received segment {
                        curr_seg_count}/{total_seg_count} {Style.RESET_ALL}")
                    recieved_seg_count += 1
                    total_bytes_received += len(payload)
                    if len(packet) < consts.MESSAGE_SIZE_PAYLOAD:  # End of transmission
                        break
                # except socket.timeout:
                #     break  # Exit on timeout
                except ValueError as e:
                    print(f"Corrupted Message: {e}")

            finish_time = time.time()
            total_time = finish_time - start_time
            return total_bytes_received, total_time, recieved_seg_count, total_seg_count
        except Exception as e:
            print(f"Error during UDP request: {e}")

    def create_udp_socket(self):
        self.udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # Bind to listen for offers
        self.udp_socket.bind(("", consts.UDP_BROADCAST_PORT))


if __name__ == "__main__":
    client = Client()
    client.start_client()
