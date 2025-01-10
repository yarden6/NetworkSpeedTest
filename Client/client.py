import socket
import threading
import time
import struct

# Client settings
UDP_BROADCAST_PORT = 12345
UDP_PORT = 13117
TCP_PORT = 7490
MAGIC_COOKIE = b"\xab\xcd\xdc\xba"  # Magic cookie for packet format


class Client:
    def __init__(self):
        self.file_size = None
        self.tcp_connections = None
        self.udp_connections = None
        self.udp_socket = None
        self.server_udp_port = None
        self.server_tcp_port = None
        self.server_address = None
        self.states = {"Startup": 0,
                       "Looking for a server": 1, "Speed test": 2}
        self.debug = True

    def start_client(self):
        self.startup()
        self.create_udp_socket()  # Create the UDP socket before looking for a server
        try:
            self.looking_for_server()
        except KeyboardInterrupt:
            if self.debug:
                print("DEBUG-----Exiting...")
            self.udp_socket.close()
            return

    def startup(self):
        self.client_state = self.states["Startup"]
        if self.debug:
            print("DEBUG-----state: ", self.client_state)
        while True:
            try:
                self.file_size = int(input("Enter file size: "))
                self.tcp_connections = int(
                    input("Enter number of TCP connections: "))
                self.udp_connections = int(
                    input("Enter number of UDP connections: "))

                if self.file_size <= 0 or self.tcp_connections <= 0 or self.udp_connections <= 0:
                    raise ValueError("Please enter positive values.")

                break  # Exit the loop if everything is correct

            except ValueError as e:
                print(f"Invalid input: {e}. Please try again.")

    def looking_for_server(self):
        self.client_state = self.states["Looking for a server"]
        if self.debug:
            print("DEBUG-----state: ", self.client_state)

        wait_for_offer = True
        while wait_for_offer:
            try:
                print(f"Client started, listening for offer requests...")
                data, address = self.udp_socket.recvfrom(1024)
                wait_for_offer = False
                self.handle_received_data(data, address)

            except KeyboardInterrupt:
                print("Exiting...")
                self.server_running = False
                self.udp_socket.close()
                return

    def handle_received_data(self, data, address):
        if self.debug:
            print(f"DEBUG-----Received message: {data[:10]}")
            print(f"DEBUG-----From address: {address}")
        if data.startswith(MAGIC_COOKIE):
            message_type = data[4]
            if message_type == 0x2:
                self.handle_offer(data, address)

    def handle_offer(self, data, address):
        self.server_udp_port = int.from_bytes(data[5:7], 'big')
        self.server_tcp_port = int.from_bytes(data[7:9], 'big')
        print(f"Received offer from {address} with UDP port {
              self.server_udp_port} and TCP port {self.server_tcp_port}")
        print(f"Received offer from {address}")
        # Save server address
        # Update self.server_address with correct TCP port and not UDP port
        self.server_address = (address[0], self.server_tcp_port)
        self.request_file()  # Proceed to request file

    def request_file(self):
        request_packet = MAGIC_COOKIE + \
            bytes([0x3]) + self.file_size.to_bytes(8, 'big')

        print(request_packet)

        # Start the requests in separate threads
        for _ in range(self.tcp_connections):
            threading.Thread(target=self.request_tcp).start()

        for _ in range(self.udp_connections):
            threading.Thread(target=self.request_udp,
                             args=(request_packet,)).start()

    def request_tcp(self):
        try:
            if self.debug:
                print("DEBUG-----Connecting to server via TCP...")
            # Create a new TCP socket per thread
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as tcp_socket:
                tcp_socket.connect(self.server_address)
                tcp_socket.sendall(f"{self.file_size}\n".encode())
                data_received = tcp_socket.recv(self.file_size)
                print(f"TCP transfer finished: received {
                      len(data_received)} bytes")
        except ConnectionRefusedError:
            print("Connection refused, server may not be available")
        except Exception as e:
            print(f"Error during TCP transfer: {e}")

    def request_udp(self, request_packet):
        try:
            if self.debug:
                print("DEBUG-----Sending UDP request...")
            # Create a new UDP socket for sending
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp_socket:
                udp_socket.sendto(request_packet, self.server_address)
                # Wait for UDP response
                udp_socket.settimeout(1.0)  # Set a timeout for receiving data
                total_bytes_received = 0
                start_time = time.time()

                while True:
                    try:
                        packet, _ = udp_socket.recvfrom(1024)
                        total_bytes_received += len(packet)
                        if len(packet) < 1024:  # End of transmission
                            break
                    except socket.timeout:
                        break  # Exit on timeout

                end_time = time.time()
                total_time = end_time - start_time
                print(f"UDP transfer finished: received {
                      total_bytes_received} bytes in {total_time:.2f} seconds")
        except Exception as e:
            print(f"Error sending UDP request: {e}")

    def create_udp_socket(self):
        self.udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # self.udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # Bind to listen for offers
        self.udp_socket.bind(("", UDP_BROADCAST_PORT))
        # if self.debug:
        #     print(f"UDP socket created and bound to port {UDP_PORT}")


if __name__ == "__main__":
    client = Client()
    client.start_client()
