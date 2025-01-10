import socket
import threading
import time

# Client settings
UDP_PORT = 13117
TCP_PORT = 12346
MAGIC_COOKIE = b"\xab\xcd\xdc\xba"  # Magic cookie for packet format


class Client:
    def __init__(self):
        self.server_udp_port = None
        self.server_tcp_port = None
        self.tcp_client = None
        self.server_address = None
        self.states = {"Startup": 0,
                       "Looking for a server": 1, "Speed test": 2}
        self.debug = True

    def start_client(self):
        self.client_state = self.states["Startup"]
        if self.debug:
            print("state: ", self.client_state)
        while True:
            self.udp_client()

    def handle_received_data(self, data, address):
        if self.debug:
            print(f"Received message: {data[:10]}")
            print(f"From address: {address}")
        if data.startswith(MAGIC_COOKIE):
            message_type = data[4]
            if message_type == 0x2:
                self.handle_offer(data, address)
            if message_type == 0x4:
                self.handle_payload(data, address)

    def handle_offer(self, data, address):
        self.server_udp_port = data[5:7]
        self.server_tcp_port = data[7:9]
        print(f"Received offer from {address}")
        # When receiving an offer, connect to the server
        self.server_address = address
        self.request_file()

    def request_file(self):
        # Ask user for file size and number of connections
        file_size = int(input("Enter the file size in bytes: "))
        tcp_connections = int(input("Enter number of TCP connections: "))
        udp_connections = int(input("Enter number of UDP connections: "))

        print("Connecting to server via TCP...")

        # Connect via TCP and send the request
        self.tcp_client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.tcp_client.connect(self.server_address)

        # Send the file size request over TCP
        self.tcp_client.sendall(f"{file_size}\n".encode())

        # Start the UDP requests in separate threads
        for i in range(udp_connections):
            threading.Thread(target=self.send_udp_request,
                             args=(file_size,)).start()

    def send_udp_request(self, file_size):
        # Send a UDP request for the file
        request_packet = MAGIC_COOKIE + \
            bytes([0x3]) + file_size.to_bytes(8, 'big')  # Example packet
        self.udp_socket.sendto(request_packet, self.server_address)

        # Implement logic to receive UDP data (in this simple example, just simulate a quick response)
        start_time = time.time()
        total_bytes_received = 0

        # Simulate receiving UDP packets - You will need a proper method for this based on server implementation
        while True:
            try:
                packet, _ = self.udp_socket.recvfrom(1024)
                total_bytes_received += len(packet)
                if len(packet) < 1024:  # Assuming we get a short packet, exit condition
                    break
            except socket.timeout:
                break  # Exit after a timeout
        end_time = time.time()

        total_time = end_time - start_time
        print(f"UDP transfer finished for file size {
              file_size} bytes, total time: {total_time:.2f} seconds.")

    def udp_client(self):

        self.create_udp_socket()
        while True:
            try:
                print(f"Client started, listening for offer requests...")
                data, address = self.udp_socket.recvfrom(1024)
                self.handle_received_data(data, address)
            except KeyboardInterrupt:
                if self.debug:
                    print("Exiting...")
                self.server_running = False
                self.udp_socket.close()
                return

    def create_udp_socket(self):
        self.udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # self.udp_socket.bind(("", 13117))
        if self.debug:
            print(f"udp socket created")


if __name__ == "__main__":
    client = Client()
    client.start_client()
