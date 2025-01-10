import socket
import struct
import threading
import time

# Server settings
UDP_PORT = 13117
TCP_PORT = 7490
MAGIC_COOKIE = b"\xab\xcd\xdc\xba"  # Magic cookie for packet format
MESSAGE_TYPE_OFFER = 0x2


class Server:
    def __init__(self, ip_address="0.0.0.0"):
        self.ip_address = ip_address
        self.udp_port = UDP_PORT
        self.tcp_port = TCP_PORT
        self.debug = False

        self.tcp_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def handle_client_connection(client_socket):
        # Handle TCP connection
        try:
            # Example: receive data from the client
            data = client_socket.recv(1024)
            print(f"Received data: {data.decode()}")
            # Mock data based on size
            file_data = b'\x00' * int(data.decode().strip())
            client_socket.sendall(file_data)  # Sending mock data
        except Exception as e:
            print(f"Error handling client: {str(e)}")
        finally:
            client_socket.close()  # Close the client connection

    def start_udp_server(self):
        self.udp_server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp_server.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        # self.udp_server.bind((self.ip_address, self.udp_port))
        print(f"Server started, listening on IP address {self.ip_address}")
        broadcast_offer_thread = threading.Thread(target=self.broadcast_offer)
        broadcast_offer_thread.start()

    def start_tcp_server(self):
        self.tcp_server.bind((self.ip_address, self.tcp_port))
        self.tcp_server.listen()
        print(f"TCP Server started, listening on {
              self.ip_address}:{self.tcp_port}")

        while True:
            client_socket, client_address = self.tcp_server.accept()
            print(f"Accepted connection from {client_address}")
            threading.Thread(target=self.handle_client_connection,
                             args=(client_socket,)).start()

    def build_offer_packet(self):
        header = struct.pack('4sB', MAGIC_COOKIE, MESSAGE_TYPE_OFFER)
        message = struct.pack('>HH', self.udp_port, self.tcp_port)
        return header + message

        # udp_port_bytes = struct.pack('!H', self.udp_port)
        # tcp_port_bytes = struct.pack('!H', self.tcp_port)
        # return MAGIC_COOKIE + \
        #     bytes([MESSAGE_TYPE_OFFER]) + udp_port_bytes + tcp_port_bytes

    def broadcast_offer(self):
        try:
            # Create the offer message
            offer_packet = self.build_offer_packet()

            print("Broadcasting offer...")
            # Broadcast the offer message
            while True:
                self.udp_server.sendto(
                    offer_packet, ('255.255.255.255', 12345))
                if self.debug:
                    print("Broadcasted offer sent!")
                time.sleep(1)
        except OSError:
            return
        except KeyboardInterrupt:
            return


if __name__ == "__main__":
    ip_address = '0.0.0.0'
    server = Server(ip_address)
    server.start_udp_server()
