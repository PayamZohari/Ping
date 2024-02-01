import os
import socket
import struct
import sys
import time
import select
from dns_functions import dns_resolve

ICMP_ECHO_REQUEST = 8


def calculate_checksum(packet):
    checksum = 0
    count_to = (len(packet) // 2) * 2

    for count in range(0, count_to, 2):
        checksum += packet[count + 1] * 256 + packet[count]
        checksum &= 0xffffffff

    if count_to < len(packet):
        checksum += packet[len(packet) - 1]
        checksum &= 0xffffffff

    checksum = (checksum >> 16) + (checksum & 0xffff)
    checksum += checksum >> 16
    checksum = ~checksum & 0xffff
    checksum = (checksum >> 8) | (checksum << 8 & 0xff00)

    return checksum


def receive_ping(my_socket, process_id, timeout):
    ready, _, _ = select.select([my_socket], [], [], timeout)

    if not ready:
        return None

    time_received = time.time()
    received_packet, _ = my_socket.recvfrom(1024)

    icmp_header = received_packet[20:28]
    packet_type, code, checksum, packet_id, sequence = struct.unpack("bbHHh", icmp_header)

    if packet_type != ICMP_ECHO_REQUEST and packet_id == process_id:
        bytes_in_double = struct.calcsize("d")
        time_sent = struct.unpack("d", received_packet[28: 28 + bytes_in_double])[0]
        return time_received - time_sent

    return None


def send_ping(my_socket, destination_address, process_id, dns_server=None):
    destination_address = resolve_with_dns_server(destination_address, dns_server) if dns_server else socket.gethostbyname(destination_address)

    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, 0, process_id, 1)
    bytes_in_double = struct.calcsize("d")
    data = (192 - bytes_in_double) * "Q"
    data = struct.pack("d", time.time()) + bytes(data, "utf-8")

    checksum = calculate_checksum(header + data)
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, socket.htons(checksum), process_id, 1)
    packet = header + data

    my_socket.sendto(packet, (destination_address, 1))


def perform_ping(destination_address, timeout=1, packet_count=4, dns_server=None):
    if timeout <= 0 or packet_count <= 0:
        print("Please enter valid timeout and packet count.")
        return

    try:
        print(f"Sending ping to \"{destination_address}\":")
        with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname("icmp")) as my_socket:
            process_id = os.getpid() & 0xFFFF
            total_time = 0
            packet_loss = 0

            for _ in range(packet_count):
                send_ping(my_socket, destination_address, process_id, dns_server)
                delay = receive_ping(my_socket, process_id, timeout)

                if delay is None:
                    packet_loss += 1
                    print("Ping Timed out")
                else:
                    total_time += delay
                    print(f"Ping successful: time={round(delay * 1000, 2)}ms" if round(delay * 1000, 2) > 0 else "Ping successful: time=<1ms")

            average_time = round(total_time * 1000 / packet_count, 2)
            packet_loss_percentage = round((packet_loss / packet_count) * 100, 2)

            if packet_loss_percentage < 100:
                print(f"+ Average Ping time: {average_time}ms" if average_time > 0 else "+ Average Ping time: <1ms")
            print(f"+ Packet Loss Percentage: {packet_loss_percentage}%")

    except socket.error as e:
        print("Socket error:", e)


if __name__ == '__main__':
    command_line_arguments = sys.argv[1:]
    if not command_line_arguments:
        perform_ping("kntu.ac.ir")
    elif len(command_line_arguments) <= 3:
        perform_ping(*command_line_arguments)
    else:
        print("Invalid number of arguments.")
