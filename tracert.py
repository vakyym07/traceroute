import os
import sys
import struct
import socket
import argparse
from ipaddress import IPv4Address
from whois import Whois


ICMP_ECHO = 8


class Tracert:
    def __init__(self, dst, packet_size=40, max_ttl=30):
        self.dst = dst
        self.max_ttl = max_ttl
        self.packet_size = packet_size
        self.own_id = os.getpid() & 0xFFFF
        self.seq_number = 0

    def run(self):
        port = 33434
        icmp = socket.getprotobyname('icmp')
        addr = self.get_ip(self.dst)

        if not addr:
            print('{} is invalid'.format(self.dst))
            return
        if self.is_local(addr):
            self.write(1, addr, '', '', '', True)
            return
        ttl = 1
        icmp_package = self.create_packet()

        while True:
            send_sock, recv_sock = Tracert.create_sockets(port, icmp, ttl)
            Tracert.send_packet(send_sock, icmp_package, addr, port)

            try:
                packet_data, resp_addr = recv_sock.recvfrom(1024)
                resp_addr = resp_addr[0]
                inf_addr = self.perform_whois(resp_addr)
                self.write(ttl, resp_addr, inf_addr['netname'],
                           inf_addr['origin'], inf_addr['country'], inf_addr['local'])
            except socket.error:
                resp_addr = None
                self.write(ttl, '*', '', '', '', False)
            finally:
                send_sock.close()
                recv_sock.close()
            ttl += 1

            if resp_addr == addr or ttl > self.max_ttl:
                break

    @staticmethod
    def send_packet(send_sock, icmp_packet, addr, port):
        for _ in range(3):
            try:
                send_sock.sendto(icmp_packet, (addr, port))
            except socket.error:
                pass

    @staticmethod
    def create_sockets(port, proto, ttl):
        try:
            recv_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, proto)
            recv_sock.settimeout(4)
            recv_sock.bind(('', port))
        except OSError as e:
            print('Accesses denied.\n' + e.args[1])
            sys.exit()

        try:
            send_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, proto)
            send_sock.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
        except OSError as e:
            print('Accesses denied.\n' + e.args[1])
            sys.exit()
        return send_sock, recv_sock

    def create_packet(self):
        checksum = 0
        header = struct.pack(
            "!BBHHH", ICMP_ECHO, 0, checksum, self.own_id, self.seq_number
        )
        pad_bytes = []
        start_value = 0x42
        for i in range(start_value, start_value + self.packet_size - 8):
            pad_bytes += [i & 0xff]
        data = bytes(pad_bytes)

        checksum = self.calculate_cheksum(header + data)
        header = struct.pack(
            "!BBHHH", ICMP_ECHO, 0, checksum, self.own_id, self.seq_number
        )

        packet = header + data
        return packet

    def is_local(self, addr):
        return IPv4Address(addr).is_private

    def get_ip(self, addr):
        if self.is_valid_ip4(addr):
            return addr
        else:
            try:
                ipv4 = socket.gethostbyname(addr)
                return ipv4
            except socket.gaierror:
                return None

    def is_valid_ip4(self, addr):
        parts = addr.split('.')
        if not len(parts) == 4:
            return False

        for part in parts:
            try:
                number = int(part)
            except ValueError:
                return False
            if number > 255 or number < 0:
                return False
        return True

    def calculate_cheksum(self, source_string):
        s = 0
        countTo = (len(source_string) // 2) * 2
        count = 0
        while count < countTo:
            if sys.byteorder == 'little':
                lo_byte = source_string[count]
                hi_byte = source_string[count + 1]
            else:
                hi_byte = source_string[count]
                lo_byte = source_string[count + 1]
            s += hi_byte * 256 + lo_byte
            s &= 0xffffffff
            count += 2

        if countTo < len(source_string):
            lo_byte = source_string[len(source_string) - 1]
            s += lo_byte
            s &= 0xffffffff

        s = (s >> 16) + (s & 0xffff)
        s += s >> 16
        answer = ~s & 0xffff
        answer = answer >> 8 | (answer << 8 & 0xff00)
        return answer

    def perform_whois(self, dst):
        wh = Whois()
        server = wh.resp_iana_parser(
            wh.perform_whois('whois.iana.org', dst))
        raw = None
        if server:
            raw = wh.perform_whois(server, dst)
        return wh.resp_whois_parser(raw, ['netname', 'origin', 'country'])

    def write(self, number_ip, ip, netname, origin, country, local):
        print(str(number_ip) + '. ' + ip, end='')
        print('\r\n')
        if local:
            print('local', end='')
            print('\r\n')
        else:
            if netname != '':
                print(netname, end='')
            if origin != '':
                print(', ' + origin, end='')
            if country != '':
                print(', ' + country, end='')
            if netname != '' or origin != '' or country != '':
                print('\r\n')
        print('\r\n')


def print_help(filename):
    with open(filename) as file:
        for line in file:
            print(line)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('source')
    args = parser.parse_args(sys.argv[1:])
    if args.source:
        tr = Tracert(args.source)
        tr.run()
    else:
        print_help('README.txt')
