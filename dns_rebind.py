#!/usr/bin/env python3
import socket
import struct
import threading
import time

class DNSServer:
    def __init__(self, first_ip, second_ip, port=5353):
        self.first_ip = first_ip
        self.second_ip = second_ip
        self.request_count = {}
        self.port = port
        
    def resolve_ip(self, domain):
        client_ip = threading.current_thread().name
        
        if client_ip not in self.request_count:
            self.request_count[client_ip] = 0
        
        self.request_count[client_ip] += 1
        print(f"Request #{self.request_count[client_ip]} from {client_ip}")
        
        if self.request_count[client_ip] == 1:
            return self.first_ip
        return self.second_ip
    
    def build_dns_response(self, domain, ip):
        transaction_id = b'\x00\x01'
        flags = b'\x81\x80'
        questions = b'\x00\x01'
        answer_rr = b'\x00\x01'
        authority_rr = b'\x00\x00'
        additional_rr = b'\x00\x00'
        
        domain_parts = domain.split('.')[:-1]
        formatted_domain = b''
        for part in domain_parts:
            formatted_domain += bytes([len(part)]) + part.encode()
        formatted_domain += b'\x00'
        
        query = transaction_id + flags + questions + answer_rr + authority_rr + additional_rr
        query += formatted_domain + b'\x00\x01\x00\x01'
        
        ip_parts = ip.split('.')
        ip_bytes = bytes([int(x) for x in ip_parts])
        
        answer = b'\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x05\x00\x04' + ip_bytes
        
        return query + answer
    
    def handle_query(self, data, addr, sock):
        try:
            domain_start = 12
            domain = ''
            i = domain_start
            while data[i] != 0:
                length = data[i]
                domain += data[i+1:i+1+length].decode() + '.'
                i += length + 1
            
            print(f"Query for: {domain}")
            
            if domain.startswith('test.'):
                ip = self.resolve_ip(domain)
                response = self.build_dns_response(domain, ip)
                sock.sendto(response, addr)
        except Exception as e:
            print(f"Error: {e}")
    
    def start(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('0.0.0.0', self.port))
        print(f"DNS Server listening on port {self.port}")
        
        while True:
            data, addr = sock.recvfrom(512)
            threading.Thread(target=self.handle_query, args=(data, addr, sock), name=str(addr)).start()

if __name__ == '__main__':
    dns = DNSServer('8.8.8.8', '127.0.0.1')
    dns.start()
