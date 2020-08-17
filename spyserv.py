# -*- coding: utf-8 -*-
#!/usr/bin/python3
# Dummy server to display uncompressed messages for Android malware
# 885d07d1532dcce08ae8e0751793ec30ed0152eee3c1321e2d051b2f0e3fa3d7

import socket
import logging
from _thread import start_new_thread
import gzip

HOST = '127.0.0.1'
PORT = 29491
max_clients = 10
current_clients = 0

logging.basicConfig(format='[%(name)s] %(asctime)s %(message)s', datefmt='%m/%d/%Y %I:%M:%S', level=logging.DEBUG)
logger = logging.getLogger('SpyServer')
logger.debug('Logger configured')

class SpyServer:
    def __init__(self, connection, client_address, timeout=500):
        self.connection = connection
        self.client_ip_address, self.client_port = (client_address)
        
    def run(self):
        while True:
            message = self.connection.recv(4096).rstrip()
            logger.info("IN: {}".format(message))
            marker, msg_len = self.get_msg_header(message)
            if msg_len > 0 and marker > 0:
                self.decompress(message, marker, msg_len)

    def get_msg_header(self, message):
        marker = message.find(b'\x00')
        if marker < 0:
            logger.warning("Message format error: no 0x00")
            return -1, -1
            
        msg_len = -1
        try:
            msg_len = int(message[0:marker])
            logger.debug("Packet indicates length={}".format(msg_len))
        except ValueError:
            logger.warning("Message format error: incorrect message length")

        logger.debug("get_msg_header() returns marker={} msg_len={}".format(marker, msg_len))
        return marker, msg_len
            
    def decompress(self, message, marker, msg_len):
        logger.debug("decompress(): marker={} msg_len={}".format(marker, msg_len))
        if len(message) != msg_len + marker + 1:
            logger.warning("Truncated message: msg_len={} packet_len={} marker={}".format(msg_len, len(message), marker))
            return
                
        logger.info("msg_len={} msg={}".format(msg_len, gzip.decompress(message[marker+1:])))
        
            
def client_thread(connection, client_address):
    global current_clients
    current_clients = current_clients + 1
    logger.debug('Connecting %s - client no. (%d)...' % (client_address, current_clients))
    bot = SpyServer(connection, client_address, timeout=300)
    
    try: 
        bot.run()
    except Exception as e:
        logger.error("client_thread(): caught an exception: {}".format(e))
        connection.shutdown(socket.SHUT_RDWR)
        connection.close()
        logger.error("client_thread(): disconnecting client %s" % (client_address))
    current_clients = current_clients - 1

if __name__ == "__main__":
    # Creating the socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_address = (HOST, PORT)
    logger.debug('Starting up server on %s port %s' % server_address )
    sock.bind(server_address)
    sock.listen(max_clients)
    logger.debug('Listening... (max clients=%d)' % (max_clients))
    try:
        while True:
            # wait for incoming connections
            connection, client_address = sock.accept()
            start_new_thread(client_thread, (connection, client_address))
    except KeyboardInterrupt:
        logger.info('KeyboardInterrupt on server')
        sock.shutdown(socket.SHUT_RDWR)
        sock.close()
