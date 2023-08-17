import time
import uuid
import socket
import threading
import zlib
import logging
from . import constants
from . import pack
from threading import Thread
import struct
import ipaddress
from . import exceptions
import random
from typing import Callable
import signal


class IPGenerator:
    def __init__(self, network: ipaddress.IPv4Network):
        self.network = network
        self.iterator = iter(self.network.hosts())

    def get_next_ip(self):
        try:
            return next(self.iterator)
        except StopIteration:
            # Все доступные адреса были использованы
            return None


class Server:
    @staticmethod
    def __parse_package(CompressedPackage: bytes):
        DecompressedPackage = zlib.decompress(CompressedPackage)

        ID, Body = DecompressedPackage[:2], DecompressedPackage[2:]
        ID = struct.unpack('!H', ID)[0]
        return ID, Body

    @staticmethod
    def __create_package(ID: int, Body: bytes):
        PackedID = pack.unsigned_short(ID)
        package = PackedID + Body

        CompressedPackage = zlib.compress(package, zlib.Z_BEST_COMPRESSION)

        return CompressedPackage

    def __init__(self, size_chunk=255, network='0.0.0.0/0', skip_local_addresses=False):
        self.skip_local_addresses = skip_local_addresses
        self.__socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.__clients = {}
        self.scan_started = False
        self.__server_close = True
        self.__chunks = {}
        self.__stop_accept_requests_event = threading.Event()
        self.__stop_accept_packages_event = threading.Event()
        self.size_chunk = size_chunk
        self.__result_func = lambda x: self.logger.debug(x)
        self.logger = logging.getLogger('server')
        self.__network = ipaddress.IPv4Network(network)
        self.__ip_generator = IPGenerator(self.__network)

    def result_handler(self, func: Callable):
        self.logger.debug(f'Set result_handler - {func} with name {func.__name__}')
        self.__result_func = func
        return func

    def set_network(self, network):
        if not self.scan_started:
            self.__network = ipaddress.IPv4Network(network)
            self.__ip_generator = IPGenerator(self.__network)
        else:
            raise exceptions.NetworkModificationError()

    def __bind(self, ip, port):
        try:
            self.__socket.bind((ip, port))
        except OSError:
            self.logger.critical('Address already in use')
            return -1

    def kick(self, UUID: str, reason='Disconnected by server'):
        pck = self.__create_package(3, reason.encode('utf-8'))
        self.__clients[UUID]['Connection'].send(pck)
        self.logger.debug(f'Send disconnect package to client {UUID} by reason: {reason}')

    def start_scanning(self, readiness='exception'):
        self.scan_started = True
        self.__stop_accept_requests_event.set()
        self.logger.debug('Stopped accepting new connections and scan_started is set to True')

        for UUID in self.__clients.keys():
            if self.__clients[UUID]['State'] == constants.States.NOT_READY:
                if readiness == constants.Check.EXCEPTION:
                    raise exceptions.NotAllClientsReadyError()
                elif readiness == constants.Check.KICK:
                    self.kick(UUID, reason=f'Client {UUID} wasn\'t ready when server start scanning')

        self.logger.debug('Completed clients verification')

        self.__stop_accept_packages_event.set()
        self.logger.debug('Started intercept the reception of packets from the client')

        for UUID in self.__clients.keys():
            self.logger.debug(f'Send start_scanning package to {UUID}')
            pck = self.__create_package(4, pack.unsigned_char(0))
            self.__clients[UUID]['Connection'].send(pck)

            while True:
                data = self.__clients[UUID]['Connection'].recv(10240)
                pck_id, pck_body = self.__parse_package(data)

                if pck_id == 4:
                    readiness_client = struct.unpack('!B', pck_body)[0]

                    if readiness_client == constants.Check.EXCEPTION:
                        raise exceptions.NotAllClientsReadyError()
                    elif readiness_client == constants.Check.KICK:
                        self.kick(UUID,
                                  reason=f'Client {UUID} wasn\'t ready when server start scanning')

                    self.logger.debug(f'Send to the client with UUID - {UUID} the final package of readiness')

                    pck = self.__create_package(4, pack.unsigned_char(1))
                    self.__clients[UUID]['Connection'].send(pck)

                    break

        self.logger.debug('Return to client threads the ability to receive packets')
        self.__stop_accept_packages_event.clear()

    def client_thread(self, conn: socket.socket, addr: tuple):
        UUID: uuid.UUID = uuid.uuid4()
        pck = self.__create_package(1, UUID.bytes)
        self.logger.debug(f'Set client with address - {addr}, UUID = {str(UUID)}')
        conn.send(pck)

        self.logger.debug(f'Add {str(UUID)} in clients')
        self.__clients.setdefault(
            str(UUID), {
                'Connection': conn,
                'Address': addr,
                'State': constants.States.NOT_READY
            }
        )

        while not self.__server_close:
            if not self.__stop_accept_packages_event.is_set():
                data = conn.recv(10240)
                if data == b'':
                    break
                pck_id, pck_body = self.__parse_package(data)
                self.logger.debug(f'Get package from {str(UUID)} with id equal {pck_id}')
                self.logger.debug(pck_body)

                if pck_id == 2:
                    if not self.scan_started:
                        new_state = struct.unpack('!B', pck_body)[0]

                        self.__clients[str(UUID)]['State'] = new_state
                        self.logger.debug(f'Set state to {str(UUID)} equal {new_state}')
                        self.logger.debug(self.__clients)
                    else:
                        self.logger.debug(f'Get set_state package from {str(UUID)}, but scan started, ignored.')
                elif pck_id == 3:
                    reason = pck_body.decode('utf-8')

                    del self.__clients[str(UUID)]
                    self.logger.debug(f'Disconnect client with UUID equal {str(UUID)} by reason: {reason}')
                    self.logger.debug(self.__clients)
                    break
                elif pck_id == 5:
                    if self.scan_started:
                        chunk = b''
                        for i in range(self.size_chunk):
                            if not self.skip_local_addresses:
                                chunk += self.__ip_generator.get_next_ip().packed
                            else:
                                while True:
                                    address = self.__ip_generator.get_next_ip()
                                    if address.is_global:
                                        chunk += address.packed
                                        break

                        chunk_id = random.randint(1, 65534)

                        self.__chunks.setdefault(chunk_id, {'UUID': str(UUID), 'Chunk': chunk})
                        self.logger.debug(f'Add chunk with ID - {chunk_id} for {str(UUID)}')
                        self.logger.debug(self.__chunks)

                        body = pack.unsigned_short(chunk_id) + chunk
                        pck = self.__create_package(5, body)
                        conn.send(pck)
                    else:
                        self.logger.warning(f'Get request_chunk package from {UUID}, but scan not started!')

                elif pck_id == 6:
                    if self.scan_started:
                        chunk_id = struct.unpack('!H', pck_body[0:2])[0]
                        result = pck_body[2:]

                        self.logger.debug(f'Get result for chunk {chunk_id} from {str(UUID)}')

                        del self.__chunks[chunk_id]

                        self.logger.debug(self.__chunks)

                        self.logger.debug(f'Send result for chunk {chunk_id} from {str(UUID)} to result function')

                        self.__result_func(result)
                    else:
                        self.logger.warning(f'Get result_chunk package from {UUID}, but scan not started!')
                else:
                    self.logger.warning(f'Get unidentified package. ID - {pck_id}')
                    self.logger.warning(pck_body)
            else:
                time.sleep(0.05)

        self.logger.debug(f'Closed client_thread with UUID {str(UUID)}')

    def accept_connections_thread(self):
        self.logger.debug('Begin to listen connections')
        self.__socket.listen()
        self.__socket.settimeout(0.05)  # Установка времени ожидания в 50 миллисекунд

        self.logger.debug('Launching loop listening')

        while not self.__server_close:
            if not self.__stop_accept_requests_event.is_set():
                try:
                    conn, addr = self.__socket.accept()
                    self.logger.debug(f'Get connect from {addr}')
                    Thread(target=self.client_thread, args=(conn, addr)).start()
                except socket.timeout:
                    pass
                except OSError:
                    break
            else:
                time.sleep(0.05)

        self.logger.debug('Closed accept_connections_thread')

    def is_close(self):
        return self.__server_close

    def close(self):
        self.__server_close = True
        if len(self.__clients) != 0:
            for UUID in self.__clients.keys():
                self.kick(UUID, 'Server closed')
        self.__socket.close()

        self.logger.debug('Closed server')

    def count_clients(self):
        return len(self.__clients)

    def run(self, ip='0.0.0.0', port=9090):
        if self.__server_close:
            self.logger.debug(f'Binding server to {ip}:{port}')
            self.__bind(ip, port)
            self.__server_close = False
            self.logger.debug('Start accept_connections thread')
            Thread(target=self.accept_connections_thread).start()
        else:
            raise exceptions.ServerIsAlreadyRunning()
