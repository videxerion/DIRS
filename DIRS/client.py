import os
import socket
import struct
from typing import Callable
import logging
import zlib
from threading import Thread
from . import constants
import uuid
from . import pack
from . import exceptions
import platform


class Client:

    @staticmethod
    def __split_chunk(stream):
        # Создаем список для хранения групп байтов
        groups = []

        # Выполняем разделение потока байтов на группы по 4 байта
        for i in range(0, len(stream), 4):
            group = stream[i:i + 4]  # Используем срезы для получения группы из 4 байтов
            groups.append(group)  # Добавляем группу в список

        return groups

    @staticmethod
    def __parse_package(CompressedPackage: bytes):
        DecompressedPackage = zlib.decompress(CompressedPackage)

        ID, Body = DecompressedPackage[:2], DecompressedPackage[2:]
        ID = struct.unpack('!H', ID)[0]
        return ID, Body

    @staticmethod
    def __create_package(ID: int, Body: bytes):
        PackedID = struct.pack('!H', ID)
        package = PackedID + Body

        CompressedPackage = zlib.compress(package, zlib.Z_BEST_COMPRESSION)

        return CompressedPackage

    def scan_started(self):
        return self.__scan_started

    def scan_paused(self):
        return self.__scan_paused

    def __init__(self):
        self.__socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.logger = logging.getLogger('client')
        self.__close = True
        self.__scan_started = False
        self.__scan_paused = False
        self.__get_chunk_func = lambda x, y: self.logger.debug(f'Get result for chunk with id {x}')
        self.__server_close_func = lambda: self.logger.debug('Server close')
        self.__UUID = None

    def get_chunk_handler(self, func: Callable):
        self.logger.debug(f'Set get_chunk_handler - {func} with name {func.__name__}')
        self.__get_chunk_func = func
        return func

    def server_closed_handler(self, func: Callable):
        self.logger.debug(f'Set get_chunk_handler - {func} with name {func.__name__}')
        self.__server_close_func = func
        return func

    def close(self, reason='Disconnected by client'):
        pck = self.__create_package(3, reason.encode('utf-8'))
        self.__socket.send(pck)
        self.logger.debug(f'Send disconnect package by reason: {reason}')
        self.__close = True

    def ready(self):
        if not self.__scan_started:
            self.logger.debug(f'Send set state package, new state - {constants.States.READY}')
            pck = self.__create_package(2, struct.pack('!B', constants.States.READY))
            self.__socket.send(pck)
        else:
            raise exceptions.ScanHasBeenStartedError()

    def not_ready(self):
        if not self.__scan_started:
            self.logger.debug(f'Send set state package, new state - {constants.States.NOT_READY}')
            pck = self.__create_package(2, struct.pack('!B', constants.States.NOT_READY))
            self.__socket.send(pck)
        else:
            raise exceptions.ScanHasBeenStartedError()

    def send_result(self, chunk_id: int, result: bytes):
        if self.__scan_started and not self.__scan_paused:
            body = struct.pack('!H', chunk_id) + result
            pck = self.__create_package(6, body)
            self.__socket.send(pck)
        elif self.__scan_started and self.__scan_paused:
            raise exceptions.ScanPauseError()
        else:
            raise exceptions.ScanHasNotBeenStartedError()

    def get_chunk(self):
        if self.__scan_started and not self.__scan_paused:
            pck = self.__create_package(5, b'')
            self.__socket.send(pck)

        elif self.__scan_started and self.__scan_paused:
            raise exceptions.ScanPauseError()
        else:
            raise exceptions.ScanHasNotBeenStartedError()

    def connection_loop_thread(self):
        self.logger.debug('Wait UUID')
        while True:
            data = self.__socket.recv(2048)
            pck_id, pck_body = self.__parse_package(data)

            if pck_id == 1:
                UUID = uuid.UUID(bytes=pck_body)
                self.logger.debug(f'Get UUID - {str(UUID)}')
                self.__UUID = UUID
                break

        while not self.__close:
            self.__socket.settimeout(1)
            try:
                data = self.__socket.recv(2048)
                pck_id, pck_body = self.__parse_package(data)

                if pck_id == 3:
                    reason = pck_body.decode('utf-8')
                    self.logger.debug(f'Kicked from server for a reason: {reason}')
                    self.__close = True
                    self.__server_close_func()
                    break
                elif pck_id == 4:
                    if not self.__scan_started:
                        stage = struct.unpack('!B', pck_body)[0]

                        if stage == 0:
                            self.logger.debug('Server starts scanning')
                            pck = self.__create_package(4, pack.unsigned_char(1))
                            self.__socket.send(pck)
                        elif stage == 1:
                            self.logger.debug('The server has finished checking and started scanning')
                            self.__scan_started = True
                        elif stage == 2:
                            self.logger.debug('The server canceled the start of the scan')
                    else:
                        self.logger.warning('The server is trying to start scanning, but it has already been started!')
                elif pck_id == 5:
                    chunk_id = struct.unpack('!H', pck_body[0:2])[0]
                    chunk = pck_body[2:]
                    split_chunk = self.__split_chunk(chunk)

                    self.logger.debug(f'Get chunk with ID {chunk_id}')
                    self.logger.debug(split_chunk)
                    self.__get_chunk_func(chunk_id, split_chunk)
                elif pck_id == 7:
                    is_set = struct.unpack('!?', pck_body)[0]
                    if is_set == self.__scan_paused:
                        if is_set:
                            self.logger.warning('Server set pause, but the scan has already been paused')
                        else:
                            self.logger.warning('Server set unpause, but the scan has already been unpause')
                    else:
                        self.__scan_paused = is_set
                        if is_set:
                            self.logger.warning('Server set pause')
                        else:
                            self.logger.warning('Server set unpause')
                elif pck_id == 8:
                    self.__scan_started = False
                    self.__scan_paused = False
                    self.logger.debug('Server stop scanning')
                elif pck_id == 9:
                    self.logger.debug('Get info request from server')
                    pck = self.__create_package(9, f"{platform.system()} {platform.release()} {' '.join(platform.architecture())}".encode('utf-8'))
                    self.__socket.send(pck)
                else:
                    self.logger.warning(f'Get unidentified package. ID - {pck_id}')
                    self.logger.warning(pck_body)
            except socket.timeout:
                pass

        self.logger.debug('Close connection_loop_thread')

    def connect(self, ip, port=9090):
        try:
            self.__socket.connect((ip, port))
        except Exception as exp:
            self.logger.critical(f'Failed to connect to the server, - {exp}')
            return False

        self.logger.debug(f'Connected to {ip}:{port}')
        self.logger.debug('Start connection_loop_thread')
        self.__close = False
        Thread(target=self.connection_loop_thread).start()
        return True
