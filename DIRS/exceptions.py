class NetworkModificationError(Exception):
    def __init__(self):
        super().__init__("Cannot modify the network while scanning is in progress")


class NotAllClientsReadyError(Exception):
    def __init__(self):
        super().__init__("Not all clients are ready to start scanning")


class ScanHasBeenStartedError(Exception):
    def __init__(self):
        super().__init__("Cannot be used while scanning is running")


class ScanHasNotBeenStartedError(Exception):
    def __init__(self):
        super().__init__("Cannot be used until scanning is started")


class ServerIsAlreadyRunningError(Exception):
    def __init__(self):
        super().__init__("Unable to start an already running server")


class NoClientsError(Exception):
    def __init__(self):
        super().__init__("Unable to start scan because there is no client")


class ScanPauseError(Exception):
    def __init__(self):
        super().__init__("Cannot be used until scanning is pause")
