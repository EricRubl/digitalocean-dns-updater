import signal
import threading
import time


class DaemonKilled(Exception):
    def __init__(self, signum, handler):
        super().__init__()
        self.__signum = signum
        self.__handler = handler

    def get_signal(self):
        return self.__signum


class Job(threading.Thread):
    def __init__(self, logger, interval, execute, *args, **kwargs):
        threading.Thread.__init__(self)
        self.daemon = True
        self.stopped = threading.Event()
        self.interval = interval
        self.execute = execute
        self.logger = logger
        self.args = args
        self.kwargs = kwargs

        signal.signal(signal.SIGTERM, self.signal_handler)
        signal.signal(signal.SIGINT, self.signal_handler)

    def signal_handler(self, signum, handler):
        raise DaemonKilled(signum, handler)

    def stop(self):
        self.stopped.set()
        self.join()

    def run(self):
        while not self.stopped.wait(self.interval.total_seconds()):
            self.execute(*self.args, **self.kwargs)

    def start(self):
        super().start()

        while True:
            try:
                time.sleep(1)
            except DaemonKilled as ex:
                if ex.get_signal() == signal.SIGINT:
                    self.logger.info('Terminated by SIGINT')
                elif ex.get_signal() == signal.SIGTERM:
                    self.logger.info('Terminated by SIGTERM')
                self.stop()
                break
