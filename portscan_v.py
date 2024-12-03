import socket
import threading
import time

def get_serv(port):
    try:
        return socket.getservbyname(port)
    except OSError:
        return 'unassigned'

class PortScan:

    def __init__(self, target: str, port_counts: int):
        self.target = target
        self.ip = self.check_target()
        self.port_counts = int(port_counts)
        self.banners_port = dict()
        self.open_port = dict()

    def check_target(self):
        if self.target.startswith("http"):
            self.target = self.target.split("/")[2]
        try:
            ip_domain = socket.gethostbyname(self.target)
            return ip_domain
        except socket.gaierror:
            return

    def scan_port(self, port: int):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        if self.ip is None:
            return
        try:
            s.connect((self.ip, port))
            try:
                banner = s.recv(1024).decode().split()
                if banner == '':
                    self.open_port.update({port: get_serv(port).upper()})
                else:
                    self.banners_port.update({port: banner})
            except OSError:
                self.open_port.update({port: get_serv(port).upper()})
            except UnicodeDecodeError:
                banner = s.recv(1024).strip()
                self.banners_port.update({port: banner})
        except (socket.timeout, ConnectionRefusedError, OSError):
            return

    def port_rotate(self):
        threads = []
        for port in range(1, self.port_counts+1):
            t = threading.Thread(target=self.scan_port, kwargs={'port': port})
            t.daemon = True
            t.start()
            threads.append(t)
            time.sleep(0.02)
        for thread in threads:
            thread.join()