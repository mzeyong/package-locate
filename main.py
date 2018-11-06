# coding=utf-8
# author=k2yk
# email=mzeyong@gmail.com
import threading
import psutil
import socket
import struct
from logging.handlers import TimedRotatingFileHandler
import logging as logg
logging = logg.getLogger()
fmt = logg.Formatter("%(asctime)s - %(levelname)s -   %(name)s[line:%(lineno)d] - %(message)s", '%Y-%m-%d %H:%M:%S')
col = logg.StreamHandler()
col.setFormatter(fmt)
fh = TimedRotatingFileHandler("test", when='D', interval=1, backupCount=7)
fh.setFormatter(fmt)
fh.suffix = "%Y-%m-%d"
fh.extMatch = r"^\d{4}-\d{2}-\d{2}(\.\w+)?$"
logging.addHandler(fh)
logging.addHandler(col)

def ethFrameP(data):
    dstMac, srcMac, proto = struct.unpack("!6s6sH", data[:14])
    return socket.htons(proto), data[14:]

def getMacAddr(bytesAddr):
    bytes_str = map("{:02x}".format, bytesAddr)
    return ':'.join(bytes_str).upper()

def ipUnPack(data):
    versionHeaderLength = data[0]
    version = versionHeaderLength >> 4
    headerLength = (versionHeaderLength & 15) * 4
    ttl, proto, src, dst = struct.unpack('! 8x B B 2x 4s 4s', data[:headerLength])
    return version, headerLength, proto, ipv4(src), ipv4(dst), data[headerLength:]

def ipv4(bytesAddr):
    return '.'.join(map(str, bytesAddr))

def tcpUnPack(data):
    srcPort, dstPort, seq, ack, lengthFlag = struct.unpack('! H H L L H', data[:14])
    offset = (lengthFlag >> 12) * 4

    return srcPort, dstPort, seq, ack, data[offset:]

def netstat():
    return psutil.net_connections()

def parse_package(rawData):
    try:
        protorol, ethData = ethFrameP(rawData)
        if protorol == 8 and len(ethData) > 20:
            version, length, proto, srcIp, dstIp, ipData = ipUnPack(ethData)

            if proto == 6 and len(ipData) >= 20:
                srcPort, dstPort, seq, ack, tcpData = tcpUnPack(ipData)
                return ((srcIp,srcPort),(dstIp,dstPort)),tcpData
    except Exception as error:
        logging.error(error)
    return None,None

class sniffer:
    def __init__(self, mode='debug'):
        self.stopSignal = False
        self.socketLayer = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        self.ThreatDict = {}
        if mode == 'run':
            self.run()
        elif mode == 'debug':
            self.debug()

    def _scan(self):
        while True:
            result = netstat()
            demo = {}
            for sockdetail in result:
                try:
                    if sockdetail.status != "LISTEN":
                        if sockdetail.laddr and sockdetail.raddr:
                            demo[(sockdetail.laddr,sockdetail.raddr)]=sockdetail.pid
                except Exception as error:
                    logging.error(sockdetail)
                    logging.error(error)
            self.ThreatDict.update(demo)

    def scan_thread(self):
        t = threading.Thread(target=self._scan)
        t.setDaemon(True)
        t.start()

    def _match(self,data):
        match_case , data = parse_package(data)
        if match_case:
            pid = self.ThreatDict.get(match_case)
            if pid:
                pp = psutil.Process(pid)

                logging.warning("{addr} - {pid} - {pname} -{cmdline} - {user} - {pdata} ".format(addr=match_case,pid=pid,cmdline=pp.cmdline() ,user=pp.username(), pdata=data[:20],pname=pp.name()))
            else:
                pid = self.ThreatDict.get((match_case[1], match_case[0]))
                if pid:
                    pp = psutil.Process(pid)
                    logging.warning("{addr} - {pid}  - {pname} -{cmdline} - {user} - {pdata}".format(addr=match_case, pid= pid,cmdline=pp.cmdline(),user=pp.username(), pdata=data[:20],pname=pp.name()))
                else:
                    logging.warning(
                        "{addr} - {pid}  - {pname} - {pdata}".format(addr=match_case, pid=pid, pdata=data[:20],
                                                                     pname=""))

    def run(self):
        logging.info("run mode")
        try:
            self.scan_thread()
            while True:
                rawData, interface = self.socketLayer.recvfrom(65535)
                self._match(rawData)
        except Exception as error:
            logging.error(error)

    def debug(self):
        logging.info("debug mode")
        try:
            self.scan_thread()
            while True:
                rawData, interface = self.socketLayer.recvfrom(65535)
                t = threading.Thread(target=self._match,args=(rawData,))
                t.setDaemon(True)
                t.start()
        except Exception as error:
            logging.error(error)

if __name__ == '__main__':
    import sys
    if len(sys.argv)==1:
        mode = "debug"
    elif sys.argv[1] == "run":
        mode = "run"
    else:
        mode = "debug"
    sniffer(mode=mode)
