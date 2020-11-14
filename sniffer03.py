from scapy.all import *
from datetime import datetime
import csv
import os

PROBE_REQUEST_TYPE = 0
PROBE_REQUEST_SUBTYPE = 4

WHITELIST = ['de:ad:be:ef:ca:fe',] # Replace this with known device's MAC address

PACKET_FILE_PATH = 'logmacs.csv'
headers = ['Date','Time','Mac','Name','Signal']

class PacketHandler(object):
    def __init__(self, packet_file_path):
        self.packet_file_path = packet_file_path
        self.handled_packets = set()

    def __enter__(self):
        self.csv_file = open(self.packet_file_path, 'a')
        self.csv_writer = csv.writer(self.csv_file)
        return self

    def __exit__(self, *exc_info):
        self.csv_file.close()

    def handle_packet(self, pkt):
        if pkt.haslayer(Dot11) and pkt.type == PROBE_REQUEST_TYPE and pkt.subtype == PROBE_REQUEST_SUBTYPE and (pkt.addr2.lower() not in WHITELIST and pkt.addr2.upper() not in WHITELIST) and pkt.addr2 not in self.handled_packets:
            self.add_packet(pkt)

    def add_packet(self, pkt):
        self.handled_packets.add(pkt.addr2)
        try:
            signal_strength = -(256 - ord(pkt.notdecoded[-4:-3]))
        except Exception, e:
            signal_strength = -100
            print "No signal strength found"
        #self.csv_writer.writerow(['Date','Time','Mac','Name','Signal'])
        
        self.csv_writer.writerow([datetime.now().strftime('%Y-%m-%d'),
                                  datetime.now().strftime('%H:%M:%S'),
                                  pkt.addr2,
                                  pkt.getlayer(Dot11ProbeReq).info,
                                  signal_strength])
        print "Added: %s SSID: %s" % (pkt.addr2, pkt.getlayer(Dot11ProbeReq).info)


def main():
    packet_handler = PacketHandler(PACKET_FILE_PATH)
    
    print "[%s] Starting scan" % datetime.now()
    print "Scanning..."
    with packet_handler as ph:
        sniff(iface=sys.argv[1], prn=ph.handle_packet)
        file_is_empty = os.stat('logmacs.csv').st_size == 0
        if file_is_empty:
            self.csv_writer.writerow(headers)

if __name__=="__main__":
    main()
