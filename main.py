import re
import time
from colored import fg, bg, attr
import sqlite3
import subprocess
import argparse

# This class find out the vulnerability of target machine
class Vulnerability():
    # Initialize the database initialization and set IPAddress
    def __init__(self, IPAddress) -> None:
        self.IPAddress = IPAddress
        self.connect()
        self.result = ""

    # Connect database and create machine table if it's not exist
    # Create database.db file using sqlite3
    def connect(self):
        self.conn = sqlite3.connect('database.db')
        self.conn.execute('''
        CREATE TABLE IF NOT EXISTS machine
        (
            ID INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
            IP CHAR(15) NOT NULL UNIQUE,
            SMB INTEGER,
            TELNET INTEGER,
            RDP INTEGER
        );''')
        self.cursor = self.conn.cursor()

    # Seprate function for update existing machine record
    def update(self):
        self.conn.execute(f"UPDATE machine SET SMB=\"{self.SMB}\", TELNET=\"{self.TELNET}\", RDP=\"{self.RDP}\" WHERE IP=\"{self.IPAddress}\"");
        self.conn.commit()
    
    # Seprate function for insert new machine record
    def insert(self):
        self.conn.execute(f"INSERT INTO machine(IP,SMB,TELNET,RDP) VALUES(\"{self.IPAddress}\", \"{self.SMB}\", \"{self.TELNET}\", \"{self.RDP}\")");
        self.conn.commit()

    # Function for scan specified ports of target IP
    def scan(self):
        output = subprocess.getoutput(f'nmap -Pn -sV {self.IPAddress} -p23,3389,445')
        search = '(?P<port>\d{1,4}/tcp)\s+(?P<state>(filtered|open|closed))'
        self.ports = list(re.finditer(search, output))

        
    def check_port_status(self, log, index):    
        port_running = 0
        try:
            port_obj = self.ports[index].groupdict()
        except:
            return port_running

        if port_obj:
            if port_obj.get('state') == 'open':
                self.result += log
                port_running = 1
            else:
                port_running = 0
        else:
            port_running = 0
        return port_running

    # Get SMB state in 0(closed) and 1(open)
    @property
    def SMB(self):
        return self._SMB
    
    # Set SMB state in 0(closed) and 1(open)
    @SMB.setter
    def SMB(self, port):
        port_running = self.check_port_status(f"\n\t{bg('red')} high {fg('white')}{attr('reset')}{fg('dark_orange')} SBM Ports are Open over TCP.{attr('reset')}\n", index=1)
        self._SMB = port_running 
    
    # Get TELNET state in 0(closed) and 1(open)
    @property
    def TELNET(self):
        return self._TELNET
    
    # Set SMB state in 0(closed) and 1(open)
    @TELNET.setter
    def TELNET(self, port):
        port_running = self.check_port_status(f"\n\t{bg('purple_4b')} critical {fg('white')}{attr('reset')}{fg('dark_orange')} FTP Service detected.{attr('reset')}\n", index=0)
        self._TELNET = port_running
    
    # Get RDP state in 0(closed) and 1(open)
    @property
    def RDP(self):
        return self._RDP
    
    # Set SMB state in 0(closed) and 1(open)
    @RDP.setter
    def RDP(self, port):
        port_running = self.check_port_status(f"\n\t{bg('sandy_brown')} medium {fg('white')}{attr('reset')}{fg('dark_orange')} RDP Server Detected over TCP.{attr('reset')}\n", index=2)
        self._RDP = port_running 
    
    # Get ip address of target machine
    @property
    def IPAddress(self):
        return self._IPAddress

    # Set ip address of target machine
    @IPAddress.setter
    def IPAddress(self, ip):
        IPAddressRegEx = "^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$"
        try:
            if not re.search(IPAddressRegEx, ip):
                raise Exception("Invalid IP Address entered")
            self._IPAddress = ip
        except Exception as e:
            print(str(e),'!!!!!')
            exit(1)
    
    # Main function to perform all operations(scan & store in DB)
    def main(self):
        start_time = time.time()
        machine = self.cursor.execute(f"SELECT * from machine where IP=\"{self.IPAddress}\"").fetchone()
        # for scan all three ports
        self.scan()
        self.SMB = 445
        self.TELNET = 23
        self.RDP = 3389
        
        if machine:
            self.update()
        else:
            self.insert()
        end_time = time.time()
        return f"{fg('blue_3b')}Scan completed in {round(end_time-start_time)}s{attr('reset')}\n\n{fg('white')}{attr('bold')}Vulnerability Threat Level{attr('reset')}" + self.result

# Get target ip address using cli
parser = argparse.ArgumentParser()
parser.add_argument('--ip', type=str, required=True)
args = parser.parse_args()
ip = args.ip
# Create instance of Vulnerability
V = Vulnerability(ip)
# print result in specified format 
print(V.main())
