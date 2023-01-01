"""
Write a web application using Flask Framework to display the DNS traffic of the hots computer. The
application needs to monitor the live network traffic of the host system and display up to 100 entries
after which it must start dropping the oldest entries. The DNS entries must appear on the screen in a
DataGrid. All the DNS requests must be coupled with their respective responses, therefore each entry
in the DataGrid must contain the following info:
1) Timestamp of the request made in human readable form (YYYY-MM-DD HH:MM:SS)
2) Domain Name the request was made for (google.com, 1tv.ge, etc. )
3) DNS response containing the IPs for the inquired Domain Names
You can use any library you want to complete this task. Use the best practices for each methodology
used, including but not limited to proper variable naming, code commenting and proper git wotkflow.
It is highly recommended to use OOP.

"""

from flask import Flask, render_template
from flask_table import Table, Col
from scapy.all import *
from datetime import datetime
import threading
import time
import socket


from scapy.layers.dns import DNS


app = Flask(__name__)


class ItemTable(Table):
    timestamp = Col('Timestamp')
    domain = Col('Domain')
    ip = Col('IP')


class Item(object):
    def __init__(self, timestamp, domain, ip):
        self.timestamp = timestamp
        self.domain = domain
        self.ip = ip


@app.route('/')
def index():
    return render_template('index.html', table=table)


def sniff_dns():
    global table
    table = []
    while True:
        sniff(filter="udp port 53", prn=parse_dns, count=1)
        time.sleep(1)


def parse_dns(pkt):
    global table
    if pkt.haslayer(DNS):
        if pkt.getlayer(DNS).qr == 0:
            timestamp = datetime.fromtimestamp(pkt.time).strftime('%Y-%m-%d %H:%M:%S')
            domain = pkt.getlayer(DNS).qd.qname
            ip = socket.gethostbyname(domain.decode())

            item = Item(timestamp, domain, ip)
            table.append(item)

            if len(table) > 100:
                table.pop(0)


if __name__ == '__main__':
    t = threading.Thread(target=sniff_dns)
    t.start()
    app.run(debug=True) # run app in debug mode on port 5000
