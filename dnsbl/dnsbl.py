#!/usr/bin/env python

import gevent
from gevent import socket
import socket

DNSBL_servers = [
    'cbl.abuseat.org',
    'zen.spamhaus.org',
    'bogons.cymru.com',
    'bl.spamcop.net',
    'aspews.ext.sorbs.net',
    'b.barracudacentral.org',
    # 'blacklist.woody.ch',
    # 'combined.abuse.ch',
    # 'dnsbl.ahbl.org',
    # 'dnsbl.inps.de',
    # 'dnsbl.njabl.org',
    # 'dnsbl.sorbs.net',
    # 'drone.abuse.ch',
    # 'duinv.aupads.org',
    # 'http.dnsbl.sorbs.net'
    # 'ips.backscatterer.org',
    # 'misc.dnsbl.sorbs.net',
    # 'orvedb.aupads.org',
    # 'pbl.spamhaus.org',
    # 'sbl.spamhaus.org',
    # 'short.rbl.jp',
    # 'smtp.dnsbl.sorbs.net',
    # 'socks.dnsbl.sorbs.net',
    # 'spam.abuse.ch',
    # 'spam.dnsbl.sorbs.net',
    # 'spamrbl.imp.ch',
    # 'web.dnsbl.sorbs.net',
    # 'wormrbl.imp.ch',
    # 'xbl.spamhaus.org',
]

class DNSBL_check():
    """A DNSBL class for checking existance of ip in DNSBL database."""

    def __init__(self, ip=None,timeout=3):
        self.ip = ip
        self.dnsbl_servers = DNSBL_servers
        self.timeout = timeout

    def form_query(self, dnsbl_server):
        reversed_ip = '.'.join(reversed(self.ip.split('.')))
        return '{reversed_ip}.{server}.'.format(reversed_ip=reversed_ip, server=dnsbl_server)

    def query(self, link):
        try:
            result = socket.gethostbyname(self.form_query(link))
        except Exception:
            result = False
        return link, result

    def check(self):
        results = []
        dnsbl_checks = [gevent.spawn(self.query, server_link) for server_link in self.dnsbl_servers]
        gevent.joinall(dnsbl_checks, self.timeout)
        for item in dnsbl_checks:
            if item.successful():
                results.append(item.value)
            else:
                results.append((item.args[0], None))
        return results

### for testing purpose
#dnsbl_instance = DNSBL_check('59.185.236.31',2)
#print dnsbl_instance.check()
