import socket
import re
from select import select


class Whois:
    def perform_whois(self, server, query, port=43):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((server, port))
        sock.send((query + '\r\n').encode())

        resp = b''
        while True:
            if select([sock], [], [], 3)[0]:
                data = sock.recv(1024)
                resp += data
                if not data:
                    break
        sock.close()
        return resp.decode()

    def resp_iana_parser(self, raw):
        regex = re.compile('(whois.+)')
        try:
            mch = regex.search(raw)
            if mch:
                return mch.group(1)
        except re.error:
            pass

    def resp_whois_parser(self, raw, findlist):
        resp = {}
        for subject in findlist:
            resp[subject] = ''
            if raw:
                regex = re.compile('{}.*:\s*?(.+)\n'.format(subject), re.IGNORECASE)
                mtch = regex.search(raw)
                if mtch:
                    resp[subject] = mtch.group(1).lstrip()
        if raw:
            resp['local'] = False
        else:
            resp['local'] = True
        return resp
