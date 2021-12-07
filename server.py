#!/bin/python3
# # -*- coding: utf-8 -*-

from __future__ import print_function


from functools import partial
from jinja2 import Environment, FileSystemLoader, TemplateNotFound
from http.server import BaseHTTPRequestHandler, HTTPServer
import urllib.parse

import json
import pathlib
import socket
import struct

from dnslib import DNSRecord, RCODE
from dnslib.server import DNSServer, DNSHandler, BaseResolver, DNSLogger

BLACKLIST = set()
WHITELIST = set()
SETTINGS = {}

blacklist_path = pathlib.Path('data', 'blacklist.txt')
whitelist_path = pathlib.Path('data', 'whitelist.txt')
settings_path = pathlib.Path('data', 'settings.json')

def load_config():
    BLACKLIST.clear()
    WHITELIST.clear()
    SETTINGS.clear()

    print('Loading config....', end='')

    if blacklist_path.is_file():
        with open(str(blacklist_path), 'r') as black_file:
            BLACKLIST.update((x.strip() for x in black_file.readlines()))

    if whitelist_path.is_file():
        with open(str(whitelist_path), 'r') as white_file:
            WHITELIST.update((x.strip() for x in white_file.readlines()))

    if settings_path.is_file():
        with open(str(settings_path), 'r') as settings_file:
            # The reason this doesn't use the file method is that I've had problems with that in the past.
            SETTINGS.update(json.load(settings_file))

    print('Loaded!')


def save_config():
    print('saving config')
    with open(blacklist_path, 'w') as black_file:
        black_file.write('\n'.join(BLACKLIST))
    with open(whitelist_path, 'w') as white_file:
        white_file.write('\n'.join(WHITELIST))
    with open(settings_path, 'w') as settings_file:
        json.dump(SETTINGS, settings_file)


def is_allowed_url(url, whitelist_mode=False):
    # If you really want this to use regex,
    # the whitelist and blacklist are going to have be the regex strings.
    # Please let me know if that is a concern. - J.S

    split_url = url[:-1].split('.')
    check_set = WHITELIST if whitelist_mode else BLACKLIST

    # We try to match the raw url.
    contained = url[:-1] in check_set
    if contained:
        return whitelist_mode == contained

    # We check for the any wildcard domain captures.
    for i in range(len(split_url) - 2, -1, -1):
        check_url = '.'.join(split_url[i:])
        # Just in case; we haven't settled on formatting in the config files.
        if f'*.{check_url}' in check_set or f'*{check_url}' in check_set:
            contained = True
            break

    # Works out
    # Mode on the top and contained on the side
    # _ | T | F |
    # T | T | F |
    # F | F | T |
    return whitelist_mode == contained


class ProxyResolver(BaseResolver):
    """
        Proxy resolver - passes all requests to upstream DNS server and
        returns response

        Note that the request/response will be each be decoded/re-encoded
        twice:

        a) Request packet received by DNSHandler and parsed into DNSRecord
        b) DNSRecord passed to ProxyResolver, serialised back into packet
           and sent to upstream DNS server
        c) Upstream DNS server returns response packet which is parsed into
           DNSRecord
        d) ProxyResolver returns DNSRecord to DNSHandler which re-serialises
           this into packet and returns to client

        In practice this is actually fairly useful for testing but for a
        'real' transparent proxy option the DNSHandler logic needs to be
        modified (see PassthroughDNSHandler) -- too bad!

    """

    def __init__(self, address, port, timeout=0):
        self.address = address
        self.port = port
        self.timeout = timeout

    def resolve(self, request: DNSRecord, handler):
        for question in request.questions:
            if not is_allowed_url(str(question.qname), whitelist_mode=SETTINGS['whitelist_mode']):
                reply = request.reply()
                # Can redirect here
                reply.header.rcode = getattr(RCODE, 'NXDOMAIN')
                return reply
        try:
            if handler.protocol == 'udp':
                proxy_r = request.send(self.address, self.port,
                                       timeout=self.timeout)
            else:
                proxy_r = request.send(self.address, self.port,
                                       tcp=True, timeout=self.timeout)
            reply = DNSRecord.parse(proxy_r)
        except socket.timeout:
            reply = request.reply()
            reply.header.rcode = getattr(RCODE, 'NXDOMAIN')

        return reply


def send_tcp(data, host, port):
    """
        Helper function to send/receive DNS TCP request
        (in/out packets will have prepended TCP length header)
    """
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((host, port))
        sock.sendall(data)
        response = sock.recv(8192)
        length = struct.unpack("!H", bytes(response[:2]))[0]
        while len(response) - 2 < length:
            response += sock.recv(8192)
        return response
    finally:
        if (sock is not None):
            sock.close()


def send_udp(data, host, port):
    """
        Helper function to send/receive DNS UDP request
    """
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(data, (host, port))
        response, server = sock.recvfrom(8192)
        return response
    finally:
        if (sock is not None):
            sock.close()


web_hostname = "localhost"
web_port = 8080


class HTTPHandler(BaseHTTPRequestHandler):
    def __init__(self, env: Environment, *args, **kwargs):
        self.env = env
        super().__init__(*args, **kwargs)

    def do_GET(self):
        try:
            template = self.env.get_template(self.path)
        except PermissionError:
            self.send_error(403)
        except TemplateNotFound:
            self.send_error(404)
        else:
            self.send_response(200)
            self.send_header("Content-type", "text/html")

            self.end_headers()

            page = template.render(WHITELIST='\n'.join(WHITELIST),
                                   BLACKLIST='\n'.join(BLACKLIST),
                                   SETTINGS=SETTINGS)
            self.wfile.write(bytes(page, 'utf-8'))

    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        body = self.rfile.read(content_length)
        self.send_response(204)
        self.end_headers()
        params = urllib.parse.parse_qs(body)
        print(params)
        if b'WHITELIST' in params:
            global WHITELIST  # yes this is dumb but it works
            WHITELIST = set(domain.decode('utf-8').strip() for domain in params[b'WHITELIST'][0].splitlines())
            print('Updated whitelist')
        if b'BLACKLIST' in params:
            global BLACKLIST  # yes this is dumb but it works
            BLACKLIST = set(domain.decode('utf-8').strip() for domain in params[b'BLACKLIST'][0].splitlines())
            print('Updated blacklist')
        if b'whitelist_mode' in params:
            SETTINGS['whitelist_mode'] = params[b'whitelist_mode'][0] == b'true'
        save_config()


if __name__ == "__main__":

    import argparse
    import time

    load_config()

    p = argparse.ArgumentParser(description="DNS Proxy")
    p.add_argument("--port", "-p", type=int, default=53,
                   metavar="<port>",
                   help="Local proxy port (default:53)")
    p.add_argument("--address", "-a", default="",
                   metavar="<address>",
                   help="Local proxy listen address (default:all)")
    p.add_argument("--upstream", "-u", default="8.8.8.8:53",
                   metavar="<dns server:port>",
                   help="Upstream DNS server:port (default:8.8.8.8:53)")
    p.add_argument("--tcp", action='store_true', default=False,
                   help="TCP proxy (default: UDP only)")
    p.add_argument("--timeout", "-o", type=float, default=5,
                   metavar="<timeout>",
                   help="Upstream timeout (default: 5s)")
    p.add_argument("--passthrough", action='store_true', default=False,
                   help="Dont decode/re-encode request/response (default: off)")
    p.add_argument("--log", default="request,reply,truncated,error",
                   help="Log hooks to enable (default: +request,+reply,+truncated,+error,-recv,-send,-data)")
    p.add_argument("--log-prefix", action='store_true', default=False,
                   help="Log prefix (timestamp/handler/resolver) (default: False)")
    args = p.parse_args()

    args.dns, _, args.dns_port = args.upstream.partition(':')
    args.dns_port = int(args.dns_port or 53)

    print("Starting Proxy Resolver (%s:%d -> %s:%d) [%s]" % (
        args.address or "*", args.port,
        args.dns, args.dns_port,
        "UDP/TCP" if args.tcp else "UDP"))
    print(f"Running in {'white' if SETTINGS['whitelist_mode'] else 'black'}list mode.")

    resolver = ProxyResolver(args.dns, args.dns_port, args.timeout)
    handler = DNSHandler
    logger = DNSLogger(args.log, args.log_prefix)
    udp_server = DNSServer(resolver,
                           port=args.port,
                           address=args.address,
                           logger=logger,
                           handler=handler)
    udp_server.start_thread()

    env = Environment(loader=FileSystemLoader('html'))
    web_server = HTTPServer((web_hostname, web_port), partial(HTTPHandler, env))
    print(f'starting webserver http://{web_hostname}:{web_port}/index.html')
    try:
        web_server.serve_forever()
    except KeyboardInterrupt:
        print('webserver stopped')

    print('Stopping DNS server')
    udp_server.stop()
