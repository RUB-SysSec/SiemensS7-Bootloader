#!/usr/bin/env python2

from sys import argv
from requests import *
import argparse
import re

parser = argparse.ArgumentParser(description='Switch power on the remote power supply')
parser.add_argument('-p', '--port', dest='port', default=80, type=lambda x: int(x, 0),
                        help='the port to use (may be changed away from 80 for local port forwarding)')
parser.add_argument('-H', '--host', dest='host', default="powersupply",
                        help='the host to connect to (may be changed away from powersupply for local port forwarding)')
parser.add_argument('mode', choices=['on', 'off'])
args = parser.parse_args()

host = "http://{}:{:d}".format(args.host, args.port)

toggle = 1 if args.mode == "on" else 0

s = Session()
r = s.get(host)
regex = re.compile('<meta name="X-Request-Token" content="([a-f0-9]+)">')
request_token = regex.findall(r.text)[0]

headers = {
	"X-Request-Token": request_token
}

r = s.post(host+"/ajax/rw_actor.php", data={"rw":1, "actor_nr": 1, "on_off":toggle,"ts":1536062812}, headers=headers)

exit(0)