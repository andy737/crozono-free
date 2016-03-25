import os
from poormanslogging import error
import subprocess

lan_deps = ["nmap", "ettercap", "tshark", "msfconsole"]
wlan_deps = ["aircrack-ng", "reaver", "pixiewps"]


def check_lan_attacks_dependencies():
	for d in lan_deps:
		if subprocess.call(["which", d],stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) != 0:
			error("Required binary for {bin} not found. Refer to the INSTALL document for requirements for running CROZONO.".format(bin=d))
			return False
	return True


def check_wlan_attacks_dependencies():
	for d in wlan_deps:
		if subprocess.call(["which", d],stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) != 0:
			error("Required binary for {bin} not found. Refer to the INSTALL document for requirements for running CROZONO.".format(bin=d))
			return False
	return True


def check_root():
	return os.geteuid() == 0
