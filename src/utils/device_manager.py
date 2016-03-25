import time
import random
import subprocess
from subprocess import Popen
from poormanslogging import info, error

import src.settings as settings

def mac_changer():
	if settings.NEW_MAC is None:
		import string
		s = "".join(random.sample(string.hexdigits, 12))
		s = (":".join([i + j for i, j in zip(s[::2], s[1::2])])).lower()
		subprocess.call(['ifconfig', settings.INTERFACE_MON, 'down'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
		subprocess.call(['macchanger', '-m', s, settings.INTERFACE_MON], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
		subprocess.call(['ifconfig', settings.INTERFACE_MON, 'up'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
		settings.NEW_MAC = s
	else:
		pass

	

def check_interfering_processes(kill=True):
	s = subprocess.Popen(['airmon-ng', 'check', 'kill' if kill else None], stdout=subprocess.DEVNULL)
	_, err = s.communicate()
	if err is not None:
		error('Error when killing interfering processes!')
		return False
	return True



def toggle_mode_monitor(setting=True):
	if setting:
		check_interfering_processes(kill=True)
		subprocess.Popen(['airmon-ng', 'start', settings.INTERFACE], stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()

		proc = Popen(['iwconfig'], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)	
		for line in proc.communicate()[0].decode().split('\n'):
			if 'Mode:Monitor' in line:
				settings.INTERFACE_MON = line.split()[0]
				return True
			else:
				error("Could not set interface in monitor mode!")
				exit()
	else:
		subprocess.call(['airmon-ng', 'stop', settings.INTERFACE_MON], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
		


def get_ifaces():
	"""Returns a list of interfaces (reported by airmon-ng) prefixed by the 'prefix' keyword"""
	ang = subprocess.Popen(['airmon-ng'], stdout=subprocess.PIPE)
	sout, serr = ang.communicate()
	i = list(filter(lambda x: x is not '' and not x.startswith("PHY"), sout.decode().split("\n")))
	return list(map(lambda x: x.split("\t")[1], i))


def hardware_setup():
	info("Setting interface to monitor mode")
	toggle_mode_monitor(True)
	mac_changer()
