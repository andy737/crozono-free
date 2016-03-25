import os
import time
import pexpect
import socket
import subprocess
from poormanslogging import info, warn, error

import src.utils.device_manager as device_mgr
import src.settings as settings

def get_gateway():
	import struct
	import socket
	with open('/proc/net/route', 'r') as fh:
		for line in fh:
			fields = line.strip().split()
			if fields[1] != '00000000' or not int(fields[3], 16) & 2:
				continue
			settings.GATEWAY = socket.inet_ntoa(struct.pack("=L", int(fields[2], 16))).strip()

def lan_range():
	net = settings.IP_LAN.split('.')
	settings.LAN_RANGE = net[0] + '.' + net[1] + '.' + net[2] + '.1-255'

def save_key():
	"""History with all keys cracked by date
	:param essid: Name of the ESSID for which the key was found
	:param key: ESSID's key
	"""
	with open(settings.OS_PATH + '/passwords_cracked', 'a') as f:
		f.write("{t} - {e}: {k} \n".format(t=time.strftime('%H:%M:%S'), e=settings.TARGET_ESSID, k=settings.TARGET_KEY))


def get_current_essid():
	iwc = subprocess.Popen(['iwconfig', settings.INTERFACE], stdout=subprocess.PIPE)
	hea = subprocess.Popen(['head', '-1'], stdin=iwc.stdout, stdout=subprocess.PIPE)
	gre = subprocess.Popen(['grep', '-oP', '\".+\"'], stdin=hea.stdout, stdout=subprocess.PIPE)
	sout, serr = gre.communicate()
	if serr is not None:
		error("Error getting the current ESSID")
		return ""
	return sout.decode().strip().replace("\"", "")

def connect_to_lan():
	import fcntl
	import struct
	sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	tries = 0

	if settings.INTERFACE_MON is not None:
			device_mgr.toggle_mode_monitor(False)
			time.sleep(1)

	def do_connect():
		nonlocal sock
		nonlocal tries
		info("Connecting to '{0}' with key '{1}'".format(settings.TARGET_ESSID, settings.TARGET_KEY if settings.TARGET_KEY is not None else ''))

		cmd_connect = pexpect.spawn('iwconfig {0} essid "{1}" key s:{2}'.format(settings.INTERFACE, settings.TARGET_ESSID, settings.TARGET_KEY))
		cmd_connect.logfile = open(settings.LOG_FILE, 'wb')
		cmd_connect.expect(['Error', pexpect.TIMEOUT, pexpect.EOF], 3)
		cmd_connect.close()
		parse_log_connect = open(settings.LOG_FILE, 'r')
		for line in parse_log_connect:
			if line.find('Error') != -1:
				wpa_supplicant = open('/etc/wpa_supplicant/wpa_supplicant.conf', 'w')
				wpa_supplicant.write('ctrl_interface=/var/run/wpa_supplicant\n')
				wpa_supplicant.write('network={\n')
				wpa_supplicant.write('ssid="' + settings.TARGET_ESSID + '"\n')
				wpa_supplicant.write('key_mgmt=WPA-PSK\n')
				wpa_supplicant.write('psk="' + settings.TARGET_KEY.strip() + '"\n')
				wpa_supplicant.write('}')
				wpa_supplicant.close()
				subprocess.call(['ifconfig', settings.INTERFACE, 'down'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
				subprocess.call(['dhclient', settings.INTERFACE, '-r'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
				subprocess.call(['ifconfig', settings.INTERFACE, 'up'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
				subprocess.call(['iwconfig', settings.INTERFACE, 'mode', 'managed'])
				subprocess.call(['killall', 'wpa_supplicant'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
				subprocess.call(['wpa_supplicant', '-B', '-c', '/etc/wpa_supplicant/wpa_supplicant.conf', '-i', settings.INTERFACE], stdout=subprocess.DEVNULL,
					stderr=subprocess.DEVNULL)
				time.sleep(2)
		parse_log_connect.close()
		os.remove(settings.LOG_FILE)
		tries += 1
		subprocess.call(['dhclient', settings.INTERFACE], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
		time.sleep(4)

	do_connect()
	if get_current_essid() != settings.TARGET_ESSID and tries < 5:
		warn('Connection to {e} failed. Retrying.'.format(e=settings.TARGET_ESSID))
		do_connect()
	if get_current_essid() == settings.TARGET_ESSID:
		ipaddr = socket.inet_ntoa(
				fcntl.ioctl(sock.fileno(), 0x8915, struct.pack('256s', bytes(settings.INTERFACE[:15], 'utf-8')))[20:24])
		info('Connection to {e} succeeded! Our IP is: {i}'.format(e=settings.TARGET_ESSID, i=ipaddr))
		settings.IP_LAN = ipaddr.strip()
	else:
		error('Could not connect to {e} after 5 tries. Aborting'.format(e=settings.TARGET_ESSID))
		exit(1)
