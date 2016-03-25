import subprocess
from poormanslogging import info, warn, error

def run():
	info("Executing Metasploit...")
	proc = subprocess.call(["msfconsole"], stderr=subprocess.DEVNULL)
