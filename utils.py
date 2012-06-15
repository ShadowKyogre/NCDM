import glob
import ConfigParser

def get_gui_sessions():
	check_here = glob.glob('/usr/share/xsessions/*') + \
				glob.glob('/etc/X11/sessions/*')
	sessions=[]
	for item in check_here:
		cfg = ConfigParser.ConfigParser()
		cfg.readfp(open(item))
		name=cfg.get('Desktop Entry','Name')
		cmd=cfg.get('Desktop Entry','Exec')
		if (name,cmd) not in sessions:
			sessions.append((name,cmd))
	return sessions
'''
#put some dbussy stuff to check :U
def check_ck():
	return True
'''