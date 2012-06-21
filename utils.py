from glob import glob
import configparser
import os
from pwd import getpwnam
from grp import getgrnam
import re

__ld_line = re.compile(r'^[ \t]*'	  # Initial whitespace
					   r'([^ \t]+)'	# Variable name
					   r'[ \t][ \t"]*' # Separator - yes, may have multiple "s
					   r'(([^"]*)".*'  # Value, case 1 - terminated by "
					   r'|([^"]*\S)?\s*' # Value, case 2 - only drop trailing \s
					   r')$')

def parse_login_defs():
	res = {}
	with open('/etc/login.defs') as f:
		for line in f:
			match = __ld_line.match(line)
			if match is not None:
				name = match.group(1)
				if name.startswith('#'):
					continue
				value = match.group(3)
				if value is None:
					value = match.group(4)
					if value is None:
						value = ''
				res[name] = value # Override previous definition
	return res

def get_gui_sessions():
	check_here = glob('/usr/share/xsessions/*') + \
				glob('/etc/X11/sessions/*')
	sessions=[]
	for item in check_here:
		cfg = configparser.ConfigParser()
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

def prepare_tty(username,n):
	ttypath=os.path.join("/dev","tty{}".format(n))
	uid=getpwnam(username).pw_uid
	ttygid=getgrnam('tty').gr_gid
	os.chown(ttypath, uid, ttygid)
	'''
	st = os.stat(ttypath)
	if st.st_uid != uid or st.st_gid != ttygid:
		raise OSError(("TTY ownership change failed!\n"
						"Was expection {}:{}, but got {}:{}!"\
						.format(uid,ttygid,st.st_uid,st.st_gid)))
	'''

def restore_tty(n):
	prepare_tty('root',n)

def next_x():
	active_xs=glob('/tmp/.X*-lock')
	if len(active_xs) > 0:
		last_d=int(os.path.basename(active_xs[0]).replace('-lock','')[2:])
	else:
		last_d=-1
	return last_d+1

def drop_privs(username):
	#we only want to temporarily drop the priveleges
	#http://comments.gmane.org/gmane.comp.web.paste.user/1641
	#http://stackoverflow.com/questions/1770209/run-child-processes-as-different-user-from-a-long-running-process
	def result():
		usr = getpwnam(username)
		#oldgroups = os.getgroups()
		os.initgroups(username,usr.pw_gid)
		os.setgid(usr.pw_gid)
		os.setuid(usr.pw_uid)
	return result

def make_child_env(username):
	usr = getpwnam(username)
	env = {}
	env['HOME']=usr.pw_dir
	env['PWD']=usr.pw_dir
	# let the wrapper handle setting TERM
	env['SHELL']=usr.pw_shell
	env['LOGNAME']=usr.pw_name
	env['USER']=usr.pw_name
	env['PATH']=os.getenv('PATH')
	env['TERM']=os.getenv('TERM')
	#http://groups.google.com/group/alt.os.linux.debian/browse_thread/thread/1b5ec66456373b99
	env['MAIL']=os.path.join(parse_login_defs().get('MAIL_DIR'),usr.pw_name)
	#XAUTHORITY and DISPLAY are X dependent!
	return usr,env
