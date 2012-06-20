import time
from subprocess import check_call, CalledProcessError
from spwd import getspnam
from crypt import crypt

def delete_session(username,tty_or_x):
	try:
		check_call(['sessreg','-d','-l', tty_or_x, username])
	except CalledProcessError as e:
		return False
	else:
		return True

def register_session(username,tty_or_x):
	try:
		check_call(['sessreg','-a','-l', tty_or_x, username])
	except CalledProcessError as e:
		return False
	else:
		return True

def check_avail(username):
	#match expiry
	usr = getspnam(username)
	daysleft = -1
	msgs=[]
	
	#translated from pam_unix/passverify.c

	today = time.time()/(3600*24)

	#check account expiry
	if today >= usr.sp_expire and usr.sp_expire != -1:
		msgs.append(("Your account has expired; please"
					" contact your system administrator"))
		#tell them them their account expired and bail out
		return '\n'.join(msgs),3
	
	if usr.sp_lstchg == 0:
		daysleft = 0
		msgs.append(("You are required to change your password"
						" immediately (root enforced)"))
		#this was because of a forced expirty
		#show a box to the user to tell them to change
		#their password or remind them with a dialog box
		return '\n'.join(msgs),1
	
	#check if pw change will happen in the future
	if today < usr.sp_lstchg:
		msgs.append(("Your password will be changed in the future."))
		return '\n'.join(msgs),0

	#did password expire?
	deltapw = today - usr.sp_lstchg
	if deltapw > usr.sp_max and deltapw > usr.sp_inact \
		and deltapw > (usr.sp_max+usr.sp_inact) and \
		-1 not in (usr.sp_inact, usr.sp_max):
		daysleft = usr.sp_lstchg+spent.sp_max-curdays
		msgs.append(("Your account expired since"
					"you didn't change it. "
					"Please contact the administrator."))
		#this was because of aging
		#show a box to the user to tell them their pw expired
		return '\n'.join(msgs),2
	
	if deltapw > usr.sp_max and sp.max != -1:
		#this was because of aging
		#show a box to user to change pw or remind them
		msgs.append(("You are required to change your "
					"password immediately (password aged)"))
		return '\n'.join(msgs),1
	
	if deltapw > usr.sp_max-usr.sp_warn and \
		-1 not in (usr.sp_warn, usr.sp_max):
		daysleft = usr.sp_lstchg+spent.sp_max-curdays
		
		if daysleft == 1:
			msgs.append(("Warning: your password will expire in %d day").format(daysleft))
		else:
			msgs.append(("Warning: your password will expire in %d days").format(daysleft))
		#show a box to the user reminding them of how long they have
	
	if deltapw < usr.sp_min and usr.sp_min != -1:
		#show a box saying that the pw change was too recent
		msgs.append(("Your password changed too recently"))
		return '\n'.join(msgs),0
		
	return '\n'.join(msgs),0

def check_pw(username,password,nopw=True):
	try:
		encrypted_password = getspnam(username).sp_pwd
	except KeyError as e:
		return False
	encrypted_attempt = crypt(password,encrypted_password)
	#allow no passwd logins by default
	#we do not need to check ! or * entries
	#since they will never match
	if len(encrypted_password) == 0 and nopw is False:
		return False
	return encrypted_attempt == encrypted_password
