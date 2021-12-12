# blue_kitty



✅ COMPLETED.
🤔 WORK IN PROGRESS.
	
RECON --> EXPLOITATION --> WORM FUNCTIONALITY (IMPLANT --> EXECUTION --> PERSISTENCE --> PROPAGATION) [worm.py]

	• RECON
	✅ Using python nmap module, we are able to generate a list of IPs are per the open ports (22 for SSH/Linux and 135,139,445 for SMB/Windows)
	✅Generate a table with list of IP/OS or differentiation as per open ports to determine attack method. 
	• EXPLOITATION
		○ Windows Machine:
		✅ SMB exploit
		✅Integrate the SMB Exploit code inside worm.py
		○ Linux Machine: 
		✅ SSH Bruteforce: Code integrated in worm.py
	• IMPLANT
	Propagate worm.py to machine having direct network connection to Attacker.
		○ ✅Windows Machine: Test whether worm.py is able to land on initial 
		○ ✅ Linux Machine: worm.py is able to land itself.
	• EXECUTION
		○ Windows Machine: 
			✅ Block ports 445, 139, 135 on both TCP and UDP from any IP address on the internet (0.0.0.0).
			✅Integrate firewall cmd commands in worm.py using os.system('cmd /c "Our Commands"')
		○ ✅ Linux Machine (Victim 1): A infected.txt marker file is placed inside /tmp
	• PERSISTENCE
		○ Windows Machine:
			✅ Add nc.exe in listening mode as a startup command through registry add.
			✅Integrate reg add command in worm.py using os.system('cmd /c "Our Commands"')
		○ 🤔 Linux Machine (Victim 1): Add an scheduled task/cronjob entry via worm.py to ensure backdoor functionality.
	• PROPAGATION FROM KALI LINUX 2021.3 TO KALI LINUX 2018.3 ON DIFFERENT SUBNET/INTERFACE
✅Develop and test whether worm.py propagates between victims connected on a different network subnet/interface with no direct network connection to Attacker machine.!
