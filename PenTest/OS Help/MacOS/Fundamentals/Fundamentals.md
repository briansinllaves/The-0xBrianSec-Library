===================
P.List Property List Files 
______------

•	Can be anywhere on a macOS system
•	Some automatically parsed by the OS once they touch disk (URLSchemes)
•	Some must be in specific locations and have specific data (LaunchAgents)
•	Two formats – XML/JSON (Dictionary) or binary blobs
•	Used to store configuration settings, permissions, preferences, etc • Usually ned in reverse DNS notation (com.apple.thing)
•	From an offensive perspective, they come into play for:
•	Persistence (LaunchAgents/LaunchDaemons)
•	Evasion (Entitlements, Application's Info.plist, Mach Services)
•	Situational Awareness (/Library/Receipts/InstallHistory.plist)
•	plutil–p file.plist
• 	plutil –convert xml1 binary_plist.plist
•	Converts binary_plist.plist to an XML plist
•	plutil–convert binary1 xml_plist.plist
•	Converts an XML plist to binary format
![[Pasted image 20230614215231.png]]

•	Plist files are opened in XCode by default which allows for viewing and modifying values

	•	Many different value types
	•	Number
	•	Dictionary
	•	Data
	•	String
	•	Many have nested values




===================
Terminal .app 
______------


The terminal application is what gives users their front
end to * sh

Starting with Catalina (10.15), the default is
zsh


• Works like most *nix terminals
	• *rc files
	•  *_history



===================
Executables 
______------

The executable file format for macOS is Mach-O
	Starting with Catalina (10.15) all binaries must be x64
	Historically, allowed x64, x86, and Fat binaries (both)
	Big Sur allows ARM executables on Apple's new chipset

Tend to be written in:
	C/C++ (.c, .h, .cpp): gcc file.c
	Objective C (.h, .m): g++ framework Foundation file1.c file2.m
	Swift (.swift)
	
Can also be written in any language that offers cross compilation:
		Golang (.go) can include native code with CGo as well 
		.NET Core

===================
Dynic Libraries (dylib)
 ______------

•	Libraries allow code to be written once and shared across programs
	Compiled by specifying the -dyniclib flag with gcc /g++

===================
Application Bundles (.app)
•	Applications are located at /Applications
•	A .app file is a folder (called a "bundle") with a specific layout:
•	Info.plist - Application specific configuration/entitlements/tasks/metadata
•	MacOS – the folder containing the Mach-O executable
•	Resources – icons, fonts, images to use with the application
 ![[Pasted image 20230615141432.png]]


Application Support
	•	An Application installed for all users on a machine still needs to store user-specific data somewhere.
	•	~/Library/Application Support/
	•	Application specific folder layout and contents
		•	Stores configurations, cached data, credentials, etc
		•	Not protected by Transparency, Consent, and Control (TCC)
		•	Some folders are protected by System Integrity Protection (SIP)

Root and Admins
	•	The elevated account on macOS, like other *nix systems, is called root
	•	Local Administrators - members of the "admin" group (UID 80) are granted full sudo access
	•	Like *nix systems, sudo access is controlled by the /etc/sudoers file
	•	Cannot list out your sudo-capable actions without running sudo
	•	sudo -l  

Keychain
	•	A user's keychain holds passwords 
(web, secure notes, etc), public/private keys (iMessage, iCloud, etc), certificates, and more
	•	~/Library/Keychains/login.keychain-db
	•	There are no protections around reading this, but it is partially encrypted
	•	System Keychain holds passwords (wifi), root certificates, domain information (if joined to AD), and local Kerberos information
	•	/Library/Keychains/System.keychain
	•	Must be root

Keychain – Application Passwords
	•	Applications need a way to store secure information (such as encryption keys), so they use the Keychain
	•	This is like DPAPI on Windows hosts
	•	Applications like Google Chrome encrypt files with a key that's stored in the user's Keychain
 
Keychain – CLI Access
	•	Security is a native binary for interacting with Keychains and more
	•	security list-keychains
	•	security dump-keychain
	•	Use –d to get the decrypted secrets (causes LOTS of security prompts)
	•	Use –a to dump all information about each entry (except the decrypted secrets)
	•	security authorizationdbread system.preferences
	•	Read/write /var/db/auth.db
	•	security execute-with-privileges /usr/bin/whoami
	•	Execute a program as sudo (does cause popup)
	•	security error –66661
	•	Get the user-readable message for an error code
Launchd
	•	Initialization daemon (pid 1) that controls 
	•	launch daemons
	•	launch agents
	•	XPC Services
	•	Boots the system
•	Launchctl 
	•  interacts with launchd to issue
		•	Both user and root commands
		•	Load/Unload commands
		•	Service listing
		•	Service status information
		•	And more
defaults
	•	Command-line utility to modify user preferences
	•	Defaults domains- shows the list of preferences that can be edited
	•	Actual preferences are located at /Library/Preferences
		
			Defaults read <domain here>
	
	Read all the settings for a specific preference component
	
	•	Defaults write <domain> <Key> <value>
	•	Update a specific key in that domain
 