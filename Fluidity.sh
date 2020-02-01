#!/bin/bash

#
# Script Name: Fluidity.sh
#
# Authors: Charalampos Kapolonaris & Vassilios Koutlas
# Date : 25.01.2020
#
# Description: Fluidity is a SOCAT SSL connection manager. It's based on
# a server - client model and focuses on the creation and management
# of SOCAT SSL connections for secure and encrypted communication.
# More specifically, it can add - remove clients and create remove and
# administer SOCAT SSL connections.
#
# Run Information: This script is run manually.


# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.


# Since BASH lacks the feature of public and private interfaces, we
# nominally define a set of functions, as the equivalent of public 
# interfaces and another set as private interfaces. Below we present a 
# list of Fluidity's public interfaces.


# Fluidity Public Interface
#
# 1. Server Creation - Configuration Functions
#		installFluidity
#		reinstallFluidity
#		mountFluidityServerFolder
# 2. Direct Client Creation - Configuration Functions
#		fluidityClientConfiguration
# 3. Client Management Functions
#		addFluidityClient
#		removeFluidityClient
# 4. Connection Management Functions
#		addFluidityConnection
#		removeFluidityConnection
#		renewSSLcerts
# 5. Fluidity Engine Functions
#		runFluidity
#		stopFluidity
# 6. Fluidity Connection Status Functions
#		showLinkStatus
# 7. General Auxillary Functions
#		recallSSHidentity
#		displaySerialDevices
#		changeRemoteHostName


# Program Structure
# 
# 1. Fluidity Intershell Variables
# 		setPingDelay
#		getPingDelay
#		setAllowExecution
#		getAllowExecution
#		setPort
#		getPort
#		setServerIsTerminated
#		getServerIsTerminated
#		setClientIsTerminated
#		getClientIsTerminated
#		setSleepPid
#		getSleepPid
#		setTerminationForcePing
#		getTerminationForcePing
#		setFluidityConnectionStatus
#		getFluidityConnectionStatus
# 2. Server Creation - Configuration Functions
# 	2.1 Public Functions
#		installFluidity
#		reinstallFluidity
#		mountFluidityServerFolder
# 	2.2 Private Functions
#		fluidityServerConfiguration
#		mainServerFolderCreation
#		serverFolderBackboneCreation
# 3. Direct Client Creation - Configuration Functions
# 	3.1 Public Functions
#		fluidityClientConfiguration
# 4. Client Management Functions
# 	4.1 Public Functions
#		addFluidityClient
#		removeFluidityClient
# 	4.2 Private Functions
#		fluidityRemoteClientConfiguration
#		remoteSeekAndEncryptDaemon
# 5. Connection Management Functions
# 	5.1 Public Functions
#		addFluidityConnection
#		removeFluidityConnection
#		renewSSLcerts
# 	5.2 Private Functions
#		installSSLcertificates
#		reinstallSSLcerts
#		clientFolderCreation
#		clientSSLinstallation
#		deleteSSLpair
#		copyDoNotEncryptToken
#		deleteDoNotEncryptToken
# 6. Fluidity Engine Functions
# 	6.1 Public Functions
#		runFluidity
#		stopFluidity
# 	6.2 Private Functions
#		6.2.1 Firewalling
#			openPort
#			closePort
#		6.2.2 Engine Administration
#			terminationForcePing
#			stopFluidityToRenewSSLcerts
#		6.2.3 Link Setup
#			establishSOCATlink
#			6.2.3.1  Link State Information Administration
#				6.2.3.1.1 Static Information
#					storeSOCATlinkStateInformation
#					deleteSOCATlinkStateInformation
#				6.2.3.1.2 Dynamic Information
#					initilizeRunTimeVars
#					destroyRunTimeVars
#			6.2.3.2 Server Setup
#				runPersistentSOCATServer
#				runSOCATserver
#				runSerialSOCATserver
#				runTUNnelSOCATserver
#			6.2.3.3 Client Setup
#				runPersistentSOCATClient
#				runSOCATclient
#				runSerialSOCATclient
#				runTUNnelSOCATclient
#				6.2.3.3.1 Client Administration
#					checkForConnectionFolder
#					isItEncryptedOnClient
#					decryptClient
#					encryptClient
# 	6.3 Engine Auxillary Functions
#		6.3.1 Public Functions
#			forcePing
# 7. Fluidity Connection Status Functions
# 	7.1 Public Functions
#		showLinkStatus
# 8. General Auxillary Functions
# 	8.1 Public Functions
#		recallSSHidentity
#		displaySerialDevices
#		changeRemoteHostName
# 	8.2 Private Functions
#		giveAnEntropyBoost
#		checkFluidityFilesystemIntegrity
#		checkLocalEntropy
#		checkRemoteEntropy


# 1. Fluidity Intershell Variables


# SET function for Intershell Variable: ping_delay
setPingDelay () {
   
   local SSH_ID=${1%.*}
   echo "sed -i '1s/.*/$(echo ping_delay="$2")/' ~/Fluidity_Server/client.$SSH_ID/connection.$1/runtimeVars/ping_delay" | bash -
   
   
}

# GET function for Intershell Variable: ping_delay
getPingDelay () {
   
   local SSH_ID=${1%.*}
   source ~/Fluidity_Server/client.$SSH_ID/connection.$1/runtimeVars/ping_delay
   echo $ping_delay
   
}

# SET function for Intershell Variable: allow_execution
setAllowExecution () {

   local SSH_ID=${1%.*}
   echo "sed -i '1s/.*/$(echo allow_execution="$2")/' ~/Fluidity_Server/client.$SSH_ID/connection.$1/runtimeVars/allow_execution" | bash -

}

# GET function for Intershell Variable: allow_execution
getAllowExecution () {
	
   local SSH_ID=${1%.*}
   source ~/Fluidity_Server/client.$SSH_ID/connection.$1/runtimeVars/allow_execution
   echo $allow_execution
	
}

# SET function for Intershell Variable: port
setPort () {
   
   local SSH_ID=${1%.*}
   echo "sed -i '1s/.*/$(echo port="$2")/' ~/Fluidity_Server/client.$SSH_ID/connection.$1/runtimeVars/port" | bash -
	
}

# GET function for Intershell Variable: port
getPort () {
	
   local SSH_ID=${1%.*}
   source ~/Fluidity_Server/client.$SSH_ID/connection.$1/runtimeVars/port
   echo $port
   
}

# SET function for Intershell Variable: server_is_terminated
setServerIsTerminated () {

   local SSH_ID=${1%.*}
   echo "sed -i '1s/.*/$(echo server_is_terminated="$2")/' ~/Fluidity_Server/client.$SSH_ID/connection.$1/runtimeVars/server_is_terminated" | bash -
	
}

# GET function for Intershell Variable: server_is_terminated
getServerIsTerminated () {
	
   local SSH_ID=${1%.*}
   source ~/Fluidity_Server/client.$SSH_ID/connection.$1/runtimeVars/server_is_terminated
   echo $server_is_terminated
   
}

# SET function for Intershell Variable: client_is_terminated
setClientIsTerminated () {

   # VARIABLE: client_is_terminated
   # Signalling variable. Two possible values, 0 or 1. 
   # 1 means that runSOCATclient is out of its main infinite loop and has
   # been terminated successfully.
   
   local SSH_ID=${1%.*}
   echo "sed -i '1s/.*/$(echo client_is_terminated="$2")/' ~/Fluidity_Server/client.$SSH_ID/connection.$1/runtimeVars/client_is_terminated" | bash -
	
}

# GET function for Intershell Variable: client_is_terminated
getClientIsTerminated () {
	
   local SSH_ID=${1%.*}
   source ~/Fluidity_Server/client.$SSH_ID/connection.$1/runtimeVars/client_is_terminated
   echo $client_is_terminated
   	
}

# SET function for Intershell Variable: sleep_pid
setSleepPid () {

   local SSH_ID=${1%.*}
   echo "sed -i '1s/.*/$(echo sleep_pid="$2")/' ~/Fluidity_Server/client.$SSH_ID/connection.$1/runtimeVars/sleep_pid" | bash -

}

# GET function for Intershell Variable: sleep_pid
getSleepPid () {
	
   local SSH_ID=${1%.*}
   source ~/Fluidity_Server/client.$SSH_ID/connection.$1/runtimeVars/sleep_pid
   echo $sleep_pid
}


# SET function for Intershell Variable: termination_force_ping
setTerminationForcePing () {

   local SSH_ID=${1%.*}
   echo "sed -i '1s/.*/$(echo termination_force_ping="$2")/' ~/Fluidity_Server/client.$SSH_ID/connection.$1/runtimeVars/termination_force_ping" | bash -
	
}

# GET function for Intershell Variable: termination_force_ping
getTerminationForcePing () {
	
   local SSH_ID=${1%.*}
   source ~/Fluidity_Server/client.$SSH_ID/connection.$1/runtimeVars/termination_force_ping
   echo $termination_force_ping

}

# SET function for Intershell Variable: connection_status
setFluidityConnectionStatus () {

   local SSH_ID=${1%.*}
   echo "sed -i '1s/.*/$(echo fluidity_connection_status="$2")/' ~/Fluidity_Server/client.$SSH_ID/connection.$1/runtimeVars/fluidity_connection_status" | bash -
	
}

# GET function for Intershell Variable: connection_status
getFluidityConnectionStatus () {
	
   local SSH_ID=${1%.*}
   
   local FILE=$(eval echo ~$USER)'/Fluidity_Server/client.'$SSH_ID'/connection.'$1'/runtimeVars/fluidity_connection_status'
   
   # Active connection detected. Echo its current status.
   if [ -f "$FILE" ]; then
      source ~/Fluidity_Server/client.$SSH_ID/connection.$1/runtimeVars/fluidity_connection_status
      echo $fluidity_connection_status
   # No active connection. Connection doesn't exists, so return to INACTIVE 
   else
      echo INACTIVE
   fi

}


# 2. Server Creation - Configuration Functions
# 2.1 Public Functions


# Arguments: NONE

# Sourced Variables: NONE

# Intershell File Variables in use: NONE

# Global Variables in use: NONE

# Generates: Nothing

# Invokes Functions:
# 1. fluidityServerConfiguration, no args
# 2. mainServerFolderCreation, no args
# 3. serverFolderBackboneCreation, no args
# 4. reinstallFluidity, no args

# Calls the script: NONE

# Function Description: Fluidity first time setup utility. The
# starting point to create a new Fluidity installation.
installFluidity () {

   # First check: If ~/Fluidity_Server already exists then reinstall 
   # Fluidity
   if [ -d ~/Fluidity_Server ]; then
      clear
      echo -e "WARNING! FLUIDITY SERVER FOLDER DETECTED!\n\n\n"
      sleep 4
      
      #Invoke reinstallFluidity
      reinstallFluidity
      
   fi

   # Looped user prompt: Ask the user whether he/she wants to proceed
   # with Fluidity installation. 
   while true; do
      clear
      echo -e \
      '\nWelcome to Fluidity first time setup utility.'\
      '\nShall we proceed with the installation?'\
      '\nType [yes]: Install Fluidity'\
      '\nType [no]: Cancel and exit back to terminal'\
      && read -p '_' choice
      # CASE 1: YES - Install Fluidity.
      case $choice in
      [yY] | [yY][Ee][Ss] )
         echo -e "\nInstalling Fluidity"
         
         #Invoke fluidityServerConfiguration
         fluidityServerConfiguration
         
         #Invoke mainServerFolderCreation
         mainServerFolderCreation
         
         #Invoke serverFolderBackboneCreation
         serverFolderBackboneCreation
         
      break;;
      # CASE 2: NO - Exit to terminal.
      [nN] | [nN][Oo] )
         echo -e "\nFluidity installation cancelled"
      break;;
      # Error handling case: Capture wrong input, display an 
      # "invalid input" message and loop again.
         * ) echo "Invalid input";;
      esac
   done
      
}


# Arguments: NONE

# Sourced Variables: NONE

# Intershell File Variables in use: NONE

# Global Variables in use: NONE

# Generates: Nothing

# Invokes Functions:
# 1. fluidityServerConfiguration, no args
# 2. mainServerFolderCreation, no args
# 3. serverFolderBackboneCreation, no args

# Calls the script: NONE

# Function Description: Fluidity reinstallation utility.
# Install Fluidity upon an existing Fluidity 
# installation. The old Fluidity data are completely erased.

reinstallFluidity () {
    
   # Looped user prompt: Ask the user whether he/she wants to proceed
   # with Fluidity re-installation.
   while true; do
      echo -e \
      '\nWelcome to Fluidity reinstallation utility.'\
      '\nShall we reinstall Fluidity?'\
      '\nType [yes]: To reinstall'\
      '\nType [no]: Cancel and exit back to terminal'\
      && read -p '_' choice
      # CASE 1: YES - Re-install Fluidity.
      case $choice in
      [yY] | [yY][Ee][Ss] )
         echo -e "\nReinstalling Fluidity"
         
         # Wipe out anything related to a previous Fluidity 
         # installation.
         cd ~
         sudo umount ~/Fluidity_Server
         rm -r ~/Fluidity_Server
         
         #Invoke fluidityServerConfiguration
         fluidityServerConfiguration
         
         #Invoke mainServerFolderCreation
         mainServerFolderCreation
         
         #Invoke serverFolderBackboneCreation
         serverFolderBackboneCreation
         
      break;;
      # CASE 2: NO - Exit to terminal.
      [nN] | [nN][Oo] )
         echo -e "\nFluidity installation cancelled"
      break;;
      # Error handling case: Capture wrong input, display an 
      # "invalid input" message and loop again.
      * ) echo "Invalid input";;
      esac
   done
   
}

# Arguments: NONE

# Sourced Variables: NONE

# Intershell File Variables in use: NONE

# Global Variables in use: NONE

# Generates: Nothing

# Invokes Functions: NONE

# Calls the script: NONE

# Function Description: Public function that mounts Fluidity's server,
# home folder, after a reboot.
mountFluidityServerFolder () {
   
   local pass
   
   echo -e \
      '\nPlease enter your Fluidity master password:'\
      && read -p '_' pass

   # Mount the main Fluidity installation folder.

expect << EOF
 spawn sudo mount -t ecryptfs \
-o key=passphrase:passphrase_passwd=$pass,\
ecryptfs_cipher=aes,\
ecryptfs_key_bytes=32,\
ecryptfs_enable_filename=y,\
ecryptfs_passthrough=n,\
ecryptfs_enable_filename_crypto=y\
 ./Fluidity_Server ./Fluidity_Server
 expect {
	 {\]: } {send "\n"}
 }
 expect {
	 "(yes/no)? :" {send "yes\n"}
	 eof {send ""}
 }
 expect {
	 "(yes/no)? :" {send "yes\n"}
	 eof {send ""}
 }
 expect eof
EOF

   cd Fluidity_Server
   
}


# 2.2 Private Functions


# Arguments: NONE

# Sourced Variables: NONE

# Intershell File Variables in use: NONE

# Global Variables in use: NONE

# Generates: Nothing

# Invokes Functions: 
# 1. giveAnEntropyBoost, no args

# Calls the script: NONE

# Function Description: Verify the existance and if necessary install
# the following list of essential Fluidity utilities.
   # 1. (SOCAT)
   # 2. (ecryptfs-utils) 
   # 3. (expect) 
   # 4. (lsof)
   # 5. (Uncomplicated Firewall, UFW)
      # Perform basic firewall configuration i.e.
         # a. Allow outgoing traffic.
         # b. Deny incoming traffic.
         # c. Allow inbound SSH connections.
   # 6. (haveged OR rng-tools)

fluidityServerConfiguration () {

   # Check for Internet availability
   if [ "`ping -c 3 www.google.com`" ]; then
      # Update the system
      sudo apt-get update
      # Verify and if not present install "SOCAT"
      if ! [ -x "$(command -v socat)" ]; then
         sudo apt-get -y install socat
      fi
      # Verify and if not present install "ECRYPTFS"
      if ! [ -x "$(command -v ecryptfsd)" ]; then
         sudo apt-get -y install ecryptfs-utils
      fi
      # Verify and if not present install  "EXPECT"
      if ! [ -x "$(command -v expect)" ]; then
         sudo apt-get -y install expect
      fi
      # Verify and if not present install "LSOF"
      if ! [ -x "$(command -v lsof)" ]; then
         sudo apt-get -y install lsof
      fi
      # Verify and if not present install "UFW", 
      # also perform the initial Firewall configuration.
      if ! [ -x "$(command -v ufw)" ]; then
         sudo apt-get -y install ufw
         
         # Basic server firewall configuration
         
         sudo systemctl enable ufw
         
         # Allow all the outgoing traffic
         sudo ufw default allow outgoing
         # Deny all the incoming traffic
         sudo ufw default deny incoming
         # Allow SSH connections
         sudo ufw allow ssh
      fi
      
      # Invoke giveAnEntropyBoost
      giveAnEntropyBoost
   # Error handling case:
   # Display a no internet access message.
   else
      echo -e 'Warning. No Internet access.' \
      '\nTo install the necessary utilities please connect to the Internet.'
   fi
  
}

# Arguments: NONE

# Sourced Variables: NONE

# Intershell File Variables in use: NONE

# Global Variables in use: NONE

# Generates: Nothing

# Invokes Functions: NONE

# Calls the script: NONE

# Function Description: Create and encrypt the Fluidity_Server folder 
# with ecryptfs-utils, by using a user defined encryption password.
mainServerFolderCreation () {

   local encr_pass
   
   echo -e \
      '\nPlease choose your Fluidity master password:'\
      && read -p '_' encr_pass
    
   # FLUIDITY -- Create the main folder
   mkdir ~/Fluidity_Server

   # Encrypt the main folder with ecryptfs-utils and the following
   # settings: 
		# Encryption cypher: AES
		# Key size: 256 bits
		# File Name Encryption: Enabled
expect << EOF
	   spawn sudo mount -t ecryptfs \
	-o key=passphrase:passphrase_passwd=$encr_pass,\
	ecryptfs_cipher=aes,\
	ecryptfs_key_bytes=32,\
	ecryptfs_enable_filename=y,\
	ecryptfs_passthrough=n,\
	ecryptfs_enable_filename_crypto=y\
	 ./Fluidity_Server ./Fluidity_Server
	   expect {\]: }
	   send "\n"
	   expect eof
EOF

   echo -e "\n\n\n"
   
   cd ~/Fluidity_Server

}

# Arguments: NONE

# Sourced Variables: NONE

# Intershell File Variables in use: NONE

# Global Variables in use: NONE

# Generates: Nothing

# Invokes Functions: NONE

# Calls the script: NONE

# Function Description: Create the main Fluidity server folder structure 
# (Fluidity_Server)
serverFolderBackboneCreation () {

   # Create "Generated_Scripts" folder to contain Fluidity's generated scripts
   mkdir ~/Fluidity_Server/Generated_Scripts

   # Create the main SSH credentials storage folder
   mkdir ~/Fluidity_Server/SSH_Vault

   # Create the SSH passphrases storage folder
   mkdir ~/Fluidity_Server/SSH_Vault/SSH_Passphrases

   # Create the SSH keys folder
   mkdir ~/Fluidity_Server/SSH_Vault/SSH_Keys

   # Folder - SSL_Cert_Vault: Will contain the subfolders for the entirety
   # of certificates and passwords produced for each individual connection
   mkdir ~/Fluidity_Server/SSL_Cert_Vault

   # Precautionary Step 1:
   # Check for the .ssh folder. If not, create it
   if [ ! -d ~/.ssh ]; then
      mkdir ~/.ssh
   else 
      echo ".ssh folder already exists"
   fi
   
}


# 3. Client Creation - Configuration Functions
# 3.1 Public Functions


# Arguments:
# $1: Server IP address.

# Sourced Variables: NONE

# Intershell File Variables in use: NONE

# Global Variables in use: NONE

# Generates: Nothing

# Invokes Functions:
# 1. giveAnEntropyBoost, no args

# Calls the script: NONE

# Function Description: Verify the existance and if necessary install
# the following list of essential utilities.
   # 1. (SOCAT)
   # 2. (ecryptfs-utils) 
   # 3. (expect) 
   # 4. (haveged OR rng-tools)
   # 5. (lsof)
   # 6. (Uncomplicated Firewall, UFW)
      # Perform basic firewall configuration i.e.
         # a. Allow outgoing traffic.
         # b. Deny incoming traffic.
         # c. Allow inbound SSH connections.

fluidityClientConfiguration () {
   
   # Check for Internet availability
   if [ "`ping -c 3 www.google.com`" ]; then
      # Update the system
      sudo apt-get update
      # Verify and if not present install "SOCAT"
      if ! [ -x "$(command -v socat)" ]; then
         sudo apt-get -y install socat
      fi
      # Verify and if not present install "ECRYPTFS"
      if ! [ -x "$(command -v ecryptfsd)" ]; then
         sudo apt-get -y install ecryptfs-utils
      fi
      # Verify and if not present install "EXPECT"
      if ! [ -x "$(command -v expect)" ]; then
         sudo apt-get -y install expect
      fi
      # Verify and if not present install "LSOF"
      if ! [ -x "$(command -v lsof)" ]; then
         sudo apt-get -y install lsof
      fi
      # Verify and if not present install "UFW", 
      # also perform the initial Firewall configuration.
      if ! [ -x "$(command -v ufw)" ]; then
         sudo apt-get -y install ufw
         
         # Basic client firewall configuration
         
         sudo systemctl enable ufw
         
         # Allow all the outgoing traffic
         sudo ufw default allow outgoing
         # Deny all the incoming traffic
         sudo ufw default deny incoming
         # Only allow SSH connections from the Fluidity Server IP.
         sudo ufw allow from $1 to any port 22 proto tcp
      fi
      
      # Invoke giveAnEntropyBoost
      giveAnEntropyBoost
      
      # Change the sshd_config. 
      
      # Set the maximum number of authentication retries to 1.
      sudo echo "sed -i '34s/.*/$(echo #MaxAuthTries 1)/' /etc/ssh/sshd_config" | bash -
      # Set the maximum number of concurrent sessions to 1.
      sudo echo "sed -i '35s/.*/$(echo #MaxSessions 1)/' /etc/ssh/sshd_config" | bash -
      
   # Error handling case:
   # Display a no internet access message.
   else
      echo -e 'Warning. No Internet access.' \
      '\nTo proceed with the installation, please connect to the Internet.'
   fi
   
   mkdir ~/Fluidity_Client
   
   # Restart ssh to make changes take effect.
   sudo service ssh restart
   
}


# 4. Client Management Functions
# 4.1 Public Functions


# Arguments: ($1), ($2), ($3), ($4) 
# $1: SSH Client ID.
# $2: Server IP address.
# $3: Client IP address.
# $4: Server Password
# $5: Client username (for raspbian OS the default is pi@)

# Sourced Variables: NONE

# Intershell File Variables in use: NONE

# Global Variables in use:
# 1. SSH_passphrase []

# Generates:
# 1. Text File (.txt): passphrase_$1.txt (8 character string)
# 2. SSH Private Key (No Extension): client$1 (The SSH private key)
# 3. SSH Public Key (.pub) File: client$1.pub
# 4. Text File (.txt): basic_client_info.txt
   # Stores and contains:
   # 1. $server_IP_address
   # 2. $client_IP_address
   # 3. $client_username

# Invokes functions:
# 1. checkLocalEntropy, no args
# 2. checkFluidityFilesystemIntegrity, no args
# 3. fluidityRemoteClientConfiguration, with args ($3), ($5), ($2)
# 4. remoteSeekAndEncryptDaemonInstallation ($3), ($5), ($1)
# 4. changeRemoteHostName, with args ($2), ($3), ($5)

# Calls the script: NONE

# Function Description: Create the SSH key, add it to the keyring and then
# sent it to the remote host.
addFluidityClient () {

   # Safety check 1: Check whether target client.[SSH_ID] already exists.
   if [ -d ~/Fluidity_Server/client.$1 ]; then
      echo "Client $1 already exists"
      return
   fi

   # Safety check 2: Check whether the server responds to 
   # pinging. 
   if ! ping -c 3 $2; then
      clear
      echo -e \
      'Destination host '$3' is unreachable.' \
      '\nWrong Server address. Cancelling addFluidityClient.'
      return
   else
      echo "Connectivity test to server $3 succeeded."
   fi

   # Safety check 3: Check whether target client.[SSH_ID] responds to 
   # pinging. 
   if ! ping -c 3 $3; then
      clear
      echo -e \
      'Destination host '$3' is unreachable.' \
      '\nCancelling addFluidityClient.'
      return
   else
      echo "Connectivity test to host $3 succeeded. Proceeding with client configuration."
   fi

   # Safety check 4: Verify that local entropy is above target value 1000. 
   if [[ $(checkLocalEntropy) == 1 ]]; then
     echo "Server entropy is above 1000. Carrying on with addFluidityClient."
   else
     echo "Insufficient entropy. addFluidityClient will not be executed."
     return
   fi
   
   # Safety check 5: Perform an overall Fluidity file structure
   # integrity check.
   if [[ $(checkFluidityFilesystemIntegrity) == 1 ]]; then
      echo "Fluidity system file integrity test passed"
   else
   
      # Invoke checkFluidityFilesystemIntegrity
      checkFluidityFilesystemIntegrity
      
      return
   fi
  
   # Based on the SSH ID calculate the array index
   local array_index=$(expr $1 - 1)

   # Trick to emulate ~/ in expect body for ssh-add
   local dir_ssh=$(echo ~/.ssh)

   # Use openssl rand to generate an 8 character string.
   # Store the outcome to $passphrase_1 so that it can be used 
   # by ssh-keygen.
   SSH_passphrase[$array_index]=$(openssl rand -base64 8)

   # Store the generated password to SSH_Vault for
   # permanent file storage and future reference.
   echo ${SSH_passphrase[$array_index]} > \
   ~/Fluidity_Server/SSH_Vault/SSH_Passphrases/passphrase.$1.txt
   
   cat ~/Fluidity_Server/SSH_Vault/SSH_Passphrases/passphrase.$1.txt

   # Generate a new SSH key. Use RSA encoding with a key size of 2048 bits.
   # $passphrase_1 variable will be used.
   # This will be the client SSH connection to client.[SSH_ID]
   ssh-keygen -t rsa -b 2048 -N ${SSH_passphrase[$array_index]} \
    -C "SSH remote connection to Fluidity client $1" \
    -f ~/.ssh/client.$1
    
   # Store the SSH key to SSH_Vault for
   # permanent file storage and future reference.
   cp ~/.ssh/client.$1  ~/.ssh/client.$1.pub \
   ~/Fluidity_Server/SSH_Vault/SSH_Keys

   # Use Expect to add client.[SSH_ID] to authentication agent.
   # At the passphrase prompt Expect will automatically use
   # variable $passphrase1.
   # This will allow to perform SSH passwordless logins
expect << EOF
      spawn ssh-add $dir_ssh/client.$1
      expect "Enter passphrase"
      send "${SSH_passphrase[$array_index]}\r"
      expect eof
EOF

   # Add the remote machine to known hosts (x03 sends a Ctrl-C)
expect << EOF
       spawn ssh $5@$3
       expect "(yes/no)?"
       send "yes\r"
       expect "password:"
       send \x03
EOF

   # Transmit the SSH credentials to the remote machine.
   # sshpass utility will be used to provide the log in password.
   sshpass -p $4 \
   ssh-copy-id -i ~/.ssh/client.$1 $5@$3
    
   mkdir ~/Fluidity_Server/client.$1
   
   # Create client state information file basic_client_info.txt, containing:
		# 1. The server IP address: $server_IP_address
		# 2. The client IP address: $client_IP_address
		# 3. The client username: $client_username
   # and store it in location:
   # ~/Fluidity_Server/client.[SSH_ID]/basic_client_info.txt
   echo -e \
'server_IP_address='$2\
'\nclient_IP_address='$3\
'\nclient_username='$5\
   > ~/Fluidity_Server/client.$1/basic_client_info.txt
   
   # Invoke function changeRemoteHostName to change client hostname
   # to fluidity_client_[SSH_ID].
   changeRemoteHostName "fluidity_client_$1" $3 $5
   
   # Invoke fluidityRemoteClientConfiguration to
   # install Fluidity's essential programs and basic firewall
   # configuration to client machine.
   fluidityRemoteClientConfiguration $3 $5 $2
   
   # Invoke remoteSeekAndEncryptDaemonInstallation to
   # install FLdaemon_SeekAndEncrypt.service.
   remoteSeekAndEncryptDaemonInstallation $3 $5 $1
   
}


# Arguments: ($1)
# $1: SSH Client ID.

# Sourced Variables:
# 1. ~/Fluidity_Server/client.$SSH_ID/basic_client_info.txt
   # 1. $server_IP_address
   # 2. $client_IP_address
   # 3. $client_username
   
# Intershell File Variables in use: NONE

# Global Variables in use: NONE

# Generates:
# 1. Bash script (.sh):  genSCRIPT_eraseClientData.sh

# Invokes Functions: NONE

# Calls the script:
# 1. genSCRIPT_eraseClientData.sh, with args, $client_username, ($1), $server_IP_address
# in: ~/Fluidity_Server/Generated_Scripts

# Function Description: 
removeFluidityClient () {
   
   # Source the variables:
      # 1. $server_IP_address
      # 2. $client_IP_address
      # 3. $client_username
   source ~/Fluidity_Server/client.$1/basic_client_info.txt
   
   # Safety check 1: Check whether target client.[SSH_ID] already exists.
   if [ ! -d ~/Fluidity_Server/client.$1 ]; then
      echo "Fluidity client $1 does not exist."
      return
   fi
   
   # Safety check 2: Check whether target client.[SSH_ID] responds to 
   # pinging. 
   if ! ping -c 3 $client_IP_address; then
      clear
      echo -e \
      'Destination host '$client_IP_address' is unreachable.' \
      '\nCancelling removeFluidityClient for client $1.'
      return
   else
      echo "Connectivity test to host $client_IP_address succeeded. Proceeding with client removal."
   fi
   
   # Generate genSCRIPT_eraseClientData.sh and store it in
   # ~/Fluidity_Server/Generated_Scripts
   if [[ ! -e ~/Fluidity_Server/Generated_Scripts/genSCRIPT_eraseClientData.sh ]]; then
   
      echo -e \
'\n'\
'# SECTION 1 (Safety check 1): Scan the client machine for active\n'\
'# SOCAT connections. If an active connection is detected make\n'\
'# $do_not_proceed=1, if not, make do_not_proceed=0 and output the\n'\
'# connection that was found active.\n'\
'folder_counter=1\n'\
'do_not_proceed=0\n'\
'\n'\
'while [[ -e /home/'$client_username'/Fluidity_Client/connection.'$1'.$folder_counter ]]; do\n'\
'   \n'\
'   if [[ $(lsof | grep "connection.'$1'.$folder_counter/clientcon.'$1'.$folder_counter.pem") ]]; then\n'\
'      echo "Warning! Fluidity connection $folder_counter is active."\n'\
'      do_not_proceed=1\n'\
'   else\n'\
'      do_not_proceed=0\n'\
'   fi\n'\
'   \n'\
'   let folder_counter=$(expr $folder_counter + 1)\n'\
'   \n'\
'done\n'\
'\n'\
'# SECTION 2: Based upon the outcome of the previous section, if\n'\
'# do_not_proceed=0, then proceed to client removal.\n'\
'# Else, print a message that concludes the list of connections\n'\
'# found active from in SECTION 1.\n'\
'if [[ $do_not_proceed == 0 ]]; then\n'\
'   \n'\
'   # SECTION 2.1: Unistall FLdaemon_SeekAndEncrypt\n'\
'   sudo systemctl stop FLdaemon_SeekAndEncrypt.service\n'\
'   sudo rm /usr/bin/FLdaemon_SeekAndEncrypt.sh\n'\
'   sudo rm /etc/systemd/system/FLdaemon_SeekAndEncrypt.service\n'\
'   \n'\
'   # SECTION 2.2 (Safety check 2): Unmount (i.e. decrypt) any \n'\
'   # possible remaining encrypted folders.\n'\
'   folder_counter=1\n'\
'   \n'\
'   while [[ -e /home/'$client_username'/Fluidity_Client/connection.'$1'.$folder_counter ]]; do\n'\
'      sudo umount ~/Fluidity_Client/connection.'$1'.$folder_counter\n'\
'      let folder_counter=$(expr $folder_counter + 1)\n'\
'   done\n'\
'   \n'\
'   # SECTION 2.3: Remove the main fluidity client folder.\n'\
'   rm -r ~/Fluidity_Client\n'\
'   # SECTION 2.3: Change client hostname to generic "blank"\n'\
'   sudo hostnamectl set-hostname "blank"\n'\
'   # SECTION 2.3: Remove the public SSH key pointing to Fluidity server\n'\
'   # (it should contain only the connection to Fluidity server!)\n'\
'   if [ -f ~/.ssh/known_hosts ]; then\n'\
'      ssh-keygen -R '$server_IP_address'\n'\
'      rm ~/.ssh/known_hosts.old\n'\
'   fi\n'\
'   \n'\
'   # SECTION 2.4 (Return message to server and Safety Check 3):\n'\
'   # Scan the ~/.ssh/authorized_keys file for the "SSH remote connection"\n'\
'   # addFluidityClient message. If the message is detected return to\n'\
'   # server a SUCCESS signal and revoke the SSH passwordless access rights \n'\
'   # to Fluidity server.\n'\
'   if cat ~/.ssh/authorized_keys | grep "SSH remote connection to Fluidity client '$1'"; then\n'\
'      echo "genSCRIPT_eraseClientData.sh reports SUCCESS"\n'\
'      sed -i '"'"'/SSH remote connection to Fluidity client '$1''"'"'/d' ~/.ssh/authorized_keys'\n'\
'   fi\n'\
'   \n'\
'else\n'\
'   \n'\
'   echo "Please shut the aforementioned connections."\n'\
'   \n'\
'fi\n'\
      > ~/Fluidity_Server/Generated_Scripts/genSCRIPT_eraseClientData.sh
   
   # genSCRIPT_eraseClientData.sh detected. Delete the previous version 
   # and build a new one, containing client's updated specific information.
   else
   
   rm ~/Fluidity_Server/Generated_Scripts/genSCRIPT_eraseClientData.sh
   
   echo -e \
'\n'\
'# SECTION 1 (Safety check 1): Scan this client machine for any active\n'\
'# SOCAT connections. If an active connection is detected make\n'\
'# $do_not_proceed=1, if not make do_not_proceed=0 and output the\n'\
'# connections found active.\n'\
'folder_counter=1\n'\
'do_not_proceed=0\n'\
'\n'\
'while [[ -e /home/'$client_username'/Fluidity_Client/connection.'$1'.$folder_counter ]]; do\n'\
'   \n'\
'   if [[ $(lsof | grep "connection.'$1'.$folder_counter/clientcon.'$1'.$folder_counter.pem") ]]; then\n'\
'      echo "Warning! Fluidity connection $folder_counter is active."\n'\
'      do_not_proceed=1\n'\
'   else\n'\
'      do_not_proceed=0\n'\
'   fi\n'\
'   \n'\
'   let folder_counter=$(expr $folder_counter + 1)\n'\
'   \n'\
'done\n'\
'\n'\
'# SECTION 2: Based upon the outcome of the previous section, if\n'\
'# do_not_proceed=0, then carry on with the set of operations necessary\n'\
'# for client removal. Else, print a message that concludes the outcome\n'\
'# of SECTION 1.\n'\
'if [[ $do_not_proceed == 0 ]]; then\n'\
'   \n'\
'   # SECTION 2.1: Unistall FLdaemon_SeekAndEncrypt\n'\
'   sudo systemctl stop FLdaemon_SeekAndEncrypt.service\n'\
'   sudo rm /usr/bin/FLdaemon_SeekAndEncrypt.sh\n'\
'   sudo rm /etc/systemd/system/FLdaemon_SeekAndEncrypt.service\n'\
'   \n'\
'   # SECTION 2.2 (Safety check 2): Unmount (i.e. decrypt) any \n'\
'   # remaining encrypted folders.\n'\
'   folder_counter=1\n'\
'   \n'\
'   while [[ -e /home/'$client_username'/Fluidity_Client/connection.'$1'.$folder_counter ]]; do\n'\
'      sudo umount ~/Fluidity_Client/connection.'$1'.$folder_counter\n'\
'      let folder_counter=$(expr $folder_counter + 1)\n'\
'   done\n'\
'   \n'\
'   # SECTION 2.3: Remove the main fluidity client folder.\n'\
'   rm -r ~/Fluidity_Client\n'\
'   # SECTION 2.3: Change the client hostname to generic "blank"\n'\
'   sudo hostnamectl set-hostname "blank"\n'\
'   # SECTION 2.3: Remove any information about possible known hosts\n'\
'   # (it should contain only the SSH connection to fluidity server.)\n'\
'   if [ -f ~/.ssh/known_hosts ]; then\n'\
'      ssh-keygen -R '$server_IP_address'\n'\
'      rm ~/.ssh/known_hosts.old\n'\
'   fi\n'\
'   \n'\
'   # SECTION 2.4 (Return message and do safety check 3):\n'\
'   # Scan ~/.ssh/authorized_keys for the "SSH remote connection"\n'\
'   # addFluidityClient message. If the message is detected return to\n'\
'   # server a SUCCESS signal and remove the line offering SSH \n'\
'   # passwordless access to the former Fluidity client.\n'\
'   if cat ~/.ssh/authorized_keys | grep "SSH remote connection to Fluidity client '$1'"; then\n'\
'      echo "genSCRIPT_eraseClientData.sh reports SUCCESS"\n'\
'      sed -i '"'"'/SSH remote connection to Fluidity client '$1''"'"'/d' ~/.ssh/authorized_keys'\n'\
'   fi\n'\
'   \n'\
'else\n'\
'   \n'\
'   echo "Please shut the aforementioned connections."\n'\
'   \n'\
'fi\n'\
      > ~/Fluidity_Server/Generated_Scripts/genSCRIPT_eraseClientData.sh
      
   fi
   
   # Used to store the outcome from genSCRIPT_eraseClientData.sh
   local eraseClientData_outcome
   
   # First, SSH remotely execute genSCRIPT_eraseClientData.sh and, then,
   # save the outcome into $eraseClientData_outcome.
   eraseClientData_outcome=$(ssh $client_username@$client_IP_address \
   'bash -s' < ~/Fluidity_Server/Generated_Scripts/genSCRIPT_eraseClientData.sh \
    $client_username $1 $server_IP_address)
   
   # Act upon the grep-ed outcome from target client. 
   # If client returns "genSCRIPT_eraseClientData.sh reports SUCCESS"
   # then, proceed with removing Fluidity Server client data. 
   if echo "$eraseClientData_outcome" | grep -q "genSCRIPT_eraseClientData.sh reports SUCCESS"; then

      # Remove client's identity.
      ssh-add -d ~/.ssh/client.$1
      
      # Delete the client's SSH related data.
      rm ~/.ssh/client.$1
      rm ~/.ssh/client.$1.pub
      
      # Delete client information stored in Fluidity Vault.
      rm ~/Fluidity_Server/SSH_Vault/SSH_Keys/client.$1
      rm ~/Fluidity_Server/SSH_Vault/SSH_Keys/client.$1.pub
      
      rm ~/Fluidity_Server/SSH_Vault/SSH_Passphrases/passphrase.$1.txt
      
      # Delete all the client data.
      rm -r ~/Fluidity_Server/client.$1
      
      # Remove the former Fluidity client from ~/.ssh/known_hosts.
      ssh-keygen -R $client_IP_address
      rm ~/.ssh/known_hosts.old
      
      # Display an operation success message.
      echo "Client $1 removed successfully."
      
   else
      
      # Display an operation failed message that follows the 
      # messages received from target Fluidity client.
      echo "Client $1 removal failed."
      echo "Manually check the Fluidity server and client. Something went wrong"
      
   fi
   
   
}


# 4.2 Private Functions


# Arguments: 
# $1: Client IP.
# $2: Client Username.
# $3: Server IP.

# Sourced Variables: NONE

# Intershell File Variables in use: NONE

# Global Variables in use: NONE

# Generates:
# Bash script (.sh): genSCRIPT_fluidityRemoteClientConfiguration.sh

# Invokes Functions: NONE

# Calls the script:
# 1. genSCRIPT_fluidityRemoteClientConfiguration.sh, no args
# in: ~/Fluidity_Server/Generated_Scripts

# Function Description: 
   # 1. Create the main folder structure  (~/Fluidity_Client)
   # 2. Verify the existance and if necessary install
   # the following set of utilities essential to Fluidity's operation 
      # 1. (socat)
      # 2. (ecryptfs-utils) 
      # 3. (expect)
      # 4. (haveged OR rng-tools)
      # 5. (lsof)
      # 6. (Uncomplicated Firewall, UFW)
         # Perform basic firewall configuration i.e.
            # a. Allow outgoing traffic.
            # b. Deny incoming traffic.
            # c. Allow inbound SSH connections.
      
fluidityRemoteClientConfiguration () {
 
   if [[ ! -e ~/Fluidity_Server/Generated_Scripts/genSCRIPT_fluidityRemoteClientConfiguration.sh ]]; then
   
      echo -e \
        'mkdir -p ~/Fluidity_Client'\
      '\nsudo apt-get update'\
      '\n'\
      '\nif ! [ -x "$(command -v socat)" ]; then'\
      '\n   sudo apt-get -y install socat'\
      '\nfi'\
      '\nif ! [ -x "$(command -v ecryptfsd)" ]; then'\
      '\n   sudo apt-get -y install ecryptfs-utils'\
      '\nfi'\
      '\n'\
      '\nif ! [ -x "$(command -v expect)" ]; then'\
      '\n   sudo apt-get -y install expect'\
      '\nfi'\
      '\n'\
      '\nif ! [ -x "$(command -v lsof)" ]; then'\
      '\n   sudo apt-get -y install lsof'\
      '\nfi'\
      '\n'\
      '\nif ! [ -x "$(command -v ufw)" ]; then'\
      '\n   sudo apt-get -y install ufw'\
      '\n   sudo systemctl enable ufw'\
      '\n   sudo ufw default allow outgoing'\
      '\n   sudo ufw default deny incoming'\
      '\n   sudo ufw allow from '$3' to any port 22 proto tcp'\
      '\nfi'\
      '\nif ! [ -x "$(command -v haveged)" ] && [ -x "$(command -v rngd)" ]; then'\
      '\n   while true; do'\
      '\n   echo "Fluidity requires a high quality entropy source" \\\n'\
      '   && echo "Which utility you prefer to choose?" \\\n'\
      '   && echo "1. for Haveged" \\\n'\
      '   && echo "2. for rng-tools" \\\n'\
      '   && read -p "_" choice '\
      '\n      case $choice in'\
      '\n         [1]* ) echo "Installing Haveged"'\
      '\n            sudo apt-get -y install haveged'\
      '\n            # Start the "HAVEGED" service'\
      '\n            sudo systemctl start haveged'\
      '\n         break;;'\
      '\n         [2]* ) echo "Installing rng-tools"'\
      '\n            sudo apt-get -y install rng-tools'\
      '\n            # Start the "rng-tools" service'\
      '\n            sudo systemctl start rng-tools'\
      '\n         break;;'\
      '\n         * ) echo "1 for Haveged, 2 for rng-tools";;'\
      '\n      esac'\
      '\n   done'\
      '\nelif [ -x "$(command -v haveged)" ]; then'\
      '\n   echo "Haveged is already installed"'\
      '\nelse'\
      '\n   echo "haveged or rng-tools are already installed"'\
      '\nfi' 
      '\nsudo echo "sed -i '34s/.*/$(echo #MaxAuthTries 1)/' /etc/ssh/sshd_config" | bash -'\
      '\nsudo echo "sed -i '35s/.*/$(echo #MaxSessions 1)/' /etc/ssh/sshd_config" | bash -'\
      '\nsudo service ssh restart' > \
      ~/Fluidity_Server/Generated_Scripts/genSCRIPT_fluidityRemoteClientConfiguration.sh
      chmod 700 ~/Fluidity_Server/Generated_Scripts/genSCRIPT_fluidityRemoteClientConfiguration.sh
      
   else
      
      echo "sed -i '24s/.*/$(echo sudo ufw allow from $3 to any port 22 proto tcp)/' ~/Fluidity_Server/Generated_Scripts/genSCRIPT_fluidityRemoteClientConfiguration.sh" | bash -
      
   fi
   
   # SSH remotely execute genSCRIPT_fluidityRemoteClientConfiguration.sh
   ssh $2@$1 'bash -s' < ~/Fluidity_Server/Generated_Scripts/genSCRIPT_fluidityRemoteClientConfiguration.sh
   
}

# Arguments:
# $1: Client IP.
# $2: Client Username.
# $3: SSH Client ID

# Sourced Variables: NONE

# Intershell File Variables in use: NONE

# Global Variables in use: NONE

# Generates: 
# 1. Bash script (.sh): FLdaemon_SeekAndEncrypt
# 2. Unit file (.service): FLdaemon_SeekAndEncrypt.service
# 3. Bash script (.sh): genSCRIPT_moveFilesAndActivateDaemon.sh

# Invokes Functions: NONE

# Calls the script:
# 1. genSCRIPT_moveFilesAndActivateDaemon.sh, no args
# in: ~/Fluidity_Server/Generated_Scripts

# Function Description: Install and activate FLdaemon_SeekAndEncrypt.sh 
# into target system. The purpose of this daemon is to ensure that no 
# ~/Fluidity_Client/connection.[SSH_ID.SSL_ID] folder remains decrypted in the 
# absence of a Fluidity / SOCAT active connection. 
remoteSeekAndEncryptDaemonInstallation () {

   # Encryption immunity token:
   
   # Create an encryption immunity token that, when present in 
   # ~/Fluidity_Client/connection.[SSH_ID.SSL_ID]/tokenSlot folder, will 
   # prohibit the FLdaemon_SeekAndEncrypt.service from automatically 
   # encrypting the contents of ~/Fluidity_Client/connection.[SSH_ID.SSL_ID] 
   # in the absence of an active Fluidity / SOCAT connection.
   
   # Our concept is a digital padlock:
 

   #                 .--------.
   #                / .------. \
   #               / /        \ \
   #               | |        | |
   #              _| |________| |_  
   #            .' |_|        |_| '.
   #            '._____ ____ _____.'
   #            |     .'____'.     |
   #            '.__.'.'    '.'.__.'
   #            '.__  | FILE |   _.' --> randomly generated filename
   #            |   '.'.____.'.'   |
   #            '.____'.____.'____.' :file within ~/Fluidity_Client/connection.[SSH_ID.SSL_ID]/tokenSlot/filename
   #            '.________________.'
   #  Key to unlock: Hash Value OPENSSL ENC seal_2 = seal_1
   #
   #  The key to unlock the padlock is represented by the following condition:
   #  [IF $client_hashed_key -<openssl enc>- $seal_2 == to $seal_1 THEN]:
   
   #  TRUE: The digital padlock OPENS:
   #  Thus, ~/Fluidity_Client/connection.[SSH_ID.SSL_ID] 
   #  folder acquires encrpytion immunity, when is scanned by 
   #  FLdaemon_SeekAndEncrypt.sh AND SOCAT connection.[SSH_ID.SSL_ID] to 
   #  Fluidity Server is closed.
   
   #  FALSE: The digital padlock CLOSES:
   #  Thus, ~/Fluidity_Client/connection.[SSH_ID.SSL_ID]
   #  folder loses its encryption immunity when scanned by 
   #  FLdaemon_SeekAndEncrypt.sh AND SOCAT connection.[SSH_ID.SSL_ID] to 
   #  Fluidity Server is closed.


   # Location that the encryption immunity token is stored and copied to 
   # Fluidity client when required.
   mkdir ~/Fluidity_Server/client.$3/do_not_encrypt_token

   # Keep the folder filename simple: 
   # Select characters from the following three ranges:
   # (1). a to f | (2). 0 to 9 (3). | A to Z.
   local filename=$(cat /dev/urandom | tr -cd 'a-f0-9A-Z' | head -c 10)
   # sed can't interpret special character '/' without using a 
   # tricky special bit of coding. 
   # So, we use tr to substite any occurencies of '/' with 'W'
   local seal_1=$(openssl rand -base64 16 | tr / W)
   # sed can't interpret special character '/'. without using a tricky 
   # special bit of coding. 
   # So, we use tr to substite any occurencies of '/' with '4'
   local seal_2=$(openssl rand -base64 16 | tr / 4)
   echo "Seek And Encrypt token filename is: $filename"
   echo "Seal 1 password is: $seal_1"
   echo "Seal 2 password is: $seal_2"
   
   # Create the token file by using the randomly generated $filename.
   echo -e '\n\n' > ~/Fluidity_Server/client.$3/do_not_encrypt_token/$filename
   
   # Inject password $seal_1 to token file $filename
   echo "sed -i '1s/.*/$(echo seal_1="$seal_1")/' ~/Fluidity_Server/client.$3/do_not_encrypt_token/$filename" | bash -
   # Inject password $seal_2 to token file $filename
   echo "sed -i '2s/.*/$(echo seal_2="$seal_2")/' ~/Fluidity_Server/client.$3/do_not_encrypt_token/$filename" | bash -
   
   # A HASHED key is generated by using function openssl enc with $seal_1 
   # and seal_2 passwords. 
   # The hashed key is subsequantly embedded to FLdaemon_SeekAndEncrypt.sh, 
   # a client specific daemon script, installed to each Fluidity client. 
   
   # Based on both passwords, create the corrensponding hash.
   local client_hashed_key=$(echo $seal_1 \
      | openssl enc -aes-128-cbc -a -salt -pass pass:$seal_2)

   # FLdaemon_SeekAndEncrypt.sh doesn't exist. Generate it and
   # store it in: ~/Fluidity_Server/Generated_Scripts
   if [[ ! -e ~/Fluidity_Server/Generated_Scripts/FLdaemon_SeekAndEncrypt.sh ]]; then
   
      # Script description:
      # 1. Generate a client specific script, named: 
      # FLdaemon_SeekAndEncrypt.sh.
      # 2. Embed client specific information into specific sections of the script 
      # by using the following variables:
      #  Variables expressing CLIENT RELATED INFORMATION
      #    a. $2: Client Username
      #    b. $3: SSH Client ID
      #  Variables related to the DIGITAL PADLOCK (encryption immunity token)
      #    c. $filename: Token's filename 
      #    d. $client_hashed_key: Token's hashed key
      # 3. Loop through the ~/Fluidity_Client/connection.[SSH_ID].x
      # Fluidity connection folders (where x is [SSL_ID] = [1,2,...]) 
      # and see whether an active SOCAT connection exists. 
      #    a. If there is an active connection, leave the folder as it is. 
      #    b. If the connection is inactive, secure the folder by 
      #     encrypting it. 
      #    c. If the encryption immunity token is detected, within its 
      #     specific container folder: 
      #     (~/Fluidity_Client/connection.[SSH_ID.SSL_ID]/tokenSlot),
      #     keep the connection folder data decrypted.
      
      sudo echo -e \
        '#!/bin/bash'\
      '\nwhile true; do'\
      '\n   folder_counter=1'\
      '\n      while [[ -e /home/'$2'/Fluidity_Client/connection.'$3'.$folder_counter ]]; do'\
      '\n         if [[ ! $(lsof | grep "connection.'$3'.$folder_counter/clientcon.'$3'.$folder_counter.pem") ]] && \\\n'\
      '         [ -f /home/'$2'/Fluidity_Client/connection.'$3'.$folder_counter/tokenSlot/'$filename' ]; then'\
      '\n            source /home/'$2'/Fluidity_Client/connection.'$3'.$folder_counter/tokenSlot/'$filename\
      '\n            result=$(echo '$client_hashed_key' |  openssl enc -aes-128-cbc -a -d -salt -pass pass:$seal_2)'\
      '\n            if [ "$seal_1" != "$result" ]; then'\
      '\n               sudo umount /home/'$2'/Fluidity_Client/connection.'$3'.$folder_counter'\
      '\n            fi'\
      '\n         elif [[ ! $(lsof | grep "connection.'$3'.$folder_counter/clientcon.'$3'.$folder_counter.pem") ]]; then'\
      '\n            sudo umount /home/'$2'/Fluidity_Client/connection.'$3'.$folder_counter'\
      '\n         fi'\
      '\n         let folder_counter=$(expr $folder_counter + 1)'\
      '\n      done'\
      '\n   sleep $(shuf -i 0-60 -n1)'\
      '\ndone' \
         > ~/Fluidity_Server/Generated_Scripts/FLdaemon_SeekAndEncrypt.sh
      chmod 700 ~/Fluidity_Server/Generated_Scripts/FLdaemon_SeekAndEncrypt.sh
      
   # FLdaemon_SeekAndEncrypt.sh detected. Delete the previous version 
   # and build a new one, containing client's updated specific information.
   else
   
      rm ~/Fluidity_Server/Generated_Scripts/FLdaemon_SeekAndEncrypt.sh
   
      # Daemon script explained in detail above.
      sudo echo -e \
        '#!/bin/bash'\
      '\nwhile true; do'\
      '\n   folder_counter=1'\
      '\n      while [[ -e /home/'$2'/Fluidity_Client/connection.'$3'.$folder_counter ]]; do'\
      '\n         if [[ ! $(lsof | grep "connection.'$3'.$folder_counter/clientcon.'$3'.$folder_counter.pem") ]] && \\\n'\
      '         [ -f /home/'$2'/Fluidity_Client/connection.'$3'.$folder_counter/tokenSlot/'$filename' ]; then'\
      '\n            source /home/'$2'/Fluidity_Client/connection.'$3'.$folder_counter/tokenSlot/'$filename\
      '\n            result=$(echo '$client_hashed_key' |  openssl enc -aes-128-cbc -a -d -salt -pass pass:$seal_2)'\
      '\n            if [ "$seal_1" != "$result" ]; then'\
      '\n               sudo umount /home/'$2'/Fluidity_Client/connection.'$3'.$folder_counter'\
      '\n            fi'\
      '\n         elif [[ ! $(lsof | grep "connection.'$3'.$folder_counter/clientcon.'$3'.$folder_counter.pem") ]]; then'\
      '\n            sudo umount /home/'$2'/Fluidity_Client/connection.'$3'.$folder_counter'\
      '\n         fi'\
      '\n         let folder_counter=$(expr $folder_counter + 1)'\
      '\n      done'\
      '\n   sleep $(shuf -i 0-60 -n1)'\
      '\ndone' \
         > ~/Fluidity_Server/Generated_Scripts/FLdaemon_SeekAndEncrypt.sh
      chmod 700 ~/Fluidity_Server/Generated_Scripts/FLdaemon_SeekAndEncrypt.sh
      
   fi

   # Generate FLdaemon_SeekAndEncrypt.service and store it in
   # ~/Fluidity_Server/Generated_Scripts
   if [[ ! -e ~/Fluidity_Server/Generated_Scripts/FLdaemon_SeekAndEncrypt.service ]]; then
      
      # This is the Daemon's Unit File
      sudo echo -e \
         '[Unit]'\
       '\nDescription=Fluidity automatic folder encryption daemon for client '$3\
       '\n'\
       '\n[Service]'\
       '\nExecStart=/usr/bin/FLdaemon_SeekAndEncrypt.sh'\
       '\nRestart=on-failure'\
       '\n'\
       '\n[Install]'\
       '\nWantedBy=multi-user.target' \
         > ~/Fluidity_Server/Generated_Scripts/FLdaemon_SeekAndEncrypt.service
      chmod 700 ~/Fluidity_Server/Generated_Scripts/FLdaemon_SeekAndEncrypt.service
   
  # FLdaemon_SeekAndEncrypt.service detected. Delete the previous version 
   # and build a new one, containing client's updated specific information.
   else
   
      # This is the Daemon's Unit File
      sudo echo -e \
         '[Unit]'\
       '\nDescription=Fluidity automatic folder encryption daemon for client '$3\
       '\n'\
       '\n[Service]'\
       '\nExecStart=/usr/bin/FLdaemon_SeekAndEncrypt.sh'\
       '\nRestart=on-failure'\
       '\n'\
       '\n[Install]'\
       '\nWantedBy=multi-user.target' \
         > ~/Fluidity_Server/Generated_Scripts/FLdaemon_SeekAndEncrypt.service
      chmod 700 ~/Fluidity_Server/Generated_Scripts/FLdaemon_SeekAndEncrypt.service
      
   fi

   # Securely copy FLdaemon_SeekAndEncrypt.sh and 
   # FLdaemon_SeekAndEncrypt.service to client machine.
   scp ~/Fluidity_Server/Generated_Scripts/FLdaemon_SeekAndEncrypt.sh \
    ~/Fluidity_Server/Generated_Scripts/FLdaemon_SeekAndEncrypt.service \
    $2@$1:Fluidity_Client
 
   # Generate genSCRIPT_moveFilesAndActivateDaemon.sh and store it in
   # ~/Fluidity_Server/Generated_Scripts
   if [[ ! -e ~/Fluidity_Server/Generated_Scripts/genSCRIPT_moveFilesAndActivateDaemon.sh ]]; then
   
      # Bash script.
      # sudo move FLdaemon_SeekAndEncrypt.sh to /usr/bin 
      # sudo move FLdaemon_SeekAndEncrypt.service to etc/systemd/system
      # sudo start the FLdaemon_SeekAndEncrypt.service.
      sudo echo -e \
         '\nsudo mv ~/Fluidity_Client/FLdaemon_SeekAndEncrypt.sh \\\n'\
      '/usr/bin'\
         '\nsudo mv ~/Fluidity_Client/FLdaemon_SeekAndEncrypt.service \\\n'\
      '/etc/systemd/system'\
         '\nsudo systemctl enable FLdaemon_SeekAndEncrypt.service' \
      '\nsudo systemctl start FLdaemon_SeekAndEncrypt.service' \
         > ~/Fluidity_Server/Generated_Scripts/genSCRIPT_moveFilesAndActivateDaemon.sh
      chmod 700 ~/Fluidity_Server/Generated_Scripts/genSCRIPT_moveFilesAndActivateDaemon.sh
      
   fi
   
   # SSH remotely execute genSCRIPT_moveFilesAndActivateDaemon.sh
   ssh $2@$1 'bash -s' < ~/Fluidity_Server/Generated_Scripts/genSCRIPT_moveFilesAndActivateDaemon.sh

}


# 5. Connection Management Functions
# 5.1 Public Functions


# Arguments: ($1), ($2)
# $1: Fluidity Client (SSH) Connection ID.
# $2: Fluidity Virtual Circuit (SSL) Connection ID. 

# Sourced Variables:
# 1. ~/Fluidity_Server/client.$SSH_ID/basic_client_info.txt
   # 1. $server_IP_address
   # 2. $client_IP_address
   # 3. $client_username
   
# Intershell File Variables in use: NONE

# Global Variables in use: NONE

# Generates: Nothing

# Invokes Functions:
# 1. installSSLcertificates ($1), ($2), $client_IP_address, ($3), $client_username $server_IP_address
# 2. checkFluidityFilesystemIntegrity, no args

# Calls the script: NONE

# Function Description: Add a Fluidity connection to target client.
   
addFluidityConnection () {
   
   # Source the variables:
      # 1. $server_IP_address
      # 2. $client_IP_address
      # 3. $client_username
   source ~/Fluidity_Server/client.$1/basic_client_info.txt
   
   # Safety check 1: Check whether target connection.[SSH_ID.SSL_ID] 
   # already exists.
   if [ -d ~/Fluidity_Server/client.$1/connection.$1.$2 ]; then
      echo "Fluidity Connection $1.$2 already exists"
      return
   fi
   
   # Safety check 2: Check whether target client.[SSH_ID] responds to 
   # pinging.  
   if ! ping -c 3 $client_IP_address; then
      clear
      echo -e \
      'Destination host '$client_IP_address' is unreachable.' \
      '\nCancelling addFluidityConnection.'
      return
   else
      echo "Connectivity test to host $client_IP_address succeeded. Proceeding with client configuration."
   fi
   
   # Safety check 3: Recall the SSH identity in case of a recent restart.
   if ! ssh-add -l | grep client.$1; then
      recallSSHidentity $1
   fi
   
   # Safety check 4: Perform a Fluidity file integrity check.
   if [[ $(checkFluidityFilesystemIntegrity) == 1 ]]; then
      echo "Fluidity system file integrity test passed"
   else
      checkFluidityFilesystemIntegrity
      return
   fi
   
   # Invoke installSSLcertificates to do a first time SSL certificate
   # installation for connection.[SSH_ID.SSL_ID].
   installSSLcertificates $1.$2 $client_IP_address $client_username $server_IP_address
   
}

# Arguments: ($1), ($2)
# $1: Fluidity Client (SSH) Connection ID.
# $2: Fluidity Virtual Circuit (SSL) Connection ID. 

# Sourced Variables:
# 1. ~/Fluidity_Server/client.$SSH_ID/basic_client_info.txt
   # 1. $server_IP_address
   # 2. $client_IP_address
   # 3. $client_username

# Intershell File Variables in use: NONE

# Global Variables in use: NONE

# Generates: Nothing

# Invokes Functions: NONE

# Calls the script: NONE

# Function Description: Delete a Fluidity connection, for a given 
# Connection ID, on both server and client.

removeFluidityConnection () {

   # Safety Check 1
   # Request connection removal while the connection is still active.
   if [ -f ~/Fluidity_Server/client.$1/connection.$1.$2/link_information.txt ]; then
      echo "connection.$1.$2 is currently ACTIVE. Use stopFluidity $1 $2 to close the connection."
      return
   fi

   # Source the following variables:
      # 1. $server_IP_address
      # 2. $client_IP_address
      # 3. $client_username
   source ~/Fluidity_Server/client.$1/basic_client_info.txt

   # Purge the Connection ID ($1) folder in ~/Fluidity_Server 
   # with the corresponding folders in SSL_Cert_Vault
   rm -r ~/Fluidity_Server/client.$1/connection.$1.$2 \
	~/Fluidity_Server/SSL_Cert_Vault/client_con.$1.$2 \
	~/Fluidity_Server/SSL_Cert_Vault/server_con.$1.$2

   # SSH remotely execute 
	# Unmount from ecryptfs the corresponding client folder.
   ssh $client_username@$client_IP_address sudo umount Fluidity_Client/connection.$1.$2
   
   # SSH remotely execute 
   # Erase the client folder.
   ssh $client_username@$client_IP_address rm -r ~/Fluidity_Client/connection.$1.$2
}

# Arguments: ($1), ($2)
# $1: Fluidity Client (SSH) Connection ID.
# $2: Fluidity Virtual Circuit (SSL) Connection ID.

# Sourced Variables: 
# 1. ~/Fluidity_Server/client.$1/connection.$1.$2/link_information.txt
   # 1. $fluidity_connection_ID
   # 2. $server_serial_int OR $server_tunnel_ip
   # 3. $server_listening_port
   # 4. $client_serial_int OR $client_tunnel_ip
   # 5. $client_ip_add
   # 6. $client_username
   # 7. $link_serial_speed OR $tunneling_network_subnet_mask
   # 8. $server_ip_add
   # 9. $fluidity_flavour_choice
   
# 2. ~/Fluidity_Server/client.$1/basic_client_info.txt
   # 1. $server_IP_address
   # 2. $client_IP_address
   # 3. $client_username

# Intershell File Variables in use: NONE

# Global Variables in use: NONE

# Generates: Nothing
 
# Invokes Functions: 
# 1. copyDoNotEncryptToken, with args:
#	a. ($fluidity_connection_ID), ($client_ip_add), ($client_username)
#	b. ($1), ($2), ($client_IP_address), ($client_username)
# 2. deleteDoNotEncryptToken, with args:
#	a. ($fluidity_connection_ID), ($client_ip_add), ($client_username)
#	b. ($1), ($2) ($client_IP_address), ($client_username)
# 3. recallSSHidentity, with args ($1)
# 4. decryptClient, with args ($1), ($2), ($client_IP_address),
#  ($client_username)
# 5. stopFluidityToRenewSSLcerts, with args ($fluidity_connection_ID)
# 6. establishSOCATlink, with args:
#	a. ($fluidity_connection_ID), ($server_serial_int), 
#	 ($server_listening_port), ($client_serial_int), ($client_ip_add), 
#	 ($client_username), ($link_serial_speed), ($server_ip_add), (-s)
#	b. ($fluidity_connection_ID), ($server_tunnel_ip), 
#	 ($server_listening_port), ($client_tunnel_ip), ($client_ip_add),
# 	 ($client_username), ($tunneling_network_subnet_mask),
#	 ($server_ip_add), (-t)
# 7. reinstallSSLcerts, with args:
#	a. ($fluidity_connection_ID), ($client_ip_add), 
#	 ($client_username), ($server_ip_add)
#	b. ($1), ($2), ($client_IP_address), ($client_username),
#	 ($server_IP_address)

# Calls the script: NONE

# Function Description: Substitute the existing SSL certificates.
# This function renews the SSL certificates, for a target Fluidity
# connection.[SSH_ID.SSL_ID] and deals with three main scenarios:
# 1st scenario: Renew the SSL certificates on an active link.
# 2nd scenario: Renew the SSL certificates on an inactive link.
# 3rd scenatio: Wrong input.

renewSSLcerts () {
   
   # Case 1: Act upon an active link.

   # link_information.txt exists.
   if [ -f ~/Fluidity_Server/client.$1/connection.$1.$2/link_information.txt ]; then
   
      # Information message: Give feedback back to user.
      echo "Connection.$1.$2 link state information file detected. "
   
      # Source the variables:
   
      # Case 1: $fluidity_flavour_choice equals to -s (i.e. serial link)
      
         # 1. $fluidity_connection_ID
         # 2. $server_serial_int
         # 3. $server_listening_port
         # 4. $client_serial_int
         # 5. $client_ip_add
         # 6. $client_username
         # 7. $link_serial_speed
         # 8. $server_ip_add
         # 9. $fluidity_flavour_choice
         
      # Case 2: $fluidity_flavour_choice equals to -t (i.e. tunnel link)
      
         # 1. $fluidity_connection_ID
         # 2. $server_tunnel_ip
         # 3. $server_listening_port
         # 4. $client_tunnel_ip
         # 5. $client_ip_add
         # 6. $client_username
         # 7. $tunneling_network_subnet_mask
         # 8. $server_ip_add
         # 9. $fluidity_flavour_choice
      source ~/Fluidity_Server/client.$1/connection.$1.$2/link_information.txt
      
      # Use netstat with grep to extract active link's connection 
      # status. Then, use $netstat_connection_status_string
      # to store the outcome.
      local netstat_connection_status_string=$(netstat -atnp 2>/dev/null | grep $server_listening_port)
   
      # Use the result from $netstat_connection_status_string, combined 
      # with cut (whitespace delimeter - sixth element), to isolate the 
      # connection state information from the targeted connection.
      local netstat_connection_status=$(echo $netstat_connection_status_string| cut -d' ' -f 6)
      
      # Good scenario: Netstat reports that connection.[SSH_ID.SSL_ID]
      # is "ESTABLISHED" AND Fluidity is in "ACTIVE" state.
      if [ $netstat_connection_status == "ESTABLISHED" ] && \
      [ $(getFluidityConnectionStatus $fluidity_connection_ID) == "ACTIVE" ]; then
         # Information message: Report to user that Fluidity will be 
         # paused and resumed in order to perform SSL substitution.
         echo "Fluidity connection.$1.$2 is in ACTIVE state. Fluidity will be paused and resumed."
      # Not so good scenario: Client is lost. Fluidity is in "PINGING" 
      # state.
      elif [ $(getFluidityConnectionStatus $fluidity_connection_ID) == "PINGING" ]; then
         # Information message: Report to user that SSL substitution
         # will not be performed, due to a lost client.
         echo "Fluidity connection.$1.$2 is in PINGING state. Canceling the SSL certificate renewal process."
         return
      # An exceptional scenario: Fluidity connection is DOWN,
      # but there is a link_information.txt file. 
      elif [ -f ~/Fluidity_Server/client.$1/connection.$1.$2/link_information.txt ]; then
         echo "Fluidity connection.$1.$2 is DOWN, but we found a link_information file."
         return
      # Bad scenario: Display what netstat reports in order to proceed 
      # with debugging.
      else 
         echo "Something went wrong. Netstat reports that Fluidity connection.$1.$2 is $netstat_connection_status"
         return
      fi
   
      # invoke copyDoNotEncryptToken
      # Block FLdaemon_SeekAndEncrypt.service from encrypting the
      # connection.[SSL_ID.SSH.ID] folder.
      copyDoNotEncryptToken $fluidity_connection_ID $client_ip_add $client_username
   
      # invoke stopFluidityToRenewSSLcerts
      # Perform a special stopFluidity that paves the way to SSL 
      # substitution.
      stopFluidityToRenewSSLcerts $fluidity_connection_ID
      
      # Information message to user.
      echo "SSL certificates renewal under way."
   
      # invoke reinstallSSLcerts
      # Reinstall the SSL certificates for target connection.
      reinstallSSLcerts $fluidity_connection_ID $client_ip_add $client_username $server_ip_add
   
      # Certificate reinstallation is done. 
      # Re-establish the SOCAT link. Based on link_information.txt
      # start the proper Fluidity flavour choice.
      
      # For a Serial link
      if [[ "$fluidity_flavour_choice" == -s ]]; then
   
         # invoke establishSOCATlink
         establishSOCATlink $fluidity_connection_ID $server_serial_int \
         $server_listening_port $client_serial_int $client_ip_add $client_username \
         $link_serial_speed $server_ip_add -s
   
      # For an Ethernet Tunnnel link
      elif [[ "$fluidity_flavour_choice" == -t ]]; then
   
         # invoke establishSOCATlink
         establishSOCATlink $fluidity_connection_ID $server_tunnel_ip \
         $server_listening_port $client_tunnel_ip $client_ip_add $client_username \
         $tunneling_network_subnet_mask $server_ip_add -t
      
      fi
   
      # invoke deleteDoNotEncryptToken
      # Unblock FLdaemon_SeekAndEncrypt.service
      deleteDoNotEncryptToken $fluidity_connection_ID $client_ip_add $client_username
   
      # Information message to user.
      echo "Client - Server SSL certificates for connection $1.$2 renewed successfully."
      
   # Case 2: Act upon an inactive INACTIVE link.
   # link_information.txt is missing.
   
   # Check that basic_client_info.txt and connection.[SSH_ID.SSL_ID]
   # exists.
   elif [ -f ~/Fluidity_Server/client.$1/basic_client_info.txt ] && \
   [ -d ~/Fluidity_Server/client.$1/connection.$1.$2 ]; then
   
      # Source the variables:
         # 1. $server_IP_address
         # 2. $client_IP_address
         # 3. $client_username
      source ~/Fluidity_Server/client.$1/basic_client_info.txt
      
      # Safety check 1: Check whether target client.[SSH_ID] responds to 
      # pinging. 
      if ! ping -c 3 $client_IP_address; then
         echo "Fluidity client $1 in IP $client_IP_address is unreachable. Canceling the renewal process."
         return
      fi
      
      # Safety check 2: Recall the SSH ID in case it isn't loaded.
      if ! ssh-add -l | grep client.$1; then
      
         #invoke recallSSHidentity
         recallSSHidentity $1
         
      fi
   
      # Information message to user.
      echo "Fluidity connection.$1.$2 is currently INACTIVE, but exists."
      echo "SSL Substitution will proceed for INACTIVE link $1.$2."
      
      # Safety check 3: Check whether target connection folder is encrypted.
      
      # Case 1: Client folder found encrypted.
      if [ -z "$(isItEncryptedOnClient $1.$2 $client_IP_address $client_username)" ] ; then
      
         # Information message to user.
         echo "connection.$1.$2 folder on client machine is encrypted. Executing ecryptFS."
         
         # invoke decryptClient
         # Decrypt the client folder.
         decryptClient $1.$2 $client_IP_address $client_username
         
         # Information message to user.
         echo "Client decrypted. Transmitting the do_not_encrypt token."
        
         # invoke copyDoNotEncryptToken
         # Transmit the immunity encryption token to client.
         copyDoNotEncryptToken $1.$2 $client_IP_address $client_username
      
      # Case 2: Client folder found decrypted.
      else
         
         # Information message to user.
         echo "connection.$1.$2 folder on client machine is decrypted. Transmitting the do_not_encrypt token"
         
         # invoke copyDoNotEncryptToken
         # Transmit the immunity encryption token to client.
         copyDoNotEncryptToken $1.$2 $client_IP_address $client_username
         
      fi
      
      # invoke reinstallSSLcerts
      # Reinstall the SSL certificates for target connection 
      # connection.[SSH_ID.SSL_ID]
      reinstallSSLcerts $1.$2 $client_IP_address $client_username $server_IP_address
      
      # invoke deleteDoNotEncryptToken
      # Remove the encryption immunity token from target client.
      deleteDoNotEncryptToken $1.$2 $client_IP_address $client_username
   
      # Information message to user.
      echo "Client - Server SSL certificates for connection $1.$2 renewed successfully."
   
   # 3rd scenario: Invalid connection SSH and SSL id.
   else
      
      # Information message to user.
      echo "Fluidity connection.$1.$2 does not exist."
      
   fi
   
}


# 5.2 Private Functions


# Arguments: ($1), ($2), ($3), ($4)
# $1: Fluidity Connection ID [SSH_ID.SSL_ID] 
# $2: Client IP address.
# $3: Client Username.
# $4: Server IP address.

# Sourced Variables: NONE

# Intershell File Variables in use: NONE

# Global Variables in use:
# 1. encr_password[]
# 2. s_password[]
# 3. c_password[]

# Generates:
# 1. Text (TXT) File: encr_password.$1.txt
# 2. Text (TXT) File: s_password.$1.txt 
# 3. Text (TXT) File: c_password.$1.txt
# 4. Server Private key (KEY) File: servercon.$1.key
# 5. Server Public key (CRT) File: servercon.$1.crt
# 6. Server Container file (PEM): servercon.$1.pem

# Invokes Functions:
# 1. checkLocalEntropy, no args
# 2. checkRemoteEntropy, with args ($2), ($3)
# 4. clientFolderCreation, with args ($1), ${encr_password[$array_index]}
# 5. clientSSLinstallation, with args ($1), ${c_password[$array_index]},
#  $server_IP_no_whitespace, $server_username, ($2), ($3)

# Calls the script: NONE

# Function Description: Create and install the SSL certificates on both
# server and client. 
installSSLcertificates () {

   # Variable declarations

   # Delete whitespace characters (i.e. ' ') from function argument 
   # $4 (Server IP address). Save the outcome to variable: 
   # $server_IP_no_whitespace.
   local server_IP_no_whitespace="$(echo -e $4 | sed -e 's/[[:space:]]*$//')"
   
   # Extract server's username from environment variable: $USER.
   local server_username="$USER"

   # Derive the array index from Fluidity ID
   local array_index=$(expr ${1#*.} - 1)
   
   # Derive the SSH ID from Fluidity ID
   local SSH_ID=${1%.*}
   
   # Use the ~/Fluidity_Server folder to temporary store the SSL 
   # certificates, perform the subsequent file operations and, then, 
   # move everything to the corresponding Fluidity connection data and
   # Vault folders.
   cd ~/Fluidity_Server

   # Safety check 1: Perform a client - server entropy check.
   # Important Note: Entropy should exceed 1000.
   if [[ $(checkLocalEntropy) == 1 && $(checkRemoteEntropy $2 $3) == 1 ]]; then
      # Information message to user.
      echo "Entropy test passed. Proceeding with installSSLcertificates."
      else
         echo "Entropy test failed. installSSLcertificates will not be executed."
            # Feedback to user in case of entropy failure.
            if [[ $(checkLocalEntropy) == 0 && $(checkRemoteEntropy $2 $3) == 0 ]]; then
               # Information message to user: Local and Remote entropy less than 1000.
               echo "Entropy is below minimum requirement ( less than 1000) at both ends."
            elif [[ $(checkLocalEntropy) == 0 ]]; then
               # Information message to user: Local entropy less than 1000.
               echo "Server entropy is below minimum certificate generation requirements ( less than 1000)"
            elif [[ $(checkRemoteEntropy $2 $3) == 0 ]]; then
               # Information message to user: Remote entropy less than 1000.
               echo "Client entropy is below minimum certificate generation requirements (less than 1000)"
            fi
      # Information message to user
      echo "installSSLcertificates will not be executed."
      return
   fi

   # SECTION 1 - Folder creation

   # Encrypted folder password for Connection 1
   encr_password[$array_index]=$(openssl rand -base64 8 | tr -dc A-Za-z0-9)
   echo ${encr_password[$array_index]} > encr_password.$1.txt
   cat encr_password.$1.txt

   # Invoke clientFolderCreation
   # Create the encrypted Fluidity_Client folder over SSH on 
   # client's side 
   clientFolderCreation $1 ${encr_password[$array_index]} $2 $3

   # Create the folder structure on server's side

   # connection[SSH_ID.SSL_ID]: The Fluidity connection folder that will
   # contain the entirety of the relevant connection files for
   # the specific SOCAT SSL link. 
   mkdir ~/Fluidity_Server/client.$SSH_ID/connection.$1 

   # Folders, that will host the backup copies of the generated SSL credentials.
   mkdir SSL_Cert_Vault/client_con.$1 \
   SSL_Cert_Vault/server_con.$1

   # SECTION 2: Generate passwords for the SSL certificates by using the 
   # openssl rand function and store the outcome to variables:
   # 1. s_password[$array_index] (Server SSL Password)
   # 2. c_password[$array_index] (Client SSL Password)
   # and subsequently save those passwords to text files:
   # 1. s_password[$array_index].txt (Server SSL Password)
   # 2. c_password[$array_index].txt (Client SSL Password)

   # Server password for connection [(X) i.e. Client ID.SSL Virtual Circuit ID]
   s_password[$array_index]=$(openssl rand -base64 8)
   echo ${s_password[$array_index]} > s_password.$1.txt
   cat s_password.$1.txt

   # Client password for connection [(X) i.e.Client ID.SSL Virtual Circuit ID]
   c_password[$array_index]=$(openssl rand -base64 8)
   echo ${c_password[$array_index]} > c_password.$1.txt
   cat c_password.$1.txt

   # SECTION3: SSL certificate password obfuscation
   
   # Change the actual SSL certificate password to a bogus password, 
   # to hide it from the arguments list, in case a process viewer (htop)
   # is executed on client machine.
   
   # Generate the client bogus password for 
   # connection [(X) i.e.Client ID.SSL Virtual Circuit ID]
   c_bogus_password[$array_index]=$(openssl rand -base64 8)
   echo ${c_bogus_password[$array_index]} > c_bogus_password.$1.txt
   cat c_bogus_password.$1.txt
   
   # Pipe c_password[$array_index] into openssl enc function and use 
   # c_bogus_password[$array_index] to generate the hash to be embedded 
   # into the dynamically Fluidity connection client genSCRIPT.
   # ~/Fluidity_Server/client.[SSH_ID]/connection.[SSH_ID.SSL_ID]/
   # genSCRIPT_client.[SSH_ID.SSL_ID].sh
   echo ${c_password[$array_index]} | \
   openssl enc -aes-128-cbc -a -salt -pass \
   pass:${c_bogus_password[$array_index]} > hashed_clientpass_con.$1.txt

   # SECTION4: Self-signed client - server certificate creation.

   # Generate the self signed server certificate

   # Generate a private key
   openssl genpkey -algorithm RSA -out servercon.$1.key \
      -aes-256-cbc -pass pass:${s_password[$array_index]}
      
   # Generate a self signed cert
expect << EOF
	   spawn openssl req \
	-new -key servercon.$1.key -x509 -days 3653 \
	-subj "/C=GR/ST=Serres/L=Serres/O=OTE Group/OU=Infrastructure Team/CN=$server_IP_no_whitespace" \
	-out servercon.$1.crt
	   expect ".key:"
	   send "${s_password[$array_index]}\n"
	   expect eof
EOF
      
   # Create the container (*.pem) file by joining the private key with the self signed public
   # certificate
   cat servercon.$1.key servercon.$1.crt > servercon.$1.pem

   # Change permissions - chmod 600 file - owner can read and write
   chmod 600 servercon.$1.key servercon.$1.pem

   # Delete the unnecessary *.key files
   rm *.key

   # Generate the SSL certificates at client's side.
   clientSSLinstallation $1 ${c_password[$array_index]} $2 $3

   # SECTION 5: Populate the folders with their corresponding files

   # Copy the private (*.pem) - public (*.crt) keys and passwords 
   # to Connection(X) folders
   cp servercon.$1.pem clientcon.$1.crt s_password.$1.txt \
   c_password.$1.txt hashed_clientpass_con.$1.txt encr_password.$1.txt \
   c_bogus_password.$1.txt ~/Fluidity_Server/client.$SSH_ID/connection.$1

   # SSH copy the corresponding *.crt 
   # file to client machine
   scp servercon.$1.crt \
    $3@$2:Fluidity_Client/connection.$1

   # Move every generated private, public key and plaintext password 
   # document to the SSL_Cert_Vault for future reference and permanent
   # storing
   mv servercon.$1.pem clientcon.$1.crt s_password.$1.txt \
    SSL_Cert_Vault/server_con.$1
   mv clientcon.$1.pem servercon.$1.crt c_password.$1.txt encr_password.$1.txt \
    c_bogus_password.$1.txt hashed_clientpass_con.$1.txt SSL_Cert_Vault/client_con.$1
    
}

# Arguments: ($1), ($2), ($3), ($4)
# $1: Fluidity Connection ID [SSH_ID.SSL_ID] 
# $2: Client IP address.
# $3: Client Username.
# $4: Server IP address.

# Sourced Variables: NONE

# Intershell File Variables in use: NONE

# Global Variables in use:
# 1. s_password[]
# 2. c_password[]

# Generates:
# 1. Text (TXT) File: encr_password.$1.txt
# 2. Text (TXT) File: s_password.$1.txt 
# 3. Text (TXT) File: c_password.$1.txt
# 4. Server Private key (KEY) File: servercon.$1.key
# 5. Server Public key (CRT) File: servercon.$1.crt
# 6. Server Container file (PEM): servercon.$1.pem

# Invokes Functions:
# 1. checkLocalEntropy, no args
# 2. checkRemoteEntropy, with args ($2), ($4)
# 3. deleteSSLpair, with args ($1)
# 4. clientSSLinstallation, with args ($1), ${c_password[$array_index]},
#  ($2), ($3)

# Calls the script: NONE

# Function Description: Create and reinstall the SSL certificates on both
# server and client. 
reinstallSSLcerts () {

   # Variable declarations

   # Delete whitespace characters (i.e. ' ') from function argument 
   # $5 (Server IP address). Save the outcome to variable: 
   # $server_IP_no_whitespace.
   local server_IP_no_whitespace="$(echo -e $4 | sed -e 's/[[:space:]]*$//')"
   
   # Extract server's username from environment variable: $USER.
   local server_username="$USER"

   # Derive the array index from Fluidity ID
   local array_index=$(expr ${1#*.} - 1)
   
   # Derive the SSH ID from Fluidity ID
   local SSH_ID=${1%.*}
   
   # Use the ~/Fluidity_Server folder to temporary store the SSL 
   # certificates, perform the subsequent file operations and, then, 
   # move everything to the corresponding Fluidity connection data and
   # Vault folders.
   cd ~/Fluidity_Server

   # Safety check 1: Perform a client - server entropy check.
   # Important Note: Entropy should exceed 1000.
   if [[ $(checkLocalEntropy) == 1 && $(checkRemoteEntropy $2 $3) == 1 ]]; then
      # Information message to user.
      echo "Entropy test passed. Proceeding with reinstallSSLcertificates."
      else
         echo "Entropy test failed. SSLcertificateInstallation will not be executed."
            # Feedback to user in case of entropy failure.
            if [[ $(checkLocalEntropy) == 0 && $(checkRemoteEntropy $2 $4) == 0 ]]; then
               # Information message to user: Local and Remote entropy less than 1000.
               echo "Entropy is below minimum requirement ( less than 1000) at both ends."
            elif [[ $(checkLocalEntropy) == 0 ]]; then
               # Information message to user: Local entropy less than 1000.
               echo "Server entropy is below minimum certificate generation requirements ( less than 1000)"
            elif [[ $(checkRemoteEntropy $2 $3) == 0 ]]; then
               # Information message to user: Remote entropy less than 1000.
               echo "Client entropy is below minimum certificate generation requirements (less than 1000)"
            fi
      # Information message to user
      echo "reinstallSSLcertificates will not be executed."
      return
   fi

   # Invoke deleteSSLpair
   # Delete the existing SSL pair.
   deleteSSLpair $1

   # SECTION 1: Generate passwords for the SSL certificates by using the 
   # openssl rand function and store the outcome to variables:
   # 1. s_password[$array_index] (Server SSL Password)
   # 2. c_password[$array_index] (Client SSL Password)
   # and subsequently save those passwords to text files:
   # 1. s_password[$array_index].txt (Server SSL Password)
   # 2. c_password[$array_index].txt (Client SSL Password)

   # Server password for connection [(X) i.e.Client ID.SSL Virtual Circuit ID]
   s_password[$array_index]=$(openssl rand -base64 8)
   echo ${s_password[$array_index]} > s_password.$1.txt
   cat s_password.$1.txt

   # Client password for connection [(X) i.e.Client ID.SSL Virtual Circuit ID]
   c_password[$array_index]=$(openssl rand -base64 8)
   echo ${c_password[$array_index]} > c_password.$1.txt
   cat c_password.$1.txt

   # SECTION2: Do the SSL certificate password obfuscation
   
   # Change the actual SSL certificate password to a bogus password, 
   # to hide it from the arguments list, in case a process viewer (htop)
   # is executed on client machine.
   
   # Generate the client bogus password for 
   # connection [(X) i.e.Client ID.SSL Virtual Circuit ID]
   c_bogus_password[$array_index]=$(openssl rand -base64 8)
   echo ${c_bogus_password[$array_index]} > c_bogus_password.$1.txt
   cat c_bogus_password.$1.txt

   # Pipe c_password[$array_index] into openssl enc function and use 
   # c_bogus_password[$array_index] to generate the hash to be embedded 
   # into the dynamically Fluidity connection client genSCRIPT.
   # ~/Fluidity_Server/client.[SSH_ID]/connection.[SSH_ID.SSL_ID]/
   # genSCRIPT_client.[SSH_ID.SSL_ID].sh
   echo ${c_password[$array_index]} | \
   openssl enc -aes-128-cbc -a -salt -pass \
   pass:${c_bogus_password[$array_index]} > hashed_clientpass_con.$1.txt

   # SECTION 3: Self-signed client - server certificate creation

   # Generate the self signed server certificate

   # Generate a private key
   openssl genpkey -algorithm RSA -out servercon.$1.key \
      -aes-256-cbc -pass pass:${s_password[$array_index]}
      
   # Generate a self signed cert
expect << EOF
	   spawn openssl req \
	-new -key servercon.$1.key -x509 -days 3653 \
	-subj "/C=GR/ST=Serres/L=Serres/O=OTE Group/OU=Infrastructure Team/CN=$server_IP_no_whitespace" \
	-out servercon.$1.crt
	   expect ".key:"
	   send "${s_password[$array_index]}\n"
	   expect eof
EOF
      
   # Create the container (*.pem) file by joining the private key with the self signed public
   # certificate
   cat servercon.$1.key servercon.$1.crt > servercon.$1.pem

   # Change permissions - chmod 600 file - owner can read and write
   chmod 600 servercon.$1.key servercon.$1.pem

   # Delete the unnecessary *.key files
   rm *.key

   # Invoke clientSSLinstallation
   # Generate the SSL certificates at client's side.
   clientSSLinstallation $1 ${c_password[$array_index]} $2 $3

   # SECTION 4: Populate the folders with their corresponding files

   # Copy the private (*.pem) - public (*.crt) keys and passwords 
   # to Connection(X) folders
   cp servercon.$1.pem clientcon.$1.crt s_password.$1.txt \
   c_password.$1.txt hashed_clientpass_con.$1.txt \
   c_bogus_password.$1.txt ~/Fluidity_Server/client.$SSH_ID/connection.$1

   # SSH copy the corresponding *.crt 
   # file to client machine
   scp servercon.$1.crt \
    $3@$2:Fluidity_Client/connection.$1

   # Move every generated private, public key and plaintext password 
   # document to the SSL_Cert_Vault for future reference and permanent
   # storing
   mv servercon.$1.pem clientcon.$1.crt s_password.$1.txt \
    SSL_Cert_Vault/server_con.$1
   mv clientcon.$1.pem servercon.$1.crt c_password.$1.txt \
    c_bogus_password.$1.txt hashed_clientpass_con.$1.txt SSL_Cert_Vault/client_con.$1
    
}

# Arguments: ($1), ($2), ($3), ($4)
# $1: Fluidity Connection ID [SSH_ID.SSL_ID]
# $2: The folder encryption password
# $3: Client IP.
# $4: Client Username.

# Sourced Variables: NONE

# Intershell File Variables in use: NONE

# Global Variables in use: NONE

# Generates: 
# 1. Bash script (.sh): genSCRIPT_clientFolderCreation.sh $1 $2

# Calls the script: 
# 1. genSCRIPT_clientFolderCreation.sh, with args ($1), ($2)
# in ~/Fluidity_Server/Generated_Scripts

# Function Description:  
# 1. Create a client connection.[SSH_ID.SSL_ID] folder within ~/Fluidity_Client
# that will contain the necessary files for establishing an SSL connection.
# 2. Encrypt connection.[SSH_ID.SSL_ID] folder by using eCryptFS.
# 3. Create a folder named "tokenSlot", within connection.[SSH_ID.SSL_ID],
# that will act as a placeholder for the encryption prevention token.

clientFolderCreation () {

   if [[ ! -e ~/Fluidity_Server/Generated_Scripts/genSCRIPT_clientFolderCreation.sh ]]; then
   
      echo -e \
'\nmkdir -p ~/Fluidity_Client/connection.$1'\
'\n'\
'\nexpect << EOF\n'\
'   spawn sudo mount -t ecryptfs \\\n'\
'-o key=passphrase:passphrase_passwd=$2,\\\n'\
'ecryptfs_cipher=aes,\\\n'\
'ecryptfs_key_bytes=32,\\\n'\
'ecryptfs_enable_filename=y,\\\n'\
'ecryptfs_passthrough=n,\\\n'\
'ecryptfs_enable_filename_crypto=y\\\n'\
' ./Fluidity_Client/connection.$1 ./Fluidity_Client/connection.$1\n'\
'   expect {\]: }\n'\
'   send "\\n"\n'\
'   expect "(yes/no)? :"\n'\
'   send "yes\\n"\n'\
'   expect "(yes/no)? :"\n'\
'   send "yes\\n"\n'\
'   expect eof'\
'\nEOF'\
'\n'\
'\nmkdir -p ~/Fluidity_Client/connection.$1/tokenSlot' > \
      ~/Fluidity_Server/Generated_Scripts/genSCRIPT_clientFolderCreation.sh
      chmod 700 ~/Fluidity_Server/Generated_Scripts/genSCRIPT_clientFolderCreation.sh
   
   fi
   
   # SSH remotely execute genSCRIPT_clientFolderCreation.sh
   ssh $4@$3 'bash -s' < ~/Fluidity_Server/Generated_Scripts/genSCRIPT_clientFolderCreation.sh \
	$1 $2
  
}

# Arguments: ($1), ($2), ($3), ($4)
# $1: Fluidity Connection ID [SSH_ID.SSL_ID]
# $2: Client certificate password.
# $3: Client IP address.
# $4: Client Username.

# Sourced Variables: NONE

# Intershell File Variables in use: NONE
 
# Global Variables in use: NONE

# Generates:
# 1. Bash script (.sh): genSCRIPT_clientSSLinstallation.sh $1 $2 $3
# 2. Client Private key (KEY) File: clientcon.$1.key
# 3. Client Public key (CRT) File: clientcon.$1.crt
# 4. Client Container file (PEM): clientcon.$1.pem

# Invokes Functions: NONE

# Calls the script:
# 1. genSCRIPT_clientSSLinstallation.sh, with args ($1), ($2) 
# ($3)
# in ~/Fluidity_Server/Generated_Scripts

# Function Description: 
# Background info:
# SOCAT requires the creation of both the SSL private keys (.key) and 
# and self-signed public certificates (.crt) to happen locally on client
# machine.
# 1. Access the Fluidity connection folder "connection.[SSH_ID.SSL_ID]".
# 2. Execute openssl genpkey and produce the private key (.key).
# 3. Execute openssl req and produce the self-signed certificate (.crt).
# 4. Merge the (.key) and (.crt) files to produce a (.pem) file.
# 5. Change permissions on (.key) and (.pem) files.
# 6. Use sshpass to send the (.crt) and (.pem) files to server.
# 7. Delete the (.key) and (.crt) files and keep only the (.pem) file
# into Fluidity connection folder "connection.[SSH_ID.SSL_ID]".

clientSSLinstallation () {
  
   if [[ ! -e ~/Fluidity_Server/Generated_Scripts/genSCRIPT_clientSSLinstallation.sh ]]; then
   
      echo -e \
'\ncd ~/Fluidity_Client/connection.$1'\
'\n'\
'\nclient_IP_no_whitespace="$(echo -e $3 | sed -e 's/[[:space:]]*$//')"'\
'\n'\
'\nopenssl genpkey -algorithm RSA -out clientcon.$1.key \\\n'\
'-aes-256-cbc -pass pass:$2'\
'\n'\
'\nexpect << EOF\n'\
'   spawn openssl req \\\n'\
'-new -key clientcon.$1.key -x509 -days 3653 \\\n'\
'-subj "/C=GR/ST=Serres/L=Serres/O=OTE Group/OU=Infrastructure Team/CN=$client_IP_no_whitespace" \\\n'\
'-out clientcon.$1.crt\n'\
'   expect ".key:"\n'\
'   send "$2\\n"\n'\
'   expect eof'\
'\nEOF\n'\
'\n'\
'\ncat clientcon.$1.key clientcon.$1.crt > clientcon.$1.pem'\
'\n'\
'\nchmod 600 clientcon.$1.key clientcon.$1.pem'\
'\n'\
'\nrm clientcon.$1.key' > \
      ~/Fluidity_Server/Generated_Scripts/genSCRIPT_clientSSLinstallation.sh
      chmod 700 ~/Fluidity_Server/Generated_Scripts/genSCRIPT_clientSSLinstallation.sh
   
   fi
   
   # SSH remotely execute genSCRIPT_clientSSLinstallation.sh
   ssh $4@$3 'bash -s' < ~/Fluidity_Server/Generated_Scripts/genSCRIPT_clientSSLinstallation.sh \
	$1 $2 $3

   # Fetch the client SSL certificates from the remote machine.
   scp $4@$3:Fluidity_Client/connection.$1/clientcon.$1.crt \
    ~/Fluidity_Server
   scp $4@$3:Fluidity_Client/connection.$1/clientcon.$1.pem \
    ~/Fluidity_Server

}

# Arguments: ($1)
# $1: Fluidity Connection ID [SSH_ID.SSL_ID] 

# Sourced Variables:
# 1. ~/Fluidity_Server/client.$SSH_ID/basic_client_info.txt
   # 1. $server_IP_address
   # 2. $client_IP_address
   # 3. $client_username

# Intershell File Variables in use: NONE

# Global Variables in use: NONE

# Generates:
# 1. Bash script (.sh): genSCRIPT__deleteClientSSLpair.sh

# Invokes Functions: NONE

# Calls the script:
# 1. genSCRIPT__deleteClientSSLpair.sh, with args, ($1)
# in: ~/Fluidity_Server/Generated_Scripts

# Function Description: Delete the generated SSL certificate pair for the
# given connection ID on both server and client.

deleteSSLpair () {
   
   # Derive SSH ID from Fluidity ID
   local SSH_ID=${1%.*}
   
   # Source the following variables:
      # 1. $server_IP_address
      # 2. $client_IP_address
      # 3. $client_username
   source ~/Fluidity_Server/client.$SSH_ID/basic_client_info.txt
   
   # Erase the passwords and credentials related to a generated SSL
   # pair.
   rm ~/Fluidity_Server/client.$SSH_ID/connection.$1/clientcon.$1.crt \
	~/Fluidity_Server/client.$SSH_ID/connection.$1/c_password.$1.txt \
	~/Fluidity_Server/client.$SSH_ID/connection.$1/servercon.$1.pem \
	~/Fluidity_Server/client.$SSH_ID/connection.$1/s_password.$1.txt

   # Delete in Vault folder ~/Fluidity_Server/SSL_Cert_Vault/server_con.$1
   rm ~/Fluidity_Server/SSL_Cert_Vault/server_con.$1/clientcon.$1.crt \
	~/Fluidity_Server/SSL_Cert_Vault/server_con.$1/servercon.$1.pem \
	~/Fluidity_Server/SSL_Cert_Vault/server_con.$1/s_password.$1.txt

   # Delete in Vault folder ~/Fluidity_Server/SSL_Cert_Vault/client_con.$1
   rm ~/Fluidity_Server/SSL_Cert_Vault/client_con.$1/clientcon.$1.pem \
	~/Fluidity_Server/SSL_Cert_Vault/client_con.$1/c_password.$1.txt \
	~/Fluidity_Server/SSL_Cert_Vault/client_con.$1/servercon.$1.crt
   
   if [[ ! -e ~/Fluidity_Server/Generated_Scripts/genSCRIPT__deleteClientSSLpair.sh ]]; then
   
      echo -e \
'\n'\
' rm ~/Fluidity_Client/connection.$1/clientcon.'$1'.pem\n'\
' rm ~/Fluidity_Client/connection.$1/servercon.'$1'.crt\n'\
      > ~/Fluidity_Server/Generated_Scripts/genSCRIPT__deleteClientSSLpair.sh
      
   fi
   
   # SSH remotely execute genSCRIPT__deleteClientSSLpair.sh
   ssh $client_username@$client_IP_address \
    'bash -s' < ~/Fluidity_Server/Generated_Scripts/genSCRIPT__deleteClientSSLpair.sh $1
   
}

# Arguments: ($1)
# $1: Fluidity Connection ID [SSH_ID.SSL_ID] 

# Sourced Variables: NONE

# Intershell File Variables in use: NONE

# Global Variables in use: NONE

# Generates:
# 1. Bash script (.sh): genSCRIPT_purgeDoNotEncryptToken.sh

# Invokes Functions: NONE

# Calls the script:
# 1. genSCRIPT_purgeDoNotEncryptToken.sh, with args, ($1)
# in: ~/Fluidity_Server/Generated_Scripts

# Function Description:
# 1. Generate genSCRIPT_purgeDoNotEncryptToken.sh
# 2. Delete any possible remaining encryption immunity tokens from 
# target client machine.
# 3. Securely copy the encryption immunity token to client machine.
copyDoNotEncryptToken() {
   
   # Derive the SSH ID from Fluidity ID
   local SSH_ID=${1%.*}
   
   # Generate genSCRIPT_purgeDoNotEncryptToken.sh and store it in
   # ~/Fluidity_Server/Generated_Scripts
   if [[ ! -e ~/Fluidity_Server/Generated_Scripts/genSCRIPT_purgeDoNotEncryptToken.sh ]]; then
      
      sudo echo -e \
       'rm ~/Fluidity_Client/connection.$1/tokenSlot/*'\
         > ~/Fluidity_Server/Generated_Scripts/genSCRIPT_purgeDoNotEncryptToken.sh
      chmod 700 ~/Fluidity_Server/Generated_Scripts/genSCRIPT_purgeDoNotEncryptToken.sh
      
   fi
   
   # SSH remotely execute genSCRIPT_purgeDoNotEncryptToken.sh
   ssh $3@$2 'bash -s' < ~/Fluidity_Server/Generated_Scripts/genSCRIPT_purgeDoNotEncryptToken.sh $1
   
   # Securely copy do_not_encrypt_token to target Fluidity client in
   # folder ~/Fluidity_Client/connection.[SSH_ID.SSL_ID]/tokenSlot
   scp ~/Fluidity_Server/client.$SSH_ID/do_not_encrypt_token/* \
    $3@$2:Fluidity_Client/connection.$1/tokenSlot
   
}

# Arguments: ($1)
# $1: Fluidity Connection ID [SSH_ID.SSL_ID] 

# Sourced Variables: NONE

# Intershell File Variables in use: NONE

# Global Variables in use: NONE

# Generates:
# 1. Bash script (.sh): genSCRIPT_purgeDoNotEncryptToken.sh

# Invokes Functions: NONE

# Calls the script:
# 1. genSCRIPT_purgeDoNotEncryptToken.sh, with args, ($1)
# in: ~/Fluidity_Server/Generated_Scripts

# Function Description:
# 1. Generate genSCRIPT_purgeDoNotEncryptToken.sh
# 2. Delete the encryption immunity token from target client machine.
deleteDoNotEncryptToken () {
   
   # Derive the SSH ID from Fluidity ID
   local SSH_ID=${1%.*}
   
   # Generate genSCRIPT_purgeDoNotEncryptToken.sh and store it in
   # ~/Fluidity_Server/Generated_Scripts
   if [[ ! -e ~/Fluidity_Server/Generated_Scripts/genSCRIPT_purgeDoNotEncryptToken.sh ]]; then
      
      sudo echo -e \
       'rm ~/Fluidity_Client/connection.$1/tokenSlot/*'\
         > ~/Fluidity_Server/Generated_Scripts/genSCRIPT_purgeDoNotEncryptToken.sh
      chmod 700 ~/Fluidity_Server/Generated_Scripts/genSCRIPT_purgeDoNotEncryptToken.sh
      
   fi
   
   # SSH remotely execute genSCRIPT_purgeDoNotEncryptToken.sh
   ssh $3@$2 'bash -s' < ~/Fluidity_Server/Generated_Scripts/genSCRIPT_purgeDoNotEncryptToken.sh $1
   
}

# 6. Fluidity Engine Functions
# 6.1 Public Functions


# Arguments:
# $1: Your Fluidity flavour choice [Can be: "-s" serial or "-t" tunnel]
# $2: Fluidity Client (SSH) Connection ID.
# $3: Fluidity Virtual Circuit (SSL) Connection ID.
# $4: Server Listening Port
# $5: CASE A: [For $1="-s"] The Server Serial Interface
#     CASE B: [For $1="-t"] Server's tunnel interface IP
# $6: CASE A: [For $1="-s"] Client's Serial Interface
#     CASE B: [For $1="-t"] Client's tunnel interface IP
# $7: CASE A: [For $1="-s"] Serial Speed
#     CASE B: [For $1="-t"] Tunneling Network Subnet Mask

# Sourced Variables:
# 1. ~/Fluidity_Server/client.$SSH_ID/basic_client_info.txt
   # 1. $server_IP_address
   # 2. $client_IP_address
   # 3. $client_hostname

# Intershell File Variables in use: NONE

# Global Variables in use: NONE

# Generates: Nothing
 
# Invokes Functions:
# 1. openPort, with args ($4)
# 2. establishSOCATlink, with args ($2), ($3), ($5), ($4), ($6), 
#   ($client_IP_address), ($client_username), ($7), ($server_IP_address), ($1)

# Calls the script: NONE

# Function Description: Initiate a fluidity connection

runFluidity () {
   
   # Import the following set of variables:
      # 1. $server_IP_address
      # 2. $client_IP_address
      # 3. $client_username
   source ~/Fluidity_Server/client.$2/basic_client_info.txt
   
   # Use netstat and pipe the output to grep. According to
   # $server_listening_port grep the line referring to that specific 
   # port and save it to $netstat_connection_status_string.
   local netstat_connection_status_string=$(netstat -atnp 2>/dev/null | grep $4)
   
   # Use cut to compartmentalize the line. Fetch the sixth element. Use
   # the whitespace ' ' delimeter character. Save the result
   # to $netstat_connection_status.
   local netstat_connection_status=$(echo $netstat_connection_status_string| cut -d' ' -f 6)
   
   # Safety check 1: Check whether targer connection exists.
   if [ ! -d ~/Fluidity_Server/client.$2/connection.$2.$3 ]; then
      # Information message to user.
      echo "No such link exists"
      return
   fi
   
   # Safety check 2: Check whether target Fluidity connection is
   # ACTIVE. If not, then take the precautionary step to delete any
   # state information file, caused from an adnormal shutdown.
   if [[ "$netstat_connection_status" == ESTABLISHED ]]\
    && [ -f ~/Fluidity_Server/client.$2/connection.$2.$3/link_information.txt ]; then
      if [[ "$1" == -s ]] && lsof | grep -e $5; then
         # Information message to user.
         echo "Serial Fluidity connection $2.$3 is ACTIVE."
         return
      elif [[ "$1" == -t ]] && ifconfig | grep $5; then
         # Information message to user.
         echo "IP tunnel Fluidity connection $2.$3 is ACTIVE."
         return
      fi
   
   # Precautionary action 1: Fluidity abnormally shut down while a SSL
   # substitution was in progress. Delete the previous state information
   # and perform a SSL substitution.
   elif [[ $(getFluidityConnectionStatus) == SSL_TERMINATING ]]\
   || [[ $(getFluidityConnectionStatus) == SSL_TERMINATION_PENDING ]]; then
   
      # Delete the runTimeVars folder.
      if [ -d ~/Fluidity_Server/client.$2/connection.$2.$3/runTimeVars ]; then
         destroyRunTimeVars $2.$3
      fi
         
      # Delete the link state information file (link_information.txt).
      if [ -f ~/Fluidity_Server/client.$2/connection.$2.$3/link_information.txt ]; then
         deleteSOCATlinkStateInformation $2.$3
      fi
   
      # Invoke reinstallSSLcerts
      reinstallSSLcerts $1.$2 $client_IP_address $client_username $server_IP_address
      
   # Precautionaty action 2: Delete remaining state information from an
   # adnormal shutdown.
   else
   
      # Conditionally invoke destroyRunTimeVars:
      # Delete the runTimeVars folder.
      if [ -d ~/Fluidity_Server/client.$2/connection.$2.$3/runTimeVars ]; then
         destroyRunTimeVars $2.$3
      fi
         
      # Conditionally invoke deleteSOCATlinkStateInformation:
      # Delete the link state information file (link_information.txt).
      if [ -f ~/Fluidity_Server/client.$2/connection.$2.$3/link_information.txt ]; then
         deleteSOCATlinkStateInformation $2.$3
      fi
      
   fi
   
   
   # Safety check 3: Check whether another ACTIVE link exists with
   # the same port.
   if netstat -atnp | grep $4; then
      # Information message to user.
      echo "Server port is used by another resource. Please use another port."
      return
   fi
   
      
   # Safety check 4: Check whether the server IP address or server Serial 
   # device is already in use
   if ifconfig | grep $5 || lsof | grep -e $5; then
      if [[ "$1" == -s ]]; then
         # Information message to user.
         echo "Server serial interface is used by another resource."
         echo "Please use a different serial interface."
      elif [[ "$1" == -t ]]; then
         # Information message to user.
         echo "Server IP addres is used by another resource."
         echo "Please use a different server IP address."
      fi
      return
   fi
   
   # Safety check 5: Check whether target client IP address is already 
   # in use.
   if ifconfig | grep $6; then
      if [[ "$1" == -t ]]; then
         # Information message to user.
         echo "Client IP address is used by another link or resource."
         echo "Please use a different client IP address."
      fi
      return
   fi
   
   # Precautionary action 3: Check whether client ssh idenity is loaded
   # to SSH keyring.
   if ! ssh-add -l | grep client.$2; then
   
      # Invoke recallSSHidentity
      # Recall the missing identity.
      recallSSHidentity $2
      
   else
      
      # Message to user.
      echo "Fluidity client identity $2 is already loaded in keyring."
      
   fi
   
   # Invoke openPort
   # Allow traffic through the designated port.
   openPort $4
   
   # Report to user the current ufw status for the specific port.
   sudo ufw status verbose | grep -e $4
   
   # Invoke establishSOCATlink
   establishSOCATlink $2.$3 $5 $4 $6 $client_IP_address $client_username $7 $server_IP_address $1
   
}

# Arguments: ($1)
# $1: Fluidity Client (SSH) Connection ID.
# $2: Fluidity Virtual Circuit (SSL) Connection ID.

# Sourced Variables:
# 1. ~/Fluidity_Server/client.$SSH_ID/connection.$1/link_information.txt
      # Case 1: $fluidity_flavour_choice equals to -s (i.e. serial link)
      
         # 1. $fluidity_connection_ID
         # 2. $server_serial_int
         # 3. $server_listening_port
         # 4. $client_serial_int
         # 5. $client_ip_add
         # 6. $client_username
         # 7. $link_serial_speed
         # 8. $server_ip_add
         # 9. $fluidity_flavour_choice
         
      # Case 2: fluidity_flavour_choice equals to -t (i.e. tunnel link)
      
         # 1. $fluidity_connection_ID
         # 2. $server_tunnel_ip
         # 3. $server_listening_port
         # 4. $client_tunnel_ip
         # 5. $client_ip_add
         # 6. $client_username
         # 7. $tunneling_network_subnet_mask
         # 8. $server_ip_add
         # 9. $fluidity_flavour_choice

# Intershell File Variables in use: 
# 1. $fluidity_connection_status (setFluidityConnectionStatus, getFluidityConnectionStatus)
# 2. $allow_execution (setAllowExecution, getAllowExecution)
# 3. $port (setPort, getPort)
# 4. $termination_force_ping (setTerminationForcePing, getTerminationForcePing)

# Global Variables in use: NONE

# Generates: Nothing

# Invokes Functions:
# 1. terminationForcePing, with args ($1)
# 2. destroyRunTimeVars, with args ($1)
# 3. deleteSOCATlinkStateInformation, with args ($1)
# 4. closePort, with args $port

# Calls the script: NONE

# Function Description: Stop FLUIDITY for a specific connection
# ID.

stopFluidity () {

   # Derive the Fluidity ID
   local fluidity_id=$(echo $1.$2)

   # Safety check 1: Check whether targer connection exists.
   if [ ! -d ~/Fluidity_Server/client.$1/connection.$1.$2 ]; then
      # Information message to user.
      echo "No such link exists"
      return
   fi
   
   # Safety check 2: Check whether the link is INACTIVE.
   if [ ! -f ~/Fluidity_Server/client.$1/connection.$1.$2/link_information.txt ]; then
      # Information message to user.
      echo "Link $1.$2 is currently INACTIVE."
      return
   # If the connection is ACTIVE, source link_information.txt
   else
      # Import the following set of variables:
   
      # Case 1: $fluidity_flavour_choice equals to -s (i.e. serial link)
      
         # 1. $fluidity_connection_ID
         # 2. $server_serial_int
         # 3. $server_listening_port
         # 4. $client_serial_int
         # 5. $client_ip_add
         # 6. $client_username
         # 7. $link_serial_speed
         # 8. $server_ip_add
         # 9. $fluidity_flavour_choice
         
      # Case 2: $fluidity_flavour_choice equals to -t (i.e. tunnel link)
      
         # 1. $fluidity_connection_ID
         # 2. $server_tunnel_ip
         # 3. $server_listening_port
         # 4. $client_tunnel_ip
         # 5. $client_ip_add
         # 6. $client_username
         # 7. $tunneling_network_subnet_mask
         # 8. $server_ip_add
         # 9. $fluidity_flavour_choice
   
      source ~/Fluidity_Server/client.$1/connection.$1.$2/link_information.txt
   fi


   # Fluidity Finite State Machine 
   # State change to: TERMINATING
   setFluidityConnectionStatus $fluidity_id "TERMINATING"
   # Send a termination signal to both runPersistentSOCATClient and 
   # runPersistentSOCATServer by turning allow_execution to 0.
   setAllowExecution $fluidity_id 0 
   
   # Get the server's port number.
   port=$(getPort $fluidity_id)
   
   # Use netstat and pipe the output to grep. According to
   # $server_listening_port grep the line referring to that specific 
   # port and save it to $netstat_connection_status_string.
   local netstat_connection_status_string=$(netstat -atnp 2>/dev/null | grep $port)
   
   # The target is to extract the remote port to $remote_port.
   # To do that, use a double cut to compartmentalize the line. 
   # First, fetch the fifth element. Use
   # the whitespace ' ' as a delimeter character.
   # Second, fetch the 2nd element. Use the semicolon ':' as a delimeter
   # character.
   # Save the result to $remote_port.
   local remote_port=$(echo $netstat_connection_status_string | cut -d' ' -f 5 | cut -d ':' -f 2)
   
   # Use cut to compartmentalize the line. Fetch the sixth element. Use
   # the whitespace ' ' as a delimeter character. Save the result
   # to $netstat_connection_status.
   local netstat_connection_status=$(echo $netstat_connection_status_string | cut -d' ' -f 6)
   
   # Case 1: The connection is ESTABLISHED. Kill the client AND server 
   # SOCAT connection process.
   if [[ "$netstat_connection_status" == ESTABLISHED ]]; then

      # Use function fuser, with client port number ($remote_port), 
      # to terminate the remote client SOCAT process. When the process 
      # is terminated, both infinite loops within 
      # runPersistentSOCATServer & runPersistentSOCATClient will restart
      # and subsequently break from execution, due to $allow_execution 
      # being 0.
      ssh $client_username@$client_ip_add sudo fuser -k $remote_port/tcp
      
      # Use function fuser, with server port number ($port), to terminate 
      # the local server SOCAT process. When the process is terminated, 
      # both infinite loops within runPersistentSOCATServer & 
      # runPersistentSOCATClient will restart and subsequently break from
      # execution, due to $allow_execution being 0.
      sudo fuser -k $port/tcp
   
   # Case 2: The connection is lost. Kill the server SOCAT connection 
   # process.
   else 
      
      # Safety Check 3: Invoke terminationForcePing
      # Here, we cover the possibility that Fluidity lost its client, thus
      # runPersistentSOCATClient is currently in SLEEPING state and is 
      # having an active sleeping process that should first be terminated, 
      # before folder runTimeVars is erased.
      terminationForcePing $fluidity_id
   
      # Command description above.
      sudo fuser -k $port/tcp
      
   fi
   
   
   # Repeatedly check whether $server_is_terminated, $client_is_terminated
   # and termination_force_ping are all equal to 1. If all are 1,
   # delete the Intershell File Variables in runTimeVars folder.
   while [ true ]; do
   echo "client_is_terminated: $(getClientIsTerminated $fluidity_id)"
   echo "server_is_terminated: $(getServerIsTerminated $fluidity_id)"
   echo "terminationForcePing is: $(getTerminationForcePing $fluidity_id)"
      if [[ $(getServerIsTerminated $fluidity_id) -eq 1 && $(getClientIsTerminated $fluidity_id) -eq 1 && $(getTerminationForcePing $fluidity_id) -ne 0 ]]; then
         
         # Fluidity Finite State Machine 
         # State change to: TERMINATED
         setFluidityConnectionStatus $fluidity_id "TERMINATED"
         
         # Invoke terminationForcePing: Repeat terminationForcePing
         terminationForcePing $fluidity_id
         
         # Invoke runTimeVars: 
         # Delete the run time variables for this link.
         destroyRunTimeVars $fluidity_id
         
         # Invoke deleteSOCATlinkStateInformation:
         # Delete Link State Information
         deleteSOCATlinkStateInformation $fluidity_id
         
         # Break from the infinite WHILE
         break
         
      else
      
         # Fluidity Finite State Machine 
         # State change to: TERMINATION PENDING
         setFluidityConnectionStatus $fluidity_id "TERMINATION_PENDING"
         
         # Invoke terminationForcePing:
         # Do a preemptive terminationForcePing.
         terminationForcePing $fluidity_id
         
         # Proceed to rechecking
         
      fi
      
   done
   
   # Invoke closePort
   # Instruct ufw to deny traffic through the designated port.
   closePort $port
   
   # Give a ufw status feedback.
   sudo ufw status verbose | grep -e $port

}

# 6.2.1 Firewalling


# Arguments: ($1)
# $1: Server Listening Port

# Sourced Variables: NONE

# Intershell File Variables in use: NONE

# Global Variables in use: NONE

# Generates: Nothing
 
# Invokes Functions: NONE

# Calls the script: NONE

# Function Description: Instruct the Uncomplicated Firewall (UFW) to 
# ALLOW traffic for the requested SOCAT server listening port.

openPort () {
   
   # UFW: Rule change for port $1
   sudo ufw allow $1
   
}

# Arguments: ($1)
# $1: Server Listening Port

# Sourced Variables: NONE

# Intershell File Variables in use: NONE

# Global Variables in use: NONE

# Generates: Nothing
 
# Invokes Functions: NONE

# Calls the script: NONE

# Function Description: Instruct the Uncomplicated Firewall (UFW) to 
# ALLOW traffic for the requested SOCAT server listening port.

closePort () {
   
    # UFW: Rule change for port $1
   sudo ufw deny $1
   
}


# 6.2 Private Functions
# 6.2.2 Engine Administration


# Arguments: ($1) 
# $1. Fluidity Connection ID [SSH_ID.SSL_ID]

# Sourced Variables: NONE

# Intershell File Variables in use:
# $1. $sleep_pid (setSleepPid, getSleepPid)
# $2. $termination_force_ping (setTerminationForcePing, getTerminationForcePing)

# Global Variables in use: NONE

# Generates: Nothing

# Invokes Functions: NONE

# Calls the script: NONE

# Function Description: Do a sleep process termination and force 
# Fluidity to re-attempt pinging its lost client.

# terminationForcePing sets Intershall File Variable
# termination_force_ping to 1, thus signalling to stopFluidity that
# runTimeVars can be safely erased.

terminationForcePing () {
   
   # kill -0 verifies the existance of a sleeping process ID.

   # Case 1: The improper scenario.
   # A garbage value has remained from a previous sleeping process. 
   # kill -0 reports that the specific $sleep_pid doesn't exist while 
   # runPersistentSOCATClient is currently in ACTIVE state.
   if ! kill -0 $(getSleepPid $1); then

      # Information message to user.
      echo "Not in sleep mode"
   
   # Case 2: The proper scenario.
   # $sleep_id is 0. There is no sleeping process to kill.
   elif [[ $(getSleepPid $1) -eq 0 ]]; then

      # Information message to user.
      echo "Not in sleep mode. sleep_pid = 0."

   # Case 3: Kill the sleeping process.
   # A sleeping process is currently running. We fetch the PID from
   # Intershall File Variable $sleep_pid and request its termination.
   else

      # Information message to user.
      echo "in sleep mode and shall be terminated. sleep_pid: $(getSleepPid $1)"
      kill $(getSleepPid $1)

   fi
   
   # The current sleeping process is terminated. Hence, erase the 
   # previous pid and get $sleep_id ready for the next sleeping process,
   # by setting $sleep_pid to 0.
   setSleepPid $1 0

   # Set $termination_force_ping to 1.
   # Signal to calling function that terminationForcePing 
   # completed successfully.
   setTerminationForcePing $1 1

}

# Arguments: ($1)
# $1. Fluidity Connection ID [SSH_ID.SSL_ID]

# Sourced Variables:
# 1. ~/Fluidity_Server/client.$SSH_ID/connection.$1/link_information.txt
      # Case 1: $fluidity_flavour_choice equals to -s (i.e. serial link)
      
         # 1. $fluidity_connection_ID
         # 2. $server_serial_int
         # 3. $server_listening_port
         # 4. $client_serial_int
         # 5. $client_ip_add
         # 6. $client_username
         # 7. $link_serial_speed
         # 8. $server_ip_add
         # 9. $fluidity_flavour_choice
         
      # Case 2: fluidity_flavour_choice equals to -t (i.e. tunnel link)
      
         # 1. $fluidity_connection_ID
         # 2. $server_tunnel_ip
         # 3. $server_listening_port
         # 4. $client_tunnel_ip
         # 5. $client_ip_add
         # 6. $client_username
         # 7. $tunneling_network_subnet_mask
         # 8. $server_ip_add
         # 9. $fluidity_flavour_choice

# Intershell File Variables in use: 
# 1. $fluidity_connection_status (setFluidityConnectionStatus, getFluidityConnectionStatus)
# 2. $allow_execution (setAllowExecution, getAllowExecution)
# 3. $port (setPort, getPort)
# 4. $termination_force_ping (setTerminationForcePing, getTerminationForcePing)

# Global Variables in use: NONE

# Generates: Nothing

# Invokes Functions:
# 1. terminationForcePing, with args ($1)
# 2. destroyRunTimeVars, with args ($1)

# Calls the script: NONE

# Function Description: A special stopFluidity called only by 
# renewSSLcertificates when a SSL substitution is requested. The 
# difference from normal stopFluidity is the absence of functions
# deleteSOCATlinkStateInformation and closePort.

stopFluidityToRenewSSLcerts () {

   # Derive the SSH ID from Fluidity ID
   local SSH_ID=${1%.*}

   # Safety check 1: Check whether targer connection exists.
   if [ ! -d ~/Fluidity_Server/client.$SSH_ID/connection.$1 ]; then
      # Information message to user.
      echo "No such link exists"
      return
   fi
   
   # Safety check 2: Check whether the link is INACTIVE.
   if [ ! -f ~/Fluidity_Server/client.$SSH_ID/connection.$1/link_information.txt ]; then
      # Information message to user.
      echo "Link $1 is currently INACTIVE."
      return
   # If the connection is ACTIVE, source link_information.txt
   else
      # Import the following set of variables:
   
      # Case 1: $fluidity_flavour_choice equals to -s (i.e. serial link)
      
         # 1. $fluidity_connection_ID
         # 2. $server_serial_int
         # 3. $server_listening_port
         # 4. $client_serial_int
         # 5. $client_ip_add
         # 6. $client_username
         # 7. $link_serial_speed
         # 8. $server_ip_add
         # 9. $fluidity_flavour_choice
         
      # Case 2: $fluidity_flavour_choice equals to -t (i.e. tunnel link)
      
         # 1. $fluidity_connection_ID
         # 2. $server_tunnel_ip
         # 3. $server_listening_port
         # 4. $client_tunnel_ip
         # 5. $client_ip_add
         # 6. $client_username
         # 7. $tunneling_network_subnet_mask
         # 8. $server_ip_add
         # 9. $fluidity_flavour_choice
   
      source ~/Fluidity_Server/client.$SSH_ID/connection.$1/link_information.txt
   fi


   # Fluidity Finite State Machine 
   # State change to: TERMINATING
   setFluidityConnectionStatus $1 "SSL_TERMINATING"
   # Send a termination signal to both runPersistentSOCATClient and 
   # runPersistentSOCATServer by turning allow_execution to 0.
   setAllowExecution $1 0 
   
   # Get the server's port number.
   port=$(getPort $1)
   
   # Use netstat and pipe the output to grep. According to
   # $server_listening_port grep the line referring to that specific 
   # port and save it to $netstat_connection_status_string.
   local netstat_connection_status_string=$(netstat -atnp 2>/dev/null | grep $port)
   
   # The target is to extract the remote port to $remote_port.
   # To do that, use a double cut to compartmentalize the line. 
   # First, fetch the fifth element. Use
   # the whitespace ' ' as a delimeter character.
   # Second, fetch the 2nd element. Use the semicolon ':' as a delimeter
   # character.
   # Save the result to $remote_port.
   local remote_port=$(echo $netstat_connection_status_string | cut -d' ' -f 5 | cut -d ':' -f 2)
   
   # Use cut to compartmentalize the line. Fetch the sixth element. Use
   # the whitespace ' ' as a delimeter character. Save the result
   # to $netstat_connection_status.
   local netstat_connection_status=$(echo $netstat_connection_status_string | cut -d ' ' -f 6)
   
   # Case 1: The connection is ESTABLISHED. Kill the client AND server 
   # connection process.
   if [[ "$netstat_connection_status" == ESTABLISHED ]]; then

      # Use function fuser, with client port number ($remote_port), 
      # to terminate the remote client SOCAT process. When the process 
      # is terminated, both infinite loops within 
      # runPersistentSOCATServer & runPersistentSOCATClient will restart
      # and subsequently break from execution, due to $allow_execution 
      # being 0.
      ssh $client_username@$client_ip_add sudo fuser -k $remote_port/tcp
      
      # Use function fuser, with server port number ($port), to terminate 
      # the local server SOCAT process. When the process is terminated, 
      # both infinite loops within runPersistentSOCATServer & 
      # runPersistentSOCATClient will restart and subsequently break from
      # execution, due to $allow_execution being 0.
      sudo fuser -k $port/tcp
   
   # Case 2: The connection is lost. Kill the server connection process.
   else 
   
      # Command description above.
      sudo fuser -k $port/tcp
      
   fi
   
   # Safety Check 3: Invoke terminationForcePing
   # Here, we cover the possibility that Fluidity lost its client, thus
   # runPersistentSOCATClient is currently in a PINGING state and is 
   # having an active sleeping process that should first be terminated, 
   # before folder runTimeVars is erased.
   terminationForcePing $1
   
   # Repeatedly check whether $server_is_terminated, $client_is_terminated
   # and termination_force_ping are all equal to 1. If all are 1,
   # delete the Intershell File Variables in runTimeVars folder.
   while [ true ]; do
   echo "client_is_terminated: $(getClientIsTerminated $1)"
   echo "server_is_terminated: $(getServerIsTerminated $1)"
   echo "terminationForcePing is: $(getTerminationForcePing $1)"
      if [[ $(getServerIsTerminated $1) -eq 1 && $(getClientIsTerminated $1) -eq 1 && $(getTerminationForcePing $1) -ne 0 ]]; then
         
         # Fluidity Finite State Machine 
         # State change to: TERMINATED
         setFluidityConnectionStatus $1 "SSL_TERMINATED"
         
         # Invoke terminationForcePing: Repeat terminationForcePing
         terminationForcePing $1
         
         # Invoke runTimeVars: 
         # Delete the run time variables for this link.
         destroyRunTimeVars $1
         
         # Break from the infinite WHILE
         break
         
      else
      
         # Fluidity Finite State Machine 
         # State change to: TERMINATION PENDING
         setFluidityConnectionStatus $1 "SSL_TERMINATION_PENDING"
         
         # Invoke terminationForcePing:
         # Do a preemptive terminationForcePing.
         terminationForcePing $1
         
         # Proceed to rechecking
         
      fi
      
   done

}


# 6.2.3 Link Setup


# Arguments: ($1), ($2), ($3), ($4), ($5), ($6), ($7), ($8), ($9)
# $1: Fluidity Connection ID [SSH_ID.SSL_ID]
# $2: CASE A: [For $9="-s"] The Server Serial Interface
#     CASE B: [For $9="-t"] Server's tunnel interface IP
# $3: Server Listening Port
# $4: CASE A: [For $9="-s-"] Client's Serial Interface
#     CASE B: [For $9="-t"] Client's tunnel interface IP
# $5: Client IP address
# $6: Client username (for raspbian OS the default is pi@)
# $7: CASE A: [For $9="-s"] Serial Speed
#     CASE B: [For $9="-t"] Tunneling Network Subnet Mask
# $8: Server IP address
# $9: Your Fluidity flavour choice [Can be: "-s" serial or "-t" tunnel]

# Sourced Variables: NONE

# Intershell File Variables in use:
# 1. $allow_execution (setAllowExecution, getAllowExecution)
# 2. $set_port (setPort, getPort)

# Global Variables in use:

# Generates: Nothing

# Invokes Functions:
# 1. initializeRunTimeVars, with args ($1)
# 2. storeSOCATlinkStateInformation, with args ($1), ($2), ($3), ($4), ($5), ($6), ($7), ($8), ($9)
# 2. runPersistentSOCATServer, with args ($1), ($2), ($3), ($7)
# 3. runPersistenSOCATClient, with args ($1) ($4), ($3), ($5), ($6), ($7)

# Calls the script: NONE

# Function Description: Initiate FLUIDITY'S two main
# functions: runPersistentSOCATServer & runPersistentSOCATClient.

establishSOCATlink () {
   
   # Invoke initializeRunTimeVars
   # Initialize the Intershell File Variables.
   initializeRunTimeVars $1
   
   # Set allow_execution to 1.
   setAllowExecution $1 1
   
   # Set the Server's $port Intershell File Variable.
   setPort $1 $3
   
   # Invoke storeSOCATlinkStateInformation
   # Export the variables that this instance is running on for Fluidity's
   # monitoring functions.
   storeSOCATlinkStateInformation $1 $2 $3 $4 $5 $6 $7 $8 $9
   
   # Invoke runPersistentSOCATServer
   # Start the server and run the process in the background. Silence the
   # output.
   (runPersistentSOCATServer $1 $2 $3 $7 $9) &>/dev/null &
   
   # Invoke runPersistentSOCATClient
   # Start the remote client and run the process in the background. 
   # Silence the output.
   (runPersistentSOCATClient $1 $4 $3 $5 $6 $7 $8 $9) &
   
   # Wait a bit... Give time to runPersistentSOCATServer and
   # runPersistentSOCATClient to get in sych.
   sleep 10
   
   # Display this session's connection status according to port server's
   # number.
   netstat -atnp | grep $3
   
}


# 6.2.3.1 Link State Information Administration
# 6.2.3.1.1 Static Information


# Arguments: ($1), ($2), ($3), ($4), ($5), ($6), ($7), ($8), ($9)
# $1: Fluidity Connection ID [SSH_ID.SSL_ID]
# $2: CASE A: [For $9="-s"] The Server Serial Interface
#     CASE B: [For $9="-t"] Server's tunnel interface IP
# $3: Server Listening Port
# $4: CASE A: [For $9="-s-"] Client's Serial Interface
#     CASE B: [For $9="-t"] Client's tunnel interface IP
# $5: Client IP address
# $6: Client username (for raspbian OS the default is pi@)
# $7: CASE A: [For $9="-s"] Serial Speed
#     CASE B: [For $9="-t"] Tunneling Network Subnet Mask
# $8: Server IP address
# $9: Your Fluidity flavour choice [Can be: "-s" serial or "-t" tunnel]

# Sourced Variables: NONE

# Intershell File Variables in use: NONE

# Global Variables in use: NONE

# Generates: 
# 1. Text (TXT) File: link_information.txt

# Invokes Functions: NONE

# Calls the script: NONE

# Function Description: Create link_information.txt containg the 
# arguments that comprise the requested SOCAT link.

storeSOCATlinkStateInformation () {
   
   local SSH_ID=${1%.*}
   
   if [[ "$9" == -s ]]; then
   
      echo -e \
      'fluidity_connection_ID='$1\
      '\nserver_serial_int='$2\
      '\nserver_listening_port='$3\
      '\nclient_serial_int='$4\
      '\nclient_ip_add='$5\
      '\nclient_username='$6\
      '\nlink_serial_speed='$7\
      '\nserver_ip_add='$8\
      '\nfluidity_flavour_choice='$9\
      > ~/Fluidity_Server/client.$SSH_ID/connection.$1/link_information.txt
   
   elif [[ "$9" == -t ]]; then
   
      echo -e \
      'fluidity_connection_ID='$1\
      '\nserver_tunnel_ip='$2\
      '\nserver_listening_port='$3\
      '\nclient_tunnel_ip='$4\
      '\nclient_ip_add='$5\
      '\nclient_username='$6\
      '\ntunneling_network_subnet_mask='$7\
      '\nserver_ip_add='$8\
      '\nfluidity_flavour_choice='$9\
      > ~/Fluidity_Server/client.$SSH_ID/connection.$1/link_information.txt
      
   else
   
      return
      
   fi
   
}


# Arguments: ($1)
# $1: Fluidity Connection ID [SSH_ID.SSL_ID]

# Sourced Variables: NONE

# Intershell File Variables in use: NONE

# Global Variables in use: NONE

# Generates: Nothing

# Invokes Functions: NONE

# Calls the script: NONE

# Function Description: Deletes the link state information.

deleteSOCATlinkStateInformation () {
   
   # Derive the SSH ID from Fluidity ID
   local SSH_ID=${1%.*}
   
   # Remove link_information.txt
   rm ~/Fluidity_Server/client.$SSH_ID/connection.$1/link_information.txt
   
}


# 6.2.3.1.2 Dynamic Information


# Arguments: ($1)
# $1: Fluidity Connection ID [SSH_ID.SSL_ID]

# Sourced Variables: NONE

# Intershell File Variables in use: NONE

# Global Variables in use: NONE

# Generates:
# 1. Intershell File Variable (No Extension): allow_execution
# 2. Intershell File Variable (No Extension): port
# 3. Intershell File Variable (No Extension): server_is_terminated
# 4. Intershell File Variable (No Extension): client_is_terminated
# 5. Intershell File Variable (No Extension): sleep_pid
# 6. Intershell File Variable (No Extension): termination_force_ping
# 7. Intershell File Variable (No Extension): fluidity_connection_status
# 8. Intershell File Variable (No Extension): ping_delay

# Invokes Functions: NONE

# Calls the script: NONE

# Function Description: Create the files and initialize the values for
# the following Intershell File Variables in folder location:
# ~/Fluidity_Server/Connection$1/runtimeVars
# VARIABLES LIST: 1. allow_execution, 2. port, 3. server_is_terminated
# 4. client_is_terminated, 5. sleep_pid, 6. termination_force_ping
# 7. fluidity_connection_status 8. ping_delay

initializeRunTimeVars () {
   
   # Derive the SSH ID from Fluidity ID
   local SSH_ID=${1%.*}
   
   mkdir ~/Fluidity_Server/client.$SSH_ID/connection.$1/runtimeVars
   
   # Create and initialize the runTimeVars into Function Description 
   # variables list.
   echo -e 'allow_execution=0' > ~/Fluidity_Server/client.$SSH_ID/connection.$1/runtimeVars/allow_execution
   echo -e 'port=0' > ~/Fluidity_Server/client.$SSH_ID/connection.$1/runtimeVars/port
   echo -e 'server_is_terminated=0' > ~/Fluidity_Server/client.$SSH_ID/connection.$1/runtimeVars/server_is_terminated
   echo -e 'client_is_terminated=0' > ~/Fluidity_Server/client.$SSH_ID/connection.$1/runtimeVars/client_is_terminated
   echo -e 'sleep_pid=0' > ~/Fluidity_Server/client.$SSH_ID/connection.$1/runtimeVars/sleep_pid
   echo -e 'termination_force_ping=0' > ~/Fluidity_Server/client.$SSH_ID/connection.$1/runtimeVars/termination_force_ping
   echo -e 'fluidity_connection_status=INITIALIZING' > ~/Fluidity_Server/client.$SSH_ID/connection.$1/runtimeVars/fluidity_connection_status
   echo -e 'ping_delay=0' > ~/Fluidity_Server/client.$SSH_ID/connection.$1/runtimeVars/ping_delay
   
}

# Arguments: ($1)
# $1: Fluidity Connection ID [SSH_ID.SSL_ID]

# Sourced Variables: NONE

# Intershell File Variables in use: NONE

# Global Variables in use: NONE

# Generates: Nothing

# Invokes Functions: NONE

# Calls the script: NONE

# Function Description: Upon invoking from another function, erase file
# runtimeVars.

destroyRunTimeVars () {
   
   # Derive the SSH ID from Fluidity ID
   local SSH_ID=${1%.*}
   
   # Delete the entire runtimeVars folder for Fluidity target connection.
   rm -rf ~/Fluidity_Server/client.$SSH_ID/connection.$1/runtimeVars
   
}


# 6.2.3.2 Server Setup


# Arguments: ($1), ($2), ($3), ($4), ($5)
# $1: Fluidity Connection ID [SSH_ID.SSL_ID]
# $2: CASE A: [For $5="-s"] The Server Serial Device
#     CASE B: [For $5="-t"] Server's tunnel interface IP
# $3: Server Listening Port
# $4: CASE A: [For $5="-s"] Serial Speed
#     CASE B: [For $5="-t"] Tunneling Network Subnet Mask
# $5: Your Fluidity flavour choice [Can be: "-s" serial or "-t" tunnel]

# Sourced Variables: NONE

# Intershell File Variables in use: 
# 1. server_is_terminated (setServerIsTerminated, getServerIsTerminated)

# Global Variables in use: NONE

# Generates: Nothing
 
# Invokes Functions: 
# 1. runSOCATserver, with args ($1), ($2), ($3), ($4)

# Calls the script: NONE

# Function Description: Adding persistance to runSOCATserver.

runPersistentSOCATServer () {
   
   # Safety check 1:
   # Stop runPersistentSOCATServer if $allow_execution is 0.
   if [ $(getAllowExecution $1) -eq 0 ]; then
         # Information message.
         echo "stopFluidity is initiated. Cancelling runPersistentSOCATServer."
         return
   fi
   
   # Intershell File Variable $server_is_terminated:
   # Value 0: runPersistentSOCATServer has started execution.
   # Value 1: runPersistentSOCATServer has broken out from the main Loop
   # and completed execution.
   
   # Signal that runPersistentSOCATServer has started execution.
   setServerIsTerminated $1 0
   
   # Main Loop: Adding persistency to the SOCAT server process.
   while [ $(getAllowExecution $1) -eq 1 ]; 
   do
   
      # allow_execution is 1. Initiate the SOCAT server process.
      runSOCATserver $1 $2 $3 $4 $5
      
   done
   
   # Signal that runPersistentSOCATServer has broken out from the main
   # Loop and completed execution.
   setServerIsTerminated $1 1
   
}


# Arguments: ($1), ($2), ($3), ($4), ($5)
# $1: Fluidity Connection ID [SSH_ID.SSL_ID]
# $2: CASE A: [For $5="-s"] The Server Serial Device
#     CASE B: [For $5="-t"] Server's tunnel interface IP
# $3: Server Listening Port
# $4: CASE A: [For $5="-s"] Serial Speed
#     CASE B: [For $5="-t"] Tunneling Network Subnet Mask
# $5: Your Fluidity flavour choice [Can be: "-s" serial or "-t" tunnel]

# Sourced Variables: NONE

# Intershell File Variables in use: NONE

# Global Variables in use: NONE

# Generates: Nothing

# Calls the script: NONE

# Invokes Functions: 
# 1. runSerialSOCATserver, with args ($1), ($2), ($3), ($4)
# 2. runTUNnelSOCATserver, with args ($1), ($2), ($3), ($4)

# Function Description: Fluidity server flavour selector. 
# Based on argument $5, choose the desirable connection type for the
# server machine.

runSOCATserver () {
   
   # Case 1: Initiate a serial connection.
   if [[ "$5" == -s ]]; then
   
      # Invoke runSerialSOCATserver
      runSerialSOCATserver $1 $2 $3 $4
   
   # Case 2: Initiate an ethernet tunneling connection.
   elif [[ "$5" == -t ]]; then
   
      # Invoke runTUNnelSOCATserver
      runTUNnelSOCATserver $1 $2 $3 $4
   
   # Error handling case: Display the acceptable values.
   else
   
      echo -e "Acceptable values \"-s\" SERIAL or \"-t\" TUNNEL."
      
   fi
   
}

# Arguments: ($1), ($2), ($3), ($4)
# $1: Fluidity Connection ID [SSH_ID.SSL_ID]
# $2: The Server Serial Device
# $3: Server Listening Port
# $4: Serial Speed

# Sourced Variables: NONE

# Intershell File Variables in use: NONE

# Global Variables in use: NONE

# Generates:
# 1. Bash script (.sh): genSCRIPT_server$1.sh $1 $2 $3 $4 $5

# Calls the script: 
# 1. genSCRIPT_server.$1.sh, with args ($1), ($2), ($3), ($4),
# $serv_pass

# Invokes Functions: NONE

# Function Description: Moves serial data through a SOCAT SSL connection.
# More specifically: 
# Retrieve the server SSL certificate password and
# store it in a local variable. Then execute a short EXPECT script that
# subsequently runs SOCAT with the desirable parameters.
# IMPORTANT NOTE 1: Default serial connection speed is 115200.
# IMPORTANT NOTE 2: Server - Client serial connection settings must match.

runSerialSOCATserver() {

   local SSH_ID=${1%.*}

   # Recall and store server's SSH certificate password
   local serv_pass=$(cat ~/Fluidity_Server/client.$SSH_ID/connection.$1/s_password.$1.txt)

   cd ~/Fluidity_Server/client.$SSH_ID/connection.$1

   if [[ ! -e ~/Fluidity_Server/client.$SSH_ID/connection.$1/genSCRIPT_server.$1.sh ]]; then
   
      echo -e 'cd ~/Fluidity_Server/client.$SSH_ID/connection.$1'\
'\nexpect << EOF'\
'\nspawn socat /dev/$2,b$4,echo=0,raw \\'\
'\nopenssl-listen:$3,reuseaddr,verify=1,cert=servercon.$1.pem,cafile=clientcon.$1.crt'\
'\nexpect "rase:"'\
'\nsend "$5\\r"'\
'\nwait'\
'\nexpect eof'\
'\nEOF'\
      > genSCRIPT_server.$1.sh
      chmod 700 genSCRIPT_server.$1.sh
      
   fi

   # Locally execute genSCRIPT_server.[SSH_ID.SSL_ID].sh
   ./genSCRIPT_server.$1.sh $1 $2 $3 $4 $serv_pass

}

# Arguments: ($1), ($2), ($3), ($4)
# $1: Fluidity Connection ID [SSH_ID.SSL_ID]
# $2: Server's tunnel interface IP
# $3: Server Listening Port
# $4: Tunneling Network Subnet Mask

# Sourced Variables: NONE

# Intershell File Variables in use: NONE

# Global Variables in use: NONE

# Generates:
# 1. Bash script (.sh): genSCRIPT_server$1.sh $1 $2 $3 $4 $5

# Calls the script: 
# 1. genSCRIPT_server$1.sh, with args ($1), ($2), ($3), ($4),
# $serv_pass

# Invokes Functions: NONE

# Function Description: Internetworking by using virtual tunnel interfaces
# through a SOCAT SSL connection.
# More specifically:
# Retrieve the server SSL certificate password and
# store it in a local variable. Then execute a short EXPECT script that
# subsequently runs SOCAT with the desirable parameters.

runTUNnelSOCATserver () {
   
   local SSH_ID=${1%.*}
   
   # Recall and store server's SSH certificate password
   local serv_pass=$(cat ~/Fluidity_Server/client.$SSH_ID/connection.$1/s_password.$1.txt)

   cd ~/Fluidity_Server/client.$SSH_ID/connection.$1
      
   if [[ ! -e ~/Fluidity_Server/client.$SSH_ID/connection.$1/genSCRIPT_server.$1.sh ]]; then
   
      echo -e 'cd ~/Fluidity_Server/client.$SSH_ID/connection.$1'\
'\nexpect << EOF'\
'\nspawn sudo socat TUN:$2/$4,up \\'\
'\nopenssl-listen:$3,reuseaddr,verify=1,cert=servercon.$1.pem,cafile=clientcon.$1.crt'\
'\nexpect "rase:"'\
'\nsend "$5\\r"'\
'\nwait'\
'\nexpect eof'\
'\nEOF'\
      > genSCRIPT_server.$1.sh
      chmod 700 genSCRIPT_server.$1.sh
      
   fi

   # Locally execute genSCRIPT_server.[SSH_ID.SSL_ID].sh
   ./genSCRIPT_server.$1.sh $1 $2 $3 $4 $serv_pass
   
}

# 6.2.3.3 Client Setup


# Arguments: ($1), ($2), ($3), ($4), ($5), ($6), ($7), ($8)
# $1. Fluidity Connection ID [SSH_ID.SSL_ID]
# $2: CASE A: [For $8="-s"] Client's Serial Interface
#     CASE B: [For $8="-t"] Client's tunnel interface IP
# $3: Server Listening Port
# $4: Client IP address
# $5: Client username (for raspbian OS the default is pi@)
# $6: CASE A: [For $8="-s"] Serial Speed
#     CASE B: [For $8="-t"] Tunneling Network Subnet Mask
# $7: Server IP
# $8: Your Fluidity flavour choice [Can be: "-s" serial or "-t" tunnel]

# Sourced Variables: NONE

# Intershell File Variables in use: 
# 1. $client_is_terminated (setClientIsTerminated, getClientIsTerminated)
# 2. $allow_execution (setAllowExecution, getAllowExecution)
# 3. $fluidity_connection_status (setFluidityConnectionStatus, getFluidityConnectionStatus)
# 4. $sleep_pid (setSleepPid, getSleepPid)

# Global Variables in use: NONE

# Generates: Nothing

# Invokes functions:
# 1. checkForConnectionFolderAndDecrypt, with args ($1), ($4), ($5)
# 2. runSOCATclient, with args ($1), ($2), ($3), ($4), ($5), ($6)
# 3. encryptClient, with args ($1), ($4), ($5)

# Function Description: Adding persistence to runSOCATclient with a few
# twists.
# Main point is that runPersistentSOCATClient executes until 
# Intershell Global Variable $allow_execution turns from 1 to 0.

runPersistentSOCATClient () {

   # Safety check 1:
   # Stop runPersistentSOCATClient if $allow_execution is 0.
   if [ $(getAllowExecution $1) -eq 0 ]; then
         # Information message.
         echo "stopFluidity requested. Cancelling runPersistentSOCATClient."
         return
   fi

   # Intershell File Variable $client_is_terminated:
   # Value 0: runPersistentSOCATClient has started execution.
   # Value 1: runPersistentSOCATClient has broken out from the main Loop
   # and completed execution.

   # Signal that runPersistentSOCATClient has started execution.
   setClientIsTerminated $1 0

   # Variable declarations
   
   # $ping_delay: Counter that increases with every failed attempt 
   # to reach the target client. Formula: ping_delay = ping_delay*3.
   # Set $ping_delay to 2 secs.
   local ping_delay=2
   setPingDelay $1 $ping_delay
   
   # $temp_id: A temporary placeholder that keeps the sleep pid. 
   local temp_pid=0
   
   # Debugging information message 1
   echo "Outside the Loop. Initiating."
   
   # Main Loop: Adding persistency to the SOCAT client process.
   while [ $(getAllowExecution $1) -eq 1 ];
   do
      
      # Ping target client $4 6 times.

      # Fluidity Finite State Machine 
      # State change to: PINGING
      setFluidityConnectionStatus $1 "PINGING"

      # Fluidity client responds.
      if ping -c 6 $4; then
      
         # Reset $ping_delay to 2 seconds.
         ping_delay=2
         
         # Debugging information message 4
         echo "Inside the Loop and proceeding with runSOCATclient."
         echo "Ping delay is: $ping_delay"
         
         # Invoke checkForConnectionFolderAndDecrypt:
         # Client communication has been established. Now see whether
         # the client folder is decrypted. If not, then decrypt it.
         checkForConnectionFolderAndDecrypt $1 $4 $5
         
         # Fluidity Finite State Machine 
         # State change to: ACTIVE
         setFluidityConnectionStatus $1 "ACTIVE"

         # Update intershell variable $ping_delay
         setPingDelay $1 $ping_delay
         
         # Invoke runSOCATclient:
         # Client is available and the FLUIDITY home folder in remote 
         # machine is decrypted. Proceed with runSOCATclient.
         runSOCATclient $1 $2 $3 $4 $5 $6 $7 $8
         
         if [[ $(getFluidityConnectionStatus $1) == "TERMINATING" || \
         $(getFluidityConnectionStatus $1) == "TERMINATION_PENDING" ]]; then 
            echo "Initiating encryptClient in state: $(getFluidityConnectionStatus $1)"
            # Invoke encryptClient
            # stopFluidity is requested. Before exiting, encrypt the client
            # connection folder.
            encryptClient $1 $4 $5
         fi
         
      # Fluidity client doesn't respond.
      else
      
         # Debugging information message 5
         echo "Inside the Loop, but Pinging failed."
         echo "Ping delay is: $ping_delay"
         
         # Fluidity Finite State Machine 
         # State change to: SLEEPING
         setFluidityConnectionStatus $1 "SLEEPING"

         # Update intershell variable $ping_delay
         setPingDelay $1 $ping_delay
         
         # Case 1:
         # $ping_delay accumulated more than 600 secs.
         # From there on pinging will occur every 600 seconds.
         if [[ $ping_delay -ge 600 ]]; then
         
            # Debugging information message 6
            echo "Inside the Loop. Pinging above 600secs."
            echo "Ping delay is: $ping_delay"
            
            # Set $ping_delay to 600.
            ping_delay=600

            # Information message to user.
            echo "Client $4 is unreachable. Retrying in 600 seconds or forcePing."
            
            # 1. Request a 600 secs sleeping process. 
            # 2. Put the sleep process in the background and release 
            # the terminal.
            # 3. Save the sleep process pid into $temp_pid. 
            sleep 600 & temp_pid=$!

            # Save $temp_pid into Intershell File Variable $sleep_pid
            setSleepPid $1 $temp_pid
            
            # Bring sleep back in the foreground, and delay everything 
            # for 600 secs.
            wait $sleep_pid
            
         # Case 2:
         # $ping_delay is less than 600 secs.
         # Next ping in $ping_delay secs.
         else
         
            # Debugging information message 7
            echo "Inside the Loop. Pinging below 600secs."
            echo "Ping delay is: $ping_delay"
            
            echo "Client $4 is unreachable. Retrying in $ping_delay seconds or forcePing."
            
            # 1. Request a $ping_delay secs sleeping process. 
            # 2. Put the sleep process in the background and release 
            # the terminal.
            # 3. Save the sleep process pid into $temp_pid.
            sleep $ping_delay & temp_pid=$!

            # Save $temp_pid into Intershell File Variable $sleep_pid
            setSleepPid $1 $temp_pid
            
            # Bring sleep back in the foreground, and delay everything 
            # for $ping_delay secs.
            wait $sleep_pid
            
            # Increase the $ping_delay counter according to the 
            # following formula.
            let ping_delay=$(expr $ping_delay \* 3)
            
         fi
         
      fi
      
   done
   
   # Debugging information message 8
   echo "Outside the Loop. Main Loop terminated."
   
   # Signal that runPersistentSOCATClient has broken out from the main
   # Loop and completed execution.
   setClientIsTerminated $1 1

}

# Arguments: ($1), ($2), ($3), ($4), ($5), ($6), ($7), ($8)
# $1: Fluidity Connection ID [SSH_ID.SSL_ID]
# $2: CASE A: [For $8="-s"] Client's Serial Interface
#     CASE B: [For $8="-t"] Client's tunnel interface IP
# $3: Server Listening Port
# $4: Client IP address
# $5: Client username (for raspbian OS the default is pi@)
# $6: CASE A: [For $8="-s"] Serial Speed
#     CASE B: [For $8="-t"] Tunneling Network Subnet Mask
# $7: Server IP
# $8: Your Fluidity flavour choice [Can be: "-s" serial or "-t" tunnel]

# Sourced Variables: NONE

# Intershell File Variables in use: NONE

# Global Variables in use: NONE

# Generates: Nothing

# Invokes Functions: 
# 1. runSerialSOCATclient, with args ($1), ($2), ($3), ($4), ($5), ($6),
# ($7)
# 2. runTUNnelSOCATclient, with args ($1), ($2), ($3), ($4), ($5), ($6),
# ($7)

# Calls the script: NONE

# Function Description: Fluidity client flavour selector. 
# Based on argument $8, choose the desirable connection type for the
# client machine.

runSOCATclient () {
  
   # Case 1: Initiate a serial connection.
   if [[ "$8" == -s ]]; then
   
      # Invoke runSerialSOCATclient
      runSerialSOCATclient $1 $2 $3 $4 $5 $6 $7
   
   # Case 2: Initiate an ethernet tunneling connecion.
   elif [[ "$8" == -t ]]; then
   
      # Invoke runTUNnelSOCATclient
      runTUNnelSOCATclient $1 $2 $3 $4 $5 $6 $7
   
   # Error handling case: Display the acceptable values.
   else
   
      echo -e "Acceptable values \"-s\" SERIAL or \"-t\" TUNNEL."
      
   fi
   
}

# Arguments: ($1), ($2), ($3), ($4), ($5), ($6), ($7)
# $1: Fluidity Connection ID [SSH_ID.SSL_ID]
# $2: Client's Serial Interface
# $3: Server Listening Port
# $4: Client IP address
# $5: Client username (for raspbian OS the default is pi@)
# $6: Serial Speed
# $7: Server IP

# Sourced Variables: NONE

# Intershell File Variables in use: NONE

# Global Variables in use: NONE

# Generates: 
# 1. Bash script (.sh): genSCRIPT_client.$1.sh $1 $2 $3 $4 $5 $6

# Invokes Functions: NONE

# Calls the script: 
# 1. genSCRIPT_client.$1.sh, with args ($1), ($2), ($3), ($6), ($7),
# $client_pass

# Function Description: Moves serial data through a SOCAT SSL connection.
# More specifically: 
# Retrieve the client SSL certificate password and
# store it an a local variable. Create the generated bash script
# genSCRIPT_client$1($1: Connection ID) that subsequently will run
# SOCAT by using an EXPECT script on client's side. Store the script in 
# server at folder ~/Fluidity_Server/Connection$1. Then, login to 
# the client through SSH and execute genSCRIPT_client$1 remotely.
# IMPORTANT NOTE 1: 
# genSCRIPT_client$1 contains the entirety of parameters necesssary for
# executing SOCAT. If an existing genSCRIPT_client$1 is found, then leave
# it as it is. Connection settings can be stored there permantly.
# IMPORTANT NOTE 1: Server - Client serial connection settings must be the same.

runSerialSOCATclient() {

   local SSH_ID=${1%.*}

   # Recall and store client's SSH certificate password
   local client_bogus_pass=$(cat ~/Fluidity_Server/client.$SSH_ID/connection.$1/c_bogus_password.$1.txt)

   cd ~/Fluidity_Server/client.$SSH_ID/connection.$1

   # Generate a bash script, named genSCRIPT_client$1.sh ($1: Fluidity connection ID),
   # that will contain the specific SOCAT connection configuration on client's side.

   # If an existing configuration file is found, leave it intact. Else,
   # create a new one with the default settings.
   if [[ ! -e ~/Fluidity_Server/client.$SSH_ID/connection.$1/genSCRIPT_client.$1.sh ]]; then
   
      echo -e 'cd ~/Fluidity_Client/connection.$1'\
'\n'\
'\npass=$(echo $hashed_pass | openssl enc -aes-128-cbc -a -d -salt -pass pass:$6)'\
'\nexpect << EOF'\
'\nspawn socat openssl:$5:$3,verify=1,\\'\
'\ncert=clientcon.$1.pem,\\'\
'\ncafile=servercon.$1.crt,\\'\
'\n /dev/$2,b$4,echo=0,raw'\
'\nexpect "rase:"'\
'\nsend "$pass\\r"'\
'\nwait'\
'\nexpect eof'\
'\nEOF'\
      > genSCRIPT_client.$1.sh
      chmod 700 genSCRIPT_client.$1.sh
      
      echo "sed -i '2s/.*/$(echo hashed_pass="$(cat ~/Fluidity_Server/client.$SSH_ID/connection.$1/hashed_clientpass_con.$1.txt)" | sed -e 's/[\/&]/\\&/g' )/' ~/Fluidity_Server/client.$SSH_ID/connection.$1/genSCRIPT_client.$1.sh" | bash -
      
   else
   
      echo "sed -i '2s/.*/$(echo hashed_pass="$(cat ~/Fluidity_Server/client.$SSH_ID/connection.$1/hashed_clientpass_con.$1.txt)" | sed -e 's/[\/&]/\\&/g' )/' ~/Fluidity_Server/client.$SSH_ID/connection.$1/genSCRIPT_client.$1.sh" | bash -
      
   fi

   # SSH remotely execute genSCRIPT_client.[SSH_ID.SSL_ID].sh
   ssh $5@$4 'bash -s' < ~/Fluidity_Server/client.$SSH_ID/connection.$1/genSCRIPT_client.$1.sh $1 $2 $3 $6 \
	$7 $client_bogus_pass
   
}

# Arguments: ($1), ($2), ($3), ($4), ($5), ($6), ($7), ($8)
# $1: Fluidity Connection ID [SSH_ID.SSL_ID]
# $2: Client's tunnel interface IP
# $3: Server Listening Port
# $4: Client IP address
# $5: Client username (for raspbian OS the default is pi@)
# $6: Tunnelling network subnet mask
# $7: Server IP

# Sourced Variables: NONE

# Intershell File Variables in use: NONE

# Global Variables in use: NONE

# Generates: 
# 1. Bash script (.sh): genSCRIPT_client.$1.sh $1 $2 $3 $4 $5 $6

# Invokes Functions: NONE

# Calls the script: 
# 1. genSCRIPT_client.$1.sh, with args ($1), ($2), ($3), ($6), ($7),
# $client_pass

# Function Description: Internetworking by using virtual tunnel interfaces
# through a SOCAT SSL connection.
# More specifically: 
# Retrieve the client SSL certificate password and
# store it an a local variable. Create the generated bash script
# genSCRIPT_client$1($1: Connection ID) that subsequently will run
# SOCAT by using an EXPECT script on client's side. Store the script in 
# server at folder ~/Fluidity_Server/Connection$1. Then, login to 
# the client through SSH and execute genSCRIPT_client$1 remotely.
# IMPORTANT NOTE 1: 
# genSCRIPT_client$1 contains the entirety of parameters necesssary for
# executing SOCAT. If an existing genSCRIPT_client$1 is found, then leave
# it as it is. Connection settings can be stored there permantly.

runTUNnelSOCATclient() {

   local SSH_ID=${1%.*}

   # Recall and store client's SSH certificate password
   local client_bogus_pass=$(cat ~/Fluidity_Server/client.$SSH_ID/connection.$1/c_bogus_password.$1.txt)

   cd ~/Fluidity_Server/client.$SSH_ID/connection.$1

   # Generate a bash script, named genSCRIPT_client$1.sh ($1: Fluidity connection ID),
   # that will contain the specific SOCAT connection configuration on client's side.

   # If an existing configuration file is found, leave it intact. Else,
   # create a new one with the default settings.
   if [[ ! -e ~/Fluidity_Server/client.$SSH_ID/connection.$1/genSCRIPT_client.$1.sh ]]; then
   
      echo -e 'cd ~/Fluidity_Client/connection.$1'\
'\n'\
'\npass=$(echo $hashed_pass | openssl enc -aes-128-cbc -a -d -salt -pass pass:$6)'\
'\nexpect << EOF'\
'\nspawn sudo socat openssl:$5:$3,verify=1,\\'\
'\ncert=clientcon.$1.pem,\\'\
'\ncafile=servercon.$1.crt,\\'\
'\n TUN:$2/$4,up'\
'\nexpect "rase:"'\
'\nsend "$pass\\r"'\
'\nwait'\
'\nexpect eof'\
'\nEOF'\
      > genSCRIPT_client.$1.sh
      chmod 700 genSCRIPT_client.$1.sh
      
      echo "sed -i '2s/.*/$(echo hashed_pass="$(cat ~/Fluidity_Server/client.$SSH_ID/connection.$1/hashed_clientpass_con.$1.txt)" | sed -e 's/[\/&]/\\&/g' )/' ~/Fluidity_Server/client.$SSH_ID/connection.$1/genSCRIPT_client.$1.sh" | bash -
      
   else
   
      echo "sed -i '2s/.*/$(echo hashed_pass="$(cat ~/Fluidity_Server/client.$SSH_ID/connection.$1/hashed_clientpass_con.$1.txt)" | sed -e 's/[\/&]/\\&/g' )/' ~/Fluidity_Server/client.$SSH_ID/connection.$1/genSCRIPT_client.$1.sh" | bash -
      
   fi

   # Remotely execute genSCRIPT_client.[SSH_ID.SSL_ID].sh
   ssh $5@$4 'bash -s' < ~/Fluidity_Server/client.$SSH_ID/connection.$1/genSCRIPT_client.$1.sh $1 $2 $3 $6 \
	$7 $client_bogus_pass
	
}


# 6.2.3.3.1 Client Administration


# Arguments: ($1), ($2), ($3)
# $1. Fluidity Connection ID [SSH_ID.SSL_ID]
# $2. Client IP address
# $3: Client username (for raspbian OS the default is pi@)

# Sourced Variables: NONE

# Intershell File Variables in use: NONE

# Global Variables in use: NONE

# Generates: Nothing

# Invokes functions:
# 1. isItEncryptedOnClient, with args ($1), ($2), ($3)
# 2. decryptClient, with args ($1), ($2), ($3)

# Function Description: Check the folder status on client machine with 
# function checkForConnectionFolderAndDecrypt. If the
# folder is encrypted, then decrypt it with function decryptClient.

checkForConnectionFolderAndDecrypt () {

   # Take the length of the return string from isItEncryptedOnClient
   # and check whehter is 0. If it is, then the folder should be decrypted
   # with decryptClient. Else, the folder is already decrypted.
   if [ -z "$(isItEncryptedOnClient $1 $2 $3)" ] ; then
      echo "connection.$1 folder on client machine is encrypted. Executing ecryptFS."
      decryptClient $1 $2 $3
   else
      echo "connection.$1 folder is already decrypted and ready for use."
   fi
   
}

# Arguments: ($1), ($2), ($3)
# $1. Fluidity Connection ID [SSH_ID.SSL_ID]
# $2. Client IP address
# $3: Client username (for raspbian OS the default is pi@)

# Sourced Variables: NONE

# Intershell File Variables in use: NONE

# Global Variables in use: NONE

# Generates:
# 1. Bash script (.sh): genSCRIPT_isItEncryptedOnClient.sh $1 $2 $3

# Invokes functions:

# Calls the script: 
# 1. genSCRIPT_isItEncryptedOnClient.sh, with args ($1), ($2), ($3)

# Function Description: Generate a script which is executed on client machine
# and polls the specific connection ID folder about its encryption status.

isItEncryptedOnClient () {
   
   
   if [[ ! -e ~/Fluidity_Server/Generated_Scripts/genSCRIPT_isItEncryptedOnClient.sh ]]; then
   
   # Grep the text output from df -T about the encryption status of folder 
   # Fluidity_Client/Connection$1. If encryptfs is mentioned in the output
   # then the folder is considered as decrypted and mounted. If not, then
   # it's encrpyted and should be decrypted.
   echo -e 'ssh $3@$2 df -T | grep -E 'Fluidity_Client/connection.\$1.*ecryptfs'' > \
   ~/Fluidity_Server/Generated_Scripts/genSCRIPT_isItEncryptedOnClient.sh
   chmod 700 ~/Fluidity_Server/Generated_Scripts/genSCRIPT_isItEncryptedOnClient.sh
   
   fi
   
   cd ~/Fluidity_Server/Generated_Scripts
   ./genSCRIPT_isItEncryptedOnClient.sh $1 $2 $3
   cd \

}

# Arguments: ($1), ($2), ($3)
# $1: Fluidity Connection ID [SSH_ID.SSL_ID]
# $2: Client IP address
# $3: Client username (for raspbian OS the default is pi@)

# Sourced Variables: NONE

# Intershell File Variables in use: NONE

# Global Variables in use: NONE

# Generates:
# 1. Bash script (.sh): genSCRIPT_decrClient.sh $1 $2

# Invokes Functions: NONE

# Calls the script:
# 1. genSCRIPT_decrClient.sh $decr_Pass
# in ~/Fluidity_Server/Generated_Scripts

# Function Description: Decrypt the contents of folder ~/Fluidity_Client/Connection$1
# at client machine.

decryptClient () {

   local SSH_ID=${1%.*}

   # Retrieve the decryption password for the specific client
   decr_Pass=$(cat ~/Fluidity_Server/client.$SSH_ID/connection.$1/encr_password.$1.txt)

   # Check whether genSCRIPT_decrClient.sh is already generated. If not,
   # create a generated script that will execute, through SSH, on client's side
   # and decrypt client's contents in ~/Fluidity_Client folder.
   if [[ ! -e ~/Fluidity_Server/Generated_Scripts/genSCRIPT_decrClient.sh ]]; then
   
      echo -e 'expect << EOF' \
'\nspawn sudo mount -t ecryptfs \\'\
'\n-o key=passphrase:passphrase_passwd=$2,\\'\
'\necryptfs_cipher=aes,\\'\
'\necryptfs_key_bytes=32,\\'\
'\necryptfs_enable_filename=y,\\'\
'\necryptfs_passthrough=n,\\'\
'\necryptfs_enable_filename_crypto=y\\'\
'\n ./Fluidity_Client/connection.$1 ./Fluidity_Client/connection.$1'\
'\n expect {'\
'\n	 {\\]: } {send "\\n"}'\
'\n }'\
'\n expect {'\
'\n	 "(yes/no)? :" {send "yes\\n"}'\
'\n	 eof {send ""}'\
'\n }'\
'\n expect {'\
'\n	 "(yes/no)? :" {send "yes\\n"}'\
'\n	 eof {send ""}'\
'\n }'\
'\n expect eof'\
'\nEOF'\
      > genSCRIPT_decrClient.sh
      chmod 700 genSCRIPT_decrClient.sh
      mv genSCRIPT_decrClient.sh ~/Fluidity_Server/Generated_Scripts
      
   fi

   # SSH remotely execute genSCRIPT_decrClient.sh
   ssh $3@$2 'bash -s' < ~/Fluidity_Server/Generated_Scripts/genSCRIPT_decrClient.sh \
	$1 $decr_Pass

}

# Arguments: ($1), ($2), ($3)
# $1: Fluidity Connection ID [SSH_ID.SSL_ID]
# $2: Client IP address
# $3: Client username (for raspbian OS the default is pi@)

# Sourced Variables: NONE

# Intershell File Variables in use: NONE

# Global Variables in use: NONE

# Generates: Nothing
 
# Invokes Functions: NONE

# Calls the script: NONE

# Function Description: When invoked, encrypts the contents of folder
# ~/Fluidity_Client.

encryptClient () {
	
   local SSH_ID=${1%.*}
   
   # Execute through SSH and unmount target directory
   # ~/Fluidity_Client/Connection$1 from ecryptfs.
   ssh $3@$2 sudo umount ~/Fluidity_Client/connection.$1

}


# 6.3 Engine Auxillary Functions
# 6.3.1 Public Functions


# Arguments: ($1) 
# $1: Fluidity Client (SSH) Connection ID.
# $2: Fluidity Virtual Circuit (SSL) Connection ID.

# Sourced Variables: NONE

# Intershell File Variables in use:
# $1. sleep_pid (setSleepPid, getSleepPid)

# Global Variables in use: NONE

# Generates: Nothing

# Invokes Functions: NONE

# Calls the script: NONE

# Function Description: This function is used to forcefully take 
# runPersistentSOCATClient out of its dormant state by terminating its 
# underlying SLEEP process, thus re-igniting a PINGing effort towards 
# the client that server lost communication.

forcePing () {
   
   # Derive the fluidity_id
   local fluidity_id=$(echo $1.$2)
   
   # kill -0 verifies the existance of a sleeping process ID.

   # Case 1: The improper scenario.
   # A garbage value has remained from a previous sleeping process. 
   # kill -0 reports that the specific $sleep_pid doesn't exist while 
   # runPersistentSOCATClient is currently in ACTIVE state.
   if ! kill -0 $(getSleepPid $fluidity_id); then

      # Information message to user.
      echo "Not in sleep mode"
   
   # Case 2: The proper scenario.
   # $sleep_id is 0. There is no sleeping process to kill.
   elif [[ $(getSleepPid $fluidity_id) -eq 0 ]]; then

      # Information message to user.
      echo "Not in sleep mode. sleep_pid = 0."

   # Case 3: Kill the sleeping process.
   # A sleeping process is currently running. We fetch the PID from
   # Intershall File Variable $sleep_pid and request its termination.
   else

      # Information message to user.
      echo "in sleep mode and shall be terminated. sleep_pid: $(getSleepPid $1)"
      kill $(getSleepPid $fluidity_id)

   fi
   
   # Set $termination_force_ping to 1.
   # Signal to calling function that terminationForcePing 
   # completed successfully.
   setSleepPid $fluidity_id 0

}


# 7. Fluidity Connection Status Functions
# 7.1 Public Functions

# Arguments: ($1)
# $1: Fluidity Client (SSH) Connection ID.
# $2: Fluidity Virtual Circuit (SSL) Connection ID.

# Sourced Variables:
# 1. ~/Fluidity_Server/client.$SSH_ID/connection.$1/link_information.txt
      # Case 1: $fluidity_flavour_choice equals to -s (i.e. serial link)
      
         # 1. $fluidity_connection_ID
         # 2. $server_serial_int
         # 3. $server_listening_port
         # 4. $client_serial_int
         # 5. $client_ip_add
         # 6. $client_username
         # 7. $link_serial_speed
         # 8. $server_ip_add
         # 9. $fluidity_flavour_choice
         
      # Case 2: fluidity_flavour_choice equals to -t (i.e. tunnel link)
      
         # 1. $fluidity_connection_ID
         # 2. $server_tunnel_ip
         # 3. $server_listening_port
         # 4. $client_tunnel_ip
         # 5. $client_ip_add
         # 6. $client_username
         # 7. $tunneling_network_subnet_mask
         # 8. $server_ip_add
         # 9. $fluidity_flavour_choice

# Intershell File Variables in use:
# 1. $fluidity_connection_status (setFluidityConnectionStatus, getFluidityConnectionStatus)

# Global Variables in use: NONE

# Generates: Nothing

# Invokes Functions: NONE

# Calls the script: NONE

# Function Description: Displays the current connection status.

showLinkStatus () {
   
   # Safety check 1:
   # Connection is missing.
   if [ ! -d ~/Fluidity_Server/client.$1/connection.$1.$2 ]; then
      # Message to user.
      echo "connection.$1.$2 does not exist."
      return
   # Safety check 2:
   # Connection is INACTIVE
   elif [ -d ~/Fluidity_Server/client.$1/connection.$1.$2 ]\
    && [ ! -f ~/Fluidity_Server/client.$1/connection.$1.$2/link_information.txt ]; then
      echo -e 'Fluidity Connection ID: '$fluidity_connection_ID\
       '\nFluidity Connection Status: '$(getFluidityConnectionStatus $fluidity_connection_ID)'\n'
      return
   fi
   
   # Import the following set of variables:
   
      # Case 1: $fluidity_flavour_choice equals to -s (i.e. serial link)
      
         # 1. $fluidity_connection_ID
         # 2. $server_serial_int
         # 3. $server_listening_port
         # 4. $client_serial_int
         # 5. $client_ip_add
         # 6. $client_username
         # 7. $link_serial_speed
         # 8. $server_ip_add
         # 9. $fluidity_flavour_choice
         
      # Case 2: $fluidity_flavour_choice equals to -t (i.e. tunnel link)
      
         # 1. $fluidity_connection_ID
         # 2. $server_tunnel_ip
         # 3. $server_listening_port
         # 4. $client_tunnel_ip
         # 5. $client_ip_add
         # 6. $client_username
         # 7. $tunneling_network_subnet_mask
         # 8. $server_ip_add
         # 9. $fluidity_flavour_choice
   source ~/Fluidity_Server/client.$1/connection.$1.$2/link_information.txt
   
   # Use netstat and pipe the output to grep. According to
   # $server_listening_port grep the line referring to that specific 
   # port and save it to $netstat_connection_status_string.
   local netstat_connection_status_string=$(netstat -atnp 2>/dev/null | grep $server_listening_port)
   
   # Use cut to compartmentalize the line. Fetch the sixth element. Use
   # the whitespace ' ' delimeter character. Save the result
   # to $netstat_connection_status.
   local netstat_connection_status=$(echo $netstat_connection_status_string| cut -d' ' -f 6)
   
   # Case 1: Serial Link
   if [[ "$fluidity_flavour_choice" == -s ]]; then
   
      echo -e 'Fluidity Connection ID: '$fluidity_connection_ID\
       '\nFluidity Flavour: Serial Link'\
       '\nSerial Link Speed: '$link_serial_speed\
       '\nServer Listening Port: '$server_listening_port\
       '\nServer Serial Interface: '$server_serial_int\
       '\nServer IP Address: '$server_ip_add\
       '\nClient Serial Interface: '$client_serial_int\
       '\nClient IP Address: '$client_ip_add\
       '\nClient Username: '$client_username\
       '\nNetstat Reports: '$netstat_connection_status\
       '\nFluidity Connection Status: '$(getFluidityConnectionStatus $fluidity_connection_ID)
       # Special case 1
       # SLEEPING state detected. Display an extra information message
       # to user, showing the remaining time until the next ping.
       if [ $(getFluidityConnectionStatus $fluidity_connection_ID) == "SLEEPING" ]; then
         echo -e 'Next Ping in '$(getPingDelay $fluidity_connection_ID)' seconds.'
       fi
   
   # Case 2: Ethernet tunnel link
   elif [[ "$fluidity_flavour_choice" == -t ]]; then
   
      echo -e 'Fluidity Connection ID: '$fluidity_connection_ID\
       '\nFluidity Flavour: Tunnel Link'\
       '\nServer Listening Port: '$server_listening_port\
       '\nServer IP Address: '$server_ip_add\
       '\nServer Tunnel IP Address: '$server_tunnel_ip\
       '\nClient IP Address: '$client_ip_add\
       '\nClient Tunnel IP Address: '$client_tunnel_ip\
       '\nNetwork Subnet Mask: '$tunneling_network_subnet_mask\
       '\nClient Username: '$client_username\
       '\nNetstat Reports: '$netstat_connection_status\
       '\nFluidity Connection Status: '$(getFluidityConnectionStatus $fluidity_connection_ID)
       # Special case 1
       # SLEEPING state detected. Display an extra information message
       # to user, showing the remaining time until the next ping.
       if [ $(getFluidityConnectionStatus $fluidity_connection_ID) == "SLEEPING" ]; then
         echo -e 'Next Ping in '$(getPingDelay $fluidity_connection_ID)' seconds.'
       fi
       
   fi
   
}


# 8. Auxillary Functions
# 8.1 Public Auxillary Functions


# Arguments: ($1)
# $1: SSH Connection ID

# Sourced Variables: NONE

# Intershell File Variables in use: NONE

# Global Variables in use: NONE

# Generates: Nothing

# Invokes Functions: NONE

# Calls the script: NONE

# Function Description: User function that imports an existing SSH ID,
# after a server reboot. 
recallSSHidentity () {

   # Trick to emulate the home directory shortcut (~/) in expect body
   # for ssh-add
   dir_ssh=$(echo ~/.ssh)

   # Import the key for clientX
expect << EOF
      spawn ssh-add $dir_ssh/client.$1
      expect "client.$1: "
      send "[read [open "~/Fluidity_Server/SSH_Vault/SSH_Passphrases/passphrase.$1.txt" r]]\n"
      expect eof
EOF

   # Display active SSH identities
   ssh-add -l

}

# Arguments: NONE

# Sourced Variables: NONE

# Intershell File Variables in use: NONE

# Global Variables in use: NONE

# Generates: Nothing

# Invokes Functions: NONE

# Calls the script: NONE

# Function Description: User function that displays in a quick, simple way
# the serial controllers installed to the specific PC. 
displaySerialDevices () {

   sudo dmesg | grep tty

}

# Arguments: ($1), ($2), ($3), ($4)
# $1: New hostname.
# $2: Client IP address.
# $3: Client username

# Sourced Variables: NONE

# Intershell File Variables in use: NONE

# Global Variables in use: NONE

# Generates: Nothing

# Invokes Functions: NONE

# Calls the script: NONE

# Function Description: Auxillary function to SSHclientAccess that changes
# the hostname to target client.
changeRemoteHostName () {

   ssh $3@$2 sudo hostnamectl set-hostname $1

}


# 8.2 Private Auxillary Functions


# Arguments: NONE

# Sourced Variables: NONE

# Intershell File Variables in use: NONE

# Global Variables in use: NONE

# Generates: Nothing

# Invokes Functions: NONE

# Calls the script: NONE

# Function Description: Boost server entropy by installing 
# HAVEGED or rng-tools.

giveAnEntropyBoost () {
   
   if ! [ -x "$(command -v haveged)" ] && [ -x "$(command -v rngd)" ]; then
   
      # Looped user prompt: Ask for input until a valid choice is given.
      # Valid choice 1.: Install Haveged
      # Valid choice 2.: Install rng-tools
      while true; do
         echo -e \
         '\nFluidity requires a high quality entropy source'\
         '\nWhich utility you prefer to choose?'\
         '\n1. for Haveged'\
         '\n2. for rng-tools'\
         && read -p '_' choice
         # CASE 1: For choice=1 install Haveged
         case $choice in
         [1]* ) echo "Installing Haveged"
            sudo apt-get -y install haveged
            # Start the "HAVEGED" service
            sudo systemctl start haveged
         break;;
         # CASE 2: For choice=2 install rng-tools
         [2]* ) echo "Installing rng-tools"
            sudo apt-get -y install rng-tools
            # Start the "rng-tools" service
            sudo systemctl start rng-tools
         break;;
         # Error handling case:
         # Display the valid choices (1 or 2) and loop again.
         * ) echo "1 for Haveged, 2 for rng-tools";;
         esac
      done
   
   elif [ -x "$(command -v haveged)" ]; then
      echo "Haveged is already installed"
   else
      echo "rng-tools are already installed"
   fi
  
   # Perform an entropy check on local machine and return a warning message if
   # entropy is still below 1000.
   if [ $(checkLocalEntropy) == 0 ]; then
      echo -e \
      'Warning!\nEntropy is below minimum entropy requirements (less than 1000).'\
      '\nIf you are on a newly configured Fluidity server,'\
      '\nwait the entropy to be increased before adding Fluidity client.'
   elif [ $(checkLocalEntropy) == 1 ]; then
      echo -e \
      'Entropy is withing limits (more than 1000).'\
      '\nIf you are on a newly configured Fluidity server, you can now'\
      '\nproceed adding a new client by using addFluidityClient.'
   fi

}

# Arguments: NONE

# Sourced Variables: NONE

# Intershell File Variables in use: NONE

# Global Variables in use: NONE

# Generates: Nothing

# Invokes Functions: NONE

# Calls the script: NONE

# Function Description: Perform a Fluidity file structure integrity 
# check. In case of success return: 1.
checkFluidityFilesystemIntegrity () {
   
   if [ ! -d ~/Fluidity_Server ]; then
      echo "Fluidity file structure integrity test FAILED. ~/Fluidity_Server folder doesn't exist."
   elif [ ! -d ~/Fluidity_Server/Generated_Scripts ]; then
      echo "Fluidity file structure integrity test FAILED. ~/Fluidity_Server/Generated_Scripts folder doesn't exist."
   elif [ ! -d ~/Fluidity_Server/SSH_Vault ]; then
      echo "Fluidity file structure integrity test FAILED. ~/Fluidity_Server/SSH_Vault folder doesn't exist."
   elif [ ! -d ~/Fluidity_Server/SSH_Vault/SSH_Passphrases ]; then
      echo "Fluidity file structure integrity test FAILED. ~/Fluidity_Server/SSH_Vault/SSH_Passphrases folder doesn't exist."
   elif [ ! -d ~/Fluidity_Server/SSH_Vault/SSH_Keys ]; then
      echo "Fluidity file structure integrity test FAILED. ~/Fluidity_Server/SSH_Vault/SSH_Keys folder doesn't exist."
   elif [ ! -d ~/Fluidity_Server/SSL_Cert_Vault ]; then
      echo "Fluidity file structure integrity test FAILED. ~/Fluidity_Server/SSL_Cert_Vault folder doesn't exist."
   elif [ ! -d ~/.ssh ]; then
      echo "Fluidity file structure integrity test FAILED. Hidden folder ~/.ssh doesn't exist."
   else
      # File structure integrity test passed. Return: 1.
      echo "1"
   fi

}

# Arguments: NONE

# Sourced Variables: NONE

# Intershell File Variables in use: NONE

# Global Variables in use: NONE

# Generates: Nothing

# Invokes Functions: NONE

# Calls the script: NONE

# Function Description: Entropy check on local system. For less than
# 1000 the function returns 0. For more than 1000 returns 1.
checkLocalEntropy () {

   if [ $(cat /proc/sys/kernel/random/entropy_avail) -lt "1000" ]; then
      echo "0"
   else
      echo "1"
   fi

}

# Arguments: ($1), ($2)
# $1: Client IP.
# $2: Client Username.

# Sourced Variables: NONE

# Intershell File Variables in use: NONE

# Global Variables in use: NONE

# Generates:
# 1. Bash script (.sh): genSCRIPT_checkRemoteEntropy.sh

# Invokes Functions: NONE

# Calls the script:
# 1. genSCRIPT_checkRemoteEntropy.sh, no args 
# in ~/Fluidity_Server/Generated_Scripts

# Function Description: Entropy check at the remote system. 
# For less than 1000 the function returns 0. For more than 1000 
# returns 1.
checkRemoteEntropy () {
   
   if [[ ! -e ~/Fluidity_Server/Generated_Scripts/genSCRIPT_checkRemoteEntropy.sh ]]; then
   
      echo -e \
      '\nif [ $(cat /proc/sys/kernel/random/entropy_avail) -lt "1000" ]; then'\
      '\n   echo "0"'\
      '\nelse'\
      '\n   echo "1"'\
      '\nfi' > \
      ~/Fluidity_Server/Generated_Scripts/genSCRIPT_checkRemoteEntropy.sh
      chmod 700 ~/Fluidity_Server/Generated_Scripts/genSCRIPT_checkRemoteEntropy.sh
   
   fi
   
   # SSH remotely execute genSCRIPT_checkRemoteEntropy.sh
   ssh $2@$1 'bash -s' < ~/Fluidity_Server/Generated_Scripts/genSCRIPT_checkRemoteEntropy.sh
  
}


