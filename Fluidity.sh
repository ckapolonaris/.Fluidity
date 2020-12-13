#!/bin/bash

#
# Script Name: Fluidity.sh
#
# Charalampos Kapolonaris: Technical Lead
# Vasilios Koutlas: Software Tester
#
# Description: .Fluidity is a SOCAT SSL connection manager. It's based on
# a server - client model and focuses on the creation and management
# of SOCAT SSL connections for secure and encrypted communication.
# More specifically, it can add - remove clients and create, remove and
# administer SOCAT SSL connections.
#
# Execution Information: This script is executed manually.


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
# nominally define a set of functions, as the equivalent of a public 
# interface and another set as the private interface. Below we present 
# the list of .Fluidity's functions that comprise the public interface.


# .Fluidity Public Interface
#
# Server Functions
# 
# 1. Server Creation - Configuration Functions
#		installFluidity
#		reinstallFluidity
#		mountFluidityServerFolder
# 2. Client Management Functions
#		addFluidityClient
#		removeFluidityClient
# 3. Connection Management Functions
#		addFluidityConnection
#		removeFluidityConnection
#		renewSSL
# 4. .Fluidity Engine Functions
#		runFluidity
#		stopFluidity
# 5. .Fluidity Connection Status Functions
#		showLinkStatus
# 6. General Auxillary Functions
#		recallSSHidentity
#		displaySerialDevices
#		findInterfaceFromIP
# 7. VPN Routing
#		addServerRoute
#		removeServerRoute
#		addClientRoute
#		removeClientRoute
# 8. Managing Internal Interfaces
#		setInternalInterface
#		removeInternalInterface
#
# Client Functions
#
# 1. Preliminary Client Configuration
#		fluidityClientConfiguration
# 2. Managing Internal Interfaces
#		setInternalInterface
#		removeInternalInterface


# The Complete .Fluidity Program Structure
# 
# 1. .Fluidity Intershell Variables
# 		setPingDelay +
#		getPingDelay +
#		setAllowExecution +
#		getAllowExecution +
#		setPort +
#		getPort +
#		setServerIsTerminated +
#		getServerIsTerminated +
#		setClientIsTerminated +
#		getClientIsTerminated +
#		setSleepPid +
#		getSleepPid +
#		setTerminationForcePing +
#		getTerminationForcePing +
#		setFluidityConnectionStatus +
#		getFluidityConnectionStatus + 16 functions
# 2. Server Creation - Configuration Functions
# 	2.1 Public Functions
#		installFluidity +
#		reinstallFluidity +
#		mountFluidityServerFolder +
# 	2.2 Private Functions
#		fluidityServerConfiguration +
#		mainServerFolderCreation +
#		serverFolderBackboneCreation + 6 functions
# 3. Direct Client Creation - Configuration Functions
# 	3.1 Public Functions
#		fluidityClientConfiguration + 1 function
# 4. Client Management Functions
# 	4.1 Public Functions
#		addFluidityClient +
#		removeFluidityClient +
# 	4.2 Private Functions
#		removeLocalClientData
#		fluidityRemoteClientConfiguration +
#		remoteSeekAndEncryptDaemon + 4 functions
# 5. Connection Management Functions
# 	5.1 Public Functions
#		addFluidityConnection +
#		removeFluidityConnection +
#		renewSSL +
# 	5.2 Private Functions
#		internalSSLrenew +
#		installSSLcertificates +
#		reinstallSSLcerts +
#		clientFolderCreation +
#		clientSSLinstallation +
#		deleteSSLpair +
#		copyDoNotEncryptToken +
#		deleteDoNotEncryptToken + 11 functions
# 6. .Fluidity Engine Functions
# 	6.1 Public Functions
#		runFluidity +
#		stopFluidity +
# 	6.2 Private Functions
#		6.2.1 Firewalling
#			openPort +
#			closePort +
#			openTheTunnelInterfaces +
#			openTheLocalTunnelInterface +
#			openTheRemoteTunnelInterface +
#			closeTheLocalTunnelInterface +
#			closeTheRemoteTunnelInterface +
#		6.2.2 Engine Administration
#			terminationForcePing +
#			stopFluidityToRenewSSLcerts +
#		6.2.3 Link Setup
#			establishSOCATlink +
#			6.2.3.1  Link State Information Administration
#				6.2.3.1.1 Managing Static Information
#					storeSOCATlinkStateInformation +
#					deleteSOCATlinkStateInformation +
#				6.2.3.1.2 Managing Dynamic Information
#					initilizeRunTimeVars +
#					destroyRunTimeVars +
#			6.2.3.2 Server Setup
#				runPersistentSOCATServer +
#				runSOCATserver +
#				runSerialSOCATserver +
#				runTUNnelSOCATserver +
#			6.2.3.3 Client Setup
#				runPersistentSOCATClient +
#				runSOCATclient +
#				runSerialSOCATclient +
#				runTUNnelSOCATclient +
#				6.2.3.3.1 Client Administration
#					checkForConnectionFolderAndDecrypt +
#					isItEncryptedOnClient +
#					decryptClient +
#					encryptClient +
#					deleteTokenFromClient +
#		6.2.4 SSL Certificates Verification Functions
#			verifyThatResetSSLisMissing +
#			verifyThatSSLCertificatesExist +
#			doAClientServerMD5EquivalencyCheck +
#			doAClientServerSHA256EquivalencyCheck +
#		6.2.5 VPN Routing
#			injectTheListOfFluidityConnectionRoutes +
#			injectTheListOfServerRoutes +
#			injectTheListOfClientRoutes +
#		6.2.6 Engine Reporting
#			reportWhenLinkIsEstablished +
#			reportWhenFirewallRulesAreAdded +
#			reportWhenFirewallRulesAreRemoved +
# 	6.3 Engine Auxillary Functions
#		6.3.1 Public Functions
#			forcePing + 39 functions
# 7. .Fluidity Connection Status Functions
# 	7.1 Public Functions
#		showLinkStatus + 1 function
# 8. General Auxillary Functions
# 	8.1 Public Functions
#		recallSSHidentity +
#		displaySerialDevices +
#		findInterfaceFromIP +
# 	8.2 Private Functions
#		giveAnEntropyBoost +
#		checkFluidityFilesystemIntegrity +
#		checkLocalEntropy +
#		checkRemoteEntropy +
#		getNetstatConnectionStatus +
#		getTheRemotePort +
#		removeFluidityClientConfigInfoFromSSHConfig + 10 functions
# 9. Managing Internal Interfaces
# 	9.1 Public Functions
#		setInternalInterface + 
#		removeInternalInterface + 2 functions
# 10. VPN Routing
# 	10.1 Public Functions
#		addServerRoute +
#		removeServerRoute +
#		addClientRoute +
#		removeClientRoute + 4 functions

# Counting 96 functions in total.

# List of Quickfind tags:
# 1.  Branching points that define the .Fluidity flavour to be used: kzjFgtUz
# 2.  Points in which .Fluidity does an SSH call to a client machine: heefhEKX
# 3.  Points in which .Fluidity uses SCP to sent a file to a client machine: vvtSng7u
# 4.  Debugging section: rZ7y4zq
# 5.  Command line suppressor: S99zBE5 
# 6.  Self-signed certificate information fields: tQscITd

# List of GREP tags:
# 1. Deduce the external interface IP from UFW SSH rule: HFBCvIa7h


# 1. .Fluidity Intershell Variables


# SET function for Intershell Variable: ping_delay
setPingDelay () {
   
   local SSH_ID=${1%.*}
   echo "sed -i '1s/.*/$(echo local ping_delay="$2")/' ~/Fluidity_Server/client.$SSH_ID/connection.$1/runtimeVars/ping_delay" | bash -
   
   
}

# GET function for Intershell Variable: ping_delay
getPingDelay () {
   
   local SSH_ID=${1%.*}
   
   local FILE=$(eval echo ~$USER)'/Fluidity_Server/client.'$SSH_ID'/connection.'$1'/runtimeVars/ping_delay'
   
   # For an active connection.
   if [ -f "$FILE" ]; then
      source ~/Fluidity_Server/client.$SSH_ID/connection.$1/runtimeVars/ping_delay
      echo $ping_delay
   # For an inactive connection 
   else
      echo null
   fi
   
}

# SET function for Intershell Variable: allow_execution
setAllowExecution () {

   local SSH_ID=${1%.*}
   echo "sed -i '1s/.*/$(echo local allow_execution="$2")/' ~/Fluidity_Server/client.$SSH_ID/connection.$1/runtimeVars/allow_execution" | bash -

}

# GET function for Intershell Variable: allow_execution
getAllowExecution () {
	
   local SSH_ID=${1%.*}
   
   local FILE=$(eval echo ~$USER)'/Fluidity_Server/client.'$SSH_ID'/connection.'$1'/runtimeVars/allow_execution'
   
   # For an active connection.
   if [ -f "$FILE" ]; then
      source ~/Fluidity_Server/client.$SSH_ID/connection.$1/runtimeVars/allow_execution
      echo $allow_execution
   # For an inactive connection 
   else
      echo null
   fi
	
}

# SET function for Intershell Variable: port
setPort () {
   
   local SSH_ID=${1%.*}
   echo "sed -i '1s/.*/$(echo local port="$2")/' ~/Fluidity_Server/client.$SSH_ID/connection.$1/runtimeVars/port" | bash -
	
}

# GET function for Intershell Variable: port
getPort () {
   
   local SSH_ID=${1%.*}
   
   local FILE=$(eval echo ~$USER)'/Fluidity_Server/client.'$SSH_ID'/connection.'$1'/runtimeVars/port'
   
   # For an active connection.
   if [ -f "$FILE" ]; then
      source ~/Fluidity_Server/client.$SSH_ID/connection.$1/runtimeVars/port
      echo $port
   # For an inactive connection 
   else
      echo null
   fi
   
}

# SET function for Intershell Variable: server_is_terminated
setServerIsTerminated () {

   local SSH_ID=${1%.*}
   echo "sed -i '1s/.*/$(echo local server_is_terminated="$2")/' ~/Fluidity_Server/client.$SSH_ID/connection.$1/runtimeVars/server_is_terminated" | bash -
	
}

# GET function for Intershell Variable: server_is_terminated
getServerIsTerminated () {
	
   local SSH_ID=${1%.*}
   
   local FILE=$(eval echo ~$USER)'/Fluidity_Server/client.'$SSH_ID'/connection.'$1'/runtimeVars/server_is_terminated'
   
   # For an active connection.
   if [ -f "$FILE" ]; then
      source ~/Fluidity_Server/client.$SSH_ID/connection.$1/runtimeVars/server_is_terminated
      echo $server_is_terminated
   # For an inactive connection 
   else
      echo null
   fi
   
}

# SET function for Intershell Variable: client_is_terminated
setClientIsTerminated () {

   # VARIABLE: client_is_terminated
   # Signalling variable. Two possible values, 0 or 1. 
   # 1 means that runSOCATclient is out of its main infinite loop and has
   # been terminated successfully.
   
   local SSH_ID=${1%.*}
   echo "sed -i '1s/.*/$(echo local client_is_terminated="$2")/' ~/Fluidity_Server/client.$SSH_ID/connection.$1/runtimeVars/client_is_terminated" | bash -
	
}

# GET function for Intershell Variable: client_is_terminated
getClientIsTerminated () {
	
   local SSH_ID=${1%.*}
   
   local FILE=$(eval echo ~$USER)'/Fluidity_Server/client.'$SSH_ID'/connection.'$1'/runtimeVars/client_is_terminated'
   
   # For an active connection.
   if [ -f "$FILE" ]; then
      source ~/Fluidity_Server/client.$SSH_ID/connection.$1/runtimeVars/client_is_terminated
      echo $client_is_terminated
   # For an inactive connection 
   else
      echo null
   fi
   	
}

# SET function for Intershell Variable: sleep_pid
setSleepPid () {

   local SSH_ID=${1%.*}
   echo "sed -i '1s/.*/$(echo local sleep_pid="$2")/' ~/Fluidity_Server/client.$SSH_ID/connection.$1/runtimeVars/sleep_pid" | bash -

}

# GET function for Intershell Variable: sleep_pid
getSleepPid () {
	
   local SSH_ID=${1%.*}
   
   local FILE=$(eval echo ~$USER)'/Fluidity_Server/client.'$SSH_ID'/connection.'$1'/runtimeVars/sleep_pid'
   
   # For an active connection.
   if [ -f "$FILE" ]; then
      source ~/Fluidity_Server/client.$SSH_ID/connection.$1/runtimeVars/sleep_pid
      echo $sleep_pid
   # For an inactive connection 
   else
      echo null
   fi
}


# SET function for Intershell Variable: termination_force_ping
setTerminationForcePing () {

   local SSH_ID=${1%.*}
   echo "sed -i '1s/.*/$(echo local termination_force_ping="$2")/' ~/Fluidity_Server/client.$SSH_ID/connection.$1/runtimeVars/termination_force_ping" | bash -
	
}

# GET function for Intershell Variable: termination_force_ping
getTerminationForcePing () {
   
   local SSH_ID=${1%.*}
   
   local FILE=$(eval echo ~$USER)'/Fluidity_Server/client.'$SSH_ID'/connection.'$1'/runtimeVars/termination_force_ping'
   
   # For an active connection.
   if [ -f "$FILE" ]; then
      source ~/Fluidity_Server/client.$SSH_ID/connection.$1/runtimeVars/termination_force_ping
      echo $termination_force_ping
   # For an inactive connection 
   else
      echo null
   fi

}

# SET function for Intershell Variable: connection_status
setFluidityConnectionStatus () {

   local SSH_ID=${1%.*}
   echo "sed -i '1s/.*/$(echo local fluidity_connection_status="$2")/' ~/Fluidity_Server/client.$SSH_ID/connection.$1/runtimeVars/fluidity_connection_status" | bash -
	
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

# Function Description: .Fluidity first time setup utility. This
# is the starting point to a new .Fluidity installation.
installFluidity () {

   # First check: If ~/Fluidity_Server already exists then reinstall 
   # .Fluidity
   if [ -d ~/Fluidity_Server ]; then
      clear
      echo -e "WARNING! FLUIDITY SERVER FOLDER DETECTED!\n\n\n"
      sleep 4
      
      #Invoke reinstallFluidity
      if reinstallFluidity | tee /dev/stderr | grep "Fluidity installation cancelled"; then
         return
      fi
      
   fi

   # Looped user prompt: Ask the user whether he/she wants to proceed
   # with a new .Fluidity installation. 
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
         if fluidityServerConfiguration | tee /dev/stderr | grep "fluidityServerConfiguration failed"; then
            return
         fi
         
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

# Function Description: .Fluidity reinstallation utility.
# Re-install .Fluidity on an existing .Fluidity 
# installation. The previews installation is totally erased.

reinstallFluidity () {
    
   # Looped user prompt: Ask the user whether he/she wants to proceed
   # with .Fluidity re-installation.
   while true; do
      echo -e \
      '\nWelcome to Fluidity reinstallation utility.'\
      '\nShall we reinstall Fluidity?'\
      '\nType [yes]: To reinstall'\
      '\nType [no]: Cancel and exit back to terminal'\
      && read -p '_' choice
      # CASE 1: YES - Re-install .Fluidity.
      case $choice in
      [yY] | [yY][Ee][Ss] )
         echo -e "\nReinstalling Fluidity"
         
         # Wipe out anything related to a previous .Fluidity 
         # installation.
         cd ~
         sudo umount ~/Fluidity_Server
         rm -r ~/Fluidity_Server
         
         #Invoke fluidityServerConfiguration
         if fluidityServerConfiguration | tee /dev/stderr | grep "fluidityServerConfiguration failed"; then
            return
         fi
         
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

# Function Description: Mount the .Fluidity server folder after a 
# potential reboot.
mountFluidityServerFolder () {
   
   if ! [ -d ~/Fluidity_Server ]; then
   
      echo -e \
      '\n.Fluidity server folder is missing.'\
      '\nPlease check your .Fluidity installation.'
      return
      
   else
   
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
	 {\[**************\]: } {send "\n"}
	 eof {send "\n"}
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
      
      if sudo ufw status | grep "Status: inactive"; then
         expect << EOF
         spawn sudo ufw enable
         expect "operation (y|n)?"
         send "y\r"
         expect eof
EOF
      fi
      
      # Enable the IP forwarding after a potential reboot.
      sudo sysctl -w net.ipv4.ip_forward=1
      
   fi
   
}


# 2. Server Creation - Configuration Functions
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
# the following list of programs.
   # 1. (SOCAT)
   # 2. (ecryptfs-utils) 
   # 3. (expect) 
   # 4. (lsof)
   # 5. (nmap)
   # 6. (sshpass)
   # 7. (Uncomplicated Firewall, UFW)
      # Perform basic firewall configuration i.e.
         # a. Allow outgoing traffic.
         # b. Deny incoming traffic.
         # c. Allow traffic through the firewall.
         # d. Allow inbound SSH connections on port 22.
   # 8. (haveged OR rng-tools)
fluidityServerConfiguration () {

   if [ -x "$(command -v socat)" ] && [ -x "$(command -v ecryptfsd)" ] && \
    [ -x "$(command -v expect)" ] && [ -x "$(command -v lsof)" ] && \
    [ -x "$(command -v nmap)" ] && [ -x "$(command -v sshpass)" ] && \
    [ -x "$(command -v ufw)" ]; then
    
      echo "All packages are present in the system."
      echo ".Fluidity is ready to be installed."
    
   else

      # Perform a system update.
      if ping -c 3 8.8.8.8; then
         sudo apt-get update && sudo apt-get -y upgrade
      else
         echo -e 'System update failed.'\
          '\nPlease check your internet connection to proceed with the'\
          '\n.Fluidity installation.'\
          '\nCanceling the installation procedures.'
          echo "fluidityServerConfiguration failed"
          return
      fi
      # Verify and if not present install "SOCAT"
      if ! [ -x "$(command -v socat)" ]; then
         if ! sudo apt-get -y install socat; then
            echo -e 'SOCAT installation failed.'\
             '\nPlease check your internet connection to proceed with the'\
             '\n.Fluidity installation.'\
             '\nCanceling the installation procedures.'
             echo "fluidityServerConfiguration failed"
             return
         fi
      fi
      # Verify and if not present install the 111.5 ecryptfs version
      if ! [ -x "$(command -v ecryptfsd)" ]; then
         if ping -c 3 8.8.8.8; then
         
            DEPS="gettext-base keyutils libassuan0 libgpg-error0 libc6 libkeyutils1 libpam-runtime 
            libgpg-error0 libpam0g libgpgme11 libtspi1 cryptsetup cryptsetup lsof rsync libnss3"
            sudo apt-get install $DEPS
            
            if lscpu | grep ARM; then
            
               wget http://snapshot.debian.org/archive/debian-debug/20200802T203936Z/pool/main/e/ecryptfs-utils/libecryptfs1-dbgsym_111-5_armhf.deb
               wget http://snapshot.debian.org/archive/debian/20200802T204950Z/pool/main/e/ecryptfs-utils/libecryptfs1_111-5_armhf.deb
               wget http://snapshot.debian.org/archive/debian/20200802T204950Z/pool/main/e/ecryptfs-utils/libecryptfs-dev_111-5_armhf.deb
               wget http://snapshot.debian.org/archive/debian-debug/20200802T203936Z/pool/main/e/ecryptfs-utils/ecryptfs-utils-dbgsym_111-5_armhf.deb
               wget http://snapshot.debian.org/archive/debian/20200802T204950Z/pool/main/e/ecryptfs-utils/ecryptfs-utils_111-5_armhf.deb
            
               sudo dpkg -i libecryptfs1_111-5_armhf.deb
               sudo dpkg -i libecryptfs1-dbgsym_111-5_armhf.deb
               sudo dpkg -i libecryptfs-dev_111-5_armhf.deb
               sudo dpkg -i ecryptfs-utils_111-5_armhf.deb
               sudo dpkg -i ecryptfs-utils-dbgsym_111-5_armhf.deb
               
            elif lscpu | grep AMD; then
            
               wget http://snapshot.debian.org/archive/debian-debug/20200802T203936Z/pool/main/e/ecryptfs-utils/libecryptfs1-dbgsym_111-5_amd64.deb
               wget http://snapshot.debian.org/archive/debian/20200802T204950Z/pool/main/e/ecryptfs-utils/libecryptfs1_111-5_amd64.deb
               wget http://snapshot.debian.org/archive/debian/20200802T204950Z/pool/main/e/ecryptfs-utils/libecryptfs-dev_111-5_amd64.deb
               wget http://snapshot.debian.org/archive/debian-debug/20200802T203936Z/pool/main/e/ecryptfs-utils/ecryptfs-utils-dbgsym_111-5_amd64.deb
               wget http://snapshot.debian.org/archive/debian/20200802T204950Z/pool/main/e/ecryptfs-utils/ecryptfs-utils_111-5_amd64.deb
               
               sudo dpkg -i libecryptfs1_111-5_amd64.deb
               sudo dpkg -i libecryptfs1-dbgsym_111-5_amd64.deb
               sudo dpkg -i libecryptfs-dev_111-5_amd64.deb
               sudo dpkg -i ecryptfs-utils_111-5_amd64.deb
               sudo dpkg -i ecryptfs-utils-dbgsym_111-5_amd64.deb
               
            elif lscpu | grep GenuineIntel; then
            
               wget http://snapshot.debian.org/archive/debian-debug/20200802T203936Z/pool/main/e/ecryptfs-utils/libecryptfs1-dbgsym_111-5_i386.deb
               wget http://snapshot.debian.org/archive/debian/20200802T204950Z/pool/main/e/ecryptfs-utils/libecryptfs1_111-5_i386.deb
               wget http://snapshot.debian.org/archive/debian/20200802T204950Z/pool/main/e/ecryptfs-utils/libecryptfs-dev_111-5_i386.deb
               wget http://snapshot.debian.org/archive/debian-debug/20200802T203936Z/pool/main/e/ecryptfs-utils/ecryptfs-utils-dbgsym_111-5_i386.deb
               wget http://snapshot.debian.org/archive/debian/20200802T204950Z/pool/main/e/ecryptfs-utils/ecryptfs-utils_111-5_i386.deb
               
               sudo dpkg -i libecryptfs1_111-5_i386.deb
               sudo dpkg -i libecryptfs1-dbgsym_111-5_i386.deb
               sudo dpkg -i libecryptfs-dev_111-5_i386.deb
               sudo dpkg -i ecryptfs-utils_111-5_i386.deb
               sudo dpkg -i ecryptfs-utils-dbgsym_111-5_i386.deb
               
            fi
         else
            echo -e 'EcryptFS installation failed.'\
             '\nPlease check your internet connection to proceed with the'\
             '\n.Fluidity installation.'\
             '\nCanceling the installation procedures.'
            return
         fi
      fi
      
      # Correct the dependencies and do some cleaning before proceeding
      # to the next application.
      sleep 10
      sudo apt-get install --fix-broken --assume-yes
      sleep 10
      sudo apt --fix-broken install
      sleep 10
      
      # Verify and if not present install  "EXPECT"
      if ! [ -x "$(command -v expect)" ]; then
         if ! sudo apt-get -y install expect; then
            echo -e 'Expect installation failed.'\
             '\nPlease check your internet connection to proceed with the'\
             '\n.Fluidity installation.'\
             '\nCanceling the installation procedures.'
             echo "fluidityServerConfiguration failed"
            return
         fi
      fi
      # Verify and if not present install "LSOF"
      if ! [ -x "$(command -v lsof)" ]; then
         if ! sudo apt-get -y install lsof; then
            echo -e 'LSOF installation failed.'\
             '\nPlease check your internet connection to proceed with the'\
             '\n.Fluidity installation.'\
             '\nCanceling the installation procedures.'
             echo "fluidityServerConfiguration failed"
            return
         fi
      fi
      # Verify and if not present install "NMAP"
      if ! [ -x "$(command -v nmap)" ]; then
         if ! sudo apt-get -y install nmap; then
            echo -e 'nmap installation failed.'\
             '\nPlease check your internet connection to proceed with the'\
             '\n.Fluidity installation.'\
             '\nCanceling the installation procedures.'
             echo "fluidityServerConfiguration failed"
            return
         fi
      fi
      # Verify and if not present install "SSHPASS"
      if ! [ -x "$(command -v sshpass)" ]; then
         if ! sudo apt-get -y install sshpass; then
            echo -e 'sshpass installation failed.'\
             '\nPlease check your internet connection to proceed with the'\
             '\n.Fluidity installation.'\
             '\nCanceling the installation procedures.'
             echo "fluidityServerConfiguration failed"
            return
         fi
      fi
      # Verify and if not present install "UFW", 
      # also perform the initial Firewall configuration.
      if ! [ -x "$(command -v ufw)" ]; then
         if ! sudo apt-get -y install ufw; then
            echo -e 'UFW installation failed.'\
             '\nPlease check your internet connection to proceed with the'\
             '\n.Fluidity installation.'\
             '\nCanceling the installation procedures.'
             echo "fluidityServerConfiguration failed"
            return
         fi
      fi
      
   fi
   
   # Basic server firewall configuration
            
   sudo systemctl enable ufw
            
   # Allow all the outgoing traffic
   sudo ufw default allow outgoing
   # Deny all the incoming traffic
   sudo ufw default deny incoming
   # Allow traffic to be forwarded through UFW
   sudo ufw default allow routed
   # Allow SSH connections
   sudo ufw allow ssh
         
   # Invoke giveAnEntropyBoost
   if giveAnEntropyBoost | tee /dev/stderr | grep "giveAnEntropyBoost failed"; then
      echo "fluidityServerConfiguration failed"
   fi
         
   # Enable IP forwarding on Server
   sudo sysctl -w net.ipv4.ip_forward=1
  
}

# Arguments: NONE

# Sourced Variables: NONE

# Intershell File Variables in use: NONE

# Global Variables in use: NONE

# Generates: Nothing

# Invokes Functions: NONE

# Calls the script: NONE

# Function Description: Create and encrypt the .Fluidity_Server folder 
# with ecryptfs-utils, by using a user defined encryption password.
mainServerFolderCreation () {

   # Erase the contents of sig-cache.txt from previous .Fluidity
   # installation attempts.
   sudo truncate -s 0 /root/.ecryptfs/sig-cache.txt

   local encr_pass
   
   echo -e \
      '\nPlease choose your Fluidity master password:'\
      && read -p '_' encr_pass
    
   # FLUIDITY -- Create the main folder
   mkdir ~/Fluidity_Server

   # Encrypt the main folder with ecryptfs-utils and use the following
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
 expect {
	 {\[**************\]: } {send "\n"}
	 eof {send "\n"}
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

# Function Description: Create the main .Fluidity server folder structure 
# (Fluidity_Server)
serverFolderBackboneCreation () {

   # Create "Generated_Scripts" folder to contain .Fluidity's generated scripts
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


# Arguments: NONE

# Sourced Variables: NONE

# Intershell File Variables in use: NONE

# Global Variables in use: NONE

# Generates: Nothing

# Invokes Functions:
# 1. giveAnEntropyBoost, no args

# Calls the script: NONE

# Function Description: Verify the existance and if necessary install
# the following list of programs.
   # 1. (SOCAT)
   # 2. (ecryptfs-utils) 
   # 3. (expect) 
   # 4. (haveged OR rng-tools)
   # 5. (lsof)
   # 6. (Uncomplicated Firewall, UFW)
      # Perform basic firewall configuration i.e.
         # a. Allow outgoing traffic.
         # b. Deny incoming traffic.
         # c. Allow inbound SSH connections on port 22.
fluidityClientConfiguration () {
   
   if [ -x "$(command -v socat)" ] && [ -x "$(command -v ecryptfsd)" ] && \
    [ -x "$(command -v expect)" ] && [ -x "$(command -v lsof)" ] && \
    [ -x "$(command -v ufw)" ]; then
    
      echo "All packages are present in the system."
      echo ".Fluidity is ready to be installed."
    
   else
   
      # Perform a system update.
      if ping -c 3 8.8.8.8; then
         sudo apt-get update && sudo apt-get -y upgrade
      else
         echo -e 'System update failed.'\
          '\nPlease check your internet connection to proceed with the'\
          '\n.Fluidity installation.'\
          '\nCanceling the installation procedures.'
          return
      fi
      # Verify and if not present install "SOCAT"
      if ! [ -x "$(command -v socat)" ]; then
         if ! sudo apt-get -y install socat; then
            echo -e 'SOCAT installation failed.'\
             '\nPlease check your internet connection to proceed with the'\
             '\n.Fluidity installation.'\
             '\nCanceling the installation procedures.'
             return
         fi
      fi
      # Verify and if not present install the 111.5 ecryptfs version
      if ! [ -x "$(command -v ecryptfsd)" ]; then
         if ping -c 3 8.8.8.8; then
         
            DEPS="gettext-base keyutils libassuan0 libgpg-error0 libc6 libkeyutils1 libpam-runtime 
            libgpg-error0 libpam0g libgpgme11 libtspi1 cryptsetup cryptsetup lsof rsync libnss3"
            sudo apt-get install $DEPS
            
            if lscpu | grep ARM; then
            
               wget http://snapshot.debian.org/archive/debian-debug/20200802T203936Z/pool/main/e/ecryptfs-utils/libecryptfs1-dbgsym_111-5_armhf.deb
               wget http://snapshot.debian.org/archive/debian/20200802T204950Z/pool/main/e/ecryptfs-utils/libecryptfs1_111-5_armhf.deb
               wget http://snapshot.debian.org/archive/debian/20200802T204950Z/pool/main/e/ecryptfs-utils/libecryptfs-dev_111-5_armhf.deb
               wget http://snapshot.debian.org/archive/debian-debug/20200802T203936Z/pool/main/e/ecryptfs-utils/ecryptfs-utils-dbgsym_111-5_armhf.deb
               wget http://snapshot.debian.org/archive/debian/20200802T204950Z/pool/main/e/ecryptfs-utils/ecryptfs-utils_111-5_armhf.deb
            
               sudo dpkg -i libecryptfs1_111-5_armhf.deb
               sudo dpkg -i libecryptfs1-dbgsym_111-5_armhf.deb
               sudo dpkg -i libecryptfs-dev_111-5_armhf.deb
               sudo dpkg -i ecryptfs-utils_111-5_armhf.deb
               sudo dpkg -i ecryptfs-utils-dbgsym_111-5_armhf.deb
               
            elif lscpu | grep AMD; then
            
               wget http://snapshot.debian.org/archive/debian-debug/20200802T203936Z/pool/main/e/ecryptfs-utils/libecryptfs1-dbgsym_111-5_amd64.deb
               wget http://snapshot.debian.org/archive/debian/20200802T204950Z/pool/main/e/ecryptfs-utils/libecryptfs1_111-5_amd64.deb
               wget http://snapshot.debian.org/archive/debian/20200802T204950Z/pool/main/e/ecryptfs-utils/libecryptfs-dev_111-5_amd64.deb
               wget http://snapshot.debian.org/archive/debian-debug/20200802T203936Z/pool/main/e/ecryptfs-utils/ecryptfs-utils-dbgsym_111-5_amd64.deb
               wget http://snapshot.debian.org/archive/debian/20200802T204950Z/pool/main/e/ecryptfs-utils/ecryptfs-utils_111-5_amd64.deb
               
               sudo dpkg -i libecryptfs1_111-5_amd64.deb
               sudo dpkg -i libecryptfs1-dbgsym_111-5_amd64.deb
               sudo dpkg -i libecryptfs-dev_111-5_amd64.deb
               sudo dpkg -i ecryptfs-utils_111-5_amd64.deb
               sudo dpkg -i ecryptfs-utils-dbgsym_111-5_amd64.deb
               
            elif lscpu | grep GenuineIntel; then
            
               wget http://snapshot.debian.org/archive/debian-debug/20200802T203936Z/pool/main/e/ecryptfs-utils/libecryptfs1-dbgsym_111-5_i386.deb
               wget http://snapshot.debian.org/archive/debian/20200802T204950Z/pool/main/e/ecryptfs-utils/libecryptfs1_111-5_i386.deb
               wget http://snapshot.debian.org/archive/debian/20200802T204950Z/pool/main/e/ecryptfs-utils/libecryptfs-dev_111-5_i386.deb
               wget http://snapshot.debian.org/archive/debian-debug/20200802T203936Z/pool/main/e/ecryptfs-utils/ecryptfs-utils-dbgsym_111-5_i386.deb
               wget http://snapshot.debian.org/archive/debian/20200802T204950Z/pool/main/e/ecryptfs-utils/ecryptfs-utils_111-5_i386.deb
               
               sudo dpkg -i libecryptfs1_111-5_i386.deb
               sudo dpkg -i libecryptfs1-dbgsym_111-5_i386.deb
               sudo dpkg -i libecryptfs-dev_111-5_i386.deb
               sudo dpkg -i ecryptfs-utils_111-5_i386.deb
               sudo dpkg -i ecryptfs-utils-dbgsym_111-5_i386.deb
               
            fi
         else
            echo -e 'EcryptFS installation failed.'\
             '\nPlease check your internet connection to proceed with the'\
             '\n.Fluidity installation.'\
             '\nCanceling the installation procedures.'
            return
         fi
      fi
      
      # Correct the dependencies and do some cleaning before proceeding
      # to the next application.
      sleep 10
      sudo apt-get install --fix-broken --assume-yes
      sleep 10
      sudo apt --fix-broken install
      sleep 10
      
      # Verify and if not present install  "EXPECT"
      if ! [ -x "$(command -v expect)" ]; then
         if ! sudo apt-get -y install expect; then
            echo -e 'Expect installation failed.'\
             '\nPlease check your internet connection to proceed with the'\
             '\n.Fluidity installation.'\
             '\nCanceling the installation procedures.'
            return
         fi
      fi
      # Verify and if not present install "LSOF"
      if ! [ -x "$(command -v lsof)" ]; then
         if ! sudo apt-get -y install lsof; then
            echo -e 'LSOF installation failed.'\
             '\nPlease check your internet connection to proceed with the'\
             '\n.Fluidity installation.'\
             '\nCanceling the installation procedures.'
            return
         fi
      fi
      # Verify and if not present install "UFW", 
      # also perform the initial Firewall configuration.
      if ! [ -x "$(command -v ufw)" ]; then
         if ! sudo apt-get -y install ufw; then
            echo -e 'UFW installation failed.'\
             '\nPlease check your internet connection to proceed with the'\
             '\n.Fluidity installation.'\
             '\nCanceling the installation procedures.'
            return
         fi
         
            # Activate ufw
            sudo systemctl enable ufw
            sudo systemctl start ufw
      fi
   
   fi
      
   # Invoke giveAnEntropyBoost
   giveAnEntropyBoost
   
   mkdir ~/Fluidity_Client
   
}


# 4. Client Management Functions
# 4.1 Public Functions


# Arguments: ($1), ($2), ($3), ($4) 
# $1: SSH Client ID.
# $2: Server IP address.
# $3: Client IP address.
# $4: Client Password
# $5: Client username (for raspbian OS the default is pi@)

# Sourced Variables: NONE

# Intershell File Variables in use: NONE

# Global Variables in use:
# 1. SSH_passphrase []

# Generates:
# 1. Text File (.txt): passphrase_$1.txt (8 character string)
# 2. SSH Private Key (No Extension): client$1 (The SSH private key)
# 3. SSH Public Key (.pub) File: client$1.pub
# 4. SSH configuration File (config): ~/.ssh/config
# 5. Text File (.txt): basic_client_info.txt
   # Stores and contains:
   # 1. $server_IP_address
   # 2. $client_IP_address
   # 3. $client_username
   # 4. $random_client_port (added in fluidityRemoteClientConfiguration)

# Invokes functions:
# 1. checkLocalEntropy, no args
# 2. checkFluidityFilesystemIntegrity, no args
# 3. fluidityRemoteClientConfiguration, with args ($3), ($5), ($2)
# 4. remoteSeekAndEncryptDaemonInstallation ($3), ($5), ($1), ($2)
# 5. removeLocalClientData ($1)

# Calls the script: NONE

# Function Description: Add a .Fluidity client.
addFluidityClient () {

   # Safety check 1: Check whether Fluidity_Server folder is present 
   # (functionality contained within mountFluidityServerFolder) and 
   # decrypted.
   if [ -z "$(df -T | grep -E 'Fluidity_Server ecryptfs')" ] ; then 

      # Fluidity_Server folder found encrpyted. Use 
      # mountFluidityServerFolder to decrypt it.
      # Invoke mountFluidityServerFolder
      mountFluidityServerFolder
      
   fi

   # Safety check 2: Check whether target client.[SSH_ID] already exists.
   if [ -d ~/Fluidity_Server/client.$1 ]; then
      echo "Client $1 already exists"
      return
   fi

   # Safety check 3: Check whether the server responds to 
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

   # Safety check 4: Check whether target client.[SSH_ID] responds to 
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
   
   # Safety check 5: Stop execution if SSH is not active on client 
   # machine.
   if ! nmap $3 -PN -p ssh | grep open; then
      echo "Activate SSH on target machine"
      return
   fi

   # Safety check 6: Verify that local entropy is above target value 1000. 
   if [[ $(checkLocalEntropy) == 1 ]]; then
     echo "Server entropy is above 1000. Carrying on with addFluidityClient."
   else
     echo "Insufficient entropy. addFluidityClient will not be executed."
     return
   fi
   
   # Safety check 7: Perform an overall .Fluidity file structure
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
   SSH_passphrase[$array_index]=$(openssl rand -base64 12)

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

   # If not present, create an SSH configuration file in ~/.ssh
   # This will contain (1/2):
      # 1. "Host ": The IP address of the remote .Fluidity machine.
      # 2. "IdentityFile ": The exact location of the identity file to 
      # be used for the SSH connection with the specified host (client).
      # 3. "Port ": Specify a random connection port to remote host. 
       # (Added later in fluidityRemoteClientConfiguration).
   echo -e 'Host '$3'\n'\
   '  IdentityFile ~/.ssh/client.'$1 >> ~/.ssh/config

   # heefhEKX
   # Add the remote machine to known hosts (x03 sends a Ctrl-C)
expect << EOF
       spawn ssh $5@$3
       expect "(yes/no)?"
       send "yes\r"
       expect "password:"
       send \x03
EOF

   # Transmit the SSH credentials to the remote machine.
   # sshpass utility will be used to provide the log in password by 
   # using the client password (argument $4).
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
'local server_IP_address='$2\
'\nlocal client_IP_address='$3\
'\nlocal client_username='$5\
   > ~/Fluidity_Server/client.$1/basic_client_info.txt
   
   # Invoke fluidityRemoteClientConfiguration to
   # install .Fluidity's essential programs and basic firewall
   # configuration to client machine.
   if fluidityRemoteClientConfiguration $3 $5 $2 $1 | tee /dev/stderr \
    | grep "fluidityRemoteClientConfiguration failed"; then
      ssh $5@$3 'cat ~/fluidity_failure_cause.txt && rm ~/fluidity_failure_cause.txt'
      # S99zBE5 
      # Invoke removeLocalClientData
      removeLocalClientData $1 &>/dev/null
      # Display an operation success message.
      echo "Data from failed installation attempt removed successfully."
      return
   fi
   
   # Invoke remoteSeekAndEncryptDaemonInstallation to
   # install FLdaemon_SeekAndEncrypt.service.
   remoteSeekAndEncryptDaemonInstallation $3 $5 $1 $2

}


# Arguments: ($1)
# $1: SSH Client ID.

# Sourced Variables:
# 1. ~/Fluidity_Server/client.$SSH_ID/basic_client_info.txt
   # 1. $server_IP_address
   # 2. $client_IP_address
   # 3. $client_username
   # 4. $random_client_port
   
# Intershell File Variables in use: NONE

# Global Variables in use: NONE

# Generates:
# 1. Bash script (.sh): genSCRIPT_eraseClientData.sh

# Invokes Functions:
# 1. removeFluidityClientConfigInfoFromSSHConfig, with args: 
#  ($1) ($client_IP_address) ($random_client_port)

# Calls the script:
# 1. genSCRIPT_eraseClientData.sh, with args, $client_username, ($1), $server_IP_address
# in: ~/Fluidity_Server/Generated_Scripts

# Function Description: Remove a .Fluidity client.
removeFluidityClient () {
   
   # Safety check 1: Check whether Fluidity_Server folder is present 
   # (functionality contained within mountFluidityServerFolder) and 
   # decrypted.
   if [ -z "$(df -T | grep -E 'Fluidity_Server ecryptfs')" ] ; then 

      # Fluidity_Server folder found encrpyted. Use 
      # mountFluidityServerFolder to decrypt it.
      # Invoke mountFluidityServerFolder
      mountFluidityServerFolder
      
   fi
   
   # Source the variables:
      # 1. $server_IP_address
      # 2. $client_IP_address
      # 3. $client_username
      # 4. $random_client_port
   source ~/Fluidity_Server/client.$1/basic_client_info.txt
   
   # Safety check 2: Check whether target client.[SSH_ID] already exists.
   if [ ! -d ~/Fluidity_Server/client.$1 ]; then
      echo "Fluidity client $1 does not exist."
      return
   fi
   
   # Precautionary action 1: Check whether client ssh idenity is 
   # missing from the SSH keyring.
   if ! ssh-add -l | grep client.$1; then
   
      # Invoke recallSSHidentity
      # Recall the missing identity.
      recallSSHidentity $1
      
      # Message to user
      echo "Fluidity client identity $1 loaded in keyring."
      
   else
      
      # Message to user.
      echo "Fluidity client identity $1 is already loaded in keyring."
      
   fi
   
   # Safety check 3: Check whether target client.[SSH_ID] responds to 
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
'   # SECTION 2.3: Remove the public SSH key pointing to Fluidity server\n'\
'   # (it should contain only the connection to Fluidity server!)\n'\
'   if [ -f ~/.ssh/known_hosts ]; then\n'\
'      ssh-keygen -R '$server_IP_address'\n'\
'      rm ~/.ssh/known_hosts.old\n'\
'   fi\n'\
'   \n'\
'   # SECTION 2.4: Set sshd_config to default policies\n'\
'   echo "sudo sed -i '"'"'13s/.*/$(echo \#Port 22)/'"'"' /etc/ssh/sshd_config" | bash -\n'\
'   echo "sudo sed -i '"'"'34s/.*/$(echo \#MaxAuthTries 6)/'"'"' /etc/ssh/sshd_config" | bash -\n'\
'   echo "sudo sed -i '"'"'35s/.*/$(echo \#MaxSessions 10)/'"'"' /etc/ssh/sshd_config" | bash -\n'\
'   echo "sudo sed -i '"'"'56s/.*/$(echo \#PasswordAuthentication yes)/'"'"' /etc/ssh/sshd_config" | bash -\n'\
'   # SECTION 2.4: Sleep for 5 seconds before restarting the ssh service.\n'\
'   ( sleep 5 ; sudo service ssh restart ) &\n'\
'   \n'\
'   # SECTION 2.5: Firewall (UFW) manipulations.\n'\
'   # SECTION 2.5: Sleep for 6 seconds. Then, purge UFW rules. Reset UFW to accept SSH connections from any IP.\n'\
'   ( sleep 6 ; echo "y" | sudo ufw reset ; sudo ufw enable ; sudo ufw allow ssh ) &\n'\
'   # SECTION 2.6: (Return message to server and Safety Check 3):\n'\
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
'   # SECTION 2.3: Remove the public SSH key pointing to Fluidity server\n'\
'   # (it should contain only the connection to Fluidity server!)\n'\
'   if [ -f ~/.ssh/known_hosts ]; then\n'\
'      ssh-keygen -R '$server_IP_address'\n'\
'      rm ~/.ssh/known_hosts.old\n'\
'   fi\n'\
'   \n'\
'   # SECTION 2.4: Set sshd_config to default policies\n'\
'   echo "sudo sed -i '"'"'13s/.*/$(echo \#Port 22)/'"'"' /etc/ssh/sshd_config" | bash -\n'\
'   echo "sudo sed -i '"'"'34s/.*/$(echo \#MaxAuthTries 6)/'"'"' /etc/ssh/sshd_config" | bash -\n'\
'   echo "sudo sed -i '"'"'35s/.*/$(echo \#MaxSessions 10)/'"'"' /etc/ssh/sshd_config" | bash -\n'\
'   echo "sudo sed -i '"'"'56s/.*/$(echo \#PasswordAuthentication yes)/'"'"' /etc/ssh/sshd_config" | bash -\n'\
'   # SECTION 2.4: Sleep for 5 seconds before restarting the ssh service.\n'\
'   ( sleep 5 ; sudo service ssh restart ) &\n'\
'   \n'\
'   # SECTION 2.5: Firewall (UFW) manipulations.\n'\
'   # SECTION 2.5: Sleep for 6 seconds. Then, purge UFW rules. Reset UFW to accept SSH connections from any IP.\n'\
'   ( sleep 6 ; echo "y" | sudo ufw reset ; sudo ufw enable ; sudo ufw allow ssh ) &\n'\
'   # SECTION 2.6: (Return message to server and Safety Check 3):\n'\
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
      
   fi
   
   # Used to store the outcome from genSCRIPT_eraseClientData.sh
   local eraseClientData_outcome
   
   # heefhEKX
   # First, SSH remotely execute genSCRIPT_eraseClientData.sh and, then,
   # save the outcome into $eraseClientData_outcome.
   eraseClientData_outcome=$(ssh $client_username@$client_IP_address \
   'bash -s' < ~/Fluidity_Server/Generated_Scripts/genSCRIPT_eraseClientData.sh \
    $client_username $1 $server_IP_address)
   
   # Act upon the grep-ed outcome from target client. 
   # If client returns "genSCRIPT_eraseClientData.sh reports SUCCESS"
   # then, proceed with removing .Fluidity Server client data. 
   if echo "$eraseClientData_outcome" | grep -q "genSCRIPT_eraseClientData.sh reports SUCCESS"; then

      # Remove client's identity.
      ssh-add -d ~/.ssh/client.$1
      
      # Delete the client's SSH related data.
      rm ~/.ssh/client.$1
      rm ~/.ssh/client.$1.pub
      
      # Delete client information stored in .Fluidity Vault.
      rm ~/Fluidity_Server/SSH_Vault/SSH_Keys/client.$1
      rm ~/Fluidity_Server/SSH_Vault/SSH_Keys/client.$1.pub
      
      rm ~/Fluidity_Server/SSH_Vault/SSH_Passphrases/passphrase.$1.txt
      
      # Delete all the client data.
      rm -r ~/Fluidity_Server/client.$1
      
      # Delete the remaining vault connections data.
      rm -r ~/Fluidity_Server/SSL_Cert_Vault/client_con.$1.*
      rm -r ~/Fluidity_Server/SSL_Cert_Vault/server_con.$1.*
      
      # Remove the former .Fluidity client from ~/.ssh/known_hosts.
      ssh-keygen -R $client_IP_address
      rm ~/.ssh/known_hosts.old
      
      # Update the .ssh/config by removing the specific client 
      # information from it.
      # Invoke removeFluidityClientConfigInfoFromSSHConfig
      removeFluidityClientConfigInfoFromSSHConfig $1 $client_IP_address $random_client_port
      
      # Display an operation success message.
      echo "Client $1 removed successfully."
      
   else
      
      # Display an operation failed message that follows the 
      # messages received from target .Fluidity client.
      echo "Client $1 removal failed."
      echo "Manually check the Fluidity server and client. Something went wrong"
      
   fi
   
   # Guard interval in case an addFluidityClient follows for the same client.
   sleep 6
   
   
}


# 4. Client Management Functions
# 4.2 Private Functions


# Arguments: ($1)
# $1: SSH Client ID.

# Sourced Variables:
# 1. ~/Fluidity_Server/client.$SSH_ID/basic_client_info.txt
   # 1. $server_IP_address
   # 2. $client_IP_address
   # 3. $client_username
   # 4. $random_client_port
   
# Intershell File Variables in use: NONE

# Global Variables in use: NONE

# Generates: NOTHING

# Invokes Functions: NONE

# Calls the script: NONE

# Function Description: Remove a .Fluidity client from a failed 
# .Fluidity installation.
removeLocalClientData () {

   # Source the variables:
      # 1. $server_IP_address
      # 2. $client_IP_address
      # 3. $client_username
      # 4. $random_client_port
   source ~/Fluidity_Server/client.$1/basic_client_info.txt

   # Remove client's identity.
   ssh-add -d ~/.ssh/client.$1
   
   # Delete the client's SSH related data.
   rm ~/.ssh/client.$1
   rm ~/.ssh/client.$1.pub
   
   # Delete client information stored in .Fluidity Vault.
   rm ~/Fluidity_Server/SSH_Vault/SSH_Keys/client.$1
   rm ~/Fluidity_Server/SSH_Vault/SSH_Keys/client.$1.pub
   
   rm ~/Fluidity_Server/SSH_Vault/SSH_Passphrases/passphrase.$1.txt
   
   # Delete all the client data.
   rm -r ~/Fluidity_Server/client.$1
   
   # Delete the remaining vault connections data.
   rm -r ~/Fluidity_Server/SSL_Cert_Vault/client_con.$1.*
   rm -r ~/Fluidity_Server/SSL_Cert_Vault/server_con.$1.*
   
   # Remove the former .Fluidity client from ~/.ssh/known_hosts.
   ssh-keygen -R $client_IP_address
   rm ~/.ssh/known_hosts.old
   
   # Update the .ssh/config by removing the specific client 
   # information from it.
   # Invoke removeFluidityClientConfigInfoFromSSHConfig
   removeFluidityClientConfigInfoFromSSHConfig $1 $client_IP_address $random_client_port
}

# Arguments: 
# $1: Client IP.
# $2: Client Username.
# $3: Server IP.
# $4: SSH ID.

# Sourced Variables: NONE

# Intershell File Variables in use: NONE

# Global Variables in use: NONE

# Generates:
# 1. Bash script (.sh): genSCRIPT_fluidityRemoteClientConfiguration.sh
# 2. Bash script (.sh): genSCRIPT_remoteRNGTOOLSinstallation.sh 
# 3. Bash script (.sh): genSCRIPT_remoteHAVEGEDinstallation.sh
# 4. Bash script (.sh): genSCRIPT_fluidityRemoteClientSSHConfiguration.sh
# 5. Bash script (.sh): genSCRIPT_fluidityRemoteClientFirewallConfiguration.sh

# Invokes Functions: NONE

# Calls the script:
# 1. genSCRIPT_fluidityRemoteClientConfiguration.sh, with args: 
#  $entropy_source_user_choice
# in: ~/Fluidity_Server/Generated_Scripts
# 2. genSCRIPT_fluidityRemoteClientFirewallConfiguration.sh with args:
#  $3

# Function Description: 
   # 1. Create the main folder structure  (~/Fluidity_Client)
   # 2. Verify the existance and if necessary install
   # the following essential set of utilities: 
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

local random_ssh_port=$(shuf -i 49152-65535 -n 1)

# Add the random port number to basic_client_info.txt
echo -e 'local random_client_port='$random_ssh_port >> \
 ~/Fluidity_Server/client.$4/basic_client_info.txt
 
   if [[ ! -e ~/Fluidity_Server/Generated_Scripts/genSCRIPT_fluidityRemoteClientConfiguration.sh ]]; then
   
   cat <<- 'END_CAT' > ~/Fluidity_Server/Generated_Scripts/genSCRIPT_fluidityRemoteClientConfiguration.sh
   
      if [ -x "$(command -v socat)" ] && [ -x "$(command -v ecryptfsd)" ] && \
     [ -x "$(command -v expect)" ] && [ -x "$(command -v lsof)" ]; then
    
         echo "All packages are present in the remote system."
         echo ".Fluidity is ready to be installed."
    
      else
   
         # Perform a system update.
         if ping -c 3 8.8.8.8; then
            sudo apt-get update && sudo apt-get -y upgrade
         else
            echo -e 'System update failed.'\
             '\nPlease check your internet connection to proceed with the'\
             '\n.Fluidity installation.'\
             '\nCanceling the installation procedures.'
            echo "genSCRIPT_fluidityRemoteClientConfiguration.sh failed"
             return
         fi
         # Verify and if not present install "SOCAT"
         if ! [ -x "$(command -v socat)" ]; then
            if ! sudo apt-get -y install socat; then
               echo -e 'SOCAT installation failed.'\
                '\nPlease check your internet connection to proceed with the'\
                '\n.Fluidity installation.'\
                '\nCanceling the installation procedures.'
               echo "genSCRIPT_fluidityRemoteClientConfiguration.sh failed"
                return
            fi
         fi
         # Verify and if not present install the 111.5 ecryptfs version
         if ! [ -x "$(command -v ecryptfsd)" ]; then
            if ping -c 3 8.8.8.8; then
            
               DEPS="gettext-base keyutils libassuan0 libgpg-error0 libc6 libkeyutils1 libpam-runtime 
               libgpg-error0 libpam0g libgpgme11 libtspi1 cryptsetup cryptsetup lsof rsync libnss3"
               sudo apt-get install $DEPS
               
               if lscpu | grep ARM; then
               
                  wget http://snapshot.debian.org/archive/debian-debug/20200802T203936Z/pool/main/e/ecryptfs-utils/libecryptfs1-dbgsym_111-5_armhf.deb
                  wget http://snapshot.debian.org/archive/debian/20200802T204950Z/pool/main/e/ecryptfs-utils/libecryptfs1_111-5_armhf.deb
                  wget http://snapshot.debian.org/archive/debian/20200802T204950Z/pool/main/e/ecryptfs-utils/libecryptfs-dev_111-5_armhf.deb
                  wget http://snapshot.debian.org/archive/debian-debug/20200802T203936Z/pool/main/e/ecryptfs-utils/ecryptfs-utils-dbgsym_111-5_armhf.deb
                  wget http://snapshot.debian.org/archive/debian/20200802T204950Z/pool/main/e/ecryptfs-utils/ecryptfs-utils_111-5_armhf.deb
               
                  sudo dpkg -i libecryptfs1_111-5_armhf.deb
                  sudo dpkg -i libecryptfs1-dbgsym_111-5_armhf.deb
                  sudo dpkg -i libecryptfs-dev_111-5_armhf.deb
                  sudo dpkg -i ecryptfs-utils_111-5_armhf.deb
                  sudo dpkg -i ecryptfs-utils-dbgsym_111-5_armhf.deb
                  
               elif lscpu | grep AMD; then
               
                  wget http://snapshot.debian.org/archive/debian-debug/20200802T203936Z/pool/main/e/ecryptfs-utils/libecryptfs1-dbgsym_111-5_amd64.deb
                  wget http://snapshot.debian.org/archive/debian/20200802T204950Z/pool/main/e/ecryptfs-utils/libecryptfs1_111-5_amd64.deb
                  wget http://snapshot.debian.org/archive/debian/20200802T204950Z/pool/main/e/ecryptfs-utils/libecryptfs-dev_111-5_amd64.deb
                  wget http://snapshot.debian.org/archive/debian-debug/20200802T203936Z/pool/main/e/ecryptfs-utils/ecryptfs-utils-dbgsym_111-5_amd64.deb
                  wget http://snapshot.debian.org/archive/debian/20200802T204950Z/pool/main/e/ecryptfs-utils/ecryptfs-utils_111-5_amd64.deb
                  
                  sudo dpkg -i libecryptfs1_111-5_amd64.deb
                  sudo dpkg -i libecryptfs1-dbgsym_111-5_amd64.deb
                  sudo dpkg -i libecryptfs-dev_111-5_amd64.deb
                  sudo dpkg -i ecryptfs-utils_111-5_amd64.deb
                  sudo dpkg -i ecryptfs-utils-dbgsym_111-5_amd64.deb
                  
               elif lscpu | grep GenuineIntel; then
               
                  wget http://snapshot.debian.org/archive/debian-debug/20200802T203936Z/pool/main/e/ecryptfs-utils/libecryptfs1-dbgsym_111-5_i386.deb
                  wget http://snapshot.debian.org/archive/debian/20200802T204950Z/pool/main/e/ecryptfs-utils/libecryptfs1_111-5_i386.deb
                  wget http://snapshot.debian.org/archive/debian/20200802T204950Z/pool/main/e/ecryptfs-utils/libecryptfs-dev_111-5_i386.deb
                  wget http://snapshot.debian.org/archive/debian-debug/20200802T203936Z/pool/main/e/ecryptfs-utils/ecryptfs-utils-dbgsym_111-5_i386.deb
                  wget http://snapshot.debian.org/archive/debian/20200802T204950Z/pool/main/e/ecryptfs-utils/ecryptfs-utils_111-5_i386.deb
                  
                  sudo dpkg -i libecryptfs1_111-5_i386.deb
                  sudo dpkg -i libecryptfs1-dbgsym_111-5_i386.deb
                  sudo dpkg -i libecryptfs-dev_111-5_i386.deb
                  sudo dpkg -i ecryptfs-utils_111-5_i386.deb
                  sudo dpkg -i ecryptfs-utils-dbgsym_111-5_i386.deb
                  
               fi
            else
               echo -e 'EcryptFS installation failed.'\
                '\nPlease check your internet connection to proceed with the'\
                '\n.Fluidity installation.'\
                '\nCanceling the installation procedures.'
               return
            fi
         fi
         
         # Correct the dependencies and do some cleaning before proceeding
         # to the next application.
         sleep 10
         sudo apt-get install --fix-broken --assume-yes
         sleep 10
         sudo apt --fix-broken install
         sleep 10
         
         # Verify and if not present install  "EXPECT"
         if ! [ -x "$(command -v expect)" ]; then
            if ! sudo apt-get -y install expect; then
               echo -e 'Expect installation failed.'\
                '\nPlease check your internet connection to proceed with the'\
                '\n.Fluidity installation.'\
                '\nCanceling the installation procedures.'
               echo "genSCRIPT_fluidityRemoteClientConfiguration.sh failed"
               return
            fi
         fi
         # Verify and if not present install "LSOF"
         if ! [ -x "$(command -v lsof)" ]; then
            if ! sudo apt-get -y install lsof; then
               echo -e 'LSOF installation failed.'\
                '\nPlease check your internet connection to proceed with the'\
                '\n.Fluidity installation.'\
                '\nCanceling the installation procedures.'
               echo "genSCRIPT_fluidityRemoteClientConfiguration.sh failed"
               return
            fi
         fi
   
      fi
      
      if [ -x "$(command -v haveged)" ]; then
      
         echo "genSCRIPT_fluidityRemoteClientConfiguration.sh haveged"
         
      elif [ -x "$(command -v rngd)" ]; then
      
         echo "genSCRIPT_fluidityRemoteClientConfiguration.sh rngd"
         
      elif [ -x "$(command -v haveged)" ] && [ -x "$(command -v rngd)" ]; then
      
         if systemctl status haveged | grep "active (running)"; then
            echo "Haveged service is currently active"
         elif systemctl status rngd | grep "active (running)"; then
            echo "rng-tools service is currently active"
         fi
   
      elif ! [ -x "$(command -v haveged)" ] && ! [ -x "$(command -v rngd)" ]; then
   
         echo "genSCRIPT_fluidityRemoteClientConfiguration.sh no-entropy-boost"
      
      fi
   
      # Erase sig-cache.txt from previous .Fluidity installations.
      if [[ -e /root/.ecryptfs/sig-cache.txt ]]; then
         sudo truncate -s 0 /root/.ecryptfs/sig-cache.txt
      fi
   
      mkdir ~/Fluidity_Client
END_CAT
   
      chmod 700 ~/Fluidity_Server/Generated_Scripts/genSCRIPT_fluidityRemoteClientConfiguration.sh
      
   fi
   
   if [[ ! -e ~/Fluidity_Server/Generated_Scripts/genSCRIPT_remoteRNGTOOLSinstallation.sh ]]; then
   
   cat <<- 'END_CAT' > ~/Fluidity_Server/Generated_Scripts/genSCRIPT_remoteRNGTOOLSinstallation.sh
            
      # Install the rng-tools      
      
      # Stop the "HAVEGED" service
      sudo systemctl stop haveged
   
      # Perform a system update.
      if ping -c 3 8.8.8.8; then
         sudo apt-get update && sudo apt-get -y upgrade
      else
         echo -e 'System update failed.'\
          '\nPlease check your internet connection to proceed with the'\
          '\n.Fluidity installation.'\
          '\nCanceling the installation procedures.'
         echo "genSCRIPT_remoteRNGTOOLSinstallation.sh failed"
         return
      fi
      
      if ! sudo apt-get -y install rng-tools; then
         echo -e 'rng-tools installation failed.'\
          '\nPlease check your internet connection to proceed with the'\
          '\n.Fluidity installation.'\
          '\nCanceling the installation procedures.'
         echo "genSCRIPT_remoteRNGTOOLSinstallation.sh failed"
         return
      fi
      
      # Start the "rng-tools" service
      sudo systemctl start rng-tools
END_CAT

   chmod 700 ~/Fluidity_Server/Generated_Scripts/genSCRIPT_remoteRNGTOOLSinstallation.sh
   
   fi
   
   if [[ ! -e ~/Fluidity_Server/Generated_Scripts/genSCRIPT_remoteHAVEGEDinstallation.sh ]]; then
   
   cat <<- 'END_CAT' > ~/Fluidity_Server/Generated_Scripts/genSCRIPT_remoteHAVEGEDinstallation.sh
         
      # Install HAVEGED
         
      # Stop the "rng-tools" service
      sudo systemctl stop rng-tools

      # Perform a system update.
      if ping -c 3 8.8.8.8; then
         sudo apt-get update && sudo apt-get -y upgrade
      else
         echo -e 'System update failed.'\
          '\nPlease check your internet connection to proceed with the'\
          '\n.Fluidity installation.'\
          '\nCanceling the installation procedures.'
         echo "genSCRIPT_remoteHAVEGEDinstallation.sh failed"
         return
      fi
   
      if ! sudo apt-get -y install haveged; then
         echo -e 'HAVEGED installation failed.'\
          '\nPlease check your internet connection to proceed with the'\
          '\n.Fluidity installation.'\
          '\nCanceling the installation procedures.'
         echo "genSCRIPT_remoteHAVEGEDinstallation.sh failed"
         return
      fi
      
      # Start the HAVEGED service
      sudo systemctl start haveged
END_CAT

   chmod 700 ~/Fluidity_Server/Generated_Scripts/genSCRIPT_remoteHAVEGEDinstallation.sh

   fi
   
   if [[ ! -e ~/Fluidity_Server/Generated_Scripts/genSCRIPT_fluidityRemoteClientSSHConfiguration.sh ]]; then
   
      echo -e \
       'echo "sudo sed -i '"'"'13s/.*/$(echo Port '$random_ssh_port')/'"'"' /etc/ssh/sshd_config" | bash -'\
      '\necho "sudo sed -i '"'"'34s/.*/$(echo MaxAuthTries 1)/'"'"' /etc/ssh/sshd_config" | bash -'\
      '\necho "sudo sed -i '"'"'35s/.*/$(echo MaxSessions 2)/'"'"' /etc/ssh/sshd_config" | bash -'\
      '\necho "sudo sed -i '"'"'56s/.*/$(echo PasswordAuthentication no)/'"'"' /etc/ssh/sshd_config" | bash -'\
      '\n(sleep 2 && sudo service ssh restart) &'\
      '\necho "y" | sudo ufw delete allow ssh' > \
      ~/Fluidity_Server/Generated_Scripts/genSCRIPT_fluidityRemoteClientSSHConfiguration.sh
      chmod 700 ~/Fluidity_Server/Generated_Scripts/genSCRIPT_fluidityRemoteClientSSHConfiguration.sh
      
   else
      
      echo -e \
       'echo "sudo sed -i '"'"'13s/.*/$(echo Port '$random_ssh_port')/'"'"' /etc/ssh/sshd_config" | bash -'\
      '\necho "sudo sed -i '"'"'34s/.*/$(echo MaxAuthTries 1)/'"'"' /etc/ssh/sshd_config" | bash -'\
      '\necho "sudo sed -i '"'"'35s/.*/$(echo MaxSessions 2)/'"'"' /etc/ssh/sshd_config" | bash -'\
      '\necho "sudo sed -i '"'"'56s/.*/$(echo PasswordAuthentication no)/'"'"' /etc/ssh/sshd_config" | bash -'\
      '\n(sleep 2 && sudo service ssh restart) &'\
      '\necho "y" | sudo ufw delete allow ssh' > \
      ~/Fluidity_Server/Generated_Scripts/genSCRIPT_fluidityRemoteClientSSHConfiguration.sh
      chmod 700 ~/Fluidity_Server/Generated_Scripts/genSCRIPT_fluidityRemoteClientSSHConfiguration.sh
      
   fi
      
   if [[ ! -e ~/Fluidity_Server/Generated_Scripts/genSCRIPT_fluidityRemoteClientFirewallConfiguration.sh ]]; then
      
      cat <<- END_CAT > ~/Fluidity_Server/Generated_Scripts/genSCRIPT_fluidityRemoteClientFirewallConfiguration.sh
            
         if ! [ -x "$(command -v ufw)" ]; then
            if ! sudo apt-get -y install ufw; then
               echo -e 'UFW installation failed.'\\
                '\nPlease check your internet connection to proceed with the'\\
                '\n.Fluidity installation.'\\
                '\nCanceling the installation procedures.'
                echo "genSCRIPT_fluidityRemoteClientFirewallConfiguration.sh failed"
               exit
            fi
            
            sudo systemctl enable ufw
            sudo systemctl start ufw
            
            if sudo ufw status | grep "Status: inactive"; then
               expect << EOF
               spawn sudo ufw enable
               expect "operation (y|n)?"
               send "y\r"
               expect eof
EOF
            fi
            
            sudo ufw default allow outgoing
            sudo ufw default deny incoming
            sudo ufw default allow routed
            
            sudo ufw allow ssh
            
            sudo ufw allow from $3 to any port $random_ssh_port proto tcp comment "HFBCvIa7h $1"
            
            sudo ufw status
            
         else
         
            if systemctl status ufw | grep "inactive"; then
               sudo systemctl enable ufw
               sudo systemctl start ufw
            else
               echo "ufw is active"
            fi
            
            if sudo ufw status | grep "Status: inactive"; then
               expect << EOF
               spawn sudo ufw enable
               expect "operation (y|n)?"
               send "y\r"
               expect eof
EOF
            fi
            
            sudo ufw default allow outgoing
            sudo ufw default deny incoming
            sudo ufw default allow routed
            
            sudo ufw allow ssh
            
            sudo ufw allow from $3 to any port $random_ssh_port proto tcp comment "HFBCvIa7h $1"
            
            sudo ufw status
            
         fi
         
         mkdir -p ~/Fluidity_Client
END_CAT

      chmod 700 ~/Fluidity_Server/Generated_Scripts/genSCRIPT_fluidityRemoteClientFirewallConfiguration.sh
      
   else
      
      echo "sed -i '30s/.*/$(echo sudo ufw allow from $3 to any port $random_ssh_port proto tcp comment "\""HFBCvIa7h $1"\"")/' ~/Fluidity_Server/Generated_Scripts/genSCRIPT_fluidityRemoteClientFirewallConfiguration.sh" | bash -
      echo "sed -i '58s/.*/$(echo sudo ufw allow from $3 to any port $random_ssh_port proto tcp comment "\""HFBCvIa7h $1"\"")/' ~/Fluidity_Server/Generated_Scripts/genSCRIPT_fluidityRemoteClientFirewallConfiguration.sh" | bash -
      
   fi
   
   cat ~/Fluidity_Server/Generated_Scripts/genSCRIPT_fluidityRemoteClientConfiguration.sh \
 | ssh $2@$1 | tee /dev/stderr \
 | tee ~/genSCRIPT_fluidityRemoteClientConfiguration.outcome
   
   if cat ~/genSCRIPT_fluidityRemoteClientConfiguration.outcome | grep "genSCRIPT_fluidityRemoteClientConfiguration.sh failed"; then
   
      echo "Remote configuration failed. Try executing fluidityClientConfiguration directly on client to proceed with the installation"
      
      echo "fluidityRemoteClientConfiguration failed"
      
      return
   
   elif cat ~/genSCRIPT_fluidityRemoteClientConfiguration.outcome | grep "genSCRIPT_fluidityRemoteClientConfiguration.sh haveged"; then
    
      while true; do
         echo -e \
          '\n.Fluidity Remote Client Setup.'\
          '\nHAVEGED was found. Would you like to use rng-tools instead?'\
          '\nType [yes]: Use rng-tools'\
          '\nType [no]: Keep using HAVEGED'\
         && read -p "_" yn
         case $yn in
         [yY] | [yY][Ee][Ss] )
            echo -e "\nInstalling rng-tools"
            
            # heefhEKX
            if ssh $2@$1 'bash -s' < ~/Fluidity_Server/Generated_Scripts/genSCRIPT_remoteRNGTOOLSinstallation.sh \
             | tee /dev/stderr | grep "genSCRIPT_genSCRIPT_remoteRNGTOOLSinstallation.sh failed"; then
               echo "Remote configuration failed. Try executing fluidityClientConfiguration directly on client to proceed with the installation"
               echo "fluidityRemoteClientConfiguration failed"
               return
            fi
            
            break;;
         
         [nN] | [nN][Oo] ) break;;
         
         * ) echo "Please answer yes or no.";;
         
         esac
      done

   elif cat ~/genSCRIPT_fluidityRemoteClientConfiguration.outcome | grep "genSCRIPT_fluidityRemoteClientConfiguration.sh rngd"; then
    
      while true; do
            echo -e \
            '\n.Fluidity Remote Client Setup.'\
            '\rng-tools were found. Would you like to use HAVEGED instead?'\
            '\nType [yes]: Use HAVEGED'\
            '\nType [no]: Keep using rng-tools'\
            && read -p "_" yn
            case $yn in
            [yY] | [yY][Ee][Ss] )
               echo -e "\nInstalling HAVEGED"

               # heefhEKX
               if ssh $2@$1 'bash -s' < ~/Fluidity_Server/Generated_Scripts/genSCRIPT_remoteHAVEGEDinstallation.sh \
                | tee /dev/stderr | grep "genSCRIPT_remoteHAVEGEDinstallation.sh failed"; then
                  echo "Remote configuration failed. Try executing fluidityClientConfiguration directly on client to proceed with the installation"
                  echo "fluidityRemoteClientConfiguration failed"
                  return
               fi

               break;;
         
            [nN]|[nN][Oo]) break;;
         
            * ) echo "Please answer yes or no.";;
         
            esac
         done
         
   elif cat ~/genSCRIPT_fluidityRemoteClientConfiguration.outcome | grep "genSCRIPT_fluidityRemoteClientConfiguration.sh no-entropy-boost"; then
   
         # Looped user prompt: Ask for input until a valid choice is given.
         # Valid choice 1.: Install Haveged
         # Valid choice 2.: Install rng-tools
         while true; do
            echo -e \
            '\n.Fluidity Remote Client Setup.'\
            '\nFluidity requires a high quality entropy source'\
            '\nWhich utility you prefer to choose?'\
            '\n1. for Haveged'\
            '\n2. for rng-tools'\
            && read -p '_' choice
            
            # CASE 1: For choice=1 install Haveged
            case $choice in
            [1]* ) echo "Installing Haveged"
            
               # heefhEKX
               if ssh $2@$1 'bash -s' < ~/Fluidity_Server/Generated_Scripts/genSCRIPT_remoteHAVEGEDinstallation.sh \
                | tee /dev/stderr | grep "genSCRIPT_remoteHAVEGEDinstallation.sh failed"; then
                  echo "Remote configuration failed. Try executing fluidityClientConfiguration directly on client to proceed with the installation"
                  echo "fluidityRemoteClientConfiguration failed"
                  return
               fi
            
            break;;
         
            # CASE 2: For choice=2 install rng-tools
            [2]* ) echo "Installing rng-tools"
            
             # heefhEKX
             if ssh $2@$1 'bash -s' < ~/Fluidity_Server/Generated_Scripts/genSCRIPT_remoteRNGTOOLSinstallation.sh \
              | tee /dev/stderr | grep "genSCRIPT_genSCRIPT_remoteRNGTOOLSinstallation.sh failed"; then
               echo "Remote configuration failed. Try executing fluidityClientConfiguration directly on client to proceed with the installation"
               echo "fluidityRemoteClientConfiguration failed"
               return
            fi
            
            break;;
         
            # Error handling case:
            # Display the valid choices (1 or 2) and loop again.
            * ) echo "1 for Haveged, 2 for rng-tools";;
            esac
         done
    
   fi
   
   rm ~/genSCRIPT_fluidityRemoteClientConfiguration.outcome
   
   # heefhEKX
   # SSH remotely execute genSCRIPT_fluidityRemoteClientFirewallConfiguration.sh
   if ssh $2@$1 'bash -s' < ~/Fluidity_Server/Generated_Scripts/genSCRIPT_fluidityRemoteClientFirewallConfiguration.sh \
    | tee /dev/stderr | grep "genSCRIPT_fluidityRemoteClientFirewallConfiguration.sh failed"; then
      echo "Remote configuration failed. Try executing fluidityClientConfiguration directly on client to proceed with the installation"
      echo "fluidityRemoteClientConfiguration failed"
      return
   fi

   # heefhEKX
   # SSH remotely execute genSCRIPT_fluidityRemoteClientSSHConfiguration
   ssh $2@$1 'bash -s' < ~/Fluidity_Server/Generated_Scripts/genSCRIPT_fluidityRemoteClientSSHConfiguration.sh
   
   # Add the random port number to .shh/config (2/2).
    # (First part located in addFluidityClient)
   # From this point on, every ssh connection to this client will
   # use the specified port number.
   echo "   Port $random_ssh_port" >> ~/.ssh/config

   
}

# Arguments:
# $1: Client IP.
# $2: Client Username.
# $3: SSH Client ID.
# $4: Server IP.

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
# absence of a .Fluidity / SOCAT active connection. 
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
   #  .Fluidity Server is closed.
   
   #  FALSE: The digital padlock CLOSES:
   #  Thus, ~/Fluidity_Client/connection.[SSH_ID.SSL_ID]
   #  folder loses its encryption immunity when scanned by 
   #  FLdaemon_SeekAndEncrypt.sh AND SOCAT connection.[SSH_ID.SSL_ID] to 
   #  .Fluidity Server is closed.


   # Location that the encryption immunity token is stored and copied to 
   # .Fluidity client when required.
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
   # a client specific daemon script, installed to each .Fluidity client. 
   
   # Based on both passwords, create the corrensponding hash.
   local client_hashed_key=$(echo $seal_1 \
      | openssl enc -aes-128-cbc -md sha512 -pbkdf2 -iter 100000 -a -salt -pass pass:$seal_2)

   # FLdaemon_SeekAndEncrypt.sh doesn't exist. Generate it and
   # store it in: ~/Fluidity_Server/Generated_Scripts
   if [[ ! -e ~/Fluidity_Server/Generated_Scripts/FLdaemon_SeekAndEncrypt.sh ]]; then
   
      # Script description:
      #
      # 1. Generate the client specific script: FLdaemon_SeekAndEncrypt.sh.
      #
      # 2. Embed client specific information into specific sections of the script 
      #    by using the following variables:
      #
      #   Variables expressing SERVER RELATED INFORMATION
      #     a. $4: Server IP
      #
      #   Variables expressing CLIENT RELATED INFORMATION
      #     b. $2: Client Username
      #     c. $3: SSH Client ID
      #
      #   Variables pertinent to the DIGITAL PADLOCK (encryption immunity token)
      #     d. $filename: Token's filename 
      #     e. $client_hashed_key: Token's hashed key
      #
      #
      # 3. Scan every client connection folder (expressed by *) in
      #    ~/Fluidity_Client/connection.[SSH_ID].* and see whether an 
      #    active SOCAT connection exists. 
      #
      #   a. For an active connection, leave the folder as it is. 
      #
      #   b. For an inactive connection, secure the folder by 
      #      encrypting it. 
      #
      #   c. If the encryption immunity token is detected in tokenSlot 
      #      folder i.e. (~/Fluidity_Client/connection.[SSH_ID.SSL_ID]/tokenSlot), 
      #      and the server responds to client pinging requests, keep the
      #      client connection folder decrypted.
      
      sudo echo -e \
        '#!/bin/bash'\
      '\n'\
      '\n# Turn IPv4 forwarding ON'\
      '\nsysctl -w net.ipv4.ip_forward=1'\
      '\n'\
      '\nwhile true; do'\
      '\n'\
      '\n      # For every file contained in the Fluidity_Client folder:'\
      '\n      for file in /home/'$2'/Fluidity_Client/connection.'$3'.* ; do'\
      '\n'\
      '\n         # And only for files which are folders (i.e. for every folder)'\
      '\n         # do the following:'\
      '\n         if [ -d "$file" ]; then'\
      '\n'\
      '\n            # Isolate the connection number from the connection folders '\
      '\n            # by using two successive cut commands.'\
      '\n            # The first cut isolates the fifth element using the / delimeter character.'\
      '\n            # The second cut takes the input from the previous cut and isolates'\
      '\n            # the third element using the . delimeter character. Thus the connection_number'\
      '\n            # is derived.'\
      '\n            connection_number=$(echo $file | cut -d'/' -f5 | cut -d'.' -f3)'\
      '\n'\
      '\n            # Case 1: Connection to server exists. Maintain the encryption immunity token.'\
      '\n            # We specify three conditions which must be TRUE. '\
      '\n               # 1. The absence of a SOCAT process for a specific Fluidity connection.'\
      '\n               # 2. do_not_encrypt token not being present in tokenSlot.'\
      '\n               # 3. A successful server pinging response by performing two pinging efforts.'\
      '\n            # If the above conditions apply, then do the following:'\
      '\n            if [[ ! $(lsof | grep "connection.'$3'.$connection_number/clientcon.'$3'.$connection_number.pem") ]] && \\\n'\
      '               [ -f /home/'$2'/Fluidity_Client/connection.'$3'.$connection_number/tokenSlot/'$filename' ] && \\\n'\
      '                ping -c 2 '$4'; then'\
      '\n'\
      '\n               # Source the variables $seal_1 and $seal_2 contained in the do_not_encrypt token.'\
      '\n               source /home/'$2'/Fluidity_Client/connection.'$3'.$connection_number/tokenSlot/'$filename\
      '\n               # Derive $seal_1 from the hashed key embedded in seek_and_encrypt by using $seal_2.'\
      '\n               result=$(echo '$client_hashed_key' |  openssl enc -aes-128-cbc -md sha512 -pbkdf2 -iter 100000 -a -d -salt -pass pass:$seal_2)'\
      '\n'\
      '\n               # In case $seal_1 contained in the do_not_encrypt token doesn'"'"'t much the derived result'\
      '\n               if [ "$seal_1" != "$result" ]; then'\
      '\n                  # do_not_encrypt token is bogus and shouldn'"'"'t offer encryption immunity'\
      '\n                  # to the specific connection folder. umount the specified connection folder.'\
      '\n                  sudo umount /home/'$2'/Fluidity_Client/connection.'$3'.$connection_number'\
      '\n               fi'\
      '\n'\
      '\n            # Case 2: Connection to server is lost. Protect the encryption immunity token by deleting'\
      '\n            # and substituting it with the file "resetSSL.txt".'\
      '\n            # We specify two conditions which must be TRUE '\
      '\n               # 1. The absence of a SOCAT process for the specific Fluidity connection.'\
      '\n               # 2. do_not_encrypt token being present in tokenSlot.'\
      '\n            # If the above conditions apply, then do the following:'\
      '\n            elif [[ ! $(lsof | grep "connection.'$3'.$connection_number/clientcon.'$3'.$connection_number.pem") ]] && \\\n'\
      '               [ -f /home/'$2'/Fluidity_Client/connection.'$3'.$connection_number/tokenSlot/'$filename' ]; then'\
      '\n'\
      '\n               # Create a file containing the string "resetSSL" and named "resetSSL.txt"'\
      '\n               echo "resetSSL" > home/'$2'/Fluidity_Client/connection.'$3'.$connection_number/tokenSlot/resetSSL.txt'\
      '\n               # Delete the do_not_encrypt token from the tokenSlot folder.'\
      '\n               rm home/'$2'/Fluidity_Client/connection.'$3'.$connection_number/tokenSlot/'$filename\
      '\n               # umount the specified connection folder.'\
      '\n               sudo umount /home/'$2'/Fluidity_Client/connection.'$3'.$connection_number'\
      '\n'\
      '\n            # Case 3: A connection folder corresponding to a currently inactive Fluidity connection.'\
      '\n            # We specify one condition which should be TRUE '\
      '\n               # 1. The absence of a SOCAT process for a specific Fluidity connection.'\
      '\n            # If the above condition applies, then do the following:'\
      '\n            elif [[ ! $(lsof | grep "connection.'$3'.$connection_number/clientcon.'$3'.$connection_number.pem") ]]; then'\
      '\n'\
      '\n               # umount the specified connection folder.'\
      '\n               sudo umount /home/'$2'/Fluidity_Client/connection.'$3'.$connection_number'\
      '\n'\
      '\n            fi'\
      '\n'\
      '\n         fi'\
      '\n'\
      '\n      done'\
      '\n'\
      '\n   # invoke a sleep process to delay the next execution circle.'\
      '\n   # Sleeping time is set between a random interval between '\
      '\n   # of 5 to 7 seconds.'\
      '\n   sleep $(shuf -i 5-7 -n1)'\
      '\n'\
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
      '\n'\
      '\n# Turn IPv4 forwarding ON'\
      '\nsysctl -w net.ipv4.ip_forward=1'\
      '\n'\
      '\nwhile true; do'\
      '\n'\
      '\n      # For every file contained in the Fluidity_Client folder:'\
      '\n      for file in /home/'$2'/Fluidity_Client/connection.'$3'.* ; do'\
      '\n'\
      '\n         # And only for files which are folders (i.e. for every folder)'\
      '\n         # do the following:'\
      '\n         if [ -d "$file" ]; then'\
      '\n'\
      '\n            # Isolate the connection number from the connection folders '\
      '\n            # by using two successive cut commands.'\
      '\n            # The first cut isolates the fifth element using the / delimeter character.'\
      '\n            # The second cut takes the input from the previous cut and isolates'\
      '\n            # the third element using the . delimeter character. Thus the connection_number'\
      '\n            # is derived.'\
      '\n            connection_number=$(echo $file | cut -d'/' -f5 | cut -d'.' -f3)'\
      '\n'\
      '\n            # Case 1: Connection to server exists. Maintain the encryption immunity token.'\
      '\n            # We specify three conditions which must be TRUE. '\
      '\n               # 1. The absence of a SOCAT process for a specific Fluidity connection.'\
      '\n               # 2. do_not_encrypt token not being present in tokenSlot.'\
      '\n               # 3. A successful server pinging response by performing two pinging efforts.'\
      '\n            # If the above conditions apply, then do the following:'\
      '\n            if [[ ! $(lsof | grep "connection.'$3'.$connection_number/clientcon.'$3'.$connection_number.pem") ]] && \\\n'\
      '               [ -f /home/'$2'/Fluidity_Client/connection.'$3'.$connection_number/tokenSlot/'$filename' ] && \\\n'\
      '                ping -c 2 '$4'; then'\
      '\n'\
      '\n               # Source the variables $seal_1 and $seal_2 contained in the do_not_encrypt token.'\
      '\n               source /home/'$2'/Fluidity_Client/connection.'$3'.$connection_number/tokenSlot/'$filename\
      '\n               # Derive $seal_1 from the hashed key embedded in seek_and_encrypt by using $seal_2.'\
      '\n               result=$(echo '$client_hashed_key' |  openssl enc -aes-128-cbc -md sha512 -pbkdf2 -iter 100000 -a -d -salt -pass pass:$seal_2)'\
      '\n'\
      '\n               # In case $seal_1 contained in the do_not_encrypt token doesn'"'"'t much the derived result'\
      '\n               if [ "$seal_1" != "$result" ]; then'\
      '\n                  # do_not_encrypt token is bogus and shouldn'"'"'t offer encryption immunity'\
      '\n                  # to the specific connection folder. umount the specified connection folder.'\
      '\n                  sudo umount /home/'$2'/Fluidity_Client/connection.'$3'.$connection_number'\
      '\n               fi'\
      '\n'\
      '\n            # Case 2: Connection to server is lost. Protect the encryption immunity token by deleting'\
      '\n            # and substituting it with the file "resetSSL.txt".'\
      '\n            # We specify two conditions which must be TRUE '\
      '\n               # 1. The absence of a SOCAT process for a specific Fluidity connection.'\
      '\n               # 2. do_not_encrypt token not being present in tokenSlot.'\
      '\n            # If the above conditions apply, then do the following:'\
      '\n            elif [[ ! $(lsof | grep "connection.'$3'.$connection_number/clientcon.'$3'.$connection_number.pem") ]] && \\\n'\
      '               [ -f /home/'$2'/Fluidity_Client/connection.'$3'.$connection_number/tokenSlot/'$filename' ]; then'\
      '\n'\
      '\n               # Create a file containing the string "resetSSL" and named "resetSSL.txt"'\
      '\n               echo "resetSSL" > home/'$2'/Fluidity_Client/connection.'$3'.$connection_number/tokenSlot/resetSSL.txt'\
      '\n               # Delete the do_not_encrypt token from the tokenSlot folder.'\
      '\n               rm home/'$2'/Fluidity_Client/connection.'$3'.$connection_number/tokenSlot/'$filename\
      '\n               # umount the specified connection folder.'\
      '\n               sudo umount /home/'$2'/Fluidity_Client/connection.'$3'.$connection_number'\
      '\n'\
      '\n            # Case 3: A connection folder corresponding to a currently inactive Fluidity connection.'\
      '\n            # We specify one condition which should be TRUE '\
      '\n               # 1. The absence of a SOCAT process for a specific Fluidity connection.'\
      '\n            # If the above condition applies, then do the following:'\
      '\n            elif [[ ! $(lsof | grep "connection.'$3'.$connection_number/clientcon.'$3'.$connection_number.pem") ]]; then'\
      '\n'\
      '\n               # umount the specified connection folder.'\
      '\n               sudo umount /home/'$2'/Fluidity_Client/connection.'$3'.$connection_number'\
      '\n'\
      '\n            fi'\
      '\n'\
      '\n         fi'\
      '\n'\
      '\n      done'\
      '\n'\
      '\n   # invoke a sleep process to delay the next execution circle.'\
      '\n   # Sleeping time is set between a random interval between '\
      '\n   # of 5 to 7 seconds.'\
      '\n   sleep $(shuf -i 5-7 -n1)'\
      '\n'\
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

   # vvtSng7u
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
   
   # heefhEKX
   # SSH remotely execute genSCRIPT_moveFilesAndActivateDaemon.sh
   ssh $2@$1 'bash -s' < ~/Fluidity_Server/Generated_Scripts/genSCRIPT_moveFilesAndActivateDaemon.sh

}


# 5. Connection Management Functions
# 5.1 Public Functions


# Arguments: ($1), ($2)
# $1: .Fluidity Client (SSH) Connection ID.
# $2: .Fluidity Virtual Circuit (SSL) Connection ID. 

# Sourced Variables:
# 1. ~/Fluidity_Server/client.$SSH_ID/basic_client_info.txt
   # 1. $server_IP_address
   # 2. $client_IP_address
   # 3. $client_username
   # 4. $random_client_port
   
# Intershell File Variables in use: NONE

# Global Variables in use: NONE

# Generates: Nothing

# Invokes Functions:
# 1. installSSLcertificates ($1), ($2), $client_IP_address, ($3), $client_username $server_IP_address
# 2. checkFluidityFilesystemIntegrity, no args

# Calls the script: NONE

# Function Description: Add a .Fluidity connection to target client.
addFluidityConnection () {
   
   # Safety check 1: Check whether Fluidity_Server folder is present 
   # (functionality contained within mountFluidityServerFolder) and 
   # decrypted.
   if [ -z "$(df -T | grep -E 'Fluidity_Server ecryptfs')" ] ; then 

      # Fluidity_Server folder found encrpyted. Use 
      # mountFluidityServerFolder to decrypt it.
      # Invoke mountFluidityServerFolder
      mountFluidityServerFolder
      
   fi
   
   # Source the variables:
      # 1. $server_IP_address
      # 2. $client_IP_address
      # 3. $client_username
      # 4. $random_client_port
   source ~/Fluidity_Server/client.$1/basic_client_info.txt
   
   # Safety check 2: Check whether target connection.[SSH_ID.SSL_ID] 
   # already exists.
   if [ -d ~/Fluidity_Server/client.$1/connection.$1.$2 ]; then
      echo "Fluidity Connection $1.$2 already exists"
      return
   fi
   
   # Safety check 3: Check whether target client.[SSH_ID] responds to 
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
   
   # Safety check 4: Recall the SSH identity in case of a recent restart.
   if ! ssh-add -l | grep client.$1; then
      recallSSHidentity $1
   fi
   
   # Safety check 5: Perform a .Fluidity file integrity check.
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
# $1: .Fluidity Client (SSH) Connection ID.
# $2: .Fluidity Virtual Circuit (SSL) Connection ID. 

# Sourced Variables:
# 1. ~/Fluidity_Server/client.$SSH_ID/basic_client_info.txt
   # 1. $server_IP_address
   # 2. $client_IP_address
   # 3. $client_username
   # 4. $random_client_port

# Intershell File Variables in use: NONE

# Global Variables in use: NONE

# Generates: Nothing

# Invokes Functions: NONE

# Calls the script: NONE

# Function Description: Remove a .Fluidity connection from target client.

removeFluidityConnection () {

   # Safety check 1: Check whether Fluidity_Server folder is present 
   # (functionality contained within mountFluidityServerFolder) and 
   # decrypted.
   if [ -z "$(df -T | grep -E 'Fluidity_Server ecryptfs')" ] ; then 

      # Fluidity_Server folder found encrpyted. Use 
      # mountFluidityServerFolder to decrypt it.
      # Invoke mountFluidityServerFolder
      mountFluidityServerFolder
      
   fi

   # Safety Check 2: Request connection removal while the connection is 
   # still active.
   if [ -f ~/Fluidity_Server/client.$1/connection.$1.$2/link_information.txt ]; then
      echo "connection.$1.$2 is currently ACTIVE. Use stopFluidity $1 $2 to close the connection."
      return
   fi

   # Source the following variables:
      # 1. $server_IP_address
      # 2. $client_IP_address
      # 3. $client_username
      # 4. $random_client_port
   source ~/Fluidity_Server/client.$1/basic_client_info.txt

   # Purge the Connection ID ($1) folder in ~/Fluidity_Server 
   # with the corresponding folders in SSL_Cert_Vault
   rm -r ~/Fluidity_Server/client.$1/connection.$1.$2 \
	~/Fluidity_Server/SSL_Cert_Vault/client_con.$1.$2 \
	~/Fluidity_Server/SSL_Cert_Vault/server_con.$1.$2

   # heefhEKX
   # SSH remotely execute 
	# Unmount from ecryptfs the corresponding client folder.
   ssh $client_username@$client_IP_address sudo umount Fluidity_Client/connection.$1.$2
   
   # heefhEKX
   # SSH remotely execute 
   # Erase the client folder.
   ssh $client_username@$client_IP_address rm -r ~/Fluidity_Client/connection.$1.$2
}

# Arguments: ($1), ($2)
# $1: .Fluidity Client (SSH) Connection ID.
# $2: .Fluidity Virtual Circuit (SSL) Connection ID.

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
   # 4. $random_client_port

# Intershell File Variables in use: NONE

# Global Variables in use: NONE

# Generates: Nothing
 
# Invokes Functions: 

# 1. recallSSHidentity, with args: ($1)
# 2. checkForConnectionFolderAndDecrypt, with args: ($1) ($2) 
#  $(client_IP_address) ($client_username)
# 3. getNetstatConnectionStatus, with args: ($server_listening_port)
# 4. activeLinkInternalSSLrenew, with args: ($1) ($2)
# 5. inactiveLinkInternalSSLrenew, with args: ($1) ($2)

# Calls the script:

# 1. genSCRIPT_BlockProcess.$1.sh, with args: (

# Function Description: Substitute the existing SSL certificates.
# This function renews the SSL certificates, for a target .Fluidity
# connection.[SSH_ID.SSL_ID] and deals with three main scenarios:
# 1st scenario: Renew the SSL certificates on an active link.
# 2nd scenario: Renew the SSL certificates on an inactive link.
# 3rd scenatio: Return warning for a wrong input.

renewSSL () {
   
   # Safety check 1: Check whether Fluidity_Server folder is present 
   # (functionality contained within mountFluidityServerFolder) and 
   # decrypted.
   if [ -z "$(df -T | grep -E 'Fluidity_Server ecryptfs')" ] ; then 

      # Fluidity_Server folder found encrpyted. Use 
      # mountFluidityServerFolder to decrypt it.
      # Invoke mountFluidityServerFolder
      mountFluidityServerFolder
      
   fi
   
   # Case 1: Act upon an active link.

   # Condition: link_information.txt exists.
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
      
      
      # Good scenario: Netstat reports that connection.[SSH_ID.SSL_ID]
      # is "ESTABLISHED" AND .Fluidity is in "ACTIVE" state.
      if [ $(getNetstatConnectionStatus $server_listening_port) == "ESTABLISHED" ] && \
      [ $(getFluidityConnectionStatus $fluidity_connection_ID) == "ACTIVE" ]; then
         # Information message: Report to user that .Fluidity will be 
         # paused and resumed in order to perform SSL substitution.
         echo "Fluidity connection.$1.$2 is in ACTIVE state. Fluidity will be paused and resumed."
      # Not so good scenario: Client is lost. .Fluidity is in "PINGING" 
      # state.
      elif [ $(getFluidityConnectionStatus $fluidity_connection_ID) == "PINGING" ]; then
         # Information message: Report to user that SSL substitution
         # will not be performed, due to a lost client.
         echo "Fluidity connection.$1.$2 is in PINGING state. Canceling the SSL certificate renewal process."
         return
      # An exceptional scenario: .Fluidity connection is DOWN,
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
   
      # Invoke activeLinkInternalSSLrenew
      activeLinkInternalSSLrenew $1.$2
   
      # Information message to user.
      echo "Client - Server SSL certificates for connection $1.$2 renewed successfully."
      
   # Case 2: Act upon an inactive INACTIVE link.
   # Condition: link_information.txt is missing.
   
   # Check that basic_client_info.txt and connection.[SSH_ID.SSL_ID]
   # exists.
   elif [ -f ~/Fluidity_Server/client.$1/basic_client_info.txt ] && \
   [ -d ~/Fluidity_Server/client.$1/connection.$1.$2 ]; then
   
      # Source the variables:
         # 1. $server_IP_address
         # 2. $client_IP_address
         # 3. $client_username
         # 4. $random_client_port
      source ~/Fluidity_Server/client.$1/basic_client_info.txt
      
      # Safety check 1: Check whether target client.[SSH_ID] responds to 
      # pinging. 
      if ! ping -c 3 $client_IP_address; then
         echo "Fluidity client $1 in IP $client_IP_address is unreachable. Canceling the renewal process."
         return
      fi
      
      # Safety check 2: Recall the SSH ID in case it isn't loaded.
      if ! ssh-add -l | grep client.$1; then
      
         #Invoke recallSSHidentity
         recallSSHidentity $1
         
      fi
   
      # Information message to user.
      echo "Fluidity connection.$1.$2 is currently INACTIVE, but exists."
      echo "SSL Substitution will proceed for INACTIVE link $1.$2."
      
      # heefhEKX
      ssh $client_username@$client_IP_address 'bash -s' < ~/Fluidity_Server/client.$1/connection.$1.$2/genSCRIPT_BlockProcess.$1.$2.sh & 
      
      # Safety check 3: Check whether target connection folder is encrypted.
      checkForConnectionFolderAndDecrypt $1.$2 $client_IP_address $client_username
      
      # Invoke doAnInternalSSLrenewInactiveLink
      inactiveLinkInternalSSLrenew $1.$2
   
      # Information message to user.
      echo "Client - Server SSL certificates for connection $1.$2 renewed successfully."
   
   # 3rd scenario: Invalid connection SSH and SSL id.
   else
      
      # Information message to user.
      echo "Fluidity connection.$1.$2 does not exist."
      
   fi
   
}


# 5. Connection Management Functions
# 5.2 Private Functions


# Arguments: ($1), ($2)
# $1: .Fluidity Connection ID [SSH_ID.SSL_ID] 

# Sourced Variables:
# 1. ~/Fluidity_Server/client.$1/basic_client_info.txt
   # 1. $server_IP_address
   # 2. $client_IP_address
   # 3. $client_username
   # 4. $random_client_port

# Intershell File Variables in use: NONE

# Global Variables in use: NONE

# Generates: Nothing

# Invokes Functions:
# 1. copyDoNotEncryptToken, with args: ($1), ($client_IP_address)
#  ($client_username)
# 2. reinstallSSLcerts, with args: ($1), ($client_IP_address) 
#  ($client_username) ($server_IP_address)
# 3. deleteDoNotEncryptToken, with args: ($1), ($client_IP_address) 
#  ($client_username)

# Calls the script: NONE

# Function Description: Renew the SSL certificates on an inactive 
# .Fluidity connection.

inactiveLinkInternalSSLrenew () {
   
   local SSH_ID=${1%.*}
   
   # Source the variables:
      # 1. $server_IP_address
      # 2. $client_IP_address
      # 3. $client_username
      # 4. $random_client_port
   source ~/Fluidity_Server/client.$SSH_ID/basic_client_info.txt
   
   # invoke copyDoNotEncryptToken
   # Transmit the immunity encryption token to client.
   copyDoNotEncryptToken $1 $client_IP_address $client_username
         
   # invoke reinstallSSLcerts
   # Reinstall the SSL certificates for target connection to folder
   # connection.[SSH_ID.SSL_ID]
   reinstallSSLcerts $1 $client_IP_address $client_username $server_IP_address
      
   # invoke deleteDoNotEncryptToken
   # Remove the encryption immunity token from target client.
   deleteDoNotEncryptToken $1 $client_IP_address $client_username
   
}

# Arguments: ($1)
# $1: .Fluidity Connection ID [SSH_ID.SSL_ID] 

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

# Intershell File Variables in use: NONE

# Global Variables in use: NONE

# Generates: Nothing

# Invokes Functions:
# 1. copyDoNotEncryptToken, with args:
#  ($fluidity_connection_ID), ($client_ip_add), ($client_username)
# 2. deleteDoNotEncryptToken, with args:
#  ($fluidity_connection_ID), ($client_ip_add), ($client_username)
# 3. stopFluidityToRenewSSLcerts, with args ($fluidity_connection_ID)
# 4. establishSOCATlink, with args:
#	a. ($fluidity_connection_ID), ($server_serial_int), 
#	 ($server_listening_port), ($client_serial_int), ($client_ip_add), 
#	  ($client_username), ($link_serial_speed), ($server_ip_add), (-s)
#	b. ($fluidity_connection_ID), ($server_tunnel_ip), 
#	 ($server_listening_port), ($client_tunnel_ip), ($client_ip_add),
# 	  ($client_username), ($tunneling_network_subnet_mask),
#	   ($server_ip_add), (-t)
# 5. reinstallSSLcerts, with args:
# ($fluidity_connection_ID), ($client_ip_add), ($client_username), 
#  ($server_ip_add)

# Calls the script: NONE

# Function Description: Renew the SSL certificates on an active 
# .Fluidity connection.

activeLinkInternalSSLrenew () {
   
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
   
      # invoke copyDoNotEncryptToken
      # Block FLdaemon_SeekAndEncrypt.service from encrypting the
      # connection.[SSL_ID.SSH.ID] folder.
      copyDoNotEncryptToken $fluidity_connection_ID $client_ip_add $client_username
   
      # invoke stopFluidityToRenewSSLcerts
      # Perform a special stopFluidity that paves the way to SSL 
      # substitution.
      stopFluidityToRenewSSLcerts $fluidity_connection_ID
      
      # Information message to user.
      echo "Fluidity engine for connection $fluidity_connection_ID successfully stopped."
   
      # invoke reinstallSSLcerts
      # Reinstall the SSL certificates for target connection.
      reinstallSSLcerts $fluidity_connection_ID $client_ip_add $client_username $server_ip_add
      
      # Information message to user.
      echo "SSL substitution for connection $fluidity_connection_ID successfully completed."
   
      # Certificate reinstallation is done. 
      # Re-establish the SOCAT link. Based on link_information.txt
      # start .Fluidity with the proper .Fluidity flavour choice.
      
      # kzjFgtUz
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
      
      # Information message to user.
      echo "Fluidity link for connection $fluidity_connection_ID successfully re-established."
   
      # invoke deleteDoNotEncryptToken
      # Unblock FLdaemon_SeekAndEncrypt.service
      deleteDoNotEncryptToken $fluidity_connection_ID $client_ip_add $client_username
   
}

# Arguments: ($1), ($2), ($3), ($4)
# $1: .Fluidity Connection ID [SSH_ID.SSL_ID] 
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
# 7. Bash script (.sh): genSCRIPT_BlockProcess.$1.sh

# Invokes Functions:
# 1. checkLocalEntropy, no args
# 2. checkRemoteEntropy, with args ($2), ($3)
# 4. clientFolderCreation, with args ($1), ${encr_password[$array_index]}
# 5. clientSSLinstallation, with args ($1), ${c_password[$array_index]},
#  $server_IP_no_whitespace, $server_username, ($2), ($3)
# 6. deleteDoNotEncryptToken, with args ($1), ($2), ($3)

# Calls the script: NONE

# Function Description: Create and install a new SSL certificate pair
# for the target .Fluidity connection. 
installSSLcertificates () {

   # Variable declarations

   # Delete whitespace characters (i.e. ' ') from function argument 
   # $4 (Server IP address). Save the outcome to variable: 
   # $server_IP_no_whitespace.
   local server_IP_no_whitespace="$(echo -e $4 | sed -e 's/[[:space:]]*$//')"
   
   # Extract server's username from environment variable: $USER.
   local server_username="$USER"

   # Derive the array index from .Fluidity ID
   local array_index=$(expr ${1#*.} - 1)
   
   # Derive the SSH ID from .Fluidity ID
   local SSH_ID=${1%.*}
   
   # Use the ~/Fluidity_Server folder to temporary store the SSL 
   # certificates, perform the subsequent file operations and, then, 
   # move everything to the corresponding .Fluidity connection data and
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
   encr_password[$array_index]=$(openssl rand -base64 12 | tr -dc A-Za-z0-9)
   echo ${encr_password[$array_index]} > encr_password.$1.txt
   cat encr_password.$1.txt

   # connection[SSH_ID.SSL_ID]: The .Fluidity connection folder that will
   # contain the entirety of the relevant connection files for
   # the specific SOCAT SSL link. 
   mkdir ~/Fluidity_Server/client.$SSH_ID/connection.$1 

   # Folders, that will host the backup copies of the generated SSL credentials.
   mkdir SSL_Cert_Vault/client_con.$1 \
   SSL_Cert_Vault/server_con.$1

   if [[ ! -e ~/Fluidity_Server/client.$SSH_ID/connection.$1/genSCRIPT_BlockProcess.$1.sh ]]; then
   
   cat <<- 'END_CAT' > ~/Fluidity_Server/client.$SSH_ID/connection.$1/genSCRIPT_BlockProcess.$1.sh
   (sudo systemctl stop FLdaemon_SeekAndEncrypt.service & sleep 30;\
   sudo systemctl start FLdaemon_SeekAndEncrypt.service &)
END_CAT

   chmod 700 ~/Fluidity_Server/client.$SSH_ID/connection.$1/genSCRIPT_BlockProcess.$1.sh

   fi

   # Invoke clientFolderCreation
   # Create the encrypted Fluidity_Client folder over SSH on 
   # client's side 
   clientFolderCreation $1 ${encr_password[$array_index]} $2 $3

   # SECTION 2: Generate passwords for the SSL certificates by using the 
   # openssl rand function and store the outcome to variables:
   # 1. s_password[$array_index] (Server SSL Password)
   # 2. c_password[$array_index] (Client SSL Password)
   # and subsequently save those passwords to text files:
   # 1. s_password[$array_index].txt (Server SSL Password)
   # 2. c_password[$array_index].txt (Client SSL Password)

   # Server password for connection [(X) i.e. Client ID.SSL Virtual Circuit ID]
   s_password[$array_index]=$(openssl rand -base64 12)
   echo ${s_password[$array_index]} > s_password.$1.txt
   cat s_password.$1.txt

   # Client password for connection [(X) i.e.Client ID.SSL Virtual Circuit ID]
   c_password[$array_index]=$(openssl rand -base64 12)
   echo ${c_password[$array_index]} > c_password.$1.txt
   cat c_password.$1.txt

   # SECTION3: SSL certificate password obfuscation
   
   # Change the actual SSL certificate password to a bogus password, 
   # to hide it from the arguments list, in case a process viewer (htop)
   # is executed on client machine.
   
   # Generate the client bogus password for 
   # connection [(X) i.e.Client ID.SSL Virtual Circuit ID]
   c_bogus_password[$array_index]=$(openssl rand -base64 12)
   echo ${c_bogus_password[$array_index]} > c_bogus_password.$1.txt
   cat c_bogus_password.$1.txt
   
   # Pipe c_password[$array_index] into openssl enc function and use 
   # c_bogus_password[$array_index] to generate the hash to be embedded 
   # into the dynamically .Fluidity connection client genSCRIPT.
   # ~/Fluidity_Server/client.[SSH_ID]/connection.[SSH_ID.SSL_ID]/
   # genSCRIPT_client.[SSH_ID.SSL_ID].sh
   echo ${c_password[$array_index]} | \
   openssl enc -aes-128-cbc -md sha512 -pbkdf2 -iter 100000 -a -salt -pass \
   pass:${c_bogus_password[$array_index]} > hashed_clientpass_con.$1.txt

   # SECTION4: Self-signed client - server certificate creation.

   # Generate the self signed server certificate

   # Generate a private key
   openssl genpkey -algorithm RSA -out servercon.$1.key \
      -aes-256-cbc -pass pass:${s_password[$array_index]}
      
   # tQscITd
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

   # vvtSng7u
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
   
   # Invoke deleteDoNotEncryptToken
   deleteDoNotEncryptToken $1 $2 $3
    
}

# Arguments: ($1), ($2), ($3), ($4)
# $1: .Fluidity Connection ID [SSH_ID.SSL_ID] 
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

# Function Description: Create and re-install an SSL certificate pair
# for the target .Fluidity connection. 
reinstallSSLcerts () {

   # Variable declarations

   # Delete whitespace characters (i.e. ' ') from function argument 
   # $5 (Server IP address). Save the outcome to variable: 
   # $server_IP_no_whitespace.
   local server_IP_no_whitespace="$(echo -e $4 | sed -e 's/[[:space:]]*$//')"
   
   # Extract server's username from environment variable: $USER.
   local server_username="$USER"

   # Derive the array index from .Fluidity ID
   local array_index=$(expr ${1#*.} - 1)
   
   # Derive the SSH ID from .Fluidity ID
   local SSH_ID=${1%.*}
   
   # Use the ~/Fluidity_Server folder to temporary store the SSL 
   # certificates, perform the subsequent file operations and, then, 
   # move everything to the corresponding .Fluidity connection data and
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
   s_password[$array_index]=$(openssl rand -base64 12)
   echo ${s_password[$array_index]} > s_password.$1.txt
   cat s_password.$1.txt

   # Client password for connection [(X) i.e.Client ID.SSL Virtual Circuit ID]
   c_password[$array_index]=$(openssl rand -base64 12)
   echo ${c_password[$array_index]} > c_password.$1.txt
   cat c_password.$1.txt

   # SECTION2: Do the SSL certificate password obfuscation
   
   # Change the actual SSL certificate password to a bogus password, 
   # to hide it from the arguments list, in case a process viewer (htop)
   # is executed on client machine.
   
   # Generate the client bogus password for 
   # connection [(X) i.e.Client ID.SSL Virtual Circuit ID]
   c_bogus_password[$array_index]=$(openssl rand -base64 12)
   echo ${c_bogus_password[$array_index]} > c_bogus_password.$1.txt
   cat c_bogus_password.$1.txt

   # Pipe c_password[$array_index] into openssl enc function and use 
   # c_bogus_password[$array_index] to generate the hash to be embedded 
   # into the dynamically .Fluidity connection client genSCRIPT.
   # ~/Fluidity_Server/client.[SSH_ID]/connection.[SSH_ID.SSL_ID]/
   # genSCRIPT_client.[SSH_ID.SSL_ID].sh
   echo ${c_password[$array_index]} | \
   openssl enc -aes-128-cbc -md sha512 -pbkdf2 -iter 100000 -a -salt -pass \
   pass:${c_bogus_password[$array_index]} > hashed_clientpass_con.$1.txt

   # SECTION 3: Self-signed client - server certificate creation

   # Generate the self signed server certificate

   # Generate a private key
   openssl genpkey -algorithm RSA -out servercon.$1.key \
      -aes-256-cbc -pass pass:${s_password[$array_index]}
   
   # tQscITd
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

   # vvtSng7u
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
# $1: .Fluidity Connection ID [SSH_ID.SSL_ID]
# $2: The folder encryption password
# $3: Client IP.
# $4: Client Username.

# Sourced Variables: NONE

# Intershell File Variables in use: NONE

# Global Variables in use: NONE

# Generates: 
# 1. Bash script (.sh): genSCRIPT_clientFolderCreation.sh $1 $2

# Invokes Functions:
# 1. copyDoNotEncryptToken, with args: ($1), ($3), ($4)

# Calls the script: 
# 1. genSCRIPT_BlockProcess.[SSH_ID.SSL_ID].sh, no args.
# 2. genSCRIPT_clientFolderCreation.sh, with args ($1), ($2)
# in ~/Fluidity_Server/Generated_Scripts

# Function Description:  
# 1. Create a client connection.[SSH_ID.SSL_ID] folder within ~/Fluidity_Client
# that will contain the necessary files for establishing an SSL connection.
# 2. Encrypt connection.[SSH_ID.SSL_ID] folder by using eCryptFS.
# 3. Create a folder named "tokenSlot", within connection.[SSH_ID.SSL_ID],
# that will act as a placeholder for the encryption prevention token.

clientFolderCreation () {
   
   local SSH_ID=${1%.*}

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
   
   # heefhEKX
   ssh $4@$3 'bash -s' < ~/Fluidity_Server/client.$SSH_ID/connection.$1/genSCRIPT_BlockProcess.$1.sh &
   
   # heefhEKX
   # SSH remotely execute genSCRIPT_clientFolderCreation.sh
   ssh $4@$3 'bash -s' < ~/Fluidity_Server/Generated_Scripts/genSCRIPT_clientFolderCreation.sh \
	$1 $2
  
   # Invoke copyDoNotEncryptToken
   copyDoNotEncryptToken $1 $3 $4
}

# Arguments: ($1), ($2), ($3), ($4)
# $1: .Fluidity Connection ID [SSH_ID.SSL_ID]
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
# 1. Access the .Fluidity connection folder "connection.[SSH_ID.SSL_ID]".
# 2. Execute openssl genpkey and produce the private key (.key).
# 3. Execute openssl req and produce the self-signed certificate (.crt).
# 4. Merge the (.key) and (.crt) files to produce a (.pem) file.
# 5. Change permissions on (.key) and (.pem) files.
# 6. Use sshpass to send the (.crt) and (.pem) files to server.
# 7. Delete the (.key) and (.crt) files and keep only the (.pem) file
# into .Fluidity connection folder "connection.[SSH_ID.SSL_ID]".

clientSSLinstallation () {
  
   # tQscITd
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
   
   # heefhEKX
   # SSH remotely execute genSCRIPT_clientSSLinstallation.sh
   ssh $4@$3 'bash -s' < ~/Fluidity_Server/Generated_Scripts/genSCRIPT_clientSSLinstallation.sh \
	$1 $2 $3

   # vvtSng7u
   # Fetch the client SSL certificates from the remote machine.
   scp $4@$3:Fluidity_Client/connection.$1/clientcon.$1.crt \
    ~/Fluidity_Server
   # vvtSng7u
   scp $4@$3:Fluidity_Client/connection.$1/clientcon.$1.pem \
    ~/Fluidity_Server

}

# Arguments: ($1)
# $1: .Fluidity Connection ID [SSH_ID.SSL_ID] 

# Sourced Variables:
# 1. ~/Fluidity_Server/client.$SSH_ID/basic_client_info.txt
   # 1. $server_IP_address
   # 2. $client_IP_address
   # 3. $client_username
   # 4. $random_client_port

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
   
   # Derive SSH ID from .Fluidity ID
   local SSH_ID=${1%.*}
   
   # Source the following variables:
      # 1. $server_IP_address
      # 2. $client_IP_address
      # 3. $client_username
      # 4. $random_client_port
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
'rm ~/Fluidity_Client/connection.$1/clientcon.*.pem\n'\
'rm ~/Fluidity_Client/connection.$1/servercon.*.crt\n'\
      > ~/Fluidity_Server/Generated_Scripts/genSCRIPT__deleteClientSSLpair.sh
      
   fi
   
   # heefhEKX
   # SSH remotely execute genSCRIPT__deleteClientSSLpair.sh
   ssh $client_username@$client_IP_address \
    'bash -s' < ~/Fluidity_Server/Generated_Scripts/genSCRIPT__deleteClientSSLpair.sh $1
   
}

# Arguments: ($1), ($2), ($3)
# $1: .Fluidity Connection ID [SSH_ID.SSL_ID]
# $2: Client IP address.
# $3: Client Username.

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
# the target client machine.
# 3. Securely copy the encryption immunity token to client machine.
copyDoNotEncryptToken() {
   
   # Derive the SSH ID from .Fluidity ID
   local SSH_ID=${1%.*}
   
   # Generate genSCRIPT_purgeDoNotEncryptToken.sh and store it in
   # ~/Fluidity_Server/Generated_Scripts
   if [[ ! -e ~/Fluidity_Server/Generated_Scripts/genSCRIPT_purgeDoNotEncryptToken.sh ]]; then
      
      sudo echo -e \
       'rm ~/Fluidity_Client/connection.$1/tokenSlot/*'\
         > ~/Fluidity_Server/Generated_Scripts/genSCRIPT_purgeDoNotEncryptToken.sh
      chmod 700 ~/Fluidity_Server/Generated_Scripts/genSCRIPT_purgeDoNotEncryptToken.sh
      
   fi
   
   # heefhEKX
   # SSH remotely execute genSCRIPT_purgeDoNotEncryptToken.sh
   ssh $3@$2 'bash -s' < ~/Fluidity_Server/Generated_Scripts/genSCRIPT_purgeDoNotEncryptToken.sh $1
   
   # vvtSng7u
   # Securely copy do_not_encrypt_token to target .Fluidity client in
   # folder ~/Fluidity_Client/connection.[SSH_ID.SSL_ID]/tokenSlot
   scp ~/Fluidity_Server/client.$SSH_ID/do_not_encrypt_token/* \
    $3@$2:Fluidity_Client/connection.$1/tokenSlot
   
}

# Arguments: ($1), ($2), ($3)
# $1: .Fluidity Connection ID [SSH_ID.SSL_ID]
# $2: Client IP address.
# $3: Client Username.

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
   
   # Derive the SSH ID from .Fluidity ID
   local SSH_ID=${1%.*}
   
   # Generate genSCRIPT_purgeDoNotEncryptToken.sh and store it in
   # ~/Fluidity_Server/Generated_Scripts
   if [[ ! -e ~/Fluidity_Server/Generated_Scripts/genSCRIPT_purgeDoNotEncryptToken.sh ]]; then
      
      sudo echo -e \
       'rm ~/Fluidity_Client/connection.$1/tokenSlot/*'\
         > ~/Fluidity_Server/Generated_Scripts/genSCRIPT_purgeDoNotEncryptToken.sh
      chmod 700 ~/Fluidity_Server/Generated_Scripts/genSCRIPT_purgeDoNotEncryptToken.sh
      
   fi
   
   # heefhEKX
   # SSH remotely execute genSCRIPT_purgeDoNotEncryptToken.sh
   ssh $3@$2 'bash -s' < ~/Fluidity_Server/Generated_Scripts/genSCRIPT_purgeDoNotEncryptToken.sh $1
   
}

# 6. .Fluidity Engine Functions
# 6.1 Public Functions


# Arguments:
# $1: Your Fluidity flavour choice [Can be: "-s" serial or "-t" tunnel]
# $2: .Fluidity Client (SSH) Connection ID.
# $3: .Fluidity Virtual Circuit (SSL) Connection ID.
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
   # 4. $random_client_port

# Intershell File Variables in use: NONE

# Global Variables in use: NONE

# Generates: Nothing
 
# Invokes Functions:
# 1. getNetstatConnectionStatus, with args: ($4)
# 2. inactiveLinkInternalSSLrenew, with args: ($2) ($3)
# 3. destroyRunTimeVars, with args: ($2) ($3)
# 4. deleteSOCATlinkStateInformation, with args: ($2) ($3)
# 5. checkForConnectionFolderAndDecrypt, with args: ($2) ($3) 
#     ($client_IP_address) ($client_username)
# 6. recallSSHidentity, with args: ($2)
# 7. establishSOCATlink, with args: ($2), ($3), ($5), ($4), ($6), 
#    ($client_IP_address), ($client_username), ($7), 
#     ($server_IP_address), ($1)

# Calls the script: NONE

# Function Description: Initiate a fluidity connection

runFluidity () {
   
   
   # Safety check 1: Check whether Fluidity_Server folder is present 
   # (functionality contained within mountFluidityServerFolder) and 
   # decrypted.
   if [ -z "$(df -T | grep -E 'Fluidity_Server ecryptfs')" ] ; then 

      # Fluidity_Server folder found encrpyted. Use 
      # mountFluidityServerFolder to decrypt it.
      # Invoke mountFluidityServerFolder
      mountFluidityServerFolder
      
   fi
   
   # Safety check 2: Verify that the total number arguments are no less than 7.
   if [ "$#" -ne 7 ]; then
      echo "Illegal number of parameters"
      return
   fi
   
   # kzjFgtUz
   # Safety check 3: Argument $1 only -s or -t
   if ! [[ $1 == "-s" || $1 == "-t" ]]; then
      echo -e "Acceptable values \"-s\" SERIAL or \"-t\" TUNNEL."
      return
   fi
   
   # Import the following set of variables:
      # 1. $server_IP_address
      # 2. $client_IP_address
      # 3. $client_username
      # 4. $random_client_port
   source ~/Fluidity_Server/client.$2/basic_client_info.txt
   
   # Safety check 4: Check whether target connection exists.
   if [ ! -d ~/Fluidity_Server/client.$2/connection.$2.$3 ]; then
      # Information message to user.
      echo "No such link exists"
      return
   fi
   
   # kzjFgtUz
   # Safety check 5: Check whether target .Fluidity connection is
   # ACTIVE. If not, then take the precautionary step to delete any
   # state information file, caused from an adnormal shutdown.
   if [[ $(getNetstatConnectionStatus $4) == "ESTABLISHED" ]]\
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
   
   # Precautionary action 1: .Fluidity server abnormally shut down while 
   # a SSL substitution was in progress. Delete the previous state 
   # information and complete the substitution.
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
   
      # Invoke checkForConnectionFolderAndDecrypt
      checkForConnectionFolderAndDecrypt $2.$3 $client_IP_address $client_username

      # Invoke internalSSLrenew
      inactiveLinkInternalSSLrenew $2.$3
      
   # Precautionaty action 2: Delete the remaining state information 
   # caused by an adnormal shutdown.
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
   
   # Safety check 6: Check whether another ACTIVE link exists with
   # the same port.
   if netstat -atnp 2>/dev/null | grep $4; then
      # Information message to user.
      echo "Server port is used by another resource. Please use another port."
      return
   fi
   
   # kzjFgtUz
   # Safety check 7: Check whether the server IP address or server Serial 
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
   
   # kzjFgtUz
   # Safety check 8: Check whether target client IP address is already 
   # in use.
   if ifconfig | grep $6; then
      if [[ "$1" == -t ]]; then
         # Information message to user.
         echo "Client IP address is used by another link or resource."
         echo "Please use a different client IP address."
      fi
      return
   fi
   
   # Precautionary action 3: Check whether client ssh idenity is missing
   # from the SSH keyring.
   if ! ssh-add -l | grep client.$2; then
   
      # Invoke recallSSHidentity
      # Recall the missing identity.
      recallSSHidentity $2
      
      # Message to user
      echo "Fluidity client identity $2 loaded in keyring."
      
   else
      
      # Message to user.
      echo "Fluidity client identity $2 is already loaded in keyring."
      
   fi
   
   # Invoke establishSOCATlink
   establishSOCATlink $2.$3 $5 $4 $6 $client_IP_address $client_username $7 $server_IP_address $1

}

# Arguments: ($1)
# $1: .Fluidity Client (SSH) Connection ID.
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
# 1. getNetstatConnectionStatus, with args: ($port)
# 2. getTheRemotePort, with args: ($port)
# 2. closeTheLocalTunnelInterface, with args: ($server_tunnel_ip)
# 3. closeTheRemoteTunnelInterface, with args: ($1), ($client_tunnel_ip)
# 4. terminationForcePing, with args: ($1)
# 5. destroyRunTimeVars, with args: ($1)
# 6. deleteSOCATlinkStateInformation, with args: ($1)
# 7. closePort, with args: $port

# Calls the script: NONE

# Function Description: Stop .Fluidity for a specific connection
# ID.

stopFluidity () {

   # Safety check 1: Check whether Fluidity_Server folder is present 
   # (functionality contained within mountFluidityServerFolder) and 
   # decrypted.
   if [ -z "$(df -T | grep -E 'Fluidity_Server ecryptfs')" ] ; then 

      # Fluidity_Server folder found encrpyted. Use 
      # mountFluidityServerFolder to decrypt it.
      # Invoke mountFluidityServerFolder
      mountFluidityServerFolder
      
   fi

   # Derive the .Fluidity ID
   local fluidity_id=$(echo $1.$2)

   # Safety check 2: Check whether targer connection exists.
   if [ ! -d ~/Fluidity_Server/client.$1/connection.$1.$2 ]; then
      # Information message to user.
      echo "No such link exists"
      return
   fi
   
   # Safety check 3: Check whether the link is INACTIVE.
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

   # .Fluidity Finite State Machine 
   # State change to: TERMINATING
   setFluidityConnectionStatus $fluidity_id "TERMINATING"
   # Send a termination signal to both runPersistentSOCATClient and 
   # runPersistentSOCATServer by turning allow_execution to 0.
   setAllowExecution $fluidity_id 0 
   
   # Get the server's port number.
   port=$(getPort $fluidity_id)
   
   # Case 1: The connection is ESTABLISHED. Kill the client AND server 
   # SOCAT connection process.
   if [[ $(getNetstatConnectionStatus $port) == "ESTABLISHED" ]]; then

         # kzjFgtUz
         # For .Fluidity -t
         # Delete the firewall rules that allow traffic through the
         # client - server tunnel interfaces before the connection ends.
         if [[ "$fluidity_flavour_choice" == -t ]]; then
   
            # Invoke closeTheLocalTunnelInterface
            closeTheLocalTunnelInterface $server_tunnel_ip
            # Invoke closeTheRemoteTunnelInterface
            closeTheRemoteTunnelInterface $1 $client_tunnel_ip
      
         fi

      # heefhEKX
      # Use function fuser, with client port number ($remote_port), 
      # to terminate the remote client SOCAT process. When the process 
      # is terminated, both infinite loops within 
      # runPersistentSOCATServer & runPersistentSOCATClient will restart
      # and subsequently break from execution, due to $allow_execution 
      # being 0.
      ssh $client_username@$client_ip_add sudo fuser -k $(getTheRemotePort $port)/tcp
      
      # Use function fuser, with server port number ($port), to terminate 
      # the local server SOCAT process. When the process is terminated, 
      # both infinite loops within runPersistentSOCATServer & 
      # runPersistentSOCATClient will restart and subsequently break from
      # execution, due to $allow_execution being 0.
      sudo fuser -k $port/tcp
   
   # Case 2: The connection is lost. Kill the server SOCAT connection 
   # process.
   else 
      
      # Safety Check 4: Invoke terminationForcePing
      # Here, we cover the possibility that .Fluidity lost its client, thus
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
   # rZ7y4zq
   # Debugging Section
   # echo "client_is_terminated: $(getClientIsTerminated $fluidity_id)"
   # echo "server_is_terminated: $(getServerIsTerminated $fluidity_id)"
   # echo "terminationForcePing is: $(getTerminationForcePing $fluidity_id)"
      if [[ $(getServerIsTerminated $fluidity_id) -eq 1 && $(getClientIsTerminated $fluidity_id) -eq 1 && $(getTerminationForcePing $fluidity_id) -ne 0 ]]; then
         
         # .Fluidity Finite State Machine 
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
      
         # .Fluidity Finite State Machine 
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
   
   reportWhenFirewallRulesAreRemoved $1 $server_listening_port &

}


# 6. .Fluidity Engine Functions
# 6.2 Private Functions
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
# allow traffic (create ALLOW rule) through the SOCAT listening port.

openPort () {
   
   # S99zBE5
   # UFW: Rule change for port $1
   sudo ufw allow $1 &>/dev/null
   
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
# deny the traffic (delete ALLOW rule) through the SOCAT listening port.

closePort () {
   
   # S99zBE5
   # UFW: Rule change for port $1
   sudo ufw delete allow $1 &>/dev/null
   
}

# Arguments: ($1), ($2), ($3)
# $1: .Fluidity Connection ID [SSH_ID.SSL_ID]
# $2: Server's IP address
# $3: Server Listening Port
# $4: Client's IP address
# $5: .Fluidity Flavour

# Sourced Variables: NONE

# Intershell File Variables in use:
# 1. $allow_execution (setAllowExecution, getAllowExecution)

# Global Variables in use: NONE

# Generates: Nothing

# Invokes Functions:
# 1. openTheLocalTunnelInterface, with args: $2
# 2. openTheRemoteTunnelInterface, with args: $1, $4

# Calls the script: NONE

# Function Description: Allow traffic through the SOCAT connect tunnel
# interfaces.
openTheTunnelInterfaces () {
   
   # kzjFgtUz
   # Get into loop only for option -t (tunnel connections)
   if [[ "$5" == -t ]]; then

      # While $allow_execution is 1 (.Fluidity execution is allowed)
      while [ $(getAllowExecution $1) -eq 1 ];
      do
      
         # And If netstat reports that the specific SOCAT connection is
         # established
         if [[ $(getNetstatConnectionStatus $3) == "ESTABLISHED" ]]; then
         
            echo "ready to execute"
         
         
            # Allow the traffic through the local tunnel interface.
            # Invoke openTheLocalTunnelInterface
            openTheLocalTunnelInterface $2
            
            # Allow the traffic through the remote tunnel interface.
            # Invoke openTheRemoteTunnelInterface
            openTheRemoteTunnelInterface $1 $4
            
            # Break the loop.
            break
            
         else
         
            # Link is still not ESTABLISHED. Sleep for 1 sec.
            sleep 1
            
         fi
         
      done

   fi

}

# Arguments: ($1)
# $1: Server's tunnel interface IP

# Sourced Variables: NONE

# Intershell File Variables in use: NONE

# Global Variables in use: NONE

# Generates: NOTHING

# Calls the script: NONE

# Invokes Functions:
# 1. findInterfaceFromIP with args: ($1)

# Function Description: Allow inbound and outbound traffic from the
# tunX Server interface. 
openTheLocalTunnelInterface () {
   
   local interface
   
   interface=$(findInterfaceFromIP $1)
   
   # S99zBE5
   sudo ufw allow in on $interface &>/dev/null
   sudo ufw allow out on $interface &>/dev/null
   
}

# Arguments: ($1), ($2)
# $1: .Fluidity Client (SSH) Connection ID.
# $2: Client's tunnel interface IP

# Sourced Variables:
# 1. ~/Fluidity_Server/client.$SSH_ID/basic_client_info.txt
   # 1. $server_IP_address
   # 2. $client_IP_address
   # 3. $client_hostname
   # 4. $random_client_port

# Intershell File Variables in use: NONE

# Global Variables in use: NONE

# Generates:
# 1. Bash script (.sh): genSCRIPT_openTheRemoteTunnelInterface
#  $1 $2 $3

# Calls the script: 
# 1. genSCRIPT_openTheRemoteTunnelInterface, with args ($1), ($2), ($3)

# Invokes Functions:
# In genSCRIPT_openTheRemoteTunnelInterface.sh:
#   1. findInterfaceFromIP with args: ($1)

# Function Description: Allow inbound and outbound traffic from the
# tunX Client interface. 
openTheRemoteTunnelInterface () {
   
      local SSH_ID=${1%.*}
   
      # Import the following set of variables:
      # 1. $server_IP_address
      # 2. $client_IP_address
      # 3. $client_username
      # 4. $random_client_port
   source ~/Fluidity_Server/client.$SSH_ID/basic_client_info.txt
   
   if [[ ! -e ~/Fluidity_Server/Generated_Scripts/genSCRIPT_openTheRemoteTunnelInterface.sh ]]; then
   
      cat << EOF > ~/Fluidity_Server/Generated_Scripts/genSCRIPT_openTheRemoteTunnelInterface.sh
interface=\$(sudo ifconfig | grep -B 2 $2 | cut -d' ' -f 1 | sed 's/://')

# S99zBE5
sudo ufw allow in on \$interface &>/dev/null
sudo ufw allow out on \$interface &>/dev/null
   
EOF

   else
   
      rm ~/Fluidity_Server/Generated_Scripts/genSCRIPT_openTheRemoteTunnelInterface.sh
      
      cat << EOF > ~/Fluidity_Server/Generated_Scripts/genSCRIPT_openTheRemoteTunnelInterface.sh
interface=\$(sudo ifconfig | grep -B 2 $2 | cut -d' ' -f 1 | sed 's/://')

# S99zBE5
sudo ufw allow in on \$interface &>/dev/null
sudo ufw allow out on \$interface &>/dev/null
   
EOF

   fi

   # heefhEKX
   ssh $client_username@$client_IP_address 'bash -s' < ~/Fluidity_Server/Generated_Scripts/genSCRIPT_openTheRemoteTunnelInterface.sh

}

# Arguments: ($1)
# $1: .Fluidity Client (SSH) Connection ID.
# $2: Clients's tunnel interface IP

# Sourced Variables: NONE

# Intershell File Variables in use: NONE

# Global Variables in use: NONE

# Generates: NOTHING

# Calls the script: NONE

# Invokes Functions:
# 1. findInterfaceFromIP with args: ($1)

# Function Description: Prohibit inbound and outbound traffic from the
# tunX Server interface.
closeTheLocalTunnelInterface () {
   
   local interface
   
   interface=$(findInterfaceFromIP $1)
   
   # S99zBE5
   sudo ufw delete allow in on $interface &>/dev/null
   sudo ufw delete allow out on $interface &>/dev/null
   
}

# Arguments: ($1)
# $1: Clients's tunnel interface IP

# Sourced Variables: NONE

# Intershell File Variables in use: NONE

# Global Variables in use: NONE

# Generates:
# 1. Bash script (.sh): genSCRIPT_closeTheRemoteTunnelInterface
#  $1 $2 $3

# Calls the script: 
# 1. genSCRIPT_closeTheRemoteTunnelInterface, with args ($1), ($2), ($3)

# Invokes Functions:
# In genSCRIPT_closeTheRemoteTunnelInterface.sh:
#   1. findInterfaceFromIP with args: ($1)

# Function Description: Prohibit inbound and outbound traffic from the
# tunX Client interface. 
closeTheRemoteTunnelInterface () {
   
   # Import the following set of variables:
      # 1. $server_IP_address
      # 2. $client_IP_address
      # 3. $client_username
      # 4. $random_client_port
   source ~/Fluidity_Server/client.$1/basic_client_info.txt
   
   if [[ ! -e ~/Fluidity_Server/Generated_Scripts/genSCRIPT_closeTheRemoteTunnelInterface.sh ]]; then
   
      cat << EOF > ~/Fluidity_Server/Generated_Scripts/genSCRIPT_closeTheRemoteTunnelInterface.sh
interface=\$(sudo ifconfig | grep -B 2 $2 | cut -d' ' -f 1 | sed 's/://')
      
# S99zBE5
sudo ufw delete allow in on \$interface &>/dev/null
sudo ufw delete allow out on \$interface &>/dev/null
   
EOF

   else
   
      rm ~/Fluidity_Server/Generated_Scripts/genSCRIPT_closeTheRemoteTunnelInterface.sh
      
      cat << EOF > ~/Fluidity_Server/Generated_Scripts/genSCRIPT_closeTheRemoteTunnelInterface.sh
interface=\$(sudo ifconfig | grep -B 2 $2 | cut -d' ' -f 1 | sed 's/://')
      
# S99zBE5
sudo ufw delete allow in on \$interface &>/dev/null
sudo ufw delete allow out on \$interface &>/dev/null
   
EOF

   fi

   # heefhEKX
   ssh $client_username@$client_IP_address 'bash -s' < ~/Fluidity_Server/Generated_Scripts/genSCRIPT_closeTheRemoteTunnelInterface.sh
   
}


# 6. .Fluidity Engine Functions
# 6.2 Private Functions
# 6.2.2 Engine Administration


# Arguments: ($1) 
# $1. .Fluidity Connection ID [SSH_ID.SSL_ID]

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

      # rZ7y4zq
      # Debugging section.
      # echo "Not in sleep mode"
      :
   
   # Case 2: The proper scenario.
   # $sleep_id is 0. There is no sleeping process to kill.
   elif [[ $(getSleepPid $1) -eq 0 ]]; then

      # rZ7y4zq
      # Debugging section.
      # echo "Not in sleep mode. sleep_pid = 0."
      :

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
# $1. .Fluidity Connection ID [SSH_ID.SSL_ID]

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
# 1. getNetstatConnectionStatus. with args ($port)
# 2. terminationForcePing, with args ($1)
# 3. destroyRunTimeVars, with args ($1)

# Calls the script: NONE

# Function Description: stopFluidity special case called only by 
# renewSSLcertificates when a SSL substitution is requested. The 
# difference from normal stopFluidity is the absence of
# deleteSOCATlinkStateInformation and closePort.

stopFluidityToRenewSSLcerts () {

   # Derive the SSH ID from .Fluidity ID
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


   # .Fluidity Finite State Machine 
   # State change to: TERMINATING
   setFluidityConnectionStatus $1 "SSL_TERMINATING"
   # Send a termination signal to both runPersistentSOCATClient and 
   # runPersistentSOCATServer by turning allow_execution to 0.
   setAllowExecution $1 0 
   
   # Get the server's port number.
   local port=$(getPort $1)
   
   # Case 1: The connection is ESTABLISHED. Kill the client AND server 
   # connection process.
   if [[ $(getNetstatConnectionStatus $port) == "ESTABLISHED" ]]; then

      # heefhEKX
      # Use function fuser, with client port number ($remote_port), 
      # to terminate the remote client SOCAT process. When the process 
      # is terminated, both infinite loops within 
      # runPersistentSOCATServer & runPersistentSOCATClient will restart
      # and subsequently break from execution, due to $allow_execution 
      # being 0.
      ssh $client_username@$client_ip_add sudo fuser -k $(getTheRemotePort $port)/tcp
      
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
   # Here, we cover the possibility that .Fluidity lost its client, thus
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
         
         # .Fluidity Finite State Machine 
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
      
         # .Fluidity Finite State Machine 
         # State change to: TERMINATION PENDING
         setFluidityConnectionStatus $1 "SSL_TERMINATION_PENDING"
         
         # Invoke terminationForcePing:
         # Do a preemptive terminationForcePing.
         terminationForcePing $1
         
         # Proceed to rechecking
         
      fi
      
   done

}


# 6. .Fluidity Engine Functions
# 6.2 Private Functions
# 6.2.3 Link Setup


# Arguments: ($1), ($2), ($3), ($4), ($5), ($6), ($7), ($8), ($9)
# $1: .Fluidity Connection ID [SSH_ID.SSL_ID]
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
# 1. initializeRunTimeVars, with args: ($1)
# 2. storeSOCATlinkStateInformation, with args: ($1), ($2), ($3), ($4), ($5), ($6), ($7), ($8), ($9)
# 3. runPersistentSOCATServer, with args: ($1), ($2), ($3), ($7)
# 4. runPersistenSOCATClient, with args: ($1) ($4), ($3), ($5), ($6), ($7)
# 5. openPort, with args: ($3)
# 6. reportWhenLinkIsEstablished, with args: ($1), ($3)
# 7. openTheTunnelInterfaces, with args: ($1), ($2), ($3), ($4), ($9)
# 8. deleteTokenFromClient ($1), ($3), ($5), ($6)
# 9. reportWhenFirewallRulesAreAdded, with args: ($1), ($3)

# Calls the script: NONE

# Function Description: Initiate .Fluidity's two main
# functions: runPersistentSOCATServer & runPersistentSOCATClient.

establishSOCATlink () {
   
   # Invoke initializeRunTimeVars
   # Initialize the Intershell File Variables.
   initializeRunTimeVars $1
   
   # Set allow_execution to 1.
   setAllowExecution $1 1
   
   # Set the Server's $port Intershell File Variable.
   setPort $1 $3
   
   # Invoke openPort
   # Change UFW rules to allow the traffic through the designated port.
   openPort $3 &>/dev/null
   
   # Invoke storeSOCATlinkStateInformation
   # Export the variables that this instance is running on for Fluidity's
   # monitoring functions.
   storeSOCATlinkStateInformation $1 $2 $3 $4 $5 $6 $7 $8 $9
   
   # S99zBE5
   # Invoke runPersistentSOCATServer
   # Start the server and run the process in the background. Suppress the
   # command line output.
   (runPersistentSOCATServer $1 $2 $3 $7 $9) &>/dev/null &
   
   # Invoke runPersistentSOCATClient
   # Start the remote client and run the process in the background. 
   (runPersistentSOCATClient $1 $4 $3 $5 $6 $7 $8 $9) &
   
   # Invoke reportWhenLinkIsEstablished
   # Report the link status when the link is detected as established.
   # (Triggered when netstat reports that the link is ESTABLISED)
   reportWhenLinkIsEstablished $1 $3 &
   
   # Invoke openTheTunnelInterfaces
   # Change UFW rules to allow traffic through the TUN interfaces.
   # (Only for -t flavour)
   # (Triggered when netstat reports that the link is ESTABLISED)
   openTheTunnelInterfaces $1 $2 $3 $4 $9 &
   
   #Invoke deleteTokenFromClient
   # Once the link is established, delete the doNotEncrypt token
   # from client machine.
   deleteTokenFromClient $1 $3 $5 $6 &
   
   # Invoke reportWhenFirewallRulesAreAdded
   # Report the UFW status when the link is detected as established.
   # (Triggered when netstat reports that the link is ESTABLISED)
   reportWhenFirewallRulesAreAdded $1 $3 &
   
}


# 6. .Fluidity Engine Functions
# 6.2 Private Functions
# 6.2.3 Link Setup
# 6.2.3.1 Link State Information Administration
# 6.2.3.1.1 Managing Static Information


# Arguments: ($1), ($2), ($3), ($4), ($5), ($6), ($7), ($8), ($9)
# $1: .Fluidity Connection ID [SSH_ID.SSL_ID]
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
# $9: Your .Fluidity flavour choice [Can be: "-s" serial or "-t" tunnel]

# Sourced Variables: NONE

# Intershell File Variables in use: NONE

# Global Variables in use: NONE

# Generates: 
# 1. Text (TXT) File: link_information.txt

# Invokes Functions: NONE

# Calls the script: NONE

# Function Description: Create a link_information.txt containing the 
# state information that comprise the specified SOCAT link.

storeSOCATlinkStateInformation () {
   
   local SSH_ID=${1%.*}
   
   # kzjFgtUz
   if [[ "$9" == -s ]]; then
   
      echo -e \
      'local fluidity_connection_ID='$1\
      '\nlocal server_serial_int='$2\
      '\nlocal server_listening_port='$3\
      '\nlocal client_serial_int='$4\
      '\nlocal client_ip_add='$5\
      '\nlocal client_username='$6\
      '\nlocal link_serial_speed='$7\
      '\nlocal server_ip_add='$8\
      '\nlocal fluidity_flavour_choice='$9\
      > ~/Fluidity_Server/client.$SSH_ID/connection.$1/link_information.txt
   
   elif [[ "$9" == -t ]]; then
   
      echo -e \
      'local fluidity_connection_ID='$1\
      '\nlocal server_tunnel_ip='$2\
      '\nlocal server_listening_port='$3\
      '\nlocal client_tunnel_ip='$4\
      '\nlocal client_ip_add='$5\
      '\nlocal client_username='$6\
      '\nlocal tunneling_network_subnet_mask='$7\
      '\nlocal server_ip_add='$8\
      '\nlocal fluidity_flavour_choice='$9\
      > ~/Fluidity_Server/client.$SSH_ID/connection.$1/link_information.txt
      
   else
   
      return
      
   fi
   
}


# Arguments: ($1)
# $1: .Fluidity Connection ID [SSH_ID.SSL_ID]

# Sourced Variables: NONE

# Intershell File Variables in use: NONE

# Global Variables in use: NONE

# Generates: Nothing

# Invokes Functions: NONE

# Calls the script: NONE

# Function Description: Deletes the link state information container file
# link_information.txt for the specified SOCAT link.

deleteSOCATlinkStateInformation () {
   
   # Derive the SSH ID from .Fluidity ID
   local SSH_ID=${1%.*}
   
   # Remove link_information.txt
   rm ~/Fluidity_Server/client.$SSH_ID/connection.$1/link_information.txt
   
}


# 6. .Fluidity Engine Functions
# 6.2 Private Functions
# 6.2.3 Link Setup
# 6.2.3.1 Link State Information Administration
# 6.2.3.1.2 Managing Dynamic Information


# Arguments: ($1)
# $1: .Fluidity Connection ID [SSH_ID.SSL_ID]

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
   
   # Derive the SSH ID from .Fluidity ID
   local SSH_ID=${1%.*}
   
   mkdir ~/Fluidity_Server/client.$SSH_ID/connection.$1/runtimeVars
   
   # Create and initialize the runTimeVars into Function Description 
   # variables list.
   echo -e 'local allow_execution=0' > ~/Fluidity_Server/client.$SSH_ID/connection.$1/runtimeVars/allow_execution
   echo -e 'local port=0' > ~/Fluidity_Server/client.$SSH_ID/connection.$1/runtimeVars/port
   echo -e 'local server_is_terminated=0' > ~/Fluidity_Server/client.$SSH_ID/connection.$1/runtimeVars/server_is_terminated
   echo -e 'local client_is_terminated=0' > ~/Fluidity_Server/client.$SSH_ID/connection.$1/runtimeVars/client_is_terminated
   echo -e 'local sleep_pid=0' > ~/Fluidity_Server/client.$SSH_ID/connection.$1/runtimeVars/sleep_pid
   echo -e 'local termination_force_ping=0' > ~/Fluidity_Server/client.$SSH_ID/connection.$1/runtimeVars/termination_force_ping
   echo -e 'local fluidity_connection_status=INITIALIZING' > ~/Fluidity_Server/client.$SSH_ID/connection.$1/runtimeVars/fluidity_connection_status
   echo -e 'local ping_delay=0' > ~/Fluidity_Server/client.$SSH_ID/connection.$1/runtimeVars/ping_delay
   
}

# Arguments: ($1)
# $1: .Fluidity Connection ID [SSH_ID.SSL_ID]

# Sourced Variables: NONE

# Intershell File Variables in use: NONE

# Global Variables in use: NONE

# Generates: Nothing

# Invokes Functions: NONE

# Calls the script: NONE

# Function Description: Erase the state information container file 
# runtimeVars.

destroyRunTimeVars () {
   
   # Derive the SSH ID from .Fluidity ID
   local SSH_ID=${1%.*}
   
   # Delete the entire runtimeVars folder for .Fluidity target connection.
   rm -rf ~/Fluidity_Server/client.$SSH_ID/connection.$1/runtimeVars
   
}


# 6. .Fluidity Engine Functions
# 6.2 Private Functions
# 6.2.3 Link Setup
# 6.2.3.2 Server Setup


# Arguments: ($1), ($2), ($3), ($4), ($5)
# $1: .Fluidity Connection ID [SSH_ID.SSL_ID]
# $2: CASE A: [For $5="-s"] The Server Serial Device
#     CASE B: [For $5="-t"] Server's tunnel interface IP
# $3: Server Listening Port
# $4: CASE A: [For $5="-s"] Serial Speed
#     CASE B: [For $5="-t"] Tunneling Network Subnet Mask
# $5: Your .Fluidity flavour choice [Can be: "-s" serial or "-t" tunnel]

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
# $1: .Fluidity Connection ID [SSH_ID.SSL_ID]
# $2: CASE A: [For $5="-s"] The Server Serial Device
#     CASE B: [For $5="-t"] Server's tunnel interface IP
# $3: Server Listening Port
# $4: CASE A: [For $5="-s"] Serial Speed
#     CASE B: [For $5="-t"] Tunneling Network Subnet Mask
# $5: Your .Fluidity flavour choice [Can be: "-s" serial or "-t" tunnel]

# Sourced Variables: NONE

# Intershell File Variables in use: NONE

# Global Variables in use: NONE

# Generates: Nothing

# Calls the script: NONE

# Invokes Functions: 
# 1. runSerialSOCATserver, with args ($1), ($2), ($3), ($4)
# 2. runTUNnelSOCATserver, with args ($1), ($2), ($3), ($4)

# Function Description: .Fluidity server flavour selector. 
# Based on argument $5, choose the desirable connection type for the
# server machine.

runSOCATserver () {
   
   # kzjFgtUz
   # Case 1: Initiate a serial connection.
   if [[ "$5" == -s ]]; then
   
      # Invoke runSerialSOCATserver
      runSerialSOCATserver $1 $2 $3 $4
   
   # Case 2: Initiate an ethernet tunneling connection.
   elif [[ "$5" == -t ]]; then
   
      # Invoke runTUNnelSOCATserver
      runTUNnelSOCATserver $1 $2 $3 $4
      
   fi
   
}

# Arguments: ($1), ($2), ($3), ($4)
# $1: .Fluidity Connection ID [SSH_ID.SSL_ID]
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
# $1: .Fluidity Connection ID [SSH_ID.SSL_ID]
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


# 6. .Fluidity Engine Functions
# 6.2 Private Functions
# 6.2.3 Link Setup
# 6.2.3.3 Client Setup


# Arguments: ($1), ($2), ($3), ($4), ($5), ($6), ($7), ($8)
# $1. .Fluidity Connection ID [SSH_ID.SSL_ID]
# $2: CASE A: [For $8="-s"] Client's Serial Interface
#     CASE B: [For $8="-t"] Client's tunnel interface IP
# $3: Server Listening Port
# $4: Client IP address
# $5: Client username (for raspbian OS the default is pi@)
# $6: CASE A: [For $8="-s"] Serial Speed
#     CASE B: [For $8="-t"] Tunneling Network Subnet Mask
# $7: Server IP
# $8: Your .Fluidity flavour choice [Can be: "-s" serial or "-t" tunnel]

# Sourced Variables: NONE

# Intershell File Variables in use: 
# 1. $client_is_terminated (setClientIsTerminated, getClientIsTerminated)
# 2. $allow_execution (setAllowExecution, getAllowExecution)
# 3. $fluidity_connection_status (setFluidityConnectionStatus, getFluidityConnectionStatus)
# 4. $sleep_pid (setSleepPid, getSleepPid)

# Global Variables in use: NONE

# Generates: Nothing

# Invokes functions:
# 1. checkForConnectionFolderAndDecrypt, with args: ($1), ($4), ($5)
# 2. copyDoNotEncryptToken, with args: ($1), ($4), ($5)
# 2. verifyThatResetSSLisMissing, with args: ($1), ($4), ($5)
# 3. verifyTheSSLCertificates, with args: ($1), ($4), ($5)
# 4. doAClientServerMD5EquivalencyCheck, with args: ($1), ($4), ($5)
# 5. doAClientServerSHA256EquivalencyCheck, with args: ($1), ($4), ($5)
# 6. reinstallSSLcerts, with args: ($1), ($4), ($5), ($7)
# 7. runSOCATclient, with args: ($1), ($2), ($3), ($4), ($5), ($6)
# 8. encryptClient, with args: ($1), ($4), ($5)

# Function Description: Adding persistence to runSOCATclient with a few
# twists.
# Main point is that runPersistentSOCATClient executes until 
# Intershell Global Variable $allow_execution turns from 1 to 0.

runPersistentSOCATClient () {

   local SSH_ID=${1%.*}

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
   
   # rZ7y4zq
   # Debugging information message 1
   # echo "Outside the Loop. Initiating."
   
   # Main Loop: Adding persistency to the SOCAT client process.
   while [ $(getAllowExecution $1) -eq 1 ];
   do
      
      # Ping target client $4 6 times.

      # .Fluidity Finite State Machine 
      # State change to: PINGING
      setFluidityConnectionStatus $1 "PINGING"

      echo -e '\n'

      # .Fluidity client responds.
      if ping -c 6 $4; then
      
         echo -e '\n'
      
         # Reset $ping_delay to 2 seconds.
         ping_delay=2
         
         # rZ7y4zq
         # Debugging information message 4
         # echo "Inside the Loop and proceeding with runSOCATclient."
         # echo "Ping delay is: $ping_delay"
         
         # heefhEKX
         ssh $5@$4 'bash -s' < ~/Fluidity_Server/client.$SSH_ID/connection.$1/genSCRIPT_BlockProcess.$1.sh &  
           
         # S99zBE5
         # Invoke checkForConnectionFolderAndDecrypt:
         # Client communication has been established. Now see whether
         # the client folder is decrypted. If not, then decrypt it.
         checkForConnectionFolderAndDecrypt $1 $4 $5  
         
         # heefhEKX
         # Invoke copyDoNotEncryptToken
         if ! ssh $5@$4 'ls ~/Fluidity_Client/connection.'$1'/tokenSlot/resetSSL.txt'; then
            copyDoNotEncryptToken $1 $4 $5
         fi
         
         # The following section covers the possiblity of a
         # corrupted - incomplete SSL installation. 
         # For a corrupted pair, an SSL substitution will be initiated.
         
         # Precautionary action 1: Verify that the SSL certificates
         # are properly installed and ready to be used. If any of the
         # following safety checks (2, 3 and 4) fails, then do a 
         # cerficate substitution.
         
         # Safety Check 2: Verify that client tokenSlot folder is empty.
         # Safety Check 3: Verify that all client and server SSL 
         # certificates are present and properly installed in their 
         # corresponding folders.
         # Safety Check 4: Verify that .crt and .pem client - server
         # MD5 hashes match.
         # Safety Check 4: Verify that .crt and .pem client - server
         # SHA256 hashes match.
         
         # Invoke verifyThatResetSSLisMissing
         # Invoke verifyTheSSLCertificates
         # Invoke doAClientServerMD5EquivalencyCheck
         # Invoke doAClientServerSHA256EquivalencyCheck
         
         # While any of the following conditions is true perform a SSL
         # substitution.
         while verifyThatResetSSLisMissing $1 $4 $5 | grep -e 'verifyThatResetSSLisMissing FAILED'\
          || verifyThatSSLCertificatesExist $1 $4 $5 | grep -e 'verifyThatSSLCertificatesExist FAILED'\
           || doAClientServerMD5EquivalencyCheck $1 $4 $5 | tee /dev/stderr | grep -e 'doAClientServerMD5EquivalencyCheck FAILED'\
            || doAClientServerSHA256EquivalencyCheck $1 $4 $5 | tee /dev/stderr | grep -e 'doAClientServerSHA256EquivalencyCheck FAILED'; do
            
            # Invoke copyDoNotEncryptToken
            copyDoNotEncryptToken $1 $4 $5
            
            if ! ping -c 4 $4; then
               # Connection to client lost. Break the loop.
               break
            fi
            
            # Message to user.
            echo "Initiating an SSL substitution."
         
            # Invoke internalSSLrenew
            # An aforomentioned safety check failed. Initiate an SSL
            # substitution.
            reinstallSSLcerts $1 $4 $5 $7
         
         done

         # .Fluidity Finite State Machine 
         # State change to: ACTIVE
         setFluidityConnectionStatus $1 "ACTIVE"

         # Update intershell variable $ping_delay
         setPingDelay $1 $ping_delay
         
         # S99zBE5
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
         
      # .Fluidity client doesn't respond.
      else
      
         # rZ7y4zq
         # Debugging information message 5
         # echo "Inside the Loop, but Pinging failed."
         # echo "Ping delay is: $ping_delay"
         
         # .Fluidity Finite State Machine 
         # State change to: SLEEPING
         setFluidityConnectionStatus $1 "SLEEPING"

         # Update intershell variable $ping_delay
         setPingDelay $1 $ping_delay
         
         # Case 1:
         # $ping_delay accumulated more than 600 secs.
         # From there on pinging will occur every 600 seconds.
         if [[ $ping_delay -ge 600 ]]; then
         
            # rZ7y4zq
            # Debugging information message 6
            # echo "Inside the Loop. Pinging above 600secs."
            # echo "Ping delay is: $ping_delay"
            
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
         
            # rZ7y4zq
            # Debugging information message 7
            # echo "Inside the Loop. Pinging below 600secs."
            # echo "Ping delay is: $ping_delay"
            
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
   
   # rZ7y4zq
   # Debugging information message 8
   # echo "Outside the Loop. Main Loop terminated."
   
   # Signal that runPersistentSOCATClient has broken out from the main
   # Loop and completed execution.
   setClientIsTerminated $1 1

}

# Arguments: ($1), ($2), ($3), ($4), ($5), ($6), ($7), ($8)
# $1: .Fluidity Connection ID [SSH_ID.SSL_ID]
# $2: CASE A: [For $8="-s"] Client's Serial Interface
#     CASE B: [For $8="-t"] Client's tunnel interface IP
# $3: Server Listening Port
# $4: Client IP address
# $5: Client username (for raspbian OS the default is pi@)
# $6: CASE A: [For $8="-s"] Serial Speed
#     CASE B: [For $8="-t"] Tunneling Network Subnet Mask
# $7: Server IP
# $8: Your .Fluidity flavour choice [Can be: "-s" serial or "-t" tunnel]

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

# Function Description: .Fluidity client flavour selector. 
# Based on argument $8, choose the desirable connection type for the
# client machine.

runSOCATclient () {
  
   # kzjFgtUz
   # Case 1: Initiate a serial connection.
   if [[ "$8" == -s ]]; then
   
      # Invoke runSerialSOCATclient
      runSerialSOCATclient $1 $2 $3 $4 $5 $6 $7
   
   # Case 2: Initiate an ethernet tunneling connecion.
   elif [[ "$8" == -t ]]; then
   
      # Invoke injectTheListOfFluidityConnectionRoutes
      # Add the client routes list stored in 
      # listOfClientRoutes.[SSH_ID.SSL_ID].sh to client machine.
      # Add the server routes list stored in 
      # listOfServerRoutes.sh to server machine.
      injectTheListOfFluidityConnectionRoutes $1 $3 $4 $5 &
   
      # Invoke runTUNnelSOCATclient
      runTUNnelSOCATclient $1 $2 $3 $4 $5 $6 $7
   
   fi
   
}

# Arguments: ($1), ($2), ($3), ($4), ($5), ($6), ($7)
# $1: .Fluidity Connection ID [SSH_ID.SSL_ID]
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

   # Generate a bash script, named genSCRIPT_client$1.sh ($1: .Fluidity connection ID),
   # that will contain the specific SOCAT connection configuration on client's side.

   # If an existing configuration file is found, leave it intact. Else,
   # create a new one with the default settings.
   if [[ ! -e ~/Fluidity_Server/client.$SSH_ID/connection.$1/genSCRIPT_client.$1.sh ]]; then
   
      echo -e 'cd ~/Fluidity_Client/connection.$1'\
'\n'\
'\npass=$(echo $hashed_pass | openssl enc -aes-128-cbc -md sha512 -pbkdf2 -iter 100000 -a -d -salt -pass pass:$6)'\
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

   # heefhEKX
   # SSH remotely execute genSCRIPT_client.[SSH_ID.SSL_ID].sh
   ssh $5@$4 'bash -s' < ~/Fluidity_Server/client.$SSH_ID/connection.$1/genSCRIPT_client.$1.sh $1 $2 $3 $6 \
	$7 $client_bogus_pass
   
}

# Arguments: ($1), ($2), ($3), ($4), ($5), ($6), ($7), ($8)
# $1: .Fluidity Connection ID [SSH_ID.SSL_ID]
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
'\npass=$(echo $hashed_pass | openssl enc -aes-128-cbc -md sha512 -pbkdf2 -iter 100000 -a -d -salt -pass pass:$6)'\
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

   # heefhEKX
   # Remotely execute genSCRIPT_client.[SSH_ID.SSL_ID].sh
   ssh $5@$4 'bash -s' < ~/Fluidity_Server/client.$SSH_ID/connection.$1/genSCRIPT_client.$1.sh $1 $2 $3 $6 \
	$7 $client_bogus_pass
	
}


# 6. .Fluidity Engine Functions
# 6.2 Private Functions
# 6.2.3 Link Setup
# 6.2.3.3 Client Setup
# 6.2.3.3.1 Client Administration


# Arguments: ($1), ($2), ($3)
# $1. .Fluidity Connection ID [SSH_ID.SSL_ID]
# $2. Client IP address
# $3: Client username (for raspbian OS the default is pi@)

# Sourced Variables: NONE

# Intershell File Variables in use: NONE

# Global Variables in use: NONE

# Generates: Nothing

# Calls the script: NONE

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
      echo "Fluidity client connection.$1 folder found encrypted. Executing ecryptFS."
      decryptClient $1 $2 $3
   else
      echo "Fluidity client connection.$1 folder found decrypted."
   fi
   
}

# Arguments: ($1), ($2), ($3)
# $1. .Fluidity Connection ID [SSH_ID.SSL_ID]
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
   
   # heefhEKX
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
# $1: .Fluidity Connection ID [SSH_ID.SSL_ID]
# $2: Client IP address
# $3: Client username (for raspbian OS the default is pi@)

# Sourced Variables: NONE

# Intershell File Variables in use: NONE

# Global Variables in use: NONE

# Generates:
# 1. Bash script (.sh): genSCRIPT_decrClient.sh $1 $2

# Invokes Functions: NONE

# Calls the script:
# 1. genSCRIPT_decrClient.sh, with args $decr_Pass
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

   # heefhEKX
   # SSH remotely execute genSCRIPT_decrClient.sh
   ssh $3@$2 'bash -s' < ~/Fluidity_Server/Generated_Scripts/genSCRIPT_decrClient.sh \
	$1 $decr_Pass

}

# Arguments: ($1), ($2), ($3)
# $1: .Fluidity Connection ID [SSH_ID.SSL_ID]
# $2: Client IP address
# $3: Client username (for raspbian OS the default is pi@)

# Sourced Variables: NONE

# Intershell File Variables in use: NONE

# Global Variables in use: NONE

# Generates: Nothing
 
# Invokes Functions: NONE

# Calls the script: NONE

# Function Description: Encrypt the contents of folder ~/Fluidity_Client.

encryptClient () {
	
   local SSH_ID=${1%.*}
   
   # heefhEKX
   # Execute through SSH and unmount target directory
   # ~/Fluidity_Client/Connection$1 from ecryptfs.
   ssh $3@$2 sudo umount ~/Fluidity_Client/connection.$1

}


# Arguments: ($1), ($2), ($3)
# $1: .Fluidity Connection ID [SSH_ID.SSL_ID]
# $2: Server Port
# $3: Client IP address
# $4: Client username (for raspbian OS the default is pi@)

# Sourced Variables: NONE

# Intershell File Variables in use: NONE

# Global Variables in use: NONE

# Generates: Nothing
 
# Invokes Functions: NONE

# Calls the script: NONE

# Function Description: Once the link is established, delete the 
# doNotEncrypt token from client machine.
deleteTokenFromClient () {
	
	 # While $allow_execution is 1 (.Fluidity execution is allowed)
   while [ $(getAllowExecution $1) -eq 1 ];
   
   do
      
      # And If netstat reports that the specific SOCAT connection is
      # established
      if [[ $(getNetstatConnectionStatus $2) == "ESTABLISHED" ]]; then
      
         # Invoke deleteDoNotEncryptToken
         deleteDoNotEncryptToken $1 $3 $4
         # Once you delete the doNotEcryptToken, break the loop.
         break
         
      else
      
         # Link is still not ESTABLISHED. Sleep for 1 sec.
         sleep 1
         
      fi
      
   done
	
}


# 6. .Fluidity Engine Functions
# 6.2 Private Functions
# 6.2.4 SSL Certificates Verification Functions


# Arguments: ($1), ($2), ($3)
# $1: .Fluidity Connection ID [SSH_ID.SSL_ID]
# $2: Client IP address
# $3: Client username (for raspbian OS the default is pi@)

# Sourced Variables: NONE

# Intershell File Variables in use: NONE

# Global Variables in use: NONE

# Generates: Nothing

# Calls the script: NONE

# Invokes Functions: NONE

# Function Description: Do a verification check that tokenSlot folder
# is empty and contains no files.
verifyThatResetSSLisMissing () {
   
   # heefhEKX
   if [ "$(ssh $3@$2 ls ~/Fluidity_Client/connection.$1/tokenSlot/resetSSL.txt)" ]; then
      # Message to calling function.
      echo "verifyThatResetSSLisMissing FAILED"
   else
      # Message to calling function.
      echo "verifyThatResetSSLisMissing PASSED"
   fi
   
}

# Arguments: ($1), ($2), ($3)
# $1: .Fluidity Connection ID [SSH_ID.SSL_ID]
# $2: Client IP address
# $3: Client username (for raspbian OS the default is pi@)

# Sourced Variables: NONE

# Intershell File Variables in use: NONE

# Global Variables in use: NONE

# Generates: Nothing

# Calls the script: NONE

# Invokes Functions: NONE

# Function Description: Perform a file check that each client-server 
# SSL certificate is present in its proper folder.
verifyThatSSLCertificatesExist () {
   
   local SSH_ID=${1%.*}
   
   if [ -d ~/Fluidity_Server/client.$SSH_ID/connection.$1 ]; then
   
      if [ ! -f ~/Fluidity_Server/client.$SSH_ID/connection.$1/clientcon.$1.crt ]; then
         echo "clientcon.$1.crt is missing."
         # Message to calling function.
         echo "verifyThatSSLCertificatesExist FAILED"
         return
      elif [ ! -f ~/Fluidity_Server/client.$SSH_ID/connection.$1/servercon.$1.pem ]; then
         echo "servercon.$1.pem is missing."
         # Message to calling function.
         echo "verifyThatSSLCertificatesExist FAILED"
         return
      # heefhEKX
      elif [ ! $(ssh $3@$2 ls -A ~/Fluidity_Client/connection.$1/servercon.$1.crt) ]; then
         echo "servercon.$1.crt is missing."
         # Message to calling function.
         echo "verifyThatSSLCertificatesExist FAILED"
         return
      # heefhEKX
      elif [ ! $(ssh $3@$2 ls -A ~/Fluidity_Client/connection.$1/clientcon.$1.pem) ]; then
         echo "clientcon.$1.pem is missing."
         # Message to calling function.
         echo "verifyThatSSLCertificatesExist FAILED"
         return
      else
         # Message to calling function.
         echo "verifyThatSSLCertificatesExist PASSED"
      fi
      
   fi
   
}

# Arguments: ($1), ($2), ($3)
# $1: .Fluidity Connection ID [SSH_ID.SSL_ID]
# $2: Client IP address
# $3: Client username (for raspbian OS the default is pi@)

# Sourced Variables: NONE

# Intershell File Variables in use: NONE

# Global Variables in use: NONE

# Generates: 
# 1. Bash script (.sh): genSCRIPT_retrieveClientPemMD5.sh

# Calls the script: 
# 1. genSCRIPT_retrieveClientPemMD5.sh, with args ($1),
# $client_bogus_pass in ~/Fluidity_Server/Generated_Scripts

# Invokes Functions: NONE

# Function Description: Do a check that the client - server .crt and 
# .pem MD5 file hashes match. If they match, the client certificates are 
# valid and ready to be used.
doAClientServerMD5EquivalencyCheck () {

   local SSH_ID=${1%.*}

   local server_pass=$(cat ~/Fluidity_Server/client.$SSH_ID/connection.$1/s_password.$1.txt)
   # Recall and store client's SSH certificate password
   local client_bogus_pass=$(cat ~/Fluidity_Server/client.$SSH_ID/connection.$1/c_bogus_password.$1.txt)
   # echo "Client bogus pass is: $client_bogus_pass"
   
   local expect_out=$(expect -c '
      spawn $env(SHELL)
      expect "\\$" {
         send "(openssl rsa -noout -modulus -in ~/Fluidity_Server/client.'$SSH_ID'/connection.'$1'/servercon.'$1'.pem | openssl md5)\r"
      }
      expect -re "servercon.'$1'.pem:" {
         send "'$server_pass'\r"
      }
      expect "\\$" {
         send "exit\r"
      }
   ')
   
   local server_pem_md5=$(echo "$expect_out" | grep -o '(stdin)=.*')
   # echo "server_pem_md5 is: $server_pem_md5"
   
   local client_crt_md5=$(openssl x509 -noout -modulus -in ~/Fluidity_Server/client.$SSH_ID/connection.$1/clientcon.$1.crt | openssl md5)
   # echo "client_crt_md5 is: $client_crt_md5"

   # Generate bash script genSCRIPT_retrieveClientPemMD5.sh

   # If an existing configuration file is found, leave it intact. Else,
   # create a new one with the default settings.
   if [[ ! -e ~/Fluidity_Server/client.$SSH_ID/connection.$1/genSCRIPT_retrieveClientPemMD5.sh ]]; then
   
      cat <<- 'END_CAT' > ~/Fluidity_Server/client.$SSH_ID/connection.$1/genSCRIPT_retrieveClientPemMD5.sh
      cd ~/Fluidity_Client/connection.$1

      pass=$(echo $hashed_pass | openssl enc -aes-128-cbc -md sha512 -pbkdf2 -iter 100000 -a -d -salt -pass pass:$2)
      expect_out=$(expect -c '
         spawn $env(SHELL)
         expect "\\$" {
            send "(openssl rsa -noout -modulus -in ~/Fluidity_Client/connection.'$1'/clientcon.'$1'.pem) | (openssl md5)\r"
         }
         expect -re "clientcon.'$1'.pem:" {
            send "'$pass'\r"
         }
         expect "\\$" {
            send "exit\r"
         }
      ')
      
      echo "$expect_out" | grep -o '(stdin)=.*'
END_CAT

      chmod 700 ~/Fluidity_Server/client.$SSH_ID/connection.$1/genSCRIPT_retrieveClientPemMD5.sh

      echo "sed -i '2s/.*/$(echo hashed_pass="$(cat ~/Fluidity_Server/client.$SSH_ID/connection.$1/hashed_clientpass_con.$1.txt)" | sed -e 's/[\/&]/\\&/g' )/' ~/Fluidity_Server/client.$SSH_ID/connection.$1/genSCRIPT_retrieveClientPemMD5.sh" | bash -
      
   fi

   # heefhEKX
   # SSH remotely execute genSCRIPT_retrieveClientPemMD5.sh
   local client_pem_md5=$(ssh $3@$2 'bash -s' < ~/Fluidity_Server/client.$SSH_ID/connection.$1/genSCRIPT_retrieveClientPemMD5.sh $1 $client_bogus_pass)
   # echo "client_pem_md5 is: $client_pem_md5"
   # heefhEKX
   local server_crt_md5=$(ssh $3@$2 openssl x509 -noout -modulus -in ~/Fluidity_Client/connection.$1/servercon.$1.crt | openssl md5)
   # echo "server_crt_md5 is: $server_crt_md5"
   
   if [[ ${server_pem_md5:9:32} == ${server_crt_md5:9:32} ]]\
    && [[ ${client_pem_md5:9:32} == ${client_crt_md5:9:32} ]]; then
    
      echo 'servercon.'$1'.pem MD5 is: '${server_pem_md5:9:32}
      echo 'servercon.'$1'.crt MD5 is: '${server_crt_md5:9:32}
      echo 'clientcon.'$1'.pem MD5 is: '${client_pem_md5:9:32}
      echo 'clientcon.'$1'.crt MD5 is: '${client_crt_md5:9:32}
      # Message to calling function.
      echo "doAClientServerMD5EquivalencyCheck PASSED"
      
   else
   
      echo 'servercon.'$1'.pem MD5 is: '${server_pem_md5:9:32}
      echo 'servercon.'$1'.crt MD5 is: '${server_crt_md5:9:32}
      echo 'clientcon.'$1'.pem MD5 is: '${client_pem_md5:9:32}
      echo 'clientcon.'$1'.crt MD5 is: '${client_crt_md5:9:32}
      # Message to calling function.
      echo "doAClientServerMD5EquivalencyCheck FAILED"
      
   fi
   
   rm ~/Fluidity_Server/client.$SSH_ID/connection.$1/genSCRIPT_retrieveClientPemMD5.sh
}

# Arguments: ($1), ($2), ($3)
# $1: .Fluidity Connection ID [SSH_ID.SSL_ID]
# $2: Client IP address
# $3: Client username (for raspbian OS the default is pi@)

# Sourced Variables: NONE

# Intershell File Variables in use: NONE

# Global Variables in use: NONE

# Generates: 
# 1. Bash script (.sh): genSCRIPT_retrieveClientPemSHA256.sh

# Calls the script: 
# 1. genSCRIPT_retrieveClientPemSHA256.sh, with args ($1),
# $client_bogus_pass in ~/Fluidity_Server/Generated_Scripts

# Invokes Functions: NONE

# Function Description: Do a check that the client - server .crt and 
# .pem SHA256 file hashes match. If they match, the client certificates 
# are valid and ready to be used.
doAClientServerSHA256EquivalencyCheck () {

   local SSH_ID=${1%.*}

   local server_pass=$(cat ~/Fluidity_Server/client.$SSH_ID/connection.$1/s_password.$1.txt)
   # Recall and store client's SSH certificate password
   local client_bogus_pass=$(cat ~/Fluidity_Server/client.$SSH_ID/connection.$1/c_bogus_password.$1.txt)
   # echo "Client bogus pass is: $client_bogus_pass"
   
   local expect_out=$(expect -c '
      spawn $env(SHELL)
      expect "\\$" {
         send "(openssl rsa -noout -modulus -in ~/Fluidity_Server/client.'$SSH_ID'/connection.'$1'/servercon.'$1'.pem | openssl dgst -sha256)\r"
      }
      expect -re "servercon.'$1'.pem:" {
         send "'$server_pass'\r"
      }
      expect "\\$" {
         send "exit\r"
      }
   ')
   
   local server_pem_SHA256=$(echo "$expect_out" | grep -o '(stdin)=.*')
   # echo "server_pem_SHA256 is: $server_pem_SHA256"
   
   local client_crt_SHA256=$(openssl x509 -noout -modulus -in ~/Fluidity_Server/client.$SSH_ID/connection.$1/clientcon.$1.crt | openssl dgst -sha256)
   # echo "client_crt_SHA256 is: $client_crt_SHA256"

   # Generate bash script genSCRIPT_retrieveClientPemSHA256.sh

   # If an existing configuration file is found, leave it intact. Else,
   # create a new one with the default settings.
   if [[ ! -e ~/Fluidity_Server/client.$SSH_ID/connection.$1/genSCRIPT_retrieveClientPemSHA256.sh ]]; then
   
      cat <<- 'END_CAT' > ~/Fluidity_Server/client.$SSH_ID/connection.$1/genSCRIPT_retrieveClientPemSHA256.sh
      cd ~/Fluidity_Client/connection.$1

      pass=$(echo $hashed_pass | openssl enc -aes-128-cbc -md sha512 -pbkdf2 -iter 100000 -a -d -salt -pass pass:$2)
      expect_out=$(expect -c '
         spawn $env(SHELL)
         expect "\\$" {
            send "(openssl rsa -noout -modulus -in ~/Fluidity_Client/connection.'$1'/clientcon.'$1'.pem) | (openssl dgst -sha256)\r"
         }
         expect -re "clientcon.'$1'.pem:" {
            send "'$pass'\r"
         }
         expect "\\$" {
            send "exit\r"
         }
      ')
      
      echo "$expect_out" | grep -o '(stdin)=.*'
END_CAT

      chmod 700 ~/Fluidity_Server/client.$SSH_ID/connection.$1/genSCRIPT_retrieveClientPemSHA256.sh

      echo "sed -i '2s/.*/$(echo hashed_pass="$(cat ~/Fluidity_Server/client.$SSH_ID/connection.$1/hashed_clientpass_con.$1.txt)" | sed -e 's/[\/&]/\\&/g' )/' ~/Fluidity_Server/client.$SSH_ID/connection.$1/genSCRIPT_retrieveClientPemSHA256.sh" | bash -
      
   fi

   # heefhEKX
   # SSH remotely execute genSCRIPT_retrieveClientPemSHA256.sh
   local client_pem_SHA256=$(ssh $3@$2 'bash -s' < ~/Fluidity_Server/client.$SSH_ID/connection.$1/genSCRIPT_retrieveClientPemSHA256.sh $1 $client_bogus_pass)
   # heefhEKX
   # echo "client_pem_SHA256 is: $client_pem_SHA256"
   local server_crt_SHA256=$(ssh $3@$2 openssl x509 -noout -modulus -in ~/Fluidity_Client/connection.$1/servercon.$1.crt | openssl dgst -sha256)
   # echo "server_crt_SHA256 is: $server_crt_SHA256"
   
   if [[ ${server_pem_SHA256:9:32} == ${server_crt_SHA256:9:32} ]]\
    && [[ ${client_pem_SHA256:9:32} == ${client_crt_SHA256:9:32} ]]; then
    
      echo 'servercon.'$1'.pem SHA256 is: '${server_pem_SHA256:9:32}
      echo 'servercon.'$1'.crt SHA256 is: '${server_crt_SHA256:9:32}
      echo 'clientcon.'$1'.pem SHA256 is: '${client_pem_SHA256:9:32}
      echo 'clientcon.'$1'.crt SHA256 is: '${client_crt_SHA256:9:32}
      # Message to calling function.
      echo "doAClientServerSHA256EquivalencyCheck PASSED"
      
   else
   
      echo 'servercon.'$1'.pem SHA256 is: '${server_pem_SHA256:9:32}
      echo 'servercon.'$1'.crt SHA256 is: '${server_crt_SHA256:9:32}
      echo 'clientcon.'$1'.pem SHA256 is: '${client_pem_SHA256:9:32}
      echo 'clientcon.'$1'.crt SHA256 is: '${client_crt_SHA256:9:32}
      # Message to calling function.
      echo "doAClientServerSHA256EquivalencyCheck FAILED"
      
   fi
   
   rm ~/Fluidity_Server/client.$SSH_ID/connection.$1/genSCRIPT_retrieveClientPemSHA256.sh
}


# 6. .Fluidity Engine Functions
# 6.2 Private Functions
# 6.2.5 VPN Routing


# Arguments: ($1), ($2), ($3), ($4), ($5)
# $1: .Fluidity Connection ID [SSH_ID.SSL_ID]
# $2: Server port
# $3: Client IP.
# $4: Client Username.

# Sourced Variables: NONE

# Intershell File Variables in use: NONE

# Global Variables in use: NONE

# Generates: Nothing

# Invokes Functions: 
# 1. injectTheListOfServerRoutes, no args.
# 2. injectTheListOfClientRoutes, with args: $1, $3, $4

# Calls the script: NONE

# Function Description: Inject the lists of VPN routes stored in the 
# container files listOfServerRoutes.sh 
# (invokes injectTheListOfServerRoutes) and 
# listOfClientRoutes.[SSH_ID.SSL_ID].sh 
# (invokes injectTheListOfClientRoutes) on both the client's and 
# server's routing tables.
injectTheListOfFluidityConnectionRoutes () {
   
   # While $allow_execution is 1 (.Fluidity execution is allowed)
   while [ $(getAllowExecution $1) -eq 1 ];
   do
   
      # And If netstat reports that the specific SOCAT connection is
      # established
      if [[ $(getNetstatConnectionStatus $2) == "ESTABLISHED" ]]; then
      
         # Inject the routes contained into: injectTheListOfServerRoutes
         # Invoke injectTheListOfServerRoutes
         injectTheListOfServerRoutes
         
         # Inject the routes contained into: injecTheListOfClientRoutes
         # Invoke injectTheListOfServerRoutes
         injectTheListOfClientRoutes $1 $3 $4
         
         # Break the loop.
         break
         
      else
      
         # Link is still not ESTABLISHED. Sleep for 1 sec.
         sleep 1
         
      fi
      
   done

}

# Arguments: NONE

# Sourced Variables: NONE

# Intershell File Variables in use: NONE

# Global Variables in use: NONE

# Generates: Nothing

# Invokes Functions: NONE

# Calls the script: 
# 1. listOfServerRoutes.sh, with no args
# in: ~/Fluidity_Server/client.$SSH_ID/connection.$1

# Function Description: Execute the script listOfServerRoutes.sh to 
# inject the server VPN routes.
injectTheListOfServerRoutes () {
   
   # Do a local execution.
   bash ~/Fluidity_Server/listOfServerRoutes.sh
   
}

# Arguments: ($1), ($2), ($3)
# $1: .Fluidity Connection ID [SSH_ID.SSL_ID]
# $2: Client IP.
# $3: Client Username.

# Sourced Variables: NONE

# Intershell File Variables in use: NONE

# Global Variables in use: NONE

# Generates: Nothing

# Invokes Functions: NONE

# Calls the script:
# 1. listOfClientRoutes.$1.sh, with no args
# in: ~/Fluidity_Server/client.$SSH_ID/connection.$1

# Function Description: Remotely execute the bash script 
# listOfClientRoutes.[SSH_ID.SSL_ID].sh to the target .Fluidity client 
# to inject the stored VPN client routes.
injectTheListOfClientRoutes () {
   
   local SSH_ID=${1%.*}
   
   # heefhEKX
   # Do a remote execution.
   ssh $3@$2 'bash -s' < ~/Fluidity_Server/client.$SSH_ID/connection.$1/listOfClientRoutes.$1.sh
   
}


# 6. .Fluidity Engine Functions
# 6.2 Private Functions
# 6.2.6 Engine Reporting


# Arguments: ($1), ($2)
# $1: .Fluidity Connection ID [SSH_ID.SSL_ID]
# $2: Server port

# Sourced Variables: NONE

# Intershell File Variables in use:
# 1. $allow_execution (setAllowExecution, getAllowExecution)

# Global Variables in use: NONE

# Generates: Nothing

# Invokes Functions: NONE

# Calls the script: NONE

# Function Description: Do a netstat status report for the active 
# .Fluidity connection [SSH_ID.SSL_ID] on active port $2.
reportWhenLinkIsEstablished () {
   
   # While $allow_execution is 1 (.Fluidity execution is allowed)
   while [ $(getAllowExecution $1) -eq 1 ];
   
   do
      
      # And If netstat reports that the specific SOCAT connection is
      # established
      if [[ $(getNetstatConnectionStatus $2) == "ESTABLISHED" ]]; then
      
         # Do a full status report for that specific connection.
         netstat -atnp 2>/dev/null | grep -e $2
         # Once you report, break the loop.
         break
         
      else
      
         # Link is still not ESTABLISHED. Sleep for 1 sec.
         sleep 1
         
      fi
      
   done

}

# Arguments: ($1), ($2)
# $1: .Fluidity Connection ID [SSH_ID.SSL_ID]
# $2: Server port

# Sourced Variables: NONE

# Intershell File Variables in use:
# 1. $allow_execution (setAllowExecution, getAllowExecution)

# Global Variables in use: NONE

# Generates: Nothing

# Invokes Functions: NONE

# Calls the script: NONE

# Function Description: Do a UFW status report for the active 
# .Fluidity connection [SSH_ID.SSL_ID] on active port $2.
reportWhenFirewallRulesAreAdded () {
   
   # While $allow_execution is 1 (.Fluidity execution is allowed)
   while [ $(getAllowExecution $1) -eq 1 ];
   
   do
   
      # And If netstat reports that the specific SOCAT connection is
      # established
      if [[ $(getNetstatConnectionStatus $2) == "ESTABLISHED" ]]; then
      
         # Do a UFW status report for that specific port.
         sudo ufw status verbose | grep -e $2
         # Once you report, break the loop.
         break
         
      else
      
         # Link is still not ESTABLISHED. Sleep for 1 sec.
         sleep 1
         
      fi
      
   done

}

# Arguments: ($1), ($2)
# $1: .Fluidity Connection ID [SSH_ID.SSL_ID]
# $2: Server port

# Sourced Variables: NONE

# Intershell File Variables in use:
# 1. $allow_execution (setAllowExecution, getAllowExecution)

# Global Variables in use: NONE

# Generates: Nothing

# Invokes Functions: NONE

# Calls the script: NONE

# Function Description: Do a UFW status report for the inactive 
# .Fluidity connection [SSH_ID.SSL_ID] on the previously active port $2.
reportWhenFirewallRulesAreRemoved () {
   
   # While .Fluidity is manually stopped.
   while [[ $(getAllowExecution $1) == "null" ]];
   
   do
   
      # And if the current SOCAT connection is terminated.
      if ! [[ $(getNetstatConnectionStatus $2) == "ESTABLISHED" ]]; then
      
         # Do a UFW status report for that specific port.
         sudo ufw status verbose | grep -e $2
         # Inform the user that the firewall rules sucessfully removed.
         echo "Firewall rules for port $2 sucessfully removed."
         # Break the loop.
         break
         
      else
      
         # SOCAT link is still established. Sleep for 1 sec.
         sleep 1
         
      fi
      
   done

}


# 6. .Fluidity Engine Functions
# 6.3 Engine Auxillary Functions
# 6.3.1 Public Functions


# Arguments: ($1) 
# $1: .Fluidity Client (SSH) Connection ID.
# $2: .Fluidity Virtual Circuit (SSL) Connection ID.

# Sourced Variables: NONE

# Intershell File Variables in use:
# $1. sleep_pid (setSleepPid, getSleepPid)

# Global Variables in use: NONE

# Generates: Nothing

# Invokes Functions: NONE

# Calls the script: NONE

# Function Description: Forcefully snatch runPersistentSOCATClient out of 
# its dormant state by terminating its underlying SLEEP process. This 
# will re-ignite a PING effort towards the client that communication was
# previously lost.

forcePing () {
   
   # Derive the fluidity_id
   local fluidity_id=$(echo $1.$2)
   
   # kill -0 verifies the existance of a sleeping process ID.

   # Case 1: The improper scenario.
   # A garbage value has remained from a previous sleeping process. 
   # kill -0 reports that the specific $sleep_pid doesn't exist while 
   # runPersistentSOCATClient is currently in ACTIVE state.
   if ! kill -0 $(getSleepPid $fluidity_id); then

      # rZ7y4zq
      # Debugging section.
      # echo "Not in sleep mode"
      :
   
   # Case 2: The proper scenario.
   # $sleep_id is 0. There is no sleeping process to kill.
   elif [[ $(getSleepPid $fluidity_id) -eq 0 ]]; then

      # rZ7y4zq
      # Debugging section.
      # echo "Not in sleep mode. sleep_pid = 0."
      :

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


# 7. .Fluidity Connection Status Functions
# 7.1 Public Functions


# Arguments: ($1)
# $1: .Fluidity Client (SSH) Connection ID.
# $2: .Fluidity Virtual Circuit (SSL) Connection ID.

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

# Function Description: Display the current connection status.
showLinkStatus () {
   
   # Safety check 1: Check whether Fluidity_Server folder is present 
   # (functionality contained within mountFluidityServerFolder) and 
   # decrypted.
   if [ -z "$(df -T | grep -E 'Fluidity_Server ecryptfs')" ] ; then 

      # Fluidity_Server folder found encrpyted. Use 
      # mountFluidityServerFolder to decrypt it.
      # Invoke mountFluidityServerFolder
      mountFluidityServerFolder
      
   fi
   
   # Safety check 2:
   # Connection is missing.
   if [ ! -d ~/Fluidity_Server/client.$1/connection.$1.$2 ]; then
      # Message to user.
      echo "connection.$1.$2 does not exist."
      return
   # Safety check 3:
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
   
   # kzjFgtUz
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

   # Safety check 1: Check whether Fluidity_Server folder is present 
   # (functionality contained within mountFluidityServerFolder) and 
   # decrypted.
   if [ -z "$(df -T | grep -E 'Fluidity_Server ecryptfs')" ] ; then 

      # Fluidity_Server folder found encrpyted. Use 
      # mountFluidityServerFolder to decrypt it.
      # Invoke mountFluidityServerFolder
      mountFluidityServerFolder
      
   fi

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
# the serial controllers installed to this PC. 
displaySerialDevices () {

   sudo dmesg | grep tty

}


# Arguments: ($1)
# $1: IP address

# Sourced Variables: NONE

# Intershell File Variables in use: NONE

# Global Variables in use: NONE

# Generates: NOTHING

# Calls the script: NONE

# Invokes Functions: NONE

# Function Description: Extract the physical interface from
# the IP address.
findInterfaceFromIP () {

   ifconfig | grep -B 2 $1 | cut -d' ' -f 1 | sed 's/://'

}


# 8. Auxillary Functions
# 8.2 Private Auxillary Functions


# Arguments: NONE

# Sourced Variables: NONE

# Intershell File Variables in use: NONE

# Global Variables in use: NONE

# Generates: Nothing

# Invokes Functions: NONE

# Calls the script: NONE

# Function Description: Give a boost to the server's entropy by 
# installing HAVEGED or rng-tools.
giveAnEntropyBoost () {
   
   if [ -x "$(command -v haveged)" ]; then
      
      while true; do
         echo -e \
          '\nHAVEGED was found. Would you like to use rng-tools instead?'\
          '\nType [yes]: Use rng-tools'\
          '\nType [no]: Keep using HAVEGED'\
         && read -p "_" yn
         case $yn in
         [yY] | [yY][Ee][Ss] )
            echo -e "\nInstalling rng-tools"
         
            # Stop the "HAVEGED" service
            sudo systemctl stop haveged
         
            # Perform a system update.
            if ping -c 3 8.8.8.8; then
               sudo apt-get update && sudo apt-get -y upgrade
            else
               echo -e 'System update failed.'\
               '\nPlease check your internet connection to proceed with the'\
               '\n.Fluidity installation.'\
               '\nCanceling the installation procedures.'
               echo "fluidityServerConfiguration failed"
               return
            fi
            
            if ! sudo apt-get -y install rng-tools; then
               echo -e 'rng-tools installation failed.'\
                '\nPlease check your internet connection to proceed with the'\
                '\n.Fluidity installation.'\
                '\nCanceling the installation procedures.'
                echo "giveAnEntropyBoost failed"
               return
            fi
            
            # Start the "rng-tools" service
            sudo systemctl start rng-tools
            
            break;;
         
         [nN] | [nN][Oo] ) exit;;
         
         * ) echo "Please answer yes or no.";;
         
         esac
      done
   
   elif [ -x "$(command -v rng-tools)" ]; then
      
      while true; do
         echo -e \
          '\rng-tools were found. Would you like to use HAVEGED instead?'\
          '\nType [yes]: Use HAVEGED'\
          '\nType [no]: Keep using rng-tools'\
         && read -p "_" yn
         case $yn in
         [yY] | [yY][Ee][Ss] )
            echo -e "\nInstalling HAVEGED"
         
            # Stop the "rng-tools" service
            sudo systemctl stop rng-tools
         
            # Perform a system update.
            if ping -c 3 8.8.8.8; then
               sudo apt-get update && sudo apt-get -y upgrade
            else
               echo -e 'System update failed.'\
               '\nPlease check your internet connection to proceed with the'\
               '\n.Fluidity installation.'\
               '\nCanceling the installation procedures.'
               echo "fluidityServerConfiguration failed"
               return
            fi
            
            if ! sudo apt-get -y install haveged; then
               echo -e 'HAVEGED installation failed.'\
                '\nPlease check your internet connection to proceed with the'\
                '\n.Fluidity installation.'\
                '\nCanceling the installation procedures.'
                echo "giveAnEntropyBoost failed"
               return
            fi
            
            # Start the "rng-tools" service
            sudo systemctl start haveged
            
            break;;
         
         [nN] | [nN][Oo] ) exit;;
         
         * ) echo "Please answer yes or no.";;
         
         esac
      done
   
   elif ! [ -x "$(command -v haveged)" ] && ! [ -x "$(command -v rngd)" ]; then
   
      # Perform a system update.
      if ping -c 3 8.8.8.8; then
         sudo apt-get update && sudo apt-get -y upgrade
      else
         echo -e 'System update failed.'\
          '\nPlease check your internet connection to proceed with the'\
          '\n.Fluidity installation.'\
          '\nCanceling the installation procedures.'
          echo "fluidityServerConfiguration failed"
          return
      fi
   
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
            if ! sudo apt-get -y install haveged; then
               echo -e 'Haveged installation failed.'\
                '\nPlease check your internet connection to proceed with the'\
                '\n.Fluidity installation.'\
                '\nCanceling the installation procedures.'
                echo "giveAnEntropyBoost failed"
               return
            fi
            
            # Start the "HAVEGED" service
            sudo systemctl start haveged
            
         break;;
         
         # CASE 2: For choice=2 install rng-tools
         [2]* ) echo "Installing rng-tools"
            if ! sudo apt-get -y install rng-tools; then
               echo -e 'rng-tools installation failed.'\
                '\nPlease check your internet connection to proceed with the'\
                '\n.Fluidity installation.'\
                '\nCanceling the installation procedures.'
                echo "giveAnEntropyBoost failed"
               return
            fi
            
            # Start the "rng-tools" service
            sudo systemctl start rng-tools
            
         break;;
         
         # Error handling case:
         # Display the valid choices (1 or 2) and loop again.
         * ) echo "1 for Haveged, 2 for rng-tools";;
         esac
         
      done
      
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

# Function Description: Perform a .Fluidity file structure integrity 
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
   
   # heefhEKX
   # SSH remotely execute genSCRIPT_checkRemoteEntropy.sh
   ssh $2@$1 'bash -s' < ~/Fluidity_Server/Generated_Scripts/genSCRIPT_checkRemoteEntropy.sh
  
}

# Arguments: ($1)
# $1: Server port

# Sourced Variables: NONE

# Intershell File Variables in use: NONE

# Global Variables in use: NONE

# Generates: Nothing

# Invokes Functions: NONE

# Calls the script: NONE

# Function Description: Based on server port, retrieve the SOCAT connection
# status from netstat.
getNetstatConnectionStatus () {

   # Use netstat and pipe the output to grep. Grep will search the
   # string and return a result according to argument $1.
   local netstat_connection_status_string=$(netstat -atnp 2>/dev/null | grep $1)
      
   # Use cut to compartmentalize the line. Fetch the sixth element. Use
   # the whitespace ' ' as a delimeter character. Save the result
   # to $netstat_connection_status.
   local netstat_connection_status=$(echo $netstat_connection_status_string | cut -d ' ' -f 6)
      
   echo $netstat_connection_status
}

# Arguments: ($1)
# $1: Server port

# Sourced Variables: NONE

# Intershell File Variables in use: NONE

# Global Variables in use: NONE

# Generates: Nothing

# Invokes Functions: NONE

# Calls the script: NONE

# Function Description: Based on server port, extract the .Fluidity 
# client port from netstat output.
getTheRemotePort () {

   # Use netstat and pipe the output to grep. Grep will search the
   # string and return a result according to argument $1.
   local netstat_connection_status_string=$(netstat -atnp 2>/dev/null | grep $1)
   
   # Extract the remote port to $remote_port. Use a double cut to 
   # compartmentalize the line. First, fetch the fifth element. Use
   # the whitespace ' ' as a delimeter character.
   # Second, fetch the 2nd element. Use the semicolon ':' as a delimeter
   # character.
   # Save the result to $remote_port.
   local remote_port=$(echo $netstat_connection_status_string | cut -d' ' -f 5 | cut -d ':' -f 2)
   
   echo $remote_port
}

# Arguments: ($1)
# $1: SSH ID
# $2: Client IP
# $3: Random SSH port

# Sourced Variables: NONE

# Intershell File Variables in use: NONE

# Global Variables in use: NONE

# Generates: Nothing

# Invokes Functions: NONE

# Calls the script: NONE

# Function Description: Remove client information from ~/.ssh/config.
removeFluidityClientConfigInfoFromSSHConfig () {
   
   grep -F -v "$(echo -e 'Host '$2'\n'\
   '  IdentityFile ~/.ssh/client.'$1'\n'\
   '  Port '$3'')" \
   ~/.ssh/config > \
   ~/.ssh/config.tmp
   rm ~/.ssh/config
   mv ~/.ssh/config.tmp ~/.ssh/config
   
}


# 9. Managing Internal Interfaces
# 9.1 Public Functions


# Arguments: ($1)
# $1: Target Internal Physical Interface

# Sourced Variables:
# 1. ~/Fluidity_Server/client.$1/basic_client_info.txt
   # 1. $server_IP_address
   # 2. $client_IP_address
   # 3. $client_username
   # 4. $random_client_port

# Intershell File Variables in use: NONE

# Global Variables in use: NONE

# Generates: NOTHING

# Calls the script: NONE

# Invokes Functions:
# 1. findInterfaceFromIP with args: ($server_IP_address)

# Function Description: Set, from a Firewall perspective, the given
# interface as "internal" by allowing all inbound and outbound traffic
# through it.
setInternalInterface () {
   
   if [ -d ~/Fluidity_Server ]; then 
   
      for file in ~/Fluidity_Server/client.* ; do
         
         # Source the variables:
            # 1. $server_IP_address
            # 2. $client_IP_address
            # 3. $client_username
            # 4. $random_client_port
         source $(echo $file)/basic_client_info.txt
            
         interface=$(findInterfaceFromIP $server_IP_address)
            
         if [[ "$interface" == "$1" ]]; then
               
            echo ".Fluidity $file with external server IP address $server_IP_address is utilizing interface $1 as an external interface."
            return;
               
         fi
            
      done
      
   elif [ -d ~/Fluidity_Client ]; then
      
      client_IP_address=$(sudo ufw status | grep "HFBCvIa7h" | tr -s " " | cut -d' ' -f 6)
      
      interface=$(findInterfaceFromIP $client_IP_address)
      
      if [[ "$interface" == "$1" ]]; then
               
         echo ".Fluidity Client with external client IP address $client_IP_address is utilizing interface $1 as an external interface."
         return;
               
      fi
      
   else
      
      # Message to user:
      echo "No .Fluidity installation detected."
      return 
      
   fi
   
   if ifconfig | cut -d' ' -f1 | cut -d':' -f1 | grep -x "$1" ; then
   
         sudo ufw allow in on $1
         sudo ufw allow out on $1
         
   else
   
      echo "$1 is not a valid interface"
      
   fi

}

# Arguments: ($1)
# $1: Target Internal Physical Interface

# Sourced Variables: NONE

# Intershell File Variables in use: NONE

# Global Variables in use: NONE

# Generates: NOTHING

# Calls the script: NONE

# Invokes Functions:
# 1. findInterfaceFromIP with args: ($1)

# Function Description: Unset, from a Firewall perspective, the given
# interface from being "internal" and turn its Firewall settings back to
# the default settings.
removeInternalInterface () {
   
   if [ -d ~/Fluidity_Server ]; then 
   
      for file in ~/Fluidity_Server/client.* ; do
         
         # Source the variables:
            # 1. $server_IP_address
            # 2. $client_IP_address
            # 3. $client_username
            # 4. $random_client_port
         source $(echo $file)/basic_client_info.txt
            
         interface=$(findInterfaceFromIP $server_IP_address)
            
         if [[ "$interface" == "$1" ]]; then
               
            echo ".Fluidity $file with external server IP address $server_IP_address is utilizing interface $1 as an external interface."
            return;
               
         fi
            
      done
      
   elif [ -d ~/Fluidity_Client ]; then
      
      client_IP_address=$(sudo ufw status | grep "HFBCvIa7h" | tr -s " " | cut -d' ' -f 6)
      
      interface=$(findInterfaceFromIP $client_IP_address)
      
      if [[ "$interface" == "$1" ]]; then
               
         echo ".Fluidity Client with external client IP address $client_IP_address is utilizing interface $1 as an external interface."
         return;
               
      fi
      
   else
      
      # Message to user:
      echo "No .Fluidity installation detected."
      return 
      
   fi

   if ifconfig | cut -d' ' -f1 | cut -d':' -f1 | grep -x "$1" ; then
   
      sudo ufw delete allow in on $1
      sudo ufw delete allow out on $1
      
   else
   
      echo "$1 is not a valid interface"
      
   fi

}


# 10. VPN Routing
# 10.1 Public Functions


# BACKGROUND INFO
# 
# The problem we faced was that Debian Linux stores its routing table in
# memory until the next restart.
#
# If a restart occurs the routing table is wiped clean.
#
# To solve this problem, we create the global script 
# listOfServerRoutes.sh in ~/Fluidity_Server/ folder and a per .Fluidity
# connection script listOfClientRoutes.[SSH_ID].[SSL_ID].sh, 
# each stored in their corresponding .Fluidity connection folders
# ~/Fluidity_Server/client.[SSH_ID]/connection.[SSH_ID].[SSL_ID]/.
#
# Those scripts work as special placeholders for the VPN routes
# of interest.
#
# The scripts are further accompanied by a set of functions that 
# constitute a public interface, through which we can safely add 
# and remove the VPN routes in a controlled manner. Functions 
# addServerRoute and removeServerRoute are responsible for adding and 
# removing routes from listOfServerRoutes.sh and functions 
# addClientRoute and removeClientRoute are responsible for adding and 
# removing routes from each listOfClientRoutes.[SSH_ID].[SSL_ID].sh that
# correspond to their respective .Fluidity client connections folders.
# 
#
# Every time a .Fluidity connection is initiated listOfServerRoutes.sh
# is locally executed on .Fluidity server and the respective
# listOfClientRoutes.[SSH_ID].[SSL_ID].sh is remotely executed in its 
# corresponding .Fluidity client (i.e. SSH_ID), for that specific 
# .Fluidity connection (i.e. SSL_ID).


# Arguments: ($1), ($2), ($3), ($4), ($5), ($6)
# $1: Fixed value: ip
# $2: Fixed value: route
# $3: Fixed value: add
# $4: IP network and subnet mask
# $5: Fixed value: via
# $6: Exit IP

# Sourced Variables: NONE

# Intershell File Variables in use: NONE

# Global Variables in use: NONE

# Generates:
# 1. Bash script (.sh): listOfServerRoutes.sh
# or adds information to it.

# Invokes Functions: NONE

# Calls the script: NONE

# Function Description: Add a server route to the .Fluidity VPN routes
# list, stored in the special purpose container script 
# ~/Fluidity_Server/listOfServerRoutes.sh.
addServerRoute () {
   
   # Safety check 1: Check whether Fluidity_Server folder is present 
   # (functionality contained within mountFluidityServerFolder) and 
   # decrypted.
   if [ -z "$(df -T | grep -E 'Fluidity_Server ecryptfs')" ] ; then 

      # Fluidity_Server folder found encrpyted. Use 
      # mountFluidityServerFolder to decrypt it.
      # Invoke mountFluidityServerFolder
      mountFluidityServerFolder
      
   fi
   
   # Safety check 2: Number of arguments should be no less than 6.
   if [ "$#" -ne 6 ]; then
      echo "Illegal number of parameters"
      return
   fi
   
   # Safety check 3: Force a specific command syntax.
   if ! [[ $1 == "ip" && $2 == "route" && $3 == "add" && $5 == "via" ]]; then
      echo "Command should be in the form of:" 
      echo "ip route add x.y.z.w/mask via x.y.z.w"
      return
   fi
   
   # Safety check 4: Cancel execution if this route is already in server
   # list.
   if [[ -e ~/Fluidity_Server/listOfServerRoutes.sh ]]; then

      if cat ~/Fluidity_Server/listOfServerRoutes.sh | grep "sudo $1 $2 $3 $4 $5 $6"; then
         echo "Route already exists in serverRoutes.sh"
         return
      fi
   
   fi
   
   if [[ ! -e ~/Fluidity_Server/listOfServerRoutes.sh ]]; then
   
      # Message to user.
      echo "Creating serverRoutes.sh"
   
      # Add the route to server list.
      echo "sudo $1 $2 $3 $4 $5 $6" >> ~/Fluidity_Server/listOfServerRoutes.sh
      
      # Change permissions.
      chmod 700 ~/Fluidity_Server/listOfServerRoutes.sh
      
   else
   
      # Add the route to server VPN route list.
      echo "sudo $1 $2 $3 $4 $5 $6" >> ~/Fluidity_Server/listOfServerRoutes.sh
      
   fi
   
}

# Arguments: ($1), ($2), ($3), ($4), ($5), ($6)
# $1: Fixed value: ip 
# $2: Fixed value: route
# $3: Fixed value: add
# $4: IP network and subnet mask
# $5: Fixed value: via
# $6: Exit IP

# Sourced Variables: NONE

# Intershell File Variables in use: NONE

# Global Variables in use: NONE

# Generates: Nothing

# Invokes Functions: NONE

# Calls the script: NONE

# Function Description: Remove a server route from the .Fluidity VPN 
# routes list, stored in the special purpose container 
# script ~/Fluidity_Server/listOfServerRoutes.sh.
removeServerRoute () {
   
   # Safety check 1: Check whether Fluidity_Server folder is present 
   # (functionality contained within mountFluidityServerFolder) and 
   # decrypted.
   if [ -z "$(df -T | grep -E 'Fluidity_Server ecryptfs')" ] ; then 

      # Fluidity_Server folder found encrpyted. Use 
      # mountFluidityServerFolder to decrypt it.
      # Invoke mountFluidityServerFolder
      mountFluidityServerFolder
      
   fi
   
   # Safety check 2: Number of arguments should be no less than 6.
   if [ "$#" -ne 6 ]; then
      echo "Illegal number of parameters"
      return
   fi
   
   # Safety check 3: Force a specific command syntax.
   if ! [[ $1 == "ip" && $2 == "route" && $3 == "add" && $5 == "via" ]]; then
      echo "Command should be in the form of:" 
      echo "ip route add x.y.z.w/mask via x.y.z.w"
      return
   fi
   
   # Safety check 4: Cancel execution if the route is absent from the 
   # server list.
   if ! cat ~/Fluidity_Server/listOfServerRoutes.sh | grep "sudo $1 $2 $3 $4 $5 $6"; then
      echo "Route does not exist in serverRoutes.sh"
      return
   fi
   
   # Remove the route from the VPN server route list.
   grep -F -v "sudo $1 $2 $3 $4 $5 $6" \
   ~/Fluidity_Server/listOfServerRoutes.sh > \
   ~/Fluidity_Server/listOfServerRoutes.sh.tmp && \
   mv ~/Fluidity_Server/listOfServerRoutes.sh.tmp \
   ~/Fluidity_Server/listOfServerRoutes.sh
   
}

# Arguments: ($1), ($2), ($3), ($4), ($5), ($6), ($7), ($8)
# $1: .Fluidity Client (SSH) Connection ID.
# $2: .Fluidity Virtual Circuit (SSL) Connection ID.
# $3: Fixed value: ip 
# $4: Fixed value: route
# $5: Fixed value: add
# $6: IP network and subnet mask
# $7: Fixed value: via
# $8: Exit IP 

# Sourced Variables: NONE

# Intershell File Variables in use: NONE

# Global Variables in use: NONE

# Generates: 
# 1. Bash script (.sh): listOfClientRoutes.$1.$2.sh
# or adds information to it.

# Invokes Functions: NONE

# Calls the script: NONE

# Function Description: Add a client route to the .Fluidity VPN routes
# list, stored in the special purpose connection container script 
# ~/Fluidity_Server/client.[SSH_ID]/connection.[SSH_ID].[SSL_ID]/listOfClientRoutes.[SSH_ID].[SSL_ID].sh.
addClientRoute () {
   
   # Safety check 1: Check whether Fluidity_Server folder is present 
   # (functionality contained within mountFluidityServerFolder) and 
   # decrypted.
   if [ -z "$(df -T | grep -E 'Fluidity_Server ecryptfs')" ] ; then 

      # Fluidity_Server folder found encrpyted. Use 
      # mountFluidityServerFolder to decrypt it.
      # Invoke mountFluidityServerFolder
      mountFluidityServerFolder
      
   fi
   
   # Safety check 2: Number of arguments should be no less than 8.
   if [ "$#" -ne 8 ]; then
      echo "Illegal number of parameters"
      return
   fi
   
   # Safety check 3: Force a specific command syntax.
   if ! [[ $3 == "ip" && $4 == "route" && $5 == "add" && $7 == "via" ]]; then
      echo "Command should be in the form of:" 
      echo "client_id connection_id ip route add x.y.z.w/mask via x.y.z.w"
      return
   fi
   
   # Safety check 4: Stop execution if this connection doesn't exist.
   if [ ! -d ~/Fluidity_Server/client.$1/connection.$1.$2 ]; then
      echo "Fluidity Connection $1.$2 does not exist"
      return
   fi
   
   # Safety check 5: Stop execution if this route is already in client
   # list.
   if [[ -e ~/Fluidity_Server/client.$1/connection.$1.$2/listOfClientRoutes.$1.$2.sh ]]; then

      if cat ~/Fluidity_Server/client.$1/connection.$1.$2/listOfClientRoutes.$1.$2.sh | grep "sudo $3 $4 $5 $6 $7 $8"; then
         echo "Route already exists in clientRoutes.$1.$2.sh"
         return
      fi
   
   fi
   
   if [[ ! -e ~/Fluidity_Server/client.$1/connection.$1.$2/listOfClientRoutes.$1.$2.sh ]]; then
   
      # Message to user.
      echo "Creating clientRoutes.$1.$2.sh"
   
      # Add the route to the VPN route client list.
      echo "sudo $3 $4 $5 $6 $7 $8" >> ~/Fluidity_Server/client.$1/connection.$1.$2/listOfClientRoutes.$1.$2.sh
      
      # Change permissions and make the script executable.
      chmod 700 ~/Fluidity_Server/client.$1/connection.$1.$2/listOfClientRoutes.$1.$2.sh
      
   else
   
      # Add the route to the client list.
      echo "sudo $3 $4 $5 $6 $7 $8" >> ~/Fluidity_Server/client.$1/connection.$1.$2/listOfClientRoutes.$1.$2.sh
      
   fi
   
}

# Arguments: ($1), ($2), ($3), ($4), ($5), ($6), ($7), ($8)
# $1: .Fluidity Client (SSH) Connection ID.
# $2: .Fluidity Virtual Circuit (SSL) Connection ID.
# $3: Fixed value: ip 
# $4: Fixed value: route
# $5: Fixed value: add
# $6: IP network and subnet mask
# $7: Fixed value: via
# $8: Exit IP

# Sourced Variables: NONE

# Intershell File Variables in use: NONE

# Global Variables in use: NONE

# Generates: Nothing

# Invokes Functions: NONE

# Calls the script: NONE

# Function Description: Remove a client route from the .Fluidity VPN 
# routes list, stored in the special purpose connection container script 
# ~/Fluidity_Server/client.[SSH_ID]/connection.[SSH_ID].[SSL_ID]/listOfClientRoutes.[SSH_ID].[SSL_ID].sh.
removeClientRoute () {
   
   # Safety check 1: Check whether Fluidity_Server folder is present 
   # (functionality contained within mountFluidityServerFolder) and 
   # decrypted.
   if [ -z "$(df -T | grep -E 'Fluidity_Server ecryptfs')" ] ; then 

      # Fluidity_Server folder found encrpyted. Use 
      # mountFluidityServerFolder to decrypt it.
      # Invoke mountFluidityServerFolder
      mountFluidityServerFolder
      
   fi
   
   # Safety check 2: Number of arguments should be no less than 8.
   if [ "$#" -ne 8 ]; then
      echo "Illegal number of parameters"
      return
   fi
   
   # Safety check 3: Force a specific command syntax.
   if ! [[ $3 == "ip" && $4 == "route" && $5 == "add" && $7 == "via" ]]; then
      echo "Command should be in the form of:" 
      echo "client_id connection_id ip route add x.y.z.w/mask via x.y.z.w"
      return
   fi
   
   # Safety check 4: Stop execution if this connection doesn't exist.
   if [ ! -d ~/Fluidity_Server/client.$1/connection.$1.$2 ]; then
      echo "Fluidity Connection $1.$2 does not exist"
      return
   fi
   
   # Safety check 5: Stop execution if this route is absent from client
   # list.
   if ! cat ~/Fluidity_Server/client.$1/connection.$1.$2/listOfClientRoutes.$1.$2.sh | grep "sudo $3 $4 $5 $6 $7 $8"; then
      echo "Route does not exist in clientRoutes.$1.$2.sh"
      return
   fi
   
   # Remove the route from the client VPN route list.
   grep -F -v "sudo $3 $4 $5 $6 $7 $8" \
   ~/Fluidity_Server/client.$1/connection.$1.$2/listOfClientRoutes.$1.$2.sh > \
   ~/Fluidity_Server/client.$1/connection.$1.$2/listOfClientRoutes.$1.$2.sh.tmp && \
   mv ~/Fluidity_Server/client.$1/connection.$1.$2/listOfClientRoutes.$1.$2.sh.tmp \
   ~/Fluidity_Server/client.$1/connection.$1.$2/listOfClientRoutes.$1.$2.sh
   
}
