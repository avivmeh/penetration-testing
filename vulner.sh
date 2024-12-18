#!/bin/bash


FOLDER=$(pwd)
# Check if necessary tools are installed
if ! command -v nmap &> /dev/null; then
    echo "nmap not found. Please install nmap first."
    exit 1
fi


function log()			#replaces echo, will print to terminal normally like echo, but will also log into logfile 
{
    echo "$1"
    echo "$(date) - $1" >> "$FOLDER/pt.log"
}


function START()
{
	echo "Welcome to Aviv's PT Project"
	sleep 1
	echo "[+] Please choose an option"
	read -p "[N]ew scan, [I]nspect previous scan, [R]ead logs or [E]xport? " INS
	case $INS in
	I)
		INSPCT
	;;
	i)
		INSPCT
	;;
	N)
		SCN
	;;
	N)
	SCN	
	;;
	E)
		EXP		
	;;
	e)
		EXP	
	;;
	R)
	readlogs
	;;
	r)
	readlogs
	;;
	*)
	echo "Wrong input, Try again! Press CTRL-C to exit."
	START
	;;
	esac
}


function VLDT() 
{
cd $FOLDER
nmap $RNG -sL 2> .chk 1> .scan
if [ ! -z "$(cat .chk)" ]
then
	echo "[!] Wrong input, run again!"
	exit
else
	echo "[+] Range is valid, let's continue"	#1.4 Make sure the input is valid
	fi
}	

function BASIC()
{
	log "[~] Scanning ip's in the range $RNG"
	sleep 1
	for IP in $(cat .scan | awk '{print $NF}' | grep ^[0-9])
	do
	nmap -F $IP > DB/$DTA/$IP.nmap	2>/dev/null	# & Running the command in the background, therefore running on all ip's at once
	done
	wait
	HDR1
}

function FULL()
{
	if [ ! -d "$output_dir" ]; then
        echo "[+] Directory $output_dir does not exist. Creating it..."
            if [ ! -d "$output_dir" ]; then
        mkdir -p "$output_dir"
    fi
    else
	cd DB/$DTA	 2>/dev/null
	fi
	
	for IP in $(cat $FOLDER/.scan | awk '{print $NF}' | grep ^[0-9])
	do
		output_file="$output_dir/$IP.nmap"
		touch "$output_file"		#nmap probably can't create a new file to save, can only save an existing file, so just making sure it exists by creating it myself
		
		log "[*] Running full scan on $IP" 
		nmap --script "vuln,default" -p 22,21,23,3389 "$IP" -oN "$output_file"	>/dev/null 2>&1	 # NSE scripts for vulnerability analysis
		
		done
		HDR1
}



function SCN()
{
	read -p "[?] Enter a range to scan: " RNG
	VLDT 		#validating the range
	read -p "[?] Enter a directory to save the data: " DTA	# Get from the user a name for the output directory.
	mkdir -p $FOLDER/DB/$DTA 2>/dev/null
	output_dir=$(realpath "$FOLDER/DB/$DTA")

read -p "[?] Choose scanning option - [B]asic or [F]ull: " CHK
case $CHK in 
	B)
	echo "[!] Running Basic scan."
	BASIC		#Basic scanning
	;;
	b)
	echo "[!] Running Basic scan."
	BASIC		#Basic scanning
	;;
	F)
	echo "[!] Running Full scan."
	FULL 	#Full scan with NSE
	;;
	f)
	echo "[!] Running Full scan."
	FULL 	#Full scan with NSE
	;;
	*)
	echo "Wrong input, Try again."
	;;
esac
}


function INSPCT() {
    echo "[!] Inspect previous scans"
    sleep 1
    echo "[~] Gathering Available IPs..."
    ips=()
    for file in $(find $FOLDER/DB -type f \( -name "*.nmap" -o -name "*.hydra" \)); do		# Using find to find .nmap or .hydra extensions in $FOLDER/DB
        if [[ $file == *.nmap ]]; then
            ip_address=$(basename "$file" .nmap)	# Removing the extension from its name, to get just the ip address
        elif [[ $file == *.hydra ]]; then
            ip_address=$(basename "$file" .hydra)
        fi
        if [[ $ip_address =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] && [[ ! " ${ips[*]} " =~ " ${ip_address} " ]]; then	#checks that the ip concludes of just an ip, and isnt equal to the original ip file name
            ips+=("$ip_address")
        fi
    done
    
    if [ ${#ips[*]} -eq 0 ]; then
        echo "No available IPs found."
        echo "Press enter to continue or ctrl-c to quit..."
        read n
        START
        return
    fi
    
    echo "[!] Available IPs:"
    for ip in "${ips[*]}"; do
        echo "$ip"
    done
    
    read -p "[?] Enter an IP or IP range to inspect: " IPI
    echo "Selected IP/Range: $IPI"
    
    echo "[~] Searching for Relevant Files..."
    files=$(find $FOLDER/DB -type f \( -name "*$IPI*.nmap" -o -name "*$IPI*.hydra" \))
    
    if [ -z "$files" ]; then
        echo "No files found for the specified IP/Range."
        echo "Press enter to continue or ctrl-c to quit..."
        read n
        START
        return
    fi
    
    echo "[!] Relevant Files Found"
    sleep 0.5
    echo "[?] Available Files for $IPI (Enter number):"
    select file in $files; do
        if [ -n "$file" ]; then
            echo "[~] Displaying Content of $file"
            cat "$file"
            break
        else
            echo "Invalid selection.. Please try again."
        fi
    done
    
    echo "Press enter to continue or ctrl-c to quit..."
    read n
    START
}

function EXP() {
    echo "[*] Exporting output folder.." #LOG
    cd $FOLDER

    read -p "[?] Do you want to save to the default location (/home/kali/Desktop/DB.zip)? (y/n): " choice
    if [[ "$choice" == "y" || "$choice" == "Y" ]]; then
        save_path="/home/kali/Desktop/DB.zip"
    else
        read -p "[?] Enter the full path where you want to save the zip file and its name: " custom_path
        save_path=$custom_path
    fi

    # Extract directory path from save_path
    dir_path=$(dirname "$save_path")

    # Check if directory exists, if not create it


    zip -r "$save_path" DB/
    echo "Exported successfully to $save_path"
}


function readlogs(){
	log "[*] Printing log file contents:"
	cat "$FOLDER/pt.log"
    echo "Press enter to continue or ctrl-c to quit..."
    read n
    START
	
	
}

function HDR1() {

    cd "$FOLDER/DB/$DTA" || { echo "[!] Failed to change directory to $FOLDER/DB/$DTA"; exit 1; }

    current_ips=$(cat $FOLDER/.scan | awk '{print $NF}' | grep ^[0-9])
    
    for ip_file in $(ls *.nmap); do
        ip_address=$(basename "$ip_file" .nmap)			#Strips the ip from the .nmap file name's extension 
			
        if echo "$current_ips" | grep -q "$ip_address"; then	#Checks if the ip exists in the requested range
            open_ports=$(grep -oP '^\d+/tcp.*open' $ip_file | awk -F'/' '{print $1}')		#Searching for open ports
			if [ -n "$open_ports" ]; then
				echo "[!] Brute forcing"
				read -p "[?] Use [D]efault password list or [C]ustom? " list    #Option to choose default or custom password list
				case "$list" in
					D)
						LOGIN_FILE=$FOLDER/default_username.lst
						PASS_FILE=$FOLDER/default_password.lst
					;;
					d)
						LOGIN_FILE=$FOLDER/default_username.lst
						PASS_FILE=$FOLDER/default_password.lst
					;;
					C)
					read -p "[?] Enter full user file path: " usr
					read -p "[?] Enter full pas file path: " pas
					if [ -f "$usr" ]; then
						echo "[*] Using $usr"
					else 
						echo "[?] User list doesn't exist, check full path"
						exit 1
					fi     			
					if [ -f "$pas" ]; then
						echo "[*] Using $pas"
					else
						echo "[?] Password list doesn't exist, check full path"
						exit 1					#Checking if the user supplied lists are existing, otherwise exit
					fi
					;;
					c)
					read -p "[?] Enter full user file path: " usr
					read -p "[?] Enter full pas file path: " pas
					if [ -f "$usr" ]; then
						echo "[*] Using $usr"
					else 
						echo "[?] User list doesn't exist, check full path"
						exit 1
					fi     			
					if [ -f "$pas" ]; then
						echo "[*] Using $pas"
					else
						echo "[?] Password list doesn't exist, check full path"
						exit 1					#Checking if the user supplied lists are existing, otherwise exit
					fi
					;;
				esac
			else
			    echo "[!] No open ports found for $ip_address."
                continue  # Skip to the next IP file if no open ports are found

			fi
            
            for port in $open_ports; do					
                log "[*] Brute-forcing $ip_file on port $port"			
                
                service=$(grep "$port/tcp" "$ip_file" | awk '{print $3}')
                
                case "$service" in
                    ssh)
                        echo "[*] Brute forcing service $service.."
                        hydra -L "$LOGIN_FILE" -P "$PASS_FILE" -VF "ssh://$ip_address:$port" -o "$ip_address.hydra" >/dev/null 2>&1
                        ;;
                    ftp)
                        echo "[*] Brute forcing service $service.."
                        hydra -L "$LOGIN_FILE" -P "$PASS_FILE" -VF "ftp://$ip_address:$port" -o "$ip_address.hydra"	>/dev/null 2>&1
                        ;;
                    telnet)
                        echo "[*] Brute forcing service $service.."
                        hydra -L "$LOGIN_FILE" -P "$PASS_FILE" -VF "telnet://$ip_address:$port" -o "$ip_address.hydra"	>/dev/null 2>&1
                        ;;
                    smb)
                        echo "[*] Brute forcing service $service.."
                        hydra -L "$LOGIN_FILE" -P "$PASS_FILE" -VF "smb://$ip_address:$port" -o "$ip_address.hydra"	>/dev/null 2>&1
                        ;;
                    *)
                        echo "[!] Unknown or unsupported service: $service on port $port"
                        ;;
                esac
            done
        else
            echo "[*] Skipping file: $ip_file (not in current scan range)"
        fi
    done
    wait
    echo "Scan has finished."
    END
}


function END()
{
	read -p "Do you want to view the scan results? (Y/N)" RES
	if [[ "$RES" == "Y" || "$RES" == "y" ]]; then 
	INSPCT
	else 
	echo "Thx for trying out my vulnerabilities scanner!"
    echo "Press enter to continue or ctrl-c to quit..."
    read n
    START
    return
	fi
}

START

