# penetration-testing
**Author:** Aviv Feldvari  

## Project Description  
The `vulner.sh` project is a powerful script aimed at automating vulnerability analysis on a target system. Its functionality includes:  
- Identifying and reporting system vulnerabilities.  
- Scanning for open ports and misconfigurations.  
- Conducting password brute-force attempts for weak password detection.  
- Mapping and presenting detailed vulnerability information.  

This project is an all-in-one tool for vulnerability detection and assessment.

---

## Functionality  

### Project's Mission  
The mission of this project is to:  
- Automate vulnerability detection and analysis.  
- Provide detailed information about system weaknesses.  
- Save and organize results for review and reporting.  

---

## Script Sections  

### 1. **Dependency Installation**  
The script verifies and installs the following tools to ensure full functionality:  
- Nmap  
- Hydra  
- Curl  
- Other essential utilities as needed  

### 2. **Target Configuration**  
Prompts the user to:  
- Input the target system's address.  
- Specify a range of ports to scan.  

### 3. **Port Scanning**  
Utilizes Nmap to:  
- Identify open ports.  
- Highlight associated services and potential vulnerabilities.  

### 4. **Weak Password Detection**  
Leverages Hydra for:  
- Brute-forcing discovered open ports.  
- Identifying weak credentials across common protocols (e.g., SSH, FTP).  

### 5. **Vulnerability Mapping**  
The script analyzes results from:  
- Nmap scans  
- Brute-force attempts  
It generates a summary of vulnerabilities, potential misconfigurations, and risk levels.

### 6. **Result Logging**  
Organizes and saves results in:  
- A structured directory based on the target’s hostname or IP.  
- Includes detailed logs of scans, detected vulnerabilities, and brute-force outcomes.  

---

## How to Run the Script  

### 1. Make the script executable:  
  chmod +x vulner.sh  
2. Run the script
  ./vulner.sh
