# 🔍 **Enumerate the Vulnerable VM to Discover Usernames**

In this step, we'll discover a list of usernames that exist on the target system. These usernames will be useful later when performing brute-force attacks to crack passwords.

---

## ⚙️ **Process**

1. Identify the IP Address of Metasploitable 2  
Start your Metasploitable 2 VM and check the IP address.

![target's IP address](Screenshots/target-ip.png)

---

2. Scan for Open Ports Using `nmap`  
In your Kali Linux terminal, run the following command to identify services running on specific ports:

    ```bash
    nmap -sV 192.168.193.137
    ```
    ![nmap](Screenshots/scanning-port.png)

3. To find the list of usernames: 
    Run the command:
    ```bash
    enum4linux -a 192.168.193.137
    ```
    ![list of usernames](Screenshots/list-usernames.png)
    ![list of usernames](Screenshots/usernames.png)

4. Here we will make a list of username in txt file so it easier to read and find.
    Run the command:
    ```bash
    enum4linux -a 192.168.193.137 | grep 'user:' | cut -d ':' -f2 | awk '{print $1}' > usernames.txt
    ```
    ![username.txt](Screenshots/user-txt%20file.png)

    | **Option**         | **Explanation**    |
    | ---------------| ---------------|
    | enum4linux -a <target-ip> | Runs a full scan on the target |
    | grep 'user' | Filters lines that contain the word **user:** |
    | cut -d ':' -f2 | Cuts the line at the colon : and takes the second part.|
    | awk '{print $1}' | Cleans up the output by printing just the username. |
    | > username.txt | Saves the final list into a file called username.txt. |

    -- List of usernames:
    ```bash
    ┌──(sheba㉿NWS23010003)-[~/pickertwee/Crypto/Labworks/Labwork-01]
    └─$ cat usernames.txt   
    games
    nobody
    bind
    proxy
    syslog
    user
    www-data
    root
    news
    postgres
    bin
    mail
    distccd
    proftpd
    dhcp
    daemon
    sshd
    man
    lp
    mysql
    gnats
    libuuid
    backup
    msfadmin
    telnetd
    sys
    klog
    postfix
    service
    list
    irc
    ftp
    tomcat55
    sync
    uucp
    ```


