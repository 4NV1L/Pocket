#!/bin/bash
# Linux Forensic shell script
##
## This is a fork from my original forensic script
## This is a non interactive TIER 1 Forensic script that obtains forensics assessment.
## There is no imaging etc. nor is there memory analysis. 
# This script needs to be stress tested

# Checks script for the /tmp directory and root user 

prog() {
    local w=80 p=$1; shift
    # create a string of spaces, then change them to dots
    printf -v dots "%*s" "$(( $p*$w/100 ))" ""; dots=${dots// /.};
    # print those dots on a fixed-width space plus the percentage etc. 
    printf "\r\e[K|%-*s| %3d %% %s" "$w" "$dots" "$p" "$*"; 
}
Bar() {
# test loop
for x in {1..100} ; do
    prog "$x" $(echo -e '\e[00;36m [ Beginning Next Phase ]\e[00m\n') $(date)
    sleep .01  # do some work here
done ; echo
}

checks() {

[[ UID == 0 || $EUID == 0 ]] || (
    echo '--------------------------------------------'
    echo -e "\e[1;91m ERROR: \e[0m root priviledges are required."
    echo '--------------------------------------------'
    exit 1
    )  || exit 1

#Confirm we are running this script in the \tmp directory, as best practice
if [ $PWD == "/tmp" ]
 then 
    echo 
    echo 'Preparing to run forensic script....'
elif [ $PWD != "/tmp" ]
then
    echo '--------------------------------------------------------------------------------------------------------'
   echo -e '\e[1;91m ERROR: \e[0m  For best forensic practice please run this script within the tmp directory'
    echo '--------------------------------------------------------------------------------------------------------'
    exit 1   
fi || exit 1
}
# Running checks 
checks 

forensicscan()
{

  # Create working Directories 
savedir=Incident

echo
echo -e "\e[1;34m Creating variable to store forenisc logs here: \e[0m \033[0;92m $savedir \e[0m" 
echo -e "\e[00;33m Script deployed at:\e[0m $(date)"
echo

[[ -d savedir ]] || mkdir -p Forensics || (
    echo -e "\e\033[1;91m Error in creating Directory \e[0m"
    exit 1
) || exit 1

[[ -d systemdna ]] || cd Forensics || (
    echo -e "\e\033[1;91m Error in creating Directory \e[0m"
    exit 1
) || exit 1

# Creating log file architecture & appending to the name of the files
saveto="$savedir/$(hostname)-$(date +%Y.%m.%d-%H.%M.%S)"
mkdir -p "$saveto"
logfile="$saveto/log.txt"

# stating data collection 
log() {
echo "$(date +"%b %d %H:%M:%S") $(hostname) Command: $1" | tee -a "$logfile"
}

echo -n > "$logfile"
log "##  Incident Response data collection script ## "
log "##  Starting data collection..."

echo -e '\033[0;92m --------------------------- [ Network Information ]---------------------------\e[0m'
Bar
netstatinfo=`netstat -nalp 2>/dev/null`
if [ "$netstatinfo" ]; then
  log "[+] Collecting all general network information" 
  log "netstat -nalp > $saveto/netstat.txt" 2>&1
  netstat -nalp > "$saveto/netstat.txt" 2>&1
else
    echo -e "\e[00;33m └─[ \e[0m \033[0;91m No information available for Command: netstat -nalp \e[0m \e[00;33m ] \e[0m" 
fi 

# Base Netstat information 
netstatestinfo=`netstat -antup 2>/dev/null`
if [ "$netstatestinfo" ]; then
  log "[+] Collecting establsihed connections information" 
  log "netstat -antup > $saveto/netstat_est.txt" 2>&1
  netstat -antup > "$saveto/netstat_est.txt" 2>&1
else
    echo -e "\e[00;33m └─[ \e[0m \033[0;91m No information available for Command: netstat -antup \e[0m \e[00;33m ] \e[0m" 
fi

netrouting=`netstat -rn 2>/dev/null`
if [ "$netrouting" ]; then
  log "[+] Collecting network Kernal IP routing table information" 
  log "netstat -rn > $saveto/netrouting.txt" 2>&1
  netstat -rn > "$saveto/netrouting.txt" 2>&1
else
    echo -e "\e[00;33m └─[ \e[0m \033[0;91m No information available for Command: netstat -rn \e[0m \e[00;33m ] \e[0m" 
fi

# Network Interface information 
netconfigs=`ifconfig 2>/dev/null`
if [ "$netconfigs" ]; then
  log "[+] Collecting network interface information" 
  log "ifconfig > $saveto/ifconfig.txt" 2>&1
  ifconfig > "$saveto/ifconfig.txt" 2>&1
else
    echo -e "\e[00;33m └─[ \e[0m \033[0;91m No information available for Command: ifconfig \e[0m \e[00;33m ] \e[0m"
fi

# Grabbing Mac Address informaton 
macmapping=`arp -aev 2>/dev/null`
if [ "$macmapping" ]; then
  log "[+] Collecting MAC Address mapping information" 
  log "arp -aev > $saveto/MacMapping.txt" 2>&1
  arp -aev > "$saveto/MacMapping.txt" 2>&1
else
    echo -e "\e[00;33m └─[ \e[0m \033[0;91m No information available for Command: arp -aev \e[0m \e[00;33m ] \e[0m" 
fi

# Checking if there are any IP table configurations on the box
iptablesconfig=`iptables --version && locate iptables 2>/dev/null`
if [ "$iptablesconfig" ]; then
  log "[+] Collecting information on if the system has iptables enabled" 
  log "iptables --version && locate iptables > $saveto/iptables.txt" 2>&1
  iptables --version > "$saveto/iptables.txt" && locate iptables >> "$saveto/iptables.txt" 2>&1
else
    echo -e "\e[00;33m └─[ \e[0m \033[0;91m No information available for Command: iptables --version \e[0m \e[00;33m ] \e[0m" 
fi

echo -e '\033[0;92m --------------------------- [ Listening Processes ]---------------------------\e[0m'
Bar
# Checking for processes on listen ports 
listeningproc=`lsof -i 2>/dev/null`
if [ "$listeningproc" ]; then
  log "[+] Collecting information on processes listening on ports" 
  log "lsof -i > $saveto/listeningproc-ALL.txt" 2>&1 
  lsof -i > "$saveto/listeningproc.txt" 2>&1
else
    echo -e "\e[00;33m └─[ \e[0m \033[0;91m No information available for Command: lsof -i \e[0m \e[00;33m ] \e[0m"
fi

listeningprocudp=`lsof -Pni udp 2>/dev/null`
if [ "$listeningprocudp" ]; then
  log "[+] Collecting information on processes listening using UDP" 
  log "lsof -Pni udp  > $saveto/listeningproc-UDP.txt" 2>&1
  lsof -Pni udp  > "$saveto/listeningproc-UDP.txt" 2>&1
else
    echo -e "\e[00;33m └─[ \e[0m \033[0;91m No information available for Command: lsof -Pni udp \e[0m \e[00;33m ] \e[0m"
fi

listeningproctcp=`lsof -Pni tcp 2>/dev/null`
if [ "$listeningproctcp" ]; then
  log "[+] Collecting information on processes listening using TCP" 
  log "lsof -Pni tcp  > $saveto/listeningproc-TCP.txt" 2>&1
  lsof -Pni tcp  > "$saveto/listeningproc-TCP.txt" 2>&1
else
     echo -e "\e[00;33m └─[ \e[0m \033[0;91m No information available for Command: lsof -Pni tcp \e[0m \e[00;33m ] \e[0m"
fi

echo -e '\033[0;92m --------------------------- [ DHCP & DNS Information ]---------------------------\e[0m'
Bar
# DHCP & DNS Information 
dhcpdredhat=`cat /var/lib/dhcpd/dhcpd.leases 2>/dev/null`
if [ "$dhcpdredhat" ]; then
  log "[+] Collecting information on DHCP Logs -- checking for RedHat" 
  log "cat /var/lib/dhcpd/dhcpd.leases > $saveto/redhat-dhcp.txt" 2>&1
  cat /var/lib/dhcpd/dhcpd.leases > "$saveto/redhat-dhcp.txt" 2>&1
else
    echo -e "\e[00;33m └─[ \e[0m \033[0;91m No information available for Command: cat /var/lib/dhcpd/dhcpd.leases \e[0m \e[00;33m ] \e[0m" 
fi

dhcpubuntu=`grep -Ei 'dhcp' /var/log/syslog.1 2>/dev/null`
if [ "$dhcpubuntu" ]; then
  log "[+] Collecting information on DHCP Logs -- checking for Ubuntu" 
  log "grep -Ei 'dhcp' /var/log/syslog.1 > $saveto/ubuntu-dhcp.txt" 2>&1
  cat grep -Ei 'dhcp' /var/log/syslog.1 > "$saveto/ubuntu-dhcp.txt" 2>&1
else
    echo -e "\e[00;33m └─[ \e[0m \033[0;91m No information available for Command: cat grep -Ei 'dhcp' /var/log/syslog.1 \e[0m \e[00;33m ] \e[0m"
fi

dnslogging=`tail /var/log/messages | grep 'named'  2>/dev/null`
if [ "$dnslogging" ]; then
  log "[+] Collecting DNS logging information " 
  log "tail -f /var/log/messages | grep 'named' > $saveto/dnslogging.txt" 2>&1
  tail -f /var/log/messages | grep 'named' > "$saveto/dnslogging.txt" 2>&1
else
    echo -e "\e[00;33m └─[ \e[0m \033[0;91m No information available for Command: tail -f /var/log/messages | grep 'named' \e[0m \e[00;33m ] \e[0m"
fi

echo -e '\033[0;92m --------------------------- [ Kernel Modules Data ]---------------------------\e[0m'
Bar
# Kernel Modules 
kernelmod=`lsmod 2>/dev/null`
if [ "$kernelmod" ]; then
  log "[+] Collecting loaded kernel module information" 
  log "lsmod > $saveto/kernel-modules.txt" 2>&1
  lsmod > "$saveto/kernel-modules.txt" 2>&1
else
    echo -e "\e[00;33m └─[ \e[0m \033[0;91m No information available for Command: lsmod \e[0m \e[00;33m ] \e[0m" 
fi

echo -e '\033[0;92m --------------------------- [ Account Information ]---------------------------\e[0m'
Bar
# Information on users
useraccountstats() {
# Gathering information on user accounts and system accounts 
_l="/etc/login.defs"
_p="/etc/passwd"

l=$(grep "^UID_MIN" $_l)  # Other Commands: awk -F':' '{ print $1}' /etc/passwd
l1=$(grep "^UID_MAX" $_l) # Other Commands: cut -d: -f1 /etc/passwd
 
## use awk to print if UID >= $MIN and UID <= $MAX and shell is not /sbin/nologin 
echo "----------[ Normal User Accounts ]---------------" 
awk -F':' -v "min=${l##UID_MIN}" -v "max=${l1##UID_MAX}" '{ if ( $3 >= min && $3 <= max  && $7 != "/sbin/nologin" ) print $0 }' "$_p" 
echo "" 
echo "----------[ System User Accounts ]---------------" 
awk -F':' -v "min=${l##UID_MIN}" -v "max=${l1##UID_MAX}" '{ if ( !($3 >= min && $3 <= max  && $7 != "/sbin/nologin")) print $0 }' "$_p"
}
# Running the user account statistics 
getuid=`useraccountstats 2>/dev/null`
if [ "$getuid" ]; then
  log "[+] Collecting User and System account information" 
  log "useraccountstats > $saveto/useraccountstats.txt" 2>&1
  useraccountstats > "$saveto/useraccountstats.txt" 2>&1
else
    echo -e "\e[00;33m └─[ \e[0m \033[0;91m Issue in grabbing user account statistics: function - useraccountstats \e[0m \e[00;33m ] \e[0m" 
fi

getadmusers=`echo -e "$grpinfo" | grep '(adm)' 2>/dev/null`
if [ "$getadmusers" ]; then
  log "[+] Collecting & identifying admin users on the system " 
  log 'echo -e "$grpinfo" | grep "(adm)" > $saveto/admin-users.txt' 2>&1
  echo -e "$grpinfo" | grep "(adm)" > "$saveto/admin-users.txt" 2>&1
else
    echo -e "\e[00;33m └─[ \e[0m \033[0;91m No information available for Command: echo -e '$grpinfo' | grep '(adm)' \e[0m \e[00;33m ] \e[0m"   
fi

currentusers=`w 2>/dev/null`
if [ "$currentusers" ]; then
  log "[+] Collecting current user logged into system information" 
  log "w > $saveto/current_users.txt" 2>&1
  w > "$saveto/current_users.txt" 2>&1
else
    echo -e "\e[00;33m └─[ \e[0m \033[0;91m No information available for Command: w \e[0m \e[00;33m ] \e[0m"  
fi

lastusers=`last 2>/dev/null`
if [ "$lastusers" ]; then
  log "[+] Collecting last user's logged into system information" 
  log "last > $saveto/last_users.txt" 2>&1
  last > "$saveto/last_users.txt" 2>&1
else
    echo -e "\e[00;33m └─[ \e[0m \033[0;91m No information available for Command: last \e[0m \e[00;33m ] \e[0m"
fi

failedlogin=`faillog -a 2>/dev/null`
if [ "$failedlogin" ]; then
  log "[+] Collecting failed login by user information" 
  log "faillog -a > $saveto/failedlogins.txt" 2>&1
  faillog -a  > "$saveto/failedlogins.txt" 2>&1
else
     echo -e "\e[00;33m └─[ \e[0m \033[0;91m No information available for Command: faillog -a \e[0m \e[00;33m ] \e[0m"
fi

echo -e '\033[0;92m --------------------------- [ Interesting Files Information ]---------------------------\e[0m'
Bar

passwdfile=`cat /etc/passwd 2>/dev/null`
if [ "$passwdfile" ]; then
  log "[+] Collecting information on /etc/passwd file" 
  log "cat /etc/passwd > $saveto/passwd_file.txt" 2>&1
  cat /etc/passwd > "$saveto/passwd_file.txt" 2>&1
else
    echo -e "\e[00;33m └─[ \e[0m \033[0;91m Issue for file contente: cat /etc/passwd \e[0m \e[00;33m ] \e[0m" 
fi

shadowfile=`cat /etc/shadow 2>/dev/null`
if [ "$shadowfile" ]; then
  log "[+] Collecting information on /etc/shadow file" 
  log "cat /etc/shadow > $saveto/shadow_file.txt" 2>&1
  cat /etc/shadow > "$saveto/shadow_file.txt" 2>&1
else
    echo -e "\e[00;33m └─[ \e[0m \033[0;91m Issue for file contents: cat /etc/shadow \e[0m \e[00;33m ] \e[0m" 
fi

groupfile=`cat /etc/group 2>/dev/null`
if [ "$groupfile" ]; then
  log "[+] Collecting information on /etc/group file" 
  log "cat /etc/group > $saveto/group_file.txt" 2>&1
  cat /etc/group > "$saveto/group_file.txt" 2>&1
else
    echo -e "\e[00;33m └─[ \e[0m \033[0;91m Issue for file contents: cat /etc/group \e[0m \e[00;33m ] \e[0m"  
fi

sudoerfile=`cat /etc/sudoers 2>/dev/null`
if [ "$sudoerfile" ]; then
  log "[+] Collecting information on /etc/sudoers file" 
  log "cat /etc/sudoers   > $saveto/sudoers_file.txt" 2>&1
  cat /etc/sudoers > "$saveto/sudoers_file.txt" 2>&1
else
    echo -e "\e[00;33m └─[ \e[0m \033[0;91m Issue for file contents: cat /etc/sudoers \e[0m \e[00;33m ] \e[0m" 
fi

roothistoryinfo=`cat /root/.bash_history 2>/dev/null`
if [ "$roothistoryinfo" ]; then
  log "[+] Collecting information on root bash history" 
  log "cat /root/.bash_history  > $saveto/roothistory.txt" 2>&1
  cat /root/.bash_history > "$saveto/roothistory.txt" 2>&1
else
    echo -e "\e[00;33m └─[ \e[0m \033[0;91m No information available for Command: cat /root/.bash_history \e[0m \e[00;33m ] \e[0m" 
fi

alluserhistoryfiles=`ls -ahtlr /home/* 2>/dev/null`
if [ "$alluserhistoryfiles" ]; then
  log "[+] Collecting information on all the users bash history files" 
  log "ls -ahtlr /home/* > $saveto/user-history-files.txt" 2>&1
  ls -ahtlr /home/* > "$saveto/user-history-files.txt" 2>&1
else
    echo -e "\e[00;33m └─[ \e[0m \033[0;91m No information available for Command: ls -ahtlr /home/* \e[0m \e[00;33m ] \e[0m" 
fi

allusercommands=`for d in /home/*/ ; do (cd "$d" && echo "$d" && cat .bash_history); done 2>/dev/null`
if [ "$allusercommands" ]; then
  log "[+] Collecting current user logged into system information" 
  log 'for d in /home/*/ ; do (cd "$d" && echo "$d" && cat .bash_history); done > $saveto/bash_history_all_users.txt' 2>&1
  for d in /home/*/ ; do (cd "$d" && echo "$d" && cat .bash_history); done > "$saveto/bash_history_all_users.txt" 2>&1
else
    echo -e '\e[00;33m └─[ \e[0m \033[0;91m No information available for Command: for d in /home/*/ ; do (cd "$d" && echo "$d" && cat .bash_history); done \e[0m \e[00;33m ] \e[0m'
fi

echo -e '\033[0;92m --------------------------- [ Hashing bin, sbin, and cron.d Files ]---------------------------\e[0m'
Bar
# Collecting File information 
# Hashing bin directories, cron.d & tmp directory 
sha1hashproc=`find /bin/* -xdev -type f -exec sha1sum -b {} \; > hashes.csv && find /tmp/* -xdev -type f -exec sha1sum -b {} \; >> hashes.csv && find /etc/cron.d/* -xdev -type f -exec sha1sum -b {} \; >> hashes.csv && find /sbin/* -xdev -type f -exec sha1sum -b {} \; >> hashes.csv && mv /etc/hashes.csv  /tmp/Forensics/hashes.csv 2>/dev/null`
if [ "$sha1hashproc" ]; then
  log "[+] Collecting hashes for bin files, sbin files cron.d, and tmp directory" 
  log "find /bin/* -xdev -type f -exec sha1sum -b {}\; > hashes.csv" 2>&1
  log "find /etc/cron.d/* -xdev -type f -exec sha1sum -b {}\; > hashes.csv" 2>&1
  log "find /tmp/* -xdev -type f -exec sha1sum -b {}\; > hashes.csv" 2>&1
  find /bin/* -xdev -type f -exec sha1sum -b {} \; > hashes.csv && find /tmp/* -xdev -type f -exec sha1sum -b {} \; >> hashes.csv && find /etc/cron.d/* -xdev -type f -exec sha1sum -b {} \; >> hashes.csv && find /sbin/* -xdev -type f -exec sha1sum -b {} \; >> hashes.csv && mv /etc/hashes.csv  /tmp/Forensics/hashes.csv 2>&1
else
     echo -e '\e[00;33m └─[ \e[0m \e[00;36m Hashing Completed \e[0m \e[00;33m ] \e[0m'
fi

echo -e '\033[0;92m --------------------------- [ Additional Notable File Information ]---------------------------\e[0m'
Bar

sbinfiles=`ls -alithr /sbin | sort -n 2>/dev/null`
if [ "$sbinfiles" ]; then
  log "[+] Collecting bin file information" 
  log "ls -alithr /sbin | sort -n > $saveto/sbinfiles.txt" 2>&1
  ls -alithr /sbin | sort -n > "$saveto/sbinfiles.txt" 2>&1
else
    echo -e "\e[00;33m └─[ \e[0m \033[0;91m No information available for Command: ls -alithr /sbin | sort -n \e[0m \e[00;33m ] \e[0m"  
fi

binfiles=`ls -alithr /bin | sort -n 2>/dev/null`
if [ "$binfiles" ]; then
  log "[+] Collecting bin file information" 
  log "ls -alithr /bin | sort -n > $saveto/binfiles.txt" 2>&1
  ls -alithr /bin | sort -n > "$saveto/binfiles.txt" 2>&1
else
    echo -e "\e[00;33m └─[ \e[0m \033[0;91m No information available for Command: ls -alithr /bin | sort -n \e[0m \e[00;33m ] \e[0m"  
fi

mountinfo=`mount 2>/dev/null`
if [ "$mountinfo" ]; then
  log "[+] Collecting information on currently mounted devices" 
  log "mount > $saveto/mount.txt" 2>&1
  mount > "$saveto/mount.txt" 2>&1
else
    echo -e "\e[00;33m └─[ \e[0m \033[0;91m No information available for Command: mount \e[0m \e[00;33m ] \e[0m"  
fi

dmesginfo=`dmesg 2>/dev/null`
if [ "$dmesginfo" ]; then
  log "[+] Collecting information on messages produced by device drivers" 
  log "dmesg > $saveto/dmesg.txt" 2>&1
  dmesg > "$saveto/dmesg.txt" 2>&1
else
    echo -e "\e[00;33m └─[ \e[0m \033[0;91m No information available for Command: dmesg \e[0m \e[00;33m ] \e[0m"
fi

tmpfiles=`ls -ailhtr /tmp/ | sort -n 2>/dev/null`
if [ "$tmpfiles" ]; then
  log "[+] Collecting tmp file information" 
  log "ls -ailhtr /tmp/ | sort -n  > $saveto/tmp.txt" 2>&1
  ls -ailhtr /tmp/ | sort -n > "$saveto/tmp.txt" 2>&1
else
    echo -e "\e[00;33m └─[ \e[0m \033[0;91m No information available for Command: ls -ailhtr /tmp/ | sort -n \e[0m \e[00;33m ] \e[0m" 
fi

etcfiles=`ls -ailhtr /etc/ | sort -n 2>/dev/null`
if [ "$etcfiles" ]; then
  log "[+] Collecting etc file information" 
  log "ls -ailhtr /etc/ | sort -n > $saveto/etc.txt" 2>&1
  ls -ailhtr /etc/ | sort -n > "$saveto/etc.txt" 2>&1
else
    echo -e "\e[00;33m └─[ \e[0m \033[0;91m No information available for Command: ls -ailhtr /etc/ | sort -n \e[0m \e[00;33m ] \e[0m"  
fi

homefiles=`ls -ailhtr /home/ | sort -n 2>/dev/null`
if [ "$homefiles" ]; then
  log "[+] Collecting home file information" 
  log "ls -ailhtr /home/ | sort -n > $saveto/home.txt" 2>&1
  ls -ailhtr /home/ | sort -n > "$saveto/home.txt" 2>&1
else
    echo -e "\e[00;33m └─[ \e[0m \033[0;91m No information available for Command: ls -ailhtr /home/ | sort -n \e[0m \e[00;33m ] \e[0m" 
fi

hiddenfiles=`find / -name ".*" -type f ! -path "/proc/*" ! -path "/sys/*" -exec ls -al {} \; 2>/dev/null`
if [ "$hiddenfiles" ]; then
  log "[+] Collecting hidden files excluding /proc/, /sys/ directories" 
  log 'find / -name ".*" -type f ! -path "/proc/*" ! -path "/sys/*" -exec ls -al {} \; > $saveto/hidden-files.txt' 2>&1
  find / -name ".*" -type f ! -path "/proc/*" ! -path "/sys/*" -exec ls -al {} \; > "$saveto/hidden-files.txt" 2>&1
else
    echo -e '\e[00;33m └─[ \e[0m \033[0;91m No information available for Command: find / -name ".*" -type f ! -path "/proc/*" ! -path "/sys/*" -exec ls -al {} \; \e[0m \e[00;33m ] \e[0m`'
fi

hashhiddenfiles=`find / -name ".*" -type f ! -path "/proc/*" ! -path "/sys/*" -exec sha1sum -b {} \; 2>/dev/null`
if [ "$hashhiddenfiles" ]; then
  log "[+] Collecting hidden file and Hashing each one excluding /proc/, /sys/ directories" 
  log 'find / -name ".*" -type f ! -path "/proc/*" ! -path "/sys/*" -exec sha1sum -b {} \; > $saveto/hidden-files-hashes.txt' 2>&1
  find / -name ".*" -type f ! -path "/proc/*" ! -path "/sys/*" -exec sha1sum -b {} \; > "$saveto/hidden-files-hashes.txt" 2>&1
else
    echo -e '\e[00;33m └─[ \e[0m \033[0;91m No information available for Command: find / -name ".*" -type f ! -path "/proc/*" ! -path "/sys/*" -exec sha1sum -b {} \; \e[0m \e[00;33m ] \e[0m'
fi

badpermsdirectory=`find / -xdev -type d \( -perm -0002 -a ! -perm -1000 \) -print 2>/dev/null`
if [ "$badpermsdirectory" ]; then
  log "[+] Collecting information for any directories that are world readable" 
  log "find / -xdev -type d \( -perm -0002 -a ! -perm -1000 \) -print > $saveto/W-R-Directory.txt" 2>&1
  find / -xdev -type d \( -perm -0002 -a ! -perm -1000 \) -print > "$saveto/W-R-Directory.txt" 2>&1
else
    echo -e "\e[00;33m └─[ \e[0m \033[0;91m No information available for Command: find / -xdev -type d \( -perm -0002 -a ! -perm -1000 \) -print \e[0m \e[00;33m ] \e[0m" 
fi

hostsfile=`cat /etc/hosts 2>/dev/null`
if [ "$hostsfile" ]; then
  log "[+] Collecting information for what is configured in the hosts file" 
  log "cat /etc/hosts > $saveto/hosts-file.txt" 2>&1
  cat /etc/hosts > "$saveto/hosts-file.txt" 2>&1
else
    echo -e "\e[00;33m └─[ \e[0m \033[0;91m No information available for Command: cat /etc/hosts \e[0m \e[00;33m ] \e[0m" 
fi

# Cron Job Information 
cronk=`ls -athrl /etc/cron* 2>/dev/null`
if [ "$cronk" ]; then
  log "[+] Collecting all cron job information" 
  log "ls -athrl /etc/cron* > $saveto/cronjobs.txt" 2>&1
  ls -athrl /etc/cron* > "$saveto/cronjobs.txt" 2>&1
else
    echo -e "\e[00;33m └─[ \e[0m \033[0;91m No information available for Command: ls -athrl /etc/cron* \e[0m \e[00;33m ] \e[0m"  
fi

crontabinfo=`cat /var/spool/cron/crontabs/* 2>/dev/null`
if [ "$crontabinfo" ]; then
  log "[+] Collecting contabs information" 
  log "cat /var/spool/cron/crontabs/* > $saveto/crontabfile.txt" 2>&1
  cat /var/spool/cron/crontabs/* > "$saveto/crontabfile.txt" 2>&1
else
    echo -e "\e[00;33m └─[ \e[0m \033[0;91m No information available for Command: cat /var/spool/cron/crontabs/* \e[0m \e[00;33m ] \e[0m" 
fi

cronfileinfo=`cat /var/spool/cron/crontabs/* 2>/dev/null`
if [ "$cronfileinfo" ]; then
  log "[+] Collecting cron files information" 
  log "ls -ailtrh /var/spool/cron > $saveto/cronfile.txt" 2>&1
  ls -ailtrh /var/spool/cron > "$saveto/cronfile.txt" 2>&1
else
    echo -e "\e[00;33m └─[ \e[0m \033[0;91m No information available for Command: ls -ailtrh /var/spool/cron \e[0m \e[00;33m ] \e[0m"  
fi

echo -e '\033[0;92m --------------------------- [ Additional Process Information ]---------------------------\e[0m'
Bar
# Information on processes 
processinfo=`ps -auxx 2>/dev/null`
if [ "$processinfo" ]; then
  log "[+] Collecting running processes on the host" 
  log "ps -auxx > $saveto/processes.txt" 2>&1
  ps -auxx > "$saveto/processes.txt" 2>&1
else
    echo -e "\e[00;33m └─[ \e[0m \033[0;91m No information available for Command: ps -auxx \e[0m \e[00;33m ] \e[0m" 
fi

proctree=`pstree 2>/dev/null`
if [ "$proctree" ]; then
  log "[+] Collecting processes on the host in a tree format" 
  log "pstree > $saveto/process-tree.txt" 2>&1
  pstree > "$saveto/process-tree.txt" 2>&1
else
    echo -e "\e[00;33m └─[ \e[0m \033[0;91 No information available for Command: pstree \e[0m \e[00;33m ] \e[0m" 
fi

eatingdisk=`du -ah /etc/ | sort -n -r 2>/dev/null`
if [ "$eatingdisk" ]; then
  log "[+] Collecting information on the top 50 directories eating up disk space" 
  log "du -ah /etc/ | sort -n -r > $saveto/diskusage.txt" 2>&1
  du -ah /etc/ | sort -n -r | head -n 50 > "$saveto/diskusage.txt" 2>&1
else
    echo -e "\e[00;33m └─[ \e[0m \033[0;91m No information available for Command: du -ah /etc/ | sort -n -r \e[0m \e[00;33m ] \e[0m" 
fi

##  Security Audit checks that could point to problems 
##  Sourced from @rebootuser's Red Team LinEnum script 

echo -e '\033[0;92m --------------------------- [ Audit checks for poor security practices ]---------------------------\e[0m'
Bar

privatekeyfiles=`for d in /home/*/ ; do (cd "$d" && echo "$d" && grep -rl "PRIVATE KEY-----"); done 2>/dev/null`
if [ "$privatekeyfiles" ]; then
  log "[+] Collecting information on any stored private ssh keys --------- AWARENESS: This does take some time ---------" 
  log 'for d in /home/*/ ; do (cd "$d" && echo "$d" && grep -rl "PRIVATE KEY-----"); done > $saveto/private_ssh_keyfiles.txt' 2>&1
  for d in /home/*/ ; do (cd "$d" && echo "$d" && grep -rl "PRIVATE KEY-----"); done > "$saveto/private_ssh_keyfiles.txt" 2>&1
else
    echo -e '\e[00;33m └─[ \e[0m \033[0;91m No information found for Private SSH keys \e[0m \e[00;33m ] \e[0m' 
fi

awskeyfiles=`for d in /home/*/ ; do (cd "$d" && echo "$d" && grep -rli "aws_secret_access_key"); done 2>/dev/null`
if [ "$awskeyfiles" ]; then
  log "[+] Collecting information on any stored AWS keys --------- AWARENESS: This does take some time ---------" 
  log 'for d in /home/*/ ; do (cd "$d" && echo "$d" && grep -rli "aws_secret_access_key"); done > $saveto/awskeyfiles.txt' 2>&1
  for d in /home/*/ ; do (cd "$d" && echo "$d" && grep -rli "aws_secret_access_key"); done > "$saveto/awskeyfiles.txt" 2>&1
else
    echo -e '\e[00;33m └─[ \e[0m \033[0;91m No information found for AWS keys \e[0m \e[00;33m ] \e[0m' 
fi

gitcredfiles=`find / -name ".git-credentials" 2>/dev/null`
if [ "$gitcredfiles" ]; then
  log "[+] Collecting information on any stored Git Credentials" 
  log 'find / -name ".git-credentials" > $saveto/gitcredfiles.txt' 2>&1
  find / -name ".git-credentials" > "$saveto/gitcredfiles.txt" 2>&1
else
    echo -e '\e[0m \e[00;33m ] \e[0m No information found for git-credentials \e[0m \e[00;33m ] \e[0m'  
fi

echo -e '\033[0;92m --------------------------- [ Mail Information ]---------------------------\e[0m'
Bar

readmail=`ls -la /var/mail 2>/dev/null`
if [ "$readmail" ]; then
  log "[+] Collecting information on any mail files" 
  log 'ls -la /var/mail > $saveto/mail.txt' 2>&1
  ls -la /var/mail > "$saveto/mail.txt" 2>&1
else
    echo "\e[0m \e[00;33m ] \e[0m No information available \e[0m \e[00;33m ] \e[0m" 
fi

readmailroot=`ls -la /var/mail/root 2>/dev/null`
if [ "$readmailroot" ]; then
  log "[+] Collecting information on any root mail files" 
  log 'ls -la /var/mail > $saveto/rootmail.txt' 2>&1
  ls -la /var/mail > "$saveto/rootmail.txt" 2>&1
else
    echo -e "\e[0m \e[00;33m ] \e[0m No information available for Command: ls -la /var/mail \e[0m \e[00;33m ] \e[0m"  
fi

echo -e '\033[0;92m --------------------------- [ Discovering System Attributes ]---------------------------\e[0m'
Bar
## Docker checks for incident awareness 
## Idea sourced by @rebootuser's Red Team LinEnum script 
docker_checks()
{

#specific checks - check to see if we're in a docker container
#specific checks - check to see if we're a docker host
dockerversiont=`docker --version && docker ps -a 2>/dev/null`
if [ "$dockerversion" ]; then
  log "[+] Collecting information if there is Docker installed" 
  log 'docker --version && docker ps -a  > $saveto/docker-version.txt' 2>&1
  docker --version && docker ps -a  > "$saveto/docker-version.txt" 2>&1
else
    echo -e "\e[0m \e[00;33m ] \e[0m No information available for Dockers \e[0m \e[00;33m ] \e[0m"
fi

#specific checks - are there any docker files present
dockerfiles=`find / -name Dockerfile -exec ls -l {} \; 2>/dev/null`
if [ "$dockerfiles" ]; then
  log "[+] Collecting information on any Docker files" 
  log 'find / -name Dockerfile -exec ls -l {} \;   > $saveto/docker-files.txt' 2>&1
  find / -name Dockerfile -exec ls -l {} \;   > "$saveto/docker-files.txt" 2>&1
else
    echo -e "\e[0m \e[00;33m ] \e[0m No information available for Dockers \e[0m \e[00;33m ] \e[0m"
fi
#specific checks - are there any docker files present
dockeryml=`find / -name docker-compose.yml -exec ls -l {} \; 2>/dev/null`
if [ "$dockeryml" ]; then
  log "[+] Collecting information on any YML Docker files" 
  log 'find / -name docker-compose.yml -exec ls -l {} \; > $saveto/docker-files.txt' 2>&1
  find / -name docker-compose.yml -exec ls -l {} \; > "$saveto/docker-files.txt" 2>&1
else
    echo -e "\e[0m \e[00;33m ] \e[0m No information available for Dockers \e[0m \e[00;33m ] \e[0m"
fi
}
# Run Docker checks 
docker_checks

echo -e '\033[0;92m --------------------------- [ Backup All logs ]---------------------------\e[0m'
Bar
# Log Collections
findlogs=`cd /var/log && find -name '*' | grep 'log' | sort -n 2>/dev/null`
if [ "$findlogs" ]; then
  log "[+] Collecting information on what logs we have available in /var/log" 
  log "cd /var/log && find -name '*' | grep 'log' | sort -n  > $saveto/available_logs.txt" 2>&1
  cd /var/log && find -name '*' | grep 'log' | sort -n > "$saveto/available_logs.txt" 2>&1
else
    echo -e "\e[0m \e[00;33m ] \e[0m No information available for Command: cd /var/log && find -name '*' | grep 'log' | sort -n \e[0m \e[00;33m ] \e[0m" 
fi

# Log Backup Collections
collectlogs=`cd /tmp/Forensics/ && mkdir -p Backuplogs && cd /var/log && cp -R -v * /tmp/Forensics/Backuplogs 2>/dev/null`
if [ "$collectlogs" ]; then
  log "[+] Collecting all logs as a backup for any further manual investigation - Stored in new directory location: /tmp/Forensics/Backuplogs" 
  log "cd /tmp/Forensics/ && mkdir -p Backuplogs && cd /var/log && cp -R -v * /tmp/Forensics/Backuplogs"
  echo -e "Initiating large log collection"
  cd /tmp/Forensics/ && mkdir -p Backuplogs && cd /var/log && cp -R -v * /tmp/Forensics/Backuplogs && cd /tmp/Forensics/  2>&1
  echo -e "Log Collection complete"
else
    echo -e "\e[0m \e[00;33m ] \e[0m Problem in log collection for Command: cd /tmp/Forensics/ && mkdir -p Backuplogs && cd /var/log && cp -R -v * /tmp/Forensics/Backuplogs \e[0m \e[00;33m ] \e[0m"  
fi
ls
echo -e '\033[0;92m --------------------------- [ Checking for Known Cryptominers ]---------------------------\e[0m'
Bar
# Known Cryptominer Checks gathered from analysis and Linux.Ekcorminer - Symantec 
Crypto() {

# Known Cryptominer Checks gathered from analysis and Linux.Ekcorminer - Symantec 
cd /tmp/Forensics && touch potential-Cryptominers.txt

log "# Analyzing low hanging fruit, for potential cryptominer IOCs in processes"
log "[+] Creating directory to store findings --> touch potential-Cryptominers.txt" 

sleep 2

array=( webnode wipefse wipefs httpsd VWTFEdbwdaEjduiWar3adW Oracleupdate Natimmonal de.gsearch.com hwlh3wlh44lh Circle_MI get.bi-chi hashvault.pro nanopool.org xmr xig ddgs qW3xT wnTKYg t00ls.ru sustes thisxxs hashfish kworkerds /tmp/devtool systemctI sustse axgtbc axgtfa 6Tx3Wq dblaunchs /boot/vmlinuz mine.moneropool.com pool.t00ls.ru xmr.crypto-pool xmr.crypto-pool zhuabcn@yahoo.com monerohash.com /tmp/a7b104c270 xmr.crypto-pool xmr.crypto-pool xmr.crypto-pool stratum.f2pool.com xmrpool.eu xiaoyao xiaoxue biosetjenkins Loopback apaceha cryptonight mixnerdx performedl JnKihGjn irqba2anc1 irqba5xnc1 irqbnc1 ir29xc1 xig irqbalance crypto-pool minexmr XJnRj mgwsl pythno jweri lx26 NXLAi BI5zj askdljlqw minerd minergate Guard.sh ysaydh bonns donns kxjd Duck.sh vbonn.sh conn.sh kworker34 vkw.sh pro.sh acpid icb5o nopxi irqbalanc1 minerd i586 gddr mstxmr ddg.2011 wnTKYg deamon disk_genius sourplum polkitd nanoWatch zigw systemctI WmiPrwSe monero.crypto-pool xmro.pooltoig AnXqV.yam XbashY bashe bashf bashg bashh bashx libapache xmrig xmrigDaemon xmrigMiner transfer.sh zer0day.ru )

    echo "Checking against ${#array[*]} Cyptominer process strings" 
for miner in ${array[*]}
  do
    ps -auxf | grep -v grep | grep $miner >> potential-Cryptominers.txt 2>&1
    echo -e "[+]Checking cryptominer string: \033[0;91m$miner\e[0m"
done

  log "################## Crypto Scan Complete ##############################"
}
# Run Crypto Scan 
Crypto

}
forensicscan
