#!/bin/bash

#  ---------------------------------------------------------------------------------
#  This script written by Howard Rogers. 
#
#  It's purpose is to install Oracle 12c onto 64-bit Ubuntu 16.04.
#
#  See http://www.dizwell.com/wordpress/technical-articles/oracle/install-oracle-12c-on-ubuntu-16-04/ for some details.
#
#  Copyright (c) 2016 Howard Rogers,Dizwell Informatics
#  The script is supplied "as-is" with no warranties or guarantees of fitness of 
#  use or otherwise. Neither Dizwell Informatics nor Howard Rogers accepts any 
#  responsibility whatsoever for any damage caused by the use or misuse of this script.
#
#  Version 1.0 - Initial Release - 29th May 2016
# 
#  ---------------------------------------------------------------------------------

#  ---------------------------------------------------------------------------------
#  Define a little function to draw a progress indicator... Jaws!
#  i forever increments; when 1 mod 60 = 0, we start decrementing $pos or
#  incrementing it, depending on current direction of travel. Requires that
#  the function is called as a background process before some task is performed, 
#  then killed when complete, which requires that you know the process spawned by the
#  background call to the function. For example:
# 
#  jaws &
#  jawsp=$!
#  apt-get install some_program
#  kill $jawsp 
#  wait $jawsp 2>/dev/null
#  ---------------------------------------------------------------------------------
jaws() {
i=0
char=">"
pos=4
tput sgr0;tput clear;tput setaf $TITLECOL;tput cup 3 5;tput smul;echo "$mytitle";
tput rmul;tput cup 5 5;tput rev; echo "$mysubtxt";
tput sgr0;tput cup 7 5;tput setaf $TEXTCOL; echo "$mybody1";
tput sgr0;tput cup 8 5;tput setaf $TEXTCOL; echo "$mybody2"
tput sgr0;tput cup 9 5;tput setaf $TEXTCOL; echo "$mybody3"
while true
do
  i=$((i+1))
  if [ $i -gt 36000 ]; then
    tput cup 18 5; echo "This is taking too long. Quitting."
	clear
	exit 1
  fi
  if [ $(($i%60)) -eq 0 ]; then   
    if [ $char = ">" ]; then 
      char="<"
    else
      char=">"
    fi
  fi
  if [ "$char" = ">" ]; then
    pos=$((pos+1))
    if [ "$pos" -gt 64 ]; then
      pos=64
    fi
  else
    pos=$((pos-1))     
    if [ "$pos" -lt 5 ]; then
      pos=5
    fi
  fi
  tput cup 18 5; echo "............................................................";
  tput cup 18 $(($pos)); echo -n $char;tput cup 23 0;
  sleep 0.2
done
}

#  ---------------------------------------------------------------------------------
#  Let's initialise  the default values for some of the variables
#  we'll be using later on
#  ---------------------------------------------------------------------------------
ROOT_UID="0";VERGOOD=0;OSGOOD=0;USRGOOD=0;NAMEGOOD=0;SETSMSML=0;SETSEMMNS=0;SETSMOPM=0;SETSMMNI=0;SETSHMAX=0;SETSHMAL=0
SETSHMNI=0;SETPRMIN=0;SETPRMAX=0;SETFSMAX=0;SETWMEMD=0;SETWMEMM=0;SETRMEMD=0;SETRMEMM=0;SETAIMAX=0;SETSUDMP=0
TITLECOL=2;TEXTCOL=0;WARNCOL=1;
ver=16.04

#  ---------------------------------------------------------------------------------
#  Check we're running on a 64-bit platform, aborting if not...
#  ---------------------------------------------------------------------------------
ARCHITECTURE="`/bin/uname -m`"
if [ "$ARCHITECTURE" != "x86_64" ]; then
  tput sgr0;tput clear;tput setaf $TITLECOL;tput cup 3 5;tput smul
  echo "UBUNTU $ver - THE DIZWELL ORACLE PREINSTALLER";tput rmul;tput cup 5 5;tput rev
  echo " W R O N G   O/S   A R C H I T E C T U R E ! ";tput sgr0;tput cup 7 5;tput setaf $WARNCOL;tput bold
  echo "This script only works on 64-bit platforms, but yours is a 32-bit one.";tput cup 16 5;tput rev
  tput cup 17 5; read -p "Press Enter to quit..." RESP
  tput sgr0
  clear
  exit 1
fi  

#  ---------------------------------------------------------------------------------
#  This script has to run with root privileges, so check you are root now
#  and if you're not, re-call the script as root having prompted for the password.
#  ---------------------------------------------------------------------------------
CMDLN_ARGS="$@" 
export CMDLN_ARGS
chk_root () {
  if [ ! $( id -u ) -eq 0 ]; then
    tput sgr0;tput clear;tput setaf $TITLECOL;tput cup 3 5;tput smul
    echo "UBUNTU $ver - THE DIZWELL ORACLE PREINSTALLER";tput rmul;tput cup 5 5;tput rev
    echo " R O O T   P R I V I L E G E S   R E Q U I R E D ";tput sgr0;tput cup 7 5;tput setaf $TEXTCOL
    echo "This script requires root privileges to run properly.";tput cup 8 5
    echo "Please enter your root password to continue... ";tput cup 17 5;tput bold;tput rev
    exec sudo -S su -c "${0} ${CMDLN_ARGS}"
    exit ${?}                 
  fi
}
chk_root

#  ---------------------------------------------------------------------------------
#  The script only runs on Ubuntu 16.04.
#  ---------------------------------------------------------------------------------

VERCHECK=`lsb_release -d`
if [ "$VERCHECK" != "Description:	Ubuntu 16.04 LTS" ]; then
  tput sgr0;tput clear;tput setaf $TITLECOL;tput cup 3 5;tput smul
  echo "UBUNTU $ver - THE DIZWELL ORACLE PREINSTALLER";tput rmul;tput cup 5 5;tput rev
  echo " W R O N G   D I S T R O   D E T E C T E D ! ";tput sgr0;tput cup 7 5;tput setaf $WARNCOL;tput bold
  echo "This script is intended to run only on the following distros:";tput sgr0;tput cup 9 5;tput setaf $TEXTCOL
  echo "* Ubuntu 16.04";tput cup 10 5;
  echo "Your OS is, however, reporting itself to be:";tput cup 12 5 
  echo `lsb_release -d` | awk '{print substr($0,14,99)}';tput cup 13 5;tput rev
  read -p "Press Enter to quit..." RESP
  tput sgr0
  clear
  exit 1  
else
  DISTRO="Deb"
fi  

#  ---------------------------------------------------------------------------------
#  With those fundamental tests out of the way, let's display some boiler-plate
#  explanation that most people probably won't read anyway...
#  ---------------------------------------------------------------------------------
tput sgr0;tput clear;tput setaf 2;tput cup 3 5;tput smul
echo "UBUNTU $ver - THE DIZWELL ORACLE PREINSTALLER";tput rmul;tput cup 5 5;tput rev
echo " P R E L I M I N A R Y   W A R N I N G S!! ";tput sgr0;tput cup 7 5;tput setaf $TEXTCOL
echo "This script will make considerable configuration changes";tput cup 8 5
echo "to your system so that it can run the Oracle relational";tput cup 9 5 
echo "database management system. ";tput cup 11 5
echo "Once these changes are made, they are only reversible ";tput cup 12 5
echo "manually ...and with a lot of effort!";tput cup 17 5;tput rev;tput bold
read -p "Are you sure you wish to proceed? [default=n] (y/n): " RESP
if [ "$RESP" == "" ]; then
  RESP=n
fi

if [ "$RESP" = "y" ]; then
  tput setaf 1
  tput clear
else
  tput sgr0
  clear
  exit 0  
fi

#  ---------------------------------------------------------------------------------
#  Next, we need to know which Oracle version is to be installed. There
#  are only two choices these days...
#  ---------------------------------------------------------------------------------
tput sgr0;tput clear;tput setaf 2;tput cup 3 5;tput smul
echo "UBUNTU $ver - THE DIZWELL ORACLE PREINSTALLER";tput rmul;tput cup 5 5;tput rev
echo " C H O O S E   O R A C L E   V E R S I O N ";tput sgr0;tput cup 7 5;tput setaf $TEXTCOL
echo "1. Oracle 12c Release 1";tput cup 9 5
echo "2. Quit";tput bold
while [ "$VERGOOD" != 1 ]; do
  tput cup 17 5
  tput rev
  read -p "Enter your choice [1-2]: " oraver
  case $oraver in
    1 ) ORAPATH="12.1.0"; 
        ORACHOICE="12c";
	VERGOOD=1;;
    2 ) tput sgr0;
        clear
	exit 1;;
    * ) tput cup 17 5;
	VERGOOD=0;
        echo "Please enter 1 or 2 only.";;
  esac
done;

#  ---------------------------------------------------------------------------------
# The IP address of the machine needs to be recorded in the /etc/hosts
# file. So we will first get the IP address of the machine. Then we'll check if that address
# is listed in /etc/hosts ...and if it isn't, we'll add it to it. Note the original hosts
# file is copied to a uniquely-named file first, so the edit is manually reversible if needed.
#  ---------------------------------------------------------------------------------
IPADD=$(ifconfig  | grep 'inet addr:'| grep -v '127.0.0.1' | cut -d: -f2 | awk '{ print $1}')
IPCHECK=$(awk '/$IPADD/{print $1}' /etc/hosts)

if [ "$IPCHECK" ] ; then
tput cup 16 5;tput setaf 4
echo 'Hosts file is already configured correctly'
else
curDate=`date '+%m-%d-%y-%s'`
cp /etc/hosts /etc/hosts.$curDate
echo "$IPADD `hostname`"|cat - /etc/hosts > /tmp/out && mv -f /tmp/out /etc/hosts
tput cup 16 5;tput setaf 4
echo "# Next line added for fresh Oracle Installation"|cat - /etc/hosts > /tmp/out && mv -f /tmp/out /etc/hosts
tput cup 17 5
echo 'Hosts file configuration updated'
fi

#  ---------------------------------------------------------------------------------
#  A user has to own the Oracle installation. By default, we'll offer to create the user 'oracle' 
#  to do that. But a user can overtype the default and specify whatever name they like, if they are
#  minded to... so long as they don't get smart and try submitting a blank name!
#  ---------------------------------------------------------------------------------
while [ "$USRGOOD" != 1 ]; do
tput clear;tput sgr0;tput setaf 2;tput cup 3 5;tput smul
echo "UBUNTU $ver - THE DIZWELL ORACLE PREINSTALLER";tput rmul;tput cup 5 5;tput rev
echo " S P E C I F Y   O R A C L E   U S E R ";tput sgr0;tput cup 7 5;tput setaf $TEXTCOL
echo "An Oracle software installation has to be 'owned' by";tput cup 8 5 
echo "a user account. By default, that account is 'oracle',";tput cup 9 5 
echo "but you can specify any account name now. If you type";tput cup 10 5 
echo "a username that doesn't already exist, that account";tput cup 11 5 
echo "will be created for you.";tput cup 17 5;tput setaf 0;tput bold;tput rev
read -p "Type in a username [default=oracle]: " ORACLEUSER
if [ "$ORACLEUSER" == "" ]; then
  ORACLEUSER=oracle
fi
LENGTHUSRNAME=`echo -n $ORACLEUSER | wc -m | sed -e s/^\s+//`
if [[ $LENGTHUSRNAME > 0 ]]; then
  USRGOOD=1 
else 
  USRGOOD=0
fi
done

egrep $ORACLEUSER /etc/passwd >/dev/null 2>&1
if [ $? -eq 0 ]; then
#  ---------------------------------------------------------------------------------
# The username specified is one that belongs to an existing user
#  ---------------------------------------------------------------------------------
  USREXISTS=1
else
  USREXISTS=0
fi

egrep "^dba" /etc/group >/dev/null 2>&1
if [ $? -eq 0 ]; then
#  ---------------------------------------------------------------------------------
# The dba group already exists
#  ---------------------------------------------------------------------------------
  DBAEXISTS=1
else
  DBAEXISTS=0
fi

egrep "^oinstall" /etc/group >/dev/null 2>&1
if [ $? -eq 0 ]; then
#  ---------------------------------------------------------------------------------
# The oinstall group already exists
#  ---------------------------------------------------------------------------------
  OINEXISTS=1
else
  OINEXISTS=0
fi

egrep "^nobody" /etc/group >/dev/null 2>&1
if [ $? -eq 0 ]; then
#  ---------------------------------------------------------------------------------
# The nobody group already exists
#  ---------------------------------------------------------------------------------
  NOBEXISTS=1
else
  NOBEXISTS=0
fi

#  ---------------------------------------------------------------------------------
#  We have to prompt for a password for the Oracle User, too, if it's a new user
#  ---------------------------------------------------------------------------------
if [ "$USREXISTS" -eq 0 ]; then
  tput clear;tput sgr0;tput setaf 2;tput cup 3 5;tput smul
  echo "UBUNTU $ver - THE DIZWELL ORACLE PREINSTALLER";tput rmul;tput cup 5 5;tput rev
  echo " O R A C L E   U S E R   P A S S W O R D ";tput sgr0;tput cup 7 5;tput setaf $TEXTCOL 
  echo "You've opted to create a new user to own the Oracle";tput cup 8 5 
  echo "installation. That new user account needs password";tput cup 9 5 
  echo "protection. The default password is 'oracle', but ";tput cup 10 5 
  echo "you can supply an alternative now if you like.";tput cup 17 5;tput bold;tput rev
  read -p "Type the new user's password [default=oracle]: " ORAPASSWD
  if [ "$ORAPASSWD" == "" ]; then
    ORAPASSWD=oracle
  fi
fi

#  ---------------------------------------------------------------------------------
#  The users get to choose their database name, if they want to.
#  But then we have to check that their proposed name is less than
#  nine characters long, not null and doesn't start with a number!
#  ---------------------------------------------------------------------------------
tput clear;tput sgr0;tput setaf 2;tput cup 3 5;tput smul
echo "UBUNTU $ver - THE DIZWELL ORACLE PREINSTALLER";tput rmul;tput cup 5 5;tput rev;
echo " S T A R T E R   D A T A B A S E   N A M E ";tput sgr0;tput cup 7 5;tput setaf $TEXTCOL
echo "When you perform the Oracle software installation, you'll ";tput cup 8 5 
echo "be prompted to create a starter database. That database will";tput cup 9 5 
echo "need a name, which needs to be specified now. By default,";tput cup 10 5 
echo "this script will assume you'll use a name of 'orc'.";tput cup 17 5 
while [ "$NAMEGOOD" != 1 ]; do
tput setaf 0
tput cup 17 5
tput bold
tput rev 
read -p "Type in a database name [default=orcl] : " DBNAME
if [ "$DBNAME" == "" ]; then
  DBNAME=orcl
fi

LENGTHDBNAME=`echo -n $DBNAME | wc -m | sed -e s/^\s+//`
NUMCHECK=`echo $DBNAME | sed -e s/^[0-9]//`

if [ "$LENGTHDBNAME" -gt 8 ]; then
  tput setaf 1;tput cup 17 5;tput bold;tput rev
  echo "That name is too long. 8 or fewer characters please!"
  NAMEGOOD=0
fi

if [ "$LENGTHDBNAME" -gt 0 ]; then
  if [ "$DBNAME" != "$NUMCHECK" ]; then    
    tput setaf 1;tput cup 17 5;tput bold;tput rev  
    echo "That name starts with a number, which isn't allowed!"
    NAMEGOOD=0
  fi
fi

if [ "$LENGTHDBNAME" -gt 0 ]; then
  if [ "$LENGTHDBNAME" -lt 9 ]; then
     if [ "$DBNAME" = "$NUMCHECK" ]; then
     NAMEGOOD=1
     fi
  fi
fi
done

#  ---------------------------------------------------------------------------------
#  That's the interactive part over with (almost!). So now it's time to
#  actually make some changes to the system. Let's begin by creating the
#  oracle user and setting his password to whatever was supplied earlier
#  ---------------------------------------------------------------------------------
if [ "$USREXISTS" -eq 0 ]; then
  if [ "$DBAEXISTS" -eq 0 ]; then
    /usr/sbin/groupadd dba
  fi
  
  if [ "$OINEXISTS" -eq 0 ]; then
    /usr/sbin/groupadd oinstall
  fi
  /usr/sbin/useradd -m $ORACLEUSER -g oinstall -G dba -s /bin/bash
  echo $ORACLEUSER:$ORAPASSWD | chpasswd
  history -c
fi

if [ "$USREXISTS" -eq 1 ]; then
#  ---------------------------------------------------------------------------------
# We have to preserve the groups the user already has -which means working
# out what those groups are to start with!
#  ---------------------------------------------------------------------------------
  GROUPLIST=`id -Gn $ORACLEUSER`
  for group in $GROUPLIST; do
    if [ "$group" != 'dba' ] && [ "$group" != 'oinstall' ] ; then
      groupstring=$groupstring,$group
    fi
  done

  if [ "$DBAEXISTS" -eq 0 ]; then
    /usr/sbin/groupadd dba
  fi
  
  if [ "$OINEXISTS" -eq 0 ]; then
    /usr/sbin/groupadd oinstall
  fi

  /usr/sbin/usermod -g oinstall -G dba$groupstring $ORACLEUSER
fi

#  ---------------------------------------------------------------------------------
#  We need some symbolic links to make Ubuntu look more Red Hattish
#  ---------------------------------------------------------------------------------
if [ ! -e "/bin/awk" ]; then 
ln -s /usr/bin/awk /bin/awk >/dev/null 2>&1
fi
if [ ! -e "/bin/rpm" ]; then 
ln -s /usr/bin/rpm /bin/rpm >/dev/null 2>&1
fi
if [ ! -e "/lib/x86_64-linux-gnu/libgcc_s.so.1" ]; then 
ln -s /lib/x86_64-linux-gnu/libgcc_s.so.1 /lib64/libgcc_s.so.1 >/dev/null 2>&1
fi
if [ ! -e "/lib/libgcc_s.so" ]; then 
ln -s /lib/libgcc_s.so.1 /lib/libgcc_s.so >/dev/null 2>&1
fi
if [ ! -e "/bin/basename" ]; then 
ln -s /usr/bin/basename /bin/basename >/dev/null 2>&1
fi
if [ ! -e "/usr/lib64" ]; then 
ln -s /usr/lib/x86_64-linux-gnu /usr/lib64 >/dev/null 2>&1
fi
if [ ! -e "/bin/sh" ]; then 
ln -sf /bin/bash /bin/sh >/dev/null 2>&1
fi
if [ "$NOBEXISTS" -eq 0 ]; then
/usr/sbin/groupadd nobody >/dev/null 2>&1
fi

#  ---------------------------------------------------------------------------------
#  Now create the directory structure for the final Oracle
#  installation. Additionally, we create an /osource directory where the
#  Oracle software can be copied to disk, avoiding an off-DVD installation.
#  ---------------------------------------------------------------------------------
if [ ! -e "/u01/app/oracle/product/$ORAPATH/db_1" ]; then 
  mkdir -p /u01/app/oracle/product/$ORAPATH/db_1
fi
if [ ! -e "/osource" ]; then 
  mkdir /osource
fi
chown -R $ORACLEUSER:oinstall /u01/app
chmod -R 775 /u01/app
chown -R $ORACLEUSER:oinstall /osource
chmod -R 775 /osource

#  ---------------------------------------------------------------------------------
#  Now we check the existing kernel parameters so we can work out if
#  they need to be changed...
#  ---------------------------------------------------------------------------------
SMSML=`cat /proc/sys/kernel/sem | awk '{print $1}'`
SMMNS=`cat /proc/sys/kernel/sem | awk '{print $2}'`
SMOPM=`cat /proc/sys/kernel/sem | awk '{print $3}'`
SMMNI=`cat /proc/sys/kernel/sem | awk '{print $4}'`
MEMSZ=`cat /proc/meminfo | grep MemTotal | awk '{print $2}'`
let "MEMSZ *= 1024"
let "MEMSZ /= 2"
let "MEMSZ += 16777216"
SHMAX=`cat /proc/sys/kernel/shmmax`
SHMAL=`cat /proc/sys/kernel/shmall`
SHMNI=`cat /proc/sys/kernel/shmmni`
PRMIN=`cat /proc/sys/net/ipv4/ip_local_port_range | awk '{print $1}'`
PRMAX=`cat /proc/sys/net/ipv4/ip_local_port_range | awk '{print $2}'`
FSMAX=`cat /proc/sys/fs/file-max`
RMEMD=`cat /proc/sys/net/core/rmem_default`
RMEMM=`cat /proc/sys/net/core/rmem_max`
WMEMD=`cat /proc/sys/net/core/wmem_default`
WMEMM=`cat /proc/sys/net/core/wmem_max`
AIMAX=`cat /proc/sys/fs/aio-max-nr`
SUDMP=`cat /proc/sys/fs/suid_dumpable`
HSTNM=`hostname`

#  ---------------------------------------------------------------------------------
#  Time to set the kernel parameters to recommended values, but only 
#  if they are NOT already set to usable minima.
#  ---------------------------------------------------------------------------------
if [ $SMSML -lt 250 ]; then
  SMSML=250
  SETSMSML=1
fi

if [ $SMMNS -lt 32000 ]; then
  SMMNS=32000
  SETSEMMNS=1
fi

if [ $SMOPM -lt 100 ]; then
  SMOPM=100
  SETSMOPM=1
fi

if [ $SMMNI -lt 128 ]; then
  SMMNI=128
  SETSMMNI=1
fi

result=`echo $SHMAX \< $MEMSZ | bc`
if [ "$result" -ne 0 ]; then
   SHMAX=$MEMSZ
   SETSHMAX=1
else
   SHMAX=8589934592
   SETSHMAX=1
fi

SHMAL=2097152
SETSHMAL=1

SHMNI=4096
SETSHMNI=1

if [ $PRMIN -gt 1024 ]; then
  PRMIN=1024
  SETPRMIN=1
fi


if [ $PRMAX -lt 65000 ]; then
  PRMAX=65000
  SETPRMAX=1
fi

if [ $FSMAX -lt 65536 ]; then
  FSMAX=65536
  SETFSMAX=1
fi

if [ $WMEMD -lt 262144 ]; then
  WMEMD=262144
  SETWMEMD=1
fi

if [ $WMEMM -lt 262144 ]; then
  WMEMM=262144
  SETWMEMM=1
fi

if [ $ORACHOICE = "11gR2" ]; then 
  if [ $FSMAX -lt 6815744 ]; then
     FSMAX=6815744
     SETFSMAX=1
  fi

  if [ $WMEMM -lt 1048576 ]; then
     WMEMM=1048576
     SETWMEMM=1
  fi

  if [ $RMEMD -lt 4194304 ]; then
    RMEMD=4194304
    SETRMEMD=1
  fi

  if [ $PRMIN -lt 9000 ]; then
     PRMIN=9000
     SETPRMIN=1
  fi

  if [ $PRMAX -lt 65500 ]; then
     PRMAX=65500
     SETPRMAX=1
  fi

  if [ $AIMAX -lt 1048576 ]; then
    AIMAX=1048576
    SETAIMAX=1
  fi

  if [ $RMEMM -lt 4194304 ]; then
    RMEMM=4194304
    SETRMEMM=1
  fi

  if [ $SUDMP -eq 0 ]; then
    SUDMP=1
    SETSUDMP=1
  fi
fi

if [ $ORACHOICE = "12c" ]; then 
  if [ $FSMAX -lt 6815744 ]; then
     FSMAX=6815744
     SETFSMAX=1
  fi

  if [ $WMEMM -lt 1048576 ]; then
     WMEMM=1048576
     SETWMEMM=1
  fi

  if [ $RMEMD -lt 262144 ]; then
    RMEMD=262144
    SETRMEMD=1
  fi

  if [ $PRMIN -lt 9000 ]; then
     PRMIN=9000
     SETPRMIN=1
  fi

  if [ $PRMAX -lt 65535 ]; then
     PRMAX=65535
     SETPRMAX=1
  fi

  if [ $AIMAX -lt 1048576 ]; then
    AIMAX=1048576
    SETAIMAX=1
  fi

  if [ $RMEMM -lt 4194304 ]; then
    RMEMM=4194304
    SETRMEMM=1
  fi

  if [ $SUDMP -eq 0 ]; then
    SUDMP=1
    SETSUDMP=1
  fi
fi

#  ---------------------------------------------------------------------------------
#  Now actually set those parameters which have been determined to need re-setting
#  ----------------------------------------------------------------------------------- 
cat >> /etc/sysctl.conf << EOF
#
#Added for fresh Oracle $ORACHOICE Installation 
EOF

if [ $SETSHMAL -eq "1" ]; then
cat >> /etc/sysctl.conf << EOF
kernel.shmall = $SHMAL
EOF
fi 

if [[ $SETSHMAX -eq "1" ]]; then
cat >> /etc/sysctl.conf << EOF
kernel.shmmax = $SHMAX
EOF
fi

if [ $SETSHMNI -eq "1" ]; then
cat >> /etc/sysctl.conf << EOF
kernel.shmmni = 4096
EOF
fi

cat >> /etc/sysctl.conf << EOF
kernel.semmni = $SHMNI
EOF

if [[ $SETSMSML -eq "1" || $SETSMMNS -eq "1" || $SETSMOPM -eq "1" || $SETSMMNI -eq "1" ]]; then
cat >> /etc/sysctl.conf << EOF
kernel.sem = $SMSML $SMMNS $SMOPM $SMMNI
EOF
fi

if [ $SETFSMAX -eq "1" ]; then
cat >> /etc/sysctl.conf << EOF
fs.file-max = $FSMAX
EOF
fi

if [[ $SETPRMIN -eq "1" || $SETPRMAX -eq "1" ]]; then
cat >> /etc/sysctl.conf << EOF
net.ipv4.ip_local_port_range = $PRMIN $PRMAX
EOF
fi

if [ $SETRMEMD -eq "1" ]; then
cat >> /etc/sysctl.conf << EOF
net.core.rmem_default = $RMEMD
EOF
fi

if [ $SETWMEMD -eq "1" ]; then
cat >> /etc/sysctl.conf << EOF
net.core.wmem_default = $WMEMD
EOF
fi

if [ $SETRMEMM -eq "1" ]; then
cat >> /etc/sysctl.conf << EOF
net.core.rmem_max = $RMEMM
EOF
fi

if [ $SETWMEMM -eq "1" ]; then
cat >> /etc/sysctl.conf << EOF
net.core.wmem_max = $WMEMM
EOF
fi

if [ $SETAIMAX -eq "1" ]; then
cat >> /etc/sysctl.conf << EOF
fs.aio-max-nr = $AIMAX
EOF
fi

if [ $SETSUDMP -eq "1" ]; then
cat >> /etc/sysctl.conf << EOF
fs.suid_dumpable = $SUDMP
EOF
fi

#  ---------------------------------------------------------------------------------
#  Now we have to set security limits.
#  ----------------------------------------------------------------------------------
cat /etc/security/limits.conf | sed /'# End of file'/d > /tmp/limits.wrk
cat >> /tmp/limits.wrk << EOF
$ORACLEUSER        soft    nproc    2047
$ORACLEUSER        hard    nproc   16384
$ORACLEUSER        soft    nofile   1024
$ORACLEUSER        hard    nofile  65536
$ORACLEUSER        soft    stack   10240
# End of file
EOF

rm /etc/security/limits.conf
mv /tmp/limits.wrk /etc/security/limits.conf

cat >> /etc/pam.d/login << EOF
session    required     pam_limits.so
EOF

DISTRIB=5

#  ---------------------------------------------------------------------------------
#  Now the Oracle User's environment variables are set
#  ---------------------------------------------------------------------------------
ENVFILE="/home/$ORACLEUSER/.bashrc"
cat >> $ENVFILE << EOF
#Added for fresh Oracle $ORACHOICE Installation
export ORACLE_HOSTNAME=$HSTNM
export ORACLE_BASE=/u01/app/oracle
export ORACLE_HOME=/u01/app/oracle/product/$ORAPATH/db_1
export ORACLE_SID=$DBNAME
export ORACLE_UNQNAME=$DBNAME
export PATH=\$ORACLE_HOME/bin:\$PATH:.
export LD_LIBRARY_PATH=\$ORACLE_HOME/lib:/lib:/usr/lib
export CLASSPATH=\$ORACLE_HOME/JRE:\$ORACLE_HOME/jlib:\$ORACLE_HOME/rdbms/jlib
DISTRIB_RELEASE=$DISTRIB

alias sqlplus="rlwrap sqlplus"
alias sql="sqlplus / as sysdba"
alias diag="cd \$ORACLE_BASE/diag/rdbms/\$ORACLE_UNQNAME/\$ORACLE_SID/trace"

EOF

#  ---------------------------------------------------------------------------------
#  We need a script to auto-start Oracle databases at server reboot. Note that whilst
#  this section will generate such a script, it won't be automatically run unless the
#  user manually remembers to alter the contents of the /etc/oratab file.
#  ---------------------------------------------------------------------------------

if [ -f /etc/init.d/dboraz ]; then
mv /etc/init.d/dboraz /etc/init.d/dboraz.original
fi

cat >> /etc/init.d/dboraz << EOF
#!/bin/bash
### BEGIN INIT INFO
# Provides:          dboraz
# Required-Start:    $remote_fs $syslog
# Required-Stop:     $remote_fs $syslog
# Default-Start:     3 4 5
# Default-Stop:      0 1 2 6
# Short-Description: Startup script for Oracle Databases
# Description:       Oracle Database Auto-Start Script
### END INIT INFO
export ORACLE_HOME=/u01/app/oracle/product/$ORAPATH/db_1
export ORACLE_SID=$DBNAME
export PATH=\$ORACLE_HOME/bin:\$PATH:.

case "\$1" in
start)
        echo -n "Starting Oracle: "
	su $ORACLEUSER -c "\$ORACLE_HOME/bin/dbstart \$ORACLE_HOME"
	su $ORACLEUSER -c "\$ORACLE_HOME/bin/emctl start dbconsole"
	touch /var/lock/oracle
	echo "OK"
	;;
stop)
	echo -n "Shutting down Oracle: "
	su $ORACLEUSER -c "\$ORACLE_HOME/bin/emctl stop dbconsole"
	su $ORACLEUSER -c "\$ORACLE_HOME/bin/dbshut \$ORACLE_HOME"
	rm -f /var/lock/oracle
	echo "OK"
	;;
restart)
	echo -n "Shutting down Oracle: "
	su $ORACLEUSER -c "\$ORACLE_HOME/bin/emctl stop dbconsole"
	su $ORACLEUSER -c "\$ORACLE_HOME/bin/dbshut \$ORACLE_HOME"
	rm -f /var/lock/oracle
	echo "OK"	
    su $ORACLEUSER -c "\$ORACLE_HOME/bin/dbstart \$ORACLE_HOME"
	su $ORACLEUSER -c "\$ORACLE_HOME/bin/emctl start dbconsole"
	touch /var/lock/oracle
	echo "OK"
	;;
esac
exit 0
EOF

chmod 775 /etc/init.d/dboraz
(update-rc.d -f dboraz remove) >/dev/null 2>&1 2>&1
tput sgr0;tput cup 16 5;tput dim;tput setaf 7
(update-rc.d dboraz defaults) >/dev/null 2>&1 2>&1

#  ---------------------------------------------------------------------------------
#  Time to get some software prerequisites installed
#  ---------------------------------------------------------------------------------
tput sgr0;tput clear;tput setaf 2;tput cup 3 5;tput smul
echo "UBUNTU $ver - THE DIZWELL ORACLE PREINSTALLER";tput rmul;tput cup 5 5;tput rev
echo " S O F T W A R E  D O W N L O A D ";tput sgr0;tput cup 7 5;tput setaf $TEXTCOL
echo "This script now wants to update your existing software and";tput cup 8 5
echo "download quite a lot of new (and necessary) packages. ";tput cup 17 5;tput bold;tput rev
read -p "Do you wish to proceed? [default=n] (y/n): " RESP
if [ "$RESP" == "" ]; then
  RESP=n
fi

if [ "$RESP" = "y" ]; then
  tput setaf 1
  #  ---------------------------------------------------------------------------------
  #  Check if the CD/DVD repository is still enabled. If so, comment it out
  #  from /etc/apt/sources.list, ensuring that software is downloaded from
  #  the Internet (otherwise you sit there for hours not realising that the O/S
  #  is asking you to insert a cd/dvd before it can proceed!)
  #  ---------------------------------------------------------------------------------
  mytitle="UBUNTU $ver - THE DIZWELL ORACLE PREINSTALLER";
  mysubtxt=" S O F T W A R E   D O W N L O A D  ";
  mybody1="Repositories are being updated. ";
  mybody2="This can take a long time, so please be patient...";
  jaws $mytitle $mysubtxt $mybody1 $mybody2 &
  jawsp=$!
  sed -i 's/deb cdrom:/#deb cdrom:/' /etc/apt/sources.list	  	 
  apt-get update >/dev/null 2>&1
  kill $jawsp
  wait $jawsp 2>/dev/null

  #  ---------------------------------------------------------------------------------
  #  Installation loop
  #  --------------------------------------------------------------------------------- 
  tput cup 17 5 
  mytitle="UBUNTU $ver - THE DIZWELL ORACLE PREINSTALLER";
  mysubtxt=" S O F T W A R E   D O W N L O A D  ";
  mybody1="Necessary software packages and libraries are being downloaded.";
  mybody2="This can take a long time, so please be patient...";
  jaws $mytitle $mysubtxt $mybody1 $mybody2 &
  jawsp=$!
  #  ---------------------------------------------------------------------------------
  #  If one package does not exist in a request to install a long list of them, apt
  #  will not install ANY of them. So, we have to treat the list of packages as an 
  #  array and install them one-by-one, by looping.
  #  ---------------------------------------------------------------------------------
  for pkg in unixodbc unixodbc-dev unzip  lsb-cxx pdksh sysstat gcc g++-multilib \
  ia32-libs ksh lesstif2 zlibc rpm libc6 libc6-dev libc6-dev-i386 libc6-i386 \
  gcc-multilib less lib32z1 libelf-dev binutils libodbcinstq4-1 libpth-dev zenity \
  libpthread-stubs0 libstdc++5 autotools-dev bzip2 elfutils g++ rlwrap libltdl-dev \
  libmotif4 libpthread-stubs0-dev build-essential expat gawk alien autoconf automake \
  lesstif2-dev make; do
	apt-get -y install $pkg >/dev/null 2>&1
	tput cup 17 5 
	echo "                                                     ";tput cup 17 5
	echo "Installing: "$pkg
  done

  tput cup 20 5;ln -s /lib/x86_64-linux-gnu/libgcc_s.so.1 /lib64/libgcc_s.so.1 >/dev/null 2>&1

  tput cup 17 5 
  echo "                                                     ";tput cup 17 5
  echo "Installing: older libaio libraries"
  wget http://ftp.us.debian.org/debian/pool/main/liba/libaio/libaio1_0.3.109-3_amd64.deb >/dev/null 2>&1
  dpkg -i libaio1_0.3.109-3_amd64.deb  >/dev/null 2>&1
  aptitude hold libaio1 >/dev/null 2>&1
  echo "libaio1 hold" | dpkg --set-selections >/dev/null 2>&1
  wget http://ftp.us.debian.org/debian/pool/main/liba/libaio/libaio-dev_0.3.109-3_amd64.deb >/dev/null 2>&1
  dpkg -i libaio-dev_0.3.109-3_amd64.deb >/dev/null 2>&1
  aptitude hold libaio-dev >/dev/null 2>&1
  echo "libaio-dev hold" | dpkg --set-selections >/dev/null 2>&1

  rm -f libaio*.deb >/dev/null 2>&1
  kill $jawsp
  wait $jawsp 2>/dev/null
#  ---------------------------------------------------------------------------------
#  Ubuntu will produce a compilation error once the Oracle 11g software 
#  installation is underway. This part of the script creates a shell script
#  in the oracle user's Documents directory which, if run, will add appropriate 
#  compiler switches to the various makefiles that will fix the problems, 
#  once a 'Retry' has been selected. 
#  ---------------------------------------------------------------------------------
mkdir -p /home/$ORACLEUSER/Documents/
cat >> /home/$ORACLEUSER/Documents/ubuntu-fixup.sh << EOF
#!/bin/bash
export ORACLE_HOME=/u01/app/oracle/product/$ORAPATH/db_1

sudo ln -s \$ORACLE_HOME/lib/libclntsh.core.so.12.1 /usr/lib
sudo ln -s \$ORACLE_HOME/lib/libclntsh.so.12.1 /usr/lib

cp \$ORACLE_HOME/rdbms/lib/ins_rdbms.mk \$ORACLE_HOME/rdbms/lib/ins_rdbms.bkp
cp \$ORACLE_HOME/rdbms/lib/env_rdbms.mk \$ORACLE_HOME/rdbms/lib/env_rdbms.bkp

sed -i 's/\$(ORAPWD_LINKLINE)/\$(ORAPWD_LINKLINE) -lnnz12/' \$ORACLE_HOME/rdbms/lib/ins_rdbms.mk
sed -i 's/\$(HSOTS_LINKLINE)/\$(HSOTS_LINKLINE) -lagtsh/' \$ORACLE_HOME/rdbms/lib/ins_rdbms.mk
sed -i 's/\$(EXTPROC_LINKLINE)/\$(EXTPROC_LINKLINE) -lagtsh/' \$ORACLE_HOME/rdbms/lib/ins_rdbms.mk
sed -i 's/\$(OPT) \$(HSOTSMAI)/\$(OPT) -Wl,--no-as-needed \$(HSOTSMAI)/' \$ORACLE_HOME/rdbms/lib/env_rdbms.mk
sed -i 's/\$(OPT) \$(HSDEPMAI)/\$(OPT) -Wl,--no-as-needed \$(HSDEPMAI)/' \$ORACLE_HOME/rdbms/lib/env_rdbms.mk
sed -i 's/\$(OPT) \$(EXTPMAI)/\$(OPT) -Wl,--no-as-needed \$(EXTPMAI)/' \$ORACLE_HOME/rdbms/lib/env_rdbms.mk
sed -i 's/^\(TNSLSNR_LINKLINE.*\$(TNSLSNR_OFILES)\) \(\$(LINKTTLIBS)\)/\1 -Wl,--no-as-needed \2/g' \$ORACLE_HOME/network/lib/env_network.mk
sed -i 's/\$(SPOBJS) \$(LLIBSERVER)/\$(SPOBJS) -Wl,--no-as-needed \$(LLIBSERVER)/' \$ORACLE_HOME/rdbms/lib/env_rdbms.mk
sed -i 's/\$(S0MAIN) \$(SSKFEDED)/\$(S0MAIN) -Wl,--no-as-needed \$(SSKFEDED)/' \$ORACLE_HOME/rdbms/lib/env_rdbms.mk
sed -i 's/\$(S0MAIN) \$(SSKFODED)/\$(S0MAIN) -Wl,--no-as-needed \$(SSKFODED)/' \$ORACLE_HOME/rdbms/lib/env_rdbms.mk
sed -i 's/\$(S0MAIN) \$(SSKFNDGED)/\$(S0MAIN) -Wl,--no-as-needed \$(SSKFNDGED)/' \$ORACLE_HOME/rdbms/lib/env_rdbms.mk
sed -i 's/\$(S0MAIN) \$(SSKFMUED)/\$(S0MAIN) -Wl,--no-as-needed \$(SSKFMUED)/' \$ORACLE_HOME/rdbms/lib/env_rdbms.mk
sed -i 's/^\(ORACLE_LINKLINE.*\$(ORACLE_LINKER)\) \($(PL_FLAGS)\)/\1 -Wl,--no-as-needed \2/g' \$ORACLE_HOME/rdbms/lib/env_rdbms.mk
sed -i 's/\$LD \$LD_RUNTIME/$LD -Wl,--no-as-needed \$LD_RUNTIME/' \$ORACLE_HOME/bin/genorasdksh
sed -i 's/\$(GETCRSHOME_OBJ1) \$(OCRLIBS_DEFAULT)/\$(GETCRSHOME_OBJ1) -Wl,--no-as-needed \$(OCRLIBS_DEFAULT)/' \$ORACLE_HOME/srvm/lib/env_srvm.mk

zenity --info --title "Fix-up Script Applied" --text="Click OK to return to the Oracle Installer, \nthen click the [Retry] option."

exit 0
EOF

chmod 775 /home/$ORACLEUSER/Documents/ubuntu-fixup.sh
fi

tput clear;tput sgr0;tput setaf 2;tput cup 3 5;tput smul
echo "UBUNTU $ver - THE DIZWELL ORACLE PREINSTALLER";tput rmul;tput cup 5 5;tput rev
echo " R E B O O T   R E Q U I R E D ";tput sgr0;tput cup 7 5;tput setaf $TEXTCOL
echo "To ensure the configuration changes made by this script take full";tput cup 8 5 
echo "effect, this PC will be rebooted as soon as you press Enter.";tput cup 10 5 
echo "When your PC comes back up, log on as '$ORACLEUSER' and launch the";tput cup 11 5 
echo "runInstaller.sh script from the Oracle software source of your choice.";tput cup 17 5;tput setaf 1;tput bold;tput rev
read -p "Press Enter to reboot..." RESP
reboot
exit 0
