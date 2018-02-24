#!/bin/bash - 
# -------------------------------------------------------
# Filename: byinit.sh
# Revision: 1.2
# Date: 2018/02/24
# Author: CHENC
# Description: init the new server
# -------------------------------------------------------

log='/tmp/init_sys.log'
installlog='/tmp/init_install.log'
baktime=$(date +"%Y%m%d_%H%M%S")
durl="http://119.147.149.194:9001/initdown"
duser="yunwei"
dpwd="master@2012"
zabbix_server='119.147.149.194,220.231.228.87'
zabbix_port='10050'
zabbix_serverhostname='ctos7'
[ -e "/home/tools/" ] || mkdir -p "/home/tools/"
[ -e "/tmp/initflag.log" ] || touch '/tmp/initflag.log'

clear
cat << EOF
#####################################################
#                                                   #
#        标越科技-服务器初始化脚本                  #
#                                                   #
#####################################################
EOF

yum install -y epel-release-6-8.noarch >> $installlog 2>&1
if [ $? == 0 ];then
  echo "epel install ok ..." |tee -a $log
else
  echo "epel install failed ..." |tee -a $log
fi

###　检查网络
echo "检查网络..."
ping -c 5 www.baidu.com >> $log 2>&1
if [ $? != 0 ];then
  echo "网络出现异常!"
  echo "DNS设置如下 :"
  cat /etc/resolv.conf
  echo "nameserver 223.5.5.5" > /etc/resolv.conf
  echo "nameserver 8.8.8.8" >> /etc/resolv.conf
else
  echo "--网络正常 ..."
fi
echo

### 删除网卡配置中的DNS设置
echo "查看网卡配置关闭DNS..."
for i in $(ls /etc/sysconfig/network-scripts/ifcfg-* |grep -v lo)
  do
    if [ $(cat $i |grep "DNS" |head -1) ];then
      sed -i '/DNS/d' $i
    fi
done
echo

### 优化VIM缩进为2个光标位
echo "优化VIM缩进为2个光标位"
wget --http-user=$duser --http-password=$dpwd $durl/vimrc -O /home/tools/vimrc >> $log 2>&1
cp /home/tools/vimrc /root/.vimrc
echo

### 检查GCC
echo "检查GCC"
for i in gcc gcc-c++ wget curl make
  do
    if [ -z "$(rpm -qa | egrep ^$i)" ];then
      yum -y install $i >> $installlog 2>&1
      if [ $? == 0 ];then
        echo "$i - Install OK ..." |tee -a $log
      else
        echo "$i - Install Failed !!" |tee -a $log
      fi
    else
      echo "$i - Installed !!" |tee -a $log
    fi
done
echo

### 设置系统字符集i18n
echo "设置系统字符集..."
file=/etc/sysconfig/i18n
echo > $file
echo 'LANG="en_US.UTF-8"' >>$file
echo 'SUPPORTED="zh_CN.GB18030:zh_CN:zh:en_US.UTF-8:en_US:en"'>>$file
echo 'SYSFONT="latarcyrheb-sun16"'>>$file
echo 'LC_ALL="en_US.UTF-8"'>>$file
echo 'export LC_ALL'>>$file
source /etc/sysconfig/i18n
if [ $? != 0 ];then
  echo "设置字符集环境变量失败..."
fi
echo

##########################################################################
#                               System部署                               #
##########################################################################
function sysinit {
clear
services=$(ls /etc/rc3.d/|grep S|cut -c 4-)
for i in $services
  do
    case $i in
      crond | sshd | syslog | irqbalance | network | messagebus | microcode_ctl | haldaemon | local | random | snmpd | rsyslog )
      echo "$i 为基础服务，开机自启动"
      ;;  
      *)
      
      chkconfig --level 35 $i off
      echo "关闭chkconfig $i 开机自启动服务" | tee -a $log > /dev/null 2>&1
      ;;
  esac
done
echo

### 初始化安装系统基础工具
echo "YUM: 安装基础工具 nc crontabs lsof ntp sysstat dstat tcpdump dmidecode chkrootkit iptraf glances rdate hdparm lshw lscpu lsscsi ipciutils fping telnet pigz iotop wget zip unzip vim lrzsz htop"
basetool=(nc crontabs lsof ntp sysstat dstat tcpdump dmidecode chkrootkit iptraf glances rdate hdparm lshw lscpu lsscsi ipciutils fping telnet pigz iotop wget zip unzip vim lrzsz htop)
for i in ${basetool[@]}
  do
    whereis $i |grep -E "bin|usr|etc" >/dev/null 2>&1
    if [ $? != 0 ];then
      yum -y install $i >> $installlog 2>&1
      if [ $? = 0 ];then
        echo "$i - Install OK ..." |tee -a $log
      else
        echo "$i - Install Faild !!" |tee -a $log
      fi
    else
      echo "$i - Installed !!" |tee -a $log
    fi
done
echo

### 初始化安装插件，如vim telnet lrzsz 等
echo "YUM: 安装插件 glibc.i686 libgcc.i686 libxml2.i686 compat-libstdc++-33.i686 bind-utils libxml2  ..."
plugin=(glibc.i686 libgcc.i686 libxml2.i686 compat-libstdc++-33.i686 bind-utils libxml2)
for i in ${plugin[@]}
  do
    if [ -z "$(rpm -qa | egrep ^$i)" ];then
      yum -y install $i >> $installlog 2>&1
      if [ $? = 0 ];then
        echo "$i - Install OK ..." |tee -a $log
      else
        echo "$i - Install Faild !!" |tee -a $log
      fi
    else
      echo "$i - Installed !!" |tee -a $log
    fi
done
echo

### 添加用户
echo "添加管理员普通用户"
user=(
'chenc'
'yery'
)

for i in ${user[*]}
  do
  if [ ! "$(cat /etc/passwd |grep $i)" ];then
    useradd $i |tee -a $log 2>&1
    echo $i@2015 |passwd --stdin $i |tee -a $log 2>&1
  fi
done
echo

### 设置中国时区
echo "设置中国时区(+0800)..."
timezone=$(date -R | awk '{print $NF}')
if test $timezone != "+0800";then
  echo "Change the tomezone to +0800" | tee -a $log
  mv /etc/localtime /etc/localtime_bak
  cp /usr/share/zoneinfo/Asia/Shanghai /etc/localtime
  echo ZONE=\"Asia/Shanghai\" > /etc/sysconfig/clock
fi
echo

### 同步时间
echo "ntpdate首次同步时间"
/usr/sbin/ntpdate 2.cn.pool.ntp.org  >> $log 2>&1
if [ $? = 0 ];then
  /sbin/hwclock -w >> $log 2>&1
else
  echo "更新时间失败..."
  /bin/ping -c 5 2.cn.pool.ntp.org
fi
echo

### 设置时间同步计划任务(ntpdate)
echo "设置时间同步计划任务(ntpdate) ..."
if [ ! -e /var/spool/cron/root ];then
  echo "50 23 * * * /usr/sbin/ntpdate 2.cn.pool.ntp.org && /sbin/hwclock -w" >> /var/spool/cron/root
else
  if [ ! "$(cat /var/spool/cron/root |grep ntpdate)" ];then
    echo "50 23 * * * /usr/sbin/ntpdate 2.cn.pool.ntp.org && /sbin/hwclock -w" >> /var/spool/cron/root
  fi
fi
echo

### 禁用SElinux
echo
echo "禁用SElinux..."
cp /etc/sysconfig/selinux /etc/sysconfig/selinux_$baktime
sed -i '/SELINUX/s/\(enforcing\|permissive\)/disabled/' /etc/sysconfig/selinux 
cp /etc/selinux/config /etc/selinux/config_$baktime
sed -i '/SELINUX/s/\(enforcing\|permissive\)/disabled/' /etc/selinux/config
setenforce 0
echo "[`date "+%Y-%m-%d %H:%M:%S"`]" selinux 关闭成功! | tee -a $log
echo

### 设置系统启动级别
echo 设置系统启动级别.....
runlevel=$(cat /etc/inittab | grep initdefault: | awk -F : '{print $2}')
if [ $runlevel != 3 ];then
  cp /etc/inittab /etc/inittab_$baktime
  sed -i "/initdefault:$/s/:$runlevel:/:3:/" /etc/inittab
fi
echo "[$(date +"%Y-%m-%d %H:%M:%S")] 设置启动进入命令行模式3..."  | tee -a $log
echo

### 修改系统打开文件数
echo "修改系统打开文件数..."
cp /etc/security/limits.conf /etc/security/limits.conf_$baktime
if [ "$(cat /etc/security/limits.conf | grep -v ^# | grep nofile.*400000)" ];then 
  echo "max open files has already set !!"
else
  sed -i '/# End of file/,$d' limits.conf 
cat >> /etc/security/limits.conf << EOF
* soft nproc 400000
* hard nproc 500000
* soft nofile 400000
* hard nofile 500000
EOF
 echo "[$(date "+%Y-%m-%d %H:%M:%S")]" 修改系统打开文件数为 50w ... | tee -a $log
fi

if [ "$(cat /etc/security/limits.d/90-nproc.conf |grep -v ^# |grep ^\*.*1024$)" ];then
  sed -i 's/1024/unlimited/g' /etc/security/limits.d/90-nproc.conf
fi
echo 

### 安装iftop - 流量监控
echo "安装iftop"
if [ "$(rpm -qa|egrep "^iftop")" ] || [ "$(ls /usr/local/sbin/iftop)" ];then
  echo "iftop 已经安装 ..."
else
  yum -y install flex byacc libpcap ncurses ncurses-devel libpcap-devel >> $installlog 2>&1
  yum -y install iftop >> $installlog 2>&1
  if [ $? == 0 ];then
    echo "iftop: yum install it ok ..."
  else
    echo "iftop: yum install it failed !!" |tee -a $log

    wget --http-user=$duser --http-password=$dpwd $durl/iftop-0.17-1.el5.rf.i386.rpm -O /home/tools/iftop-0.17-1.el5.rf.i386.rpm >> $log 2>&1
    yum -y localinstall /home/tools/iftop-0.17-1.el5.rf.i386.rpm >> $installlog 2>&1
    if [ $? == 0 ];then
      echo "iftop: yum localinstall it ok ..." |tee -a $log
    else
      echo "iftop: yum localinstall it failed !!" |tee -a $log
      wget --http-user=$duser --http-password=$dpwd $durl/iftop-0.17.tar.gz -O /home/tools/iftop-0.17.tar.gz >> $log 2>&1
      cd /home/tools && tar -xzvf iftop-0.17.tar.gz
      cd iftop-0.17
      ./configure >> $installlog 2>&1
      if [  $? == 0 ];then
        make >> $installlog 2>&1
        if [ $? == 0 ];then
          make install >> $installlog 2>&1
          if [ $? == 0 ];then
            echo "iftop: 编译安装成功 ..." |tee -a $log
          else
            echo "iftop: 编译安装失败 !!" |tee -a $log
          fi
        else
          echo "iftop make 失败 !!" |tee -a $log
        fi
      else
        echo "iftop configure 失败 !!" |tee -a $log
      fi
    fi
  fi
fi
echo

### 系统安全配置修改
echo "开始配置系统安全..."
echo "open syncookies..."
## 开启SYN Cookies。当出现SYN等待队列溢出时，启用cookies来处理，可防范少量SYN攻击，默认为0，表示关闭
[ "$(cat /etc/sysctl.conf |grep net.ipv4.tcp_syncookies)" ] || echo "net.ipv4.tcp_syncookies = 1" >> /etc/sysctl.conf
echo

echo "set TMOUT to 3600..."
## 输入空闲超时断开连接
[ "$(cat /etc/profile |grep TMOUT)" ] || echo "TMOUT=3600" >> /etc/profile
for i in /usr/bin/which /usr/bin/gcc /usr/bin/make /bin/rpm /usr/bin/locate /usr/bin/whereis
  do
    if [ -e $i ]
      then chmod 700 $i
      echo "set 700 $i"
    fi
done
echo

for i in xfs news nscd dbus vcsa games avahi haldaemon gopher ftp mailnull pcap mail shutdown halt uucp sync adm lp
  do
    if [ "$(cat /etc/passwd |awk -F : '{print $1}' |grep $i)" ];then 
      passwd -l $i >> $log
      echo "lock user $i"
    fi
done
echo
}
#sysinit


##########################################################################
#                               SSH部署                                  #
##########################################################################
function ssh {
echo Backup sshd_config...
cp /etc/ssh/sshd_config /etc/ssh/sshd_config_$baktime
echo Modify ssh port to 61122....
sed -i '/#Port 22/s/#Port 22/Port 61122/' /etc/ssh/sshd_config
echo Forbid root remote login....
sed -i '/#PermitRootLogin yes/s/#PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
echo Set MaxAuthTries to 3....
sed -i '/#MaxAuthTries/s/#Max/Max/' /etc/ssh/sshd_config
echo Disable dns....
sed -i '/#UseDNS/s/#UseDNS yes/UseDNS no/' /etc/ssh/sshd_config 

echo restart ssh server....
service sshd restart >> $log 2>&1
echo "[$(date "+%Y-%m-%d %H:%M:%S")]" The ssh configure complete! |tee -a $log
cat /dev/null > /etc/motd
}
#ssh


##########################################################################
#                               配置主机名                               #
##########################################################################
function set_hostname {
lanip=$(ifconfig |grep -A 1 -E "eth0|em1|em4|band0|ppp0" |grep "inet addr" |awk '{print $2}' |awk -F ':' '{print $2}' |head -1)
wlanip=$(ifconfig |grep -A 1 -E "eth1|em2|em3|band1|ppp0" |grep "inet addr" |awk '{print $2}' |awk -F ':' '{print $2}' |head -1)
echo "开始配置主机名..."
echo
echo "获取当前IP信息 :"
echo LAN_IP : $lanip
echo WLAN_IP : $wlanip
echo -n "请输入主机名 : "
read hname
until [[ ! -z "$hname" ]]
  do
    echo -n "请输入主机名 : "
    read hname
done
	
profile="/etc/sysconfig/network"
hostname=$(cat $profile |grep HOSTNAME |awk -F '=' '{print $2}')
sed -i "/HOSTNAME/s/$hostname/$hname/g" $profile
hostname $hname
echo "$lan $hname" >>/etc/hosts
}
#hostname


##########################################################################
#                               Install_zabbixagent                      #
##########################################################################
function install_zabbixagent {
wget --http-user=$duser --http-password=$dpwd $durl/install_zabbixagent.tar.gz -O /home/tools/install_zabbixagent.tar.gz |tee -a  $log 2>&1
if [ ! "$(cat /etc/passwd|grep zabbix)" ];then
  groupadd zabbix
  useradd -g zabbix -s /sbin/nologin -M zabbix |tee -a $log
  if [ $? = 0 ];then
    echo "add user zabbix ok ..." |tee -a $log
  else
    echo "add user zabbix failed !!" |tee -a $log
  fi
else
  echo "user zabbix already exsits !!"
fi

tools=(
'net-snmp-devel'
)

for i in ${tools[*]}
 do
    rpm -qa |grep ^"$i" > /dev/null 2>&1
    if [ -z "$(rpm -qa |grep ^$i)" ];then
      yum install -y $i >> $installlog 2>&1
      if [ $? == 0 ];then
        echo "$i: yum install it ok ..." |tee -a $log
      else
        echo "$i: yum install it failed !!" |tee -a $log
      fi
    else
      echo "$i: Package already installed and latest version !!" |tee -a $log
    fi
done

cd /home/tools && tar -xf install_zabbixagent.tar.gz && cd install_zabbixagent && tar -xf zabbix-3.2.1.tar.gz
cd zabbix-3.2.1
./configure \
  --prefix=/usr/local/zabbix \
  --enable-agent >> $installlog 2>&1
  if [ $? = 0 ];then
    echo "zabbix_agent: configure成功 ..." |tee -a $log
    make >> $installlog 2>&1
      if [ $? = 0 ];then
        echo "zabbix_agent: make成功 ..." |tee -a $log
        make install >> $installlog 2>&1
        if [ $? = 0 ];then
          echo "zabbix_agent: 编译安装成功 ..." |tee -a $log
          \cp ./misc/init.d/fedora/core/zabbix_agentd /etc/init.d/
          sed -i 's/BASEDIR=\/usr\/local/BASEDIR=\/usr\/local\/zabbix/g' /etc/init.d/zabbix_agentd
          [ -e "/var/run/zabbix" ] || mkdir -pv "/var/run/zabbix"
          [ -e "/var/log/zabbix" ] || mkdir -pv "/var/log/zabbix"
          chown zabbix.zabbix -R /var/run/zabbix
          chown zabbix.zabbix -R /var/log/zabbix
cat > /usr/local/zabbix/etc/zabbix_agentd.conf <<EOF
PidFile=/var/run/zabbix/zabbix_agentd.pid
LogFile=/var/log/zabbix/zabbix_agentd.log
Server=$zabbix_server
ServerActive=$zabbix_server_active
ListenPort=$zabbix_port
Hostname=${zabbix_serverhostname}
UnsafeUserParameters=1
AllowRoot=1
EnableRemoteCommands=1
RefreshActiveChecks=60
LogRemoteCommands=1
StartAgents=10
Timeout=30
RefreshActiveChecks=120
BufferSize=300
BufferSend=15
EOF
          chkconfig --add zabbix_agentd
          chkconfig zabbix_agentd on
        else
          echo "zabbix_agent: 编译安装失败 !!" |tee -a $log
          rm -rf ./zabbix-3.2.1
        fi
      else
        echo "zabbix_agent: make失败 !!" |tee -a $log
        rm -rf ./zabbix-3.2.1
      fi
  else
    echo "zabbix_agent: configure失败 !!" |tee -a $log
    rm -rf ./zabbix-3.2.1
  fi
hash -r
}
#zabbix_agent


##########################################################################
#                               配置java环境                             #
##########################################################################
function Configure_Java_Environment {
wget --http-user=$duser --http-password=$dpwd $durl/java.zip -O /home/tools/java.zip |tee -a $log 2>&1
if [ $? = 0 ];then
  cd /home/tools && unzip -q java.zip && cp -r java /usr/
  echo >> /etc/profile

cat >> /etc/profile << EOF
# MOD PATH
export PATH=/usr/local/sbin:\$PATH

# SET JAVA ENVIRONMENT
export JAVA_HOME=/usr/java/jdk
export CLASSPATH=.:\$JAVA_HOME/lib/dt.jar:\$JAVA_HOME/lib/tools.jar
export PATH=\$JAVA_HOME/bin:\$PATH
EOF

fi	
}
#java environment


##########################################################################
#                               安装Nginx                                #
##########################################################################
function install_nginx {
wget --http-user=$duser --http-password=$dpwd $durl/install_ngx.tar.gz -O /home/tools/install_ngx.tar.gz |tee -a $log 2>&1
if [ -z "$(cat /etc/passwd |grep nginx)" ];then
  NGTOOLS=(epel-release patch pcre pcre-devel openssl openssl-devel gcc-c++ autoconf automake zlib-devel httpd-tools)
  for i in ${NGTOOLS[@]}
   do
    yum install $i -y
    if [ $? = 0 ];then
      yum install ok - $i
    else
      yum install failed - $i
    fi
  done

  cd /home/tools && tar -xzf nginx-1.12.1.tar.gz
  unzip -q nginx_upstream_check_module-master.zip

  /usr/bin/chattr -i /etc/passwd /etc/shadow /etc/group /etc/gshadow
  userdel -fr nginx > /dev/null 2>&1
  useradd -M -s /sbin/nologin nginx

  cd nginx-1.12.1
  patch -p1 < ../nginx_upstream_check_module-master/check_1.12.1+.patch
  ./configure --prefix=/usr/local/nginx --with-stream --with-http_secure_link_module --with-http_stub_status_module --add-module=../nginx_upstream_check_module-master
  if [ $? = 0 ];then
    echo "configure OK ..."
    make
    if [ $? = 0 ];then
      echo "make OK ..."
      make install
      if [ $? = 0 ];then
        echo "install OK ..."
        ln -s /usr/local/nginx/sbin/nginx /usr/sbin/nginx
      else
        echo "install Failed !! Exit ..."
      fi
    else
      echo "make Failed !! Exit ..."
    fi
  else
    echo "configure Failed !! Exit ..."
  fi
fi
}
# install_ngx

##########################################################################
#                               退出初始化脚本                           #
##########################################################################
function quit {
if [ -z "$(cat /tmp/initflag.log |grep ok)" ];then
  echo "停止开机启动项运行..."
  for i in dnsmasq smartd avahi-daemon avahi-dnsconfd NetworkManager oddjobd yum-updatesd anacron atd conman saslauthd cups dc_server psacct rrdcached tcsd xfs dc_client gpm httpd svnserve nfs irda squid sendmail smb winbind mysqld rawdevices ibmasm netconsole snmptrapd tux vsftpd rpcsvcgssd autofs ypbind acpid apmd nscd ntpd netfs mdmonitor mdmpd rpcgssd rpcidmapd nfslock mcstrans multipathd portmap restorecond auditd pcscd wpa_supplicant dund hidd netplugd pand rdisc bluetooth capi isdn ip6tables iptables firstboot kudzu cpuspeed lvm2-monitor readahead_early readahead_later postfix named rpcbind qpidd
    do
      /etc/init.d/$i stop >> $log 2>&1
  done

  echo "禁用开机启动项运行..."
  for i in dnsmasq smartd avahi-daemon avahi-dnsconfd NetworkManager oddjobd yum-updatesd anacron atd conman saslauthd cups dc_server psacct rrdcached tcsd xfs dc_client gpm httpd svnserve nfs irda squid sendmail smb winbind mysqld rawdevices ibmasm netconsole snmptrapd tux vsftpd rpcsvcgssd autofs ypbind acpid apmd nscd ntpd netfs mdmonitor mdmpd rpcgssd rpcidmapd nfslock mcstrans multipathd portmap restorecond auditd pcscd wpa_supplicant dund hidd netplugd pand rdisc bluetooth capi isdn ip6tables iptables firstboot kudzu cpuspeed lvm2-monitor readahead_early readahead_later postfix named rpcbind qpidd
    do
      /sbin/chkconfig --level 3 $i off >> $log 2>&1
  done
  
  service postfix stop >> $log 2>&1
  echo "ok" > /tmp/initflag.log
  echo "关闭passwd shadow group修改权限..."
  echo
  if [ -z "$(cat /var/spool/cron/root|grep /usr/bin/chattr)" ];then
    echo "0 */1 * * * /usr/bin/chattr +i /etc/passwd /etc/shadow /etc/group /etc/gshadow" >> /var/spool/cron/root
  fi

  iptables -P INPUT ACCEPT
  iptables -F
  iptables -X
  /etc/init.d/iptables save >/dev/null

  echo "更改了系统时区，请重启系统..."
  echo "更改了系统时区，请重启系统..."
  echo "更改了系统时区，请重启系统..."
  echo "清空iptables..."
  echo
  break
else
  break
fi
}
#quit


clear
while [ 1 ]
 do
cat << EOF
#####################################################
# Mean: A B C 为必须安装选项                        #
#   A: Init system                                  #
#   B: Configure ssh                                #
#   C: Configure Hostname                           #
#   D: Install Zabbix_agent                         #
#   J: Configure jdk1.7                             #
#   N: Install Nginx 1.21.1                         #
#   Q: Quit                                         #
#####################################################
EOF

read -e -p "Please enter option:" option
echo

case $option in
  A|a)
    sysinit
    ;;
  B|b)
    ssh
    ;;
  C|c)
    set_hostname
    ;;
  D|d)
    install_zabbixagent
    ;;
  J|j)
    Configure_Java_Environment
    ;;
  N|n)
    install_nginx
    ;;
  Q|q)
    quit
    ;;
  *)
  echo "Error input"
  ;;
esac

echo -n "Hit any key to continue..."
read -n 1 line
clear
done
