# -*- coding:utf-8 -*- -
import os
import re
import time
import psutil
import yara
import sys
import socket
import struct
import prettytable as pt
import argparse


# 检查是否root运行
def checkroot():
    if os.popen("whoami").read() != 'root\n':
        print('[\033[1;33mwaring\033[0m]检测到当前为非root权限，部分功能可能受限哦~')

def system_state():  # 系统状态
    cpu = '{}{}'.format(str(psutil.cpu_percent(1)), '%')
    mem = '{}{}'.format(str(psutil.virtual_memory()[2]), '%')
    disk = '{}{}'.format(psutil.disk_usage('/')[3], '%')
    login=os.popen("who").read()
    system_state = pt.PrettyTable()
    system_state.field_names = ['CPU', 'MEM', 'DISK','ONLINE']
    system_state.add_row([cpu, mem, disk,login.replace('    ',' ').replace('   ',' ')])
    return system_state

########查外连模块#############
class CzIp:  # 读取解析纯真IP数据库的类
    def __init__(self, db_file='config/qqwry.dat'):
        self.f_db = open(db_file, "rb")
        bs = self.f_db.read(8)
        (self.first_index, self.last_index) = struct.unpack('II', bs)
        self.index_count = int((self.last_index - self.first_index) / 7 + 1)
        self.cur_start_ip = None
        self.cur_end_ip_offset = None
        self.cur_end_ip = None

    def _get_area_addr(self, offset=0):
        if offset:
            self.f_db.seek(offset)
        bs = self.f_db.read(1)
        (byte,) = struct.unpack('B', bs)
        if byte == 0x01 or byte == 0x02:
            p = self.getLong3()
            if p:
                return self.get_offset_string(p)
            else:
                return ""
        else:
            self.f_db.seek(-1, 1)
            return self.get_offset_string(offset)

    def _get_addr(self, offset):
        '''
        获取offset处记录区地址信息(包含国家和地区)
        如果是中国ip，则是 "xx省xx市 xxxxx地区" 这样的形式
        (比如:"福建省 电信", "澳大利亚 墨尔本Goldenit有限公司")
        :param offset:
        :return:str
        '''
        self.f_db.seek(offset + 4)
        bs = self.f_db.read(1)
        (byte,) = struct.unpack('B', bs)
        if byte == 0x01:  # 重定向模式1
            country_offset = self.getLong3()
            self.f_db.seek(country_offset)
            bs = self.f_db.read(1)
            (b,) = struct.unpack('B', bs)
            if b == 0x02:
                country_addr = self.get_offset_string(self.getLong3())
                self.f_db.seek(country_offset + 4)
            else:
                country_addr = self.get_offset_string(country_offset)
            area_addr = self._get_area_addr()
        elif byte == 0x02:  # 重定向模式2
            country_addr = self.get_offset_string(self.getLong3())
            area_addr = self._get_area_addr(offset + 8)
        else:  # 字符串模式
            country_addr = self.get_offset_string(offset + 4)
            area_addr = self._get_area_addr()
        return country_addr + " " + area_addr

    def dump(self, first, last):
        '''
        打印数据库中索引为first到索引为last(不包含last)的记录
        :param first:
        :param last:
        :return:
        '''
        if last > self.index_count:
            last = self.index_count
        for index in range(first, last):
            offset = self.first_index + index * 7
            self.f_db.seek(offset)
            buf = self.f_db.read(7)
            (ip, of1, of2) = struct.unpack("IHB", buf)
            address = self._get_addr(of1 + (of2 << 16))

    def _set_ip_range(self, index):
        offset = self.first_index + index * 7
        self.f_db.seek(offset)
        buf = self.f_db.read(7)
        (self.cur_start_ip, of1, of2) = struct.unpack("IHB", buf)
        self.cur_end_ip_offset = of1 + (of2 << 16)
        self.f_db.seek(self.cur_end_ip_offset)
        buf = self.f_db.read(4)
        (self.cur_end_ip,) = struct.unpack("I", buf)

    def get_addr_by_ip(self, ip):
        '''
        通过ip查找其地址
        :param ip: (int or str)
        :return: str
        '''
        if type(ip) == str:
            ip = self.str2ip(ip)
        L = 0
        R = self.index_count - 1
        while L < R - 1:
            M = int((L + R) / 2)
            self._set_ip_range(M)
            if ip == self.cur_start_ip:
                L = M
                break
            if ip > self.cur_start_ip:
                L = M
            else:
                R = M
        self._set_ip_range(L)
        # version information, 255.255.255.X, urgy but useful
        if ip & 0xffffff00 == 0xffffff00:
            self._set_ip_range(R)
        if self.cur_start_ip <= ip <= self.cur_end_ip:
            address = self._get_addr(self.cur_end_ip_offset)
        else:
            address = "未找到该IP的地址"
        return address

    def get_ip_range(self, ip):
        '''
        返回ip所在记录的IP段
        :param ip: ip(str or int)
        :return: str
        '''
        if type(ip) == str:
            ip = self.str2ip(ip)
        self.get_addr_by_ip(ip)
        range = self.ip2str(self.cur_start_ip) + ' - ' \
                + self.ip2str(self.cur_end_ip)
        return range

    def get_offset_string(self, offset=0):
        '''
        获取文件偏移处的字符串(以'\0'结尾)
        :param offset: 偏移
        :return: str
        '''
        if offset:
            self.f_db.seek(offset)
        bs = b''
        ch = self.f_db.read(1)
        (byte,) = struct.unpack('B', ch)
        while byte != 0:
            bs += ch
            ch = self.f_db.read(1)
            (byte,) = struct.unpack('B', ch)
        return bs.decode('gbk')

    def ip2str(self, ip):
        '''
        整数IP转化为IP字符串
        :param ip:
        :return:
        '''
        return str(ip >> 24) + '.' + str((ip >> 16) & 0xff) + '.' + str((ip >> 8) & 0xff) + '.' + str(ip & 0xff)

    def str2ip(self, s):
        '''
        IP字符串转换为整数IP
        :param s:
        :return:
        '''
        (ip,) = struct.unpack('I', socket.inet_aton(s))
        return ((ip >> 24) & 0xff) | ((ip & 0xff) << 24) | ((ip >> 8) & 0xff00) | ((ip & 0xff00) << 8)

    def getLong3(self, offset=0):
        '''
        3字节的数值
        :param offset:
        :return:
        '''
        if offset:
            self.f_db.seek(offset)
        bs = self.f_db.read(3)
        (a, b) = struct.unpack('HB', bs)
        return (b << 16) + a


def network():  # 获取对外网络连接情况
    addr_list = str(psutil.net_connections()).split('sconn')
    iptb = pt.PrettyTable()
    iptb.field_names = ['进程名', 'IP', '端口', 'PID', '归属地址']
    for addr in addr_list:
        try:
            if re.findall(r'raddr', addr) != []:  # 如果存在远程地址，就取出来
                remote = addr.split('raddr')[-1]
                local = addr.split('laddr')[-1]
                ip = re.findall(r'ip=\'(.+?)\'', remote)[0]
                port = re.findall(r'port=(.+?)\)', local)[0]
                pid = re.findall(r'pid=(.+?)\)', remote)[0]
                process = psutil.Process(int(pid)).name()
                if ip != '127.0.0.1' and ip != '::1':
                    IP_addr = CzIp().get_addr_by_ip(ip)
                    iptb.add_row([process, ip, port, pid, IP_addr])
        except:
            pass
    network = iptb
    return network


################日志分析模块#####################
def ostype():  # 判断系统类型和版本
    try:
        os_info = os.popen("cat /proc/version").read()
        sysnum = int(re.findall(r' (\d+?)\.', os_info, re.S)[0])  # 取出版本号
        system = ''
        try:
            system = re.search('CentOS', os_info).group()
        except:
            pass
        try:
            system = re.search('Ubuntu', os_info).group()
        except:
            pass
        try:
            system = re.search('openSUSE', os_info).group()
        except:
            pass
        try:
            system = re.search('Red Hat', os_info).group()
        except:
            pass
        try:
            system = re.search('Debian', os_info).group()
        except:
            pass
    except:
        print('\033[1;33m提示：系统类型获取失败，请手动输入系统类型和版本号\033[0m')
        print("\033[1;33m系统类型只能'CentOS'，'Ubuntu'，'openSUSE'，'Red Hat'，'Debian' 其中一个，注意空格和大小写，输入其他无效\033[0m")
        print("\033[1;33m版本号请输入整数，如：6\033[0m")
        system = input('系统类型：')
        sysnum = int(input('版本号：'))
    return system, sysnum


def pid_fileinfo(pid):  # 根据pid获取进程路径等信息
    fileinfo = os.popen("ls -all /proc/{} |grep \"exe ->\"".format(pid)).read()
    return fileinfo

def log_burp_ip(system):  # 定位有哪些IP在爆破
    burp_ip = ""
    if system == 'CentOS' or system == 'Red Hat':
        burp_ip = os.popen(
            "grep \"Failed\" /var/log/secure*|grep -E -o \"(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\"|uniq -c").read()
    elif system == 'Ubuntu' or system == 'Debian':
        burp_ip = os.popen(
            "grep \"Failed\" /var/log/auth.log*|grep -E -o \"(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\"|uniq -c").read()
    elif system == 'openSUSE':
        burp_ip = os.popen(
            "grep \"Failed\" /var/log/messages*|grep -E -o \"(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\"|uniq -c").read()
    return burp_ip


def log_burp_user(system):  # 被爆破用户名是什么
    burp_user = ''
    if system == 'CentOS' or system == 'Red Hat':
        burp_user = os.popen(
            "grep \"Failed\" /var/log/secure*|perl -e 'while($_=<>){ /for(.*?) from/; print \"$1\n\";}'|uniq -c|sort -nr").read()
    elif system == 'Ubuntu' or system == 'Debian':
        burp_user = os.popen(
            "grep \"Failed\" /var/log/auth.log*|perl -e 'while($_=<>){ /for(.*?) from/; print \"$1\n\";}'|uniq -c|sort -nr").read()
    elif system == 'openSUSE':
        burp_user = os.popen(
            "grep \"Failed\" /var/log/messages*|perl -e 'while($_=<>){ /for(.*?) from/; print \"$1\n\";}'|uniq -c|sort -nr").read()
    return burp_user


def log_success_ip(system):  # 登录成功的 IP 有哪些
    success_ip = ''
    if system == 'CentOS' or system == 'Red Hat':
        success_ip = os.popen(
            "grep \"Accepted \" /var/log/secure* | awk '{print $11}' | sort | uniq -c | sort -nr | more").read()
    elif system == 'Ubuntu' or system == 'Debian':
        success_ip = os.popen(
            "grep \"Accepted \" /var/log/auth.log* | awk '{print $11}' | sort | uniq -c | sort -nr | more").read()
    elif system == 'openSUSE':
        success_ip = os.popen(
            "grep \"Accepted \" /var/log/messages* | awk '{print $11}' | sort | uniq -c | sort -nr | more").read()
    return success_ip


def log_success_info(system):  # 登录成功的日期、用户名、IP
    success_info = ''
    if system == 'CentOS' or system == 'Red Hat':
        success_info = os.popen("grep \"Accepted \" /var/log/secure* | awk '{print $1,$2,$3,$9,$11}'").read()
    elif system == 'Ubuntu' or system == 'Debian':
        success_info = os.popen("grep \"Accepted \" /var/log/auth.log* | awk '{print $1,$2,$3,$9,$11}'").read()
    elif system == 'openSUSE':
        success_info = os.popen("grep \"Accepted \" /var/log/messages* | awk '{print $1,$2,$3,$9,$11}'").read()
    return success_info


def cron():  # 所有用户的定时任务
    cmd = os.popen("cd /var/spool/cron && ls").read()  # 直接到定时任务保存的位置看有没有
    timingtask_list = re.split(r'\n', cmd)
    del (timingtask_list[-1])  # 删除最后一个空值
    if timingtask_list != []:
        all_timingtask = ''
        for user in timingtask_list:
            path = "cat /var/spool/cron/{0}".format(user)
            info = os.popen(path).read()
            timingtask = '\033[1;33m用户【{0}】的定时任务有：\033[0m\n{1}\n'.format(user, info)
            all_timingtask = all_timingtask + timingtask
    else:
        all_timingtask = '\033[1;33m没有定时任务\033[0m'
    return all_timingtask


def cron_file(day):  # 按时间检查crontab文件或脚本
    cron.d = os.popen("find /etc/cron.d/ -mtime -{}".format(day)).read()
    cron.hourly = os.popen("find /etc/cron.hourly/ -mtime -{}".format(day)).read()
    cron.daily = os.popen("find /etc/cron.daily/ -mtime -{}".format(day)).read()
    cron.weekly = os.popen("find /etc/cron.weekly/ -mtime -{}".format(day)).read()
    cron.monthly = os.popen("find /etc/cron.monthly/ -mtime -{}".format(day)).read()
    cron_file_output = "\033[1;33m------------------------------/etc/cron.d/-------------------------------\033[0m\n{}\n\033[1;33m---------------------------/etc/cron.hourly/-----------------------------\033[0m\n{}\n\033[1;33m----------------------------/etc/cron.daily/-----------------------------\033[0m\n{}\n\033[1;33m---------------------------/etc/cron.weekly/-----------------------------\033[0m\n{}\n\033[1;33m---------------------------/etc/cron.monthly/----------------------------\033[0m\n{}\n".format(
        cron.d, cron.hourly, cron.daily, cron.weekly, cron.monthly)
    return cron_file_output


def starup(day):  # 按检查启动项
    rc_local = os.popen("cat /etc/rc.local").read()
    init_d = os.popen("find /etc/init.d/ -mtime -{}".format(day)).read()
    rc0_d = os.popen("find /etc/rc0.d/ -mtime -{}".format(day)).read()
    rc1_d = os.popen("find /etc/rc1.d/ -mtime -{}".format(day)).read()
    rc2_d = os.popen("find /etc/rc2.d/ -mtime -{}".format(day)).read()
    rc3_d = os.popen("find /etc/rc3.d/ -mtime -{}".format(day)).read()
    rc4_d = os.popen("find /etc/rc4.d/ -mtime -{}".format(day)).read()
    rc5_d = os.popen("find /etc/rc5.d/ -mtime -{}".format(day)).read()
    rc6_d = os.popen("find /etc/rc6.d/ -mtime -{}".format(day)).read()
    rc_d = os.popen("find /etc/init/rc.d/ -mtime -{}".format(day)).read()
    starup_output = "\033[1;33m------------------------------/etc/rc.local------------------------------\033[0m\n{}\n\033[1;33m-------------------------------/etc/init.d/------------------------------\033[0m\n{}\n\033[1;33m-------------------------------/etc/rc0.d/-------------------------------\033[0m\n{}\n\033[1;33m-------------------------------/etc/rc1.d/-------------------------------\033[0m\n{}\n\033[1;33m-------------------------------/etc/rc2.d/-------------------------------\033[0m\n{}\n\033[1;33m-------------------------------/etc/rc3.d/-------------------------------\033[0m\n{}\n\033[1;33m-------------------------------/etc/rc4.d/-------------------------------\033[0m\n{}\n\033[1;33m-------------------------------/etc/rc5.d/-------------------------------\033[0m\n{}\n\033[1;33m-------------------------------/etc/rc6.d/-------------------------------\033[0m\n{}\n\033[1;33m-----------------------------/etc/init/rc.d/-----------------------------\033[0m\n".format(
        rc_local, init_d, rc0_d, rc1_d, rc2_d, rc3_d, rc4_d, rc5_d, rc6_d, rc_d)
    return starup_output

def osfile(day):#查看系统进程是否被劫持
    osfile=os.popen("find /usr/bin/ /usr/sbin/ /bin/ /usr/local/bin/ -mtime -{}".format(day)).read()
    return osfile

def changefile(all):#查看系统中指定类型文件的修改
    changefile=os.popen("find {} -mtime -{} -name \"*.{}\"".format(all[0],all[1],all[2])).read()
    return changefile

def permfile(all):#查看系统中指定权限的文件
    permfile=os.popen("find {} -name \"*.{}\" -perm {}".format(all[0],all[1],all[2])).read()
    return permfile

def account_check():  # 检查账户情况
    account_list = []
    cmd = os.popen("cat /etc/passwd | grep '/bin/bash'").read()
    user_list = re.split(r'\n', cmd)[:-1]
    result=''
    for i in user_list:
        user=re.findall('(.+?):',i)[0]
        account_list.append(user)
        user_info=os.popen("chage --list {}".format(user)).read().replace(' ','')
        result+="\033[1;33m可登录的账户：\033[0m{0}\n\033[1;33m账户详情：\033[0m\n{1}\n".format(user,user_info)

    anonymous_account = os.popen("awk -F: 'length($2)==0 {print $1}' /etc/shadow").read()
    account = '{0}\n\033[1;33m空口令用户：\033[0m\n{1}\n'.format(result, anonymous_account)
    return account_list,account

def history():
    history=""
    user_list=account_check()[0]
    try:
        for user in user_list:
            if user!='root':
                minggan=os.popen("cat /home/{}/.bash_history |grep -E \"wget|curl|http|rsync|sftp|ssh|scp|rcp|python|java|chmod|ftp|bash｜zip|tar\"".format(user)).read()
                history+="\033[1;33m{}用户下的敏感历史命令：\033[0m\n{}\n".format(user,minggan)
            else:
                minggan = os.popen("cat /root/.bash_history |grep -E \"wget|curl|http|rsync|sftp|ssh|scp|rcp|python|java|chmod|ftp|bash｜zip|tar\"").read()
                history += "\033[1;33m{}用户下的敏感历史命令：\033[0m\n{}\n".format(user, minggan)
    except:
        pass
    return history

def webshell_scan(path):
    webshell = pt.PrettyTable()
    webshell.field_names = ['Path', 'LastChange']
    webshell.align["Path"] = "l"  # 路径字段靠右显示
    rule = yara.compile(filepath=r'rules/webshell.yar')
    print('\033[1;34m读取待检测文件中...\033[0m')
    all = os.popen("find " + path).read().split('\n')
    file_list = []  # 过滤后的文件列表
    print('\033[1;32m读取完毕，开始过滤...\033[0m')
    for file in all:  # 过滤掉部分文件
        try:
            fsize = os.path.getsize(file) / float(1024 * 1024)
        except:
            fsize = 6
        if fsize <= 5:  # 只检测小于5M的文件
            file_list.append(file)
    print('\033[1;32m过滤完毕，开始扫描...\033[0m')
    for i in range(len(file_list)):
        sys.stdout.write('\033[K' + '\r')
        print('\r','[{0}/{1}]检测中,耐心等待哦~'.format(str(i), str(len(file_list))),end=' ')
        try:
            with open(file_list[i], 'rb') as f:
                matches = rule.match(data=f.read())
        except:
            matches = []
        try:
            if matches != []:
                time_chuo = time.localtime(os.path.getmtime(file_list[i]))  # 最后修改时间戳
                lasttime = time.strftime("%Y--%m--%d %H:%M:%S", time_chuo)  # 最后修改时间
                warning = ('\033[1;31m\n告警：检测到标签{0}，文件位置{1}\033[0m'.format(matches, file_list[i]))
                webshell.add_row([file_list[i], lasttime])
                print(warning)
        except:
            pass
    print('\033[1;32m\n所有文件扫描完成，结果如下：\n\033[0m')
    print(webshell)

def file_scan(path):
    webshell = pt.PrettyTable()
    webshell.field_names = ['Path', 'LastChange']
    webshell.align["Path"] = "l"  # 路径字段靠右显示
    rule = yara.compile(filepath=r'rules/xunjian.yar')
    print('\033[1;34m读取待检测文件中...\033[0m')
    all = os.popen("find " + path).read().split('\n')
    file_list = []  # 过滤后的文件列表
    print('\033[1;32m读取完毕，开始过滤...\033[0m')
    for file in all:  # 过滤掉部分文件
        try:
            fsize = os.path.getsize(file) / float(1024 * 1024)
        except:
            fsize = 6
        if fsize <= 5:  # 只检测小于5M的文件
            file_list.append(file)
    print('\033[1;32m过滤完毕，开始扫描...\033[0m')
    for i in range(len(file_list)):
        sys.stdout.write('\033[K' + '\r')
        print('\r','[{0}/{1}]检测中,耐心等待哦~'.format(str(i), str(len(file_list))),end=' ')
        try:
            with open(file_list[i], 'rb') as f:
                matches = rule.match(data=f.read())
        except:
            matches = []
        try:
            if matches != []:
                time_chuo = time.localtime(os.path.getmtime(file_list[i]))  # 最后修改时间戳
                lasttime = time.strftime("%Y--%m--%d %H:%M:%S", time_chuo)  # 最后修改时间
                warning = ('\033[1;31m\n告警：检测到标签{0}，文件位置{1}\033[0m'.format(matches, file_list[i]))
                webshell.add_row([file_list[i], lasttime])
                print(warning)
        except:
            pass
    print('\033[1;32m\n所有文件扫描完成，结果如下：\n\033[0m')
    print(webshell)

################################################
parser = argparse.ArgumentParser(description='本工具可帮你快速定位很多关键问题，将化复杂繁琐的命令为简单。\n应急响应工具为辅，但不要只依赖于工具哦')
parser.add_argument("-user", action='store_true',help='用于查看系统可登录账户和空口令账户（无参数）')
parser.add_argument("-history", action='store_true',help='用于查看所有用户的敏感历史命令（无参数）')
parser.add_argument("-cron", action='store_true',help='用于查看所有用户的定时任务（无参数）')
parser.add_argument("-ip", action='store_true',help='用于查看外连ip（无参数）')
parser.add_argument("--pid", type=str,metavar='1234',help='用于定位进程物理路径（参数为pid号）')
parser.add_argument("--ssh-fip", action='store_true',help='用于查看ssh登录失败的ip和次数（无参数）')
parser.add_argument("--ssh-fuser", action='store_true',help='用于查看ssh登录失败的用户和次数（无参数）')
parser.add_argument("--ssh-sip", action='store_true',help='用于查看ssh登录成功的ip和次数（无参数）')
parser.add_argument("--ssh-sinfo", action='store_true',help='用于查看ssh登录成功的用户详情（无参数）')
parser.add_argument("--file-cron", type=str,metavar='7',help='用于查看系统各个级别定时任务目录中，n天内被修改的文件（参数为天数）')
parser.add_argument("--file-starup", type=str,metavar='7',help='用于查看系统启动项目录中，n天内被修改的文件（参数为天数）')
parser.add_argument("--file-os", type=str,metavar='7',help='用于查看系统重要目录中，n天内被修改的文件（参数为天数）')
parser.add_argument("--file-change", nargs=3,metavar=('/www', '7', 'php'),help='用于查看在n天内指定目录中指定后缀的被修改的文件（参数为物理路径、天数、后缀）')
parser.add_argument("--file-perm", nargs=3,metavar=('/www', 'jsp', '777'),help='用于查看指定目录下指定后缀指定权限的文件（参数为物理路径、后缀、天数）')
parser.add_argument("--s-backdoor", type=str,metavar='/home',help='用于检测指定路径下的恶意样本（参数为物理路径）')
parser.add_argument("--s-webshell", type=str,metavar='/var/www',help='用于检测指定路径下的webshell（参数为物理路径）')
args = parser.parse_args()


sys_tup = ostype()  # 判断系统类型
system = sys_tup[0]
sysnum = sys_tup[1]

banner = '''\033[1;34m
           ██╗    ██╗██╗  ██╗ ██████╗ ██████╗ ██╗  ██╗██╗  ██╗
           ██║    ██║██║  ██║██╔═══██╗╚════██╗██║  ██║██║ ██╔╝
           ██║ █╗ ██║███████║██║   ██║  ▄███╔╝███████║█████╔╝ 
           ██║███╗██║██╔══██║██║   ██║  ▀▀══╝ ██╔══██║██╔═██╗ 
           ╚███╔███╔╝██║  ██║╚██████╔╝  ██╗   ██║  ██║██║  ██╗
            ╚══╝╚══╝ ╚═╝  ╚═╝ ╚═════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝
        
           公众号：台下言书     作者：说书人     版本：v1.1\033[0m
           
\033[1;36m-------------------------------系统信息----------------------------------\033[0m
{}
\033[1;36m-------------------------------output------------------------------------\033[0m
'''.format(system_state())
print(banner)
checkroot()

if args.ip:
    print(network())
elif args.pid:
    print(pid_fileinfo(args.pid))
elif args.ssh_fip:
    print(log_burp_ip(system))
elif args.ssh_fuser:
    print(log_burp_user(system))
elif args.ssh_sip:
    print(log_success_ip(system))
elif args.ssh_sinfo:
    print(log_success_info(system))
elif args.cron:
    print(cron())
elif args.file_cron:
    print(cron_file(args.file_cron))
elif args.file_starup:
    print(starup(args.file_starup))
elif args.file_os:
    print(osfile(args.file_os))
elif args.file_change:
    print(changefile(args.file_change))
elif args.file_perm:
    print(permfile(args.file_perm))
elif args.user:
    print(account_check()[1])
elif args.history:
    print(history())
elif args.s_backdoor:
    file_scan(args.s_backdoor)
elif args.s_webshell:
    webshell_scan(args.s_webshell)
else:
    print("\033[1;33m可以带上参数 -h 或者 --help 来查看工具使用说明哦~\033[0m")
print("\033[1;36m-------------------------------------------------------------------------\033[0m")