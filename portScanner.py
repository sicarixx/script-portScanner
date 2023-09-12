#!/usr/bin/python3
# Created by Sicarixx

import os, nmap

def welcome():
    welc = 'NMAP Port Scanner'
    info = '[INFO] Python script with NMAP to scan ports'
    os.system('clear')
    print(welc + '\n' + '*' * len(welc))
    print(info + '\n' + '-' * len(info))
    return

def getAddress():
    welcome()
    try:
        ipAddress = input('[+] Enter the IP Address: ')
        while(ipAddress == ''):
            ipAddress = input('[+] Please, enter the IP Address: ')
    except(KeyboardInterrupt):
        os.system('clear')
        welcome()
        print('[-] Interrupted by user!')
        exit()
    return ipAddress

def scannerNmap():
    try:
        host = getAddress()
        print('[+] Scanning open ports ==> ' + host)
        nm = nmap.PortScanner()
        results = nm.scan(host)
        os.system('clear')
        welcome()
        for host in nm.all_hosts():
            print('Host\t: %s' % (host))
            print('State\t: %s' % nm[host].state())
            for proto in nm[host].all_protocols():
                print('Protocol: %s' % proto)
                print('------------')
                lport = nm[host][proto].keys()
                sorted(lport)
                for port in lport:
                    print('port : %s\tstate : %s' % (port, nm[host][proto][port]['state']))
    except(KeyboardInterrupt):
        print('[-] Interrupted by user!')
    return

if __name__ == '__main__':
    scannerNmap()
