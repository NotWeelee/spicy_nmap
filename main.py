import nmap
import re

nm = nmap.PortScanner()

targetFile = open('targets.txt', 'r')
ip = targetFile.readlines()
target = ''
for host in ip:
    target = target + ', ' + host
targetFile.close()

print("""
What type of scan do you want to run? Decisions, decisions...

    0. Ping Scan
    1. Basic Port Scan
    2. Fast Scan (Top 100 Ports)
    3. UDP Scan
    4. Version/OS Detection
    5. Default NSE Scripts
    6. Custom & Default NSE Scripts
    7. Version/OS Detection, NSE, Traceroute, Port Scan
""")

customFile = open('commands.txt', 'r')
lines = customFile.readlines()
count = 7
for i in range(0, len(lines)):
    if not line.strip():
        continue
    else:
        if i == 0:
            commandOne = re.match('[^,]*$', lines[0]).group(0)
        elif i == 1:
            commandOne = re.match('[^,]*$', lines[1]).group(0)
        elif i == 2:
            commandOne = re.match('[^,]*$', lines[2]).group(0)
        name = re.match('[^,]+', lines[i]).group(0)
        print("    {}. {}".format(count, name))
        count = count + 1


def menu():
    mike = int(input('Selection: '))
    if mike == 0:
        pingScan()
    elif mike == 1:
        portScan()
    elif mike == 2:
        fastScan()
    elif mike == 3:
        UDPScan()
    elif mike == 4:
        versionOS()
    elif mike == 5:
        NSEScripts()
    elif mike == 6:
        allOfTheAbove()
    elif mike == 7:
        if count > 7:
            customOne()
    elif mike == 8:
        if count > 8:
            customTwo()
    elif mike == 9:
        if count > 9:
            customTwo()
    else:
        print('Invalid option')


def pingScan():
    if target == '':
        print('\nPlease specify hosts in target.txt\n')
    else:
        nm.scan(target, arguments='-sn')



def portScan():
    if target == '':
        print('\nPlease specify hosts in target.txt\n')
    else:
        nm.scan(target, arguments='-sn')
        openPorts = open("open_ports.txt", "w+")
        for host in nm.all_hosts():
            openPorts.write("{}. {}\n".format(nm[host].hostname(), nm[host].state()))


def allOfTheAbove():
    if target == '':
        print('\nPlease specify hosts in target.txt\n')
    else:
        nm.scan(target, arguments='-A -oN /results/Version_OS_NSE_Port_Scan.txt')


def fastScan():
    if target == '':
        print('\nPlease specify hosts in target.txt\n')
    else:
        nm.scan(target, arguments='-F -oN /results/Fast_Scan.txt')


def UDPScan():
    if target == '':
        print('\nPlease specify hosts in target.txt\n')
    else:
        nm.scan(target, arguments='-sU -oN /results/UDP_Scan.txt')


def NSEScripts():
    if target == '':
        print('\nPlease specify hosts in target.txt\n')
    else:
        nm.scan(target, arguments='-sC -oN /results/NSE_Scripts.txt')


def versionOS():
    if target == '':
        print('\nPlease specify hosts in target.txt\n')
    else:
        nm.scan(target, arguments='-sV -sO -oN /results/Version_OS.txt')


def customOne():
    if target == '':
        print('\nPlease specify hosts in target.txt\n')
    else:
        nm.scan(target, arguments=commandOne)


def customTwo():
    if target == '':
        print('\nPlease specify hosts in target.txt\n')
    else:
        nm.scan(target, arguments=commandTwo)


def customThree():
    if target == '':
        print('\nPlease specify hosts in target.txt\n')
    else:
        nm.scan(target, arguments=commandThree)


menu()
