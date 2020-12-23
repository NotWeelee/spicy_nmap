import nmap3
import re

#nm = nmap.PortScanner()

targetFile = open('targets.txt', 'r')
ip = targetFile.readlines()
target = ''
for host in ip:
    target = target + ', ' + host
targetFile.close()

print("""
What type of scan do you want to run? Decisions, decisions...

    0. Ping Scan
    1. Port Scan
    2. Fast Scan (Top 100 Ports)
    3. UDP Scan
    4. Version/OS Detection
    5. Default NSE Scripts
    6. Custom NSE Scripts
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
        print('\n Running...')
        pingScan()
    elif mike == 1:
        print('\n Running...')
        portScan()
    elif mike == 2:
        print('\n Running...')
        fastScan()
    elif mike == 3:
        print('\n Running...')
        UDPScan()
    elif mike == 4:
        print('\n Running...')
        versionOS()
    elif mike == 5:
        print('\n Running...')
        NSEScripts()
    elif mike == 6:
        print('\n Running...')
        allOfTheAbove()
    elif mike == 7:
        if count > 7:
            print('\n Running...')
            customOne()
        else:
            print('Invalid option')
    elif mike == 8:
        if count > 8:
            print('\n Running...')
            customTwo()
        else:
            print('Invalid option')
    elif mike == 9:
        if count > 9:
            print('\n Running...')
            customTwo()
        else:
            print('Invalid option')
    else:
        print('Invalid option')


def pingScan():
    if target == '':
        print('\nPlease specify hosts in target.txt\n')
    else:
        nmap = nmap3.NmapHostDiscovery()
        aliveHosts = open("alive_hosts.txt", "w+")
        aliveDict = nmap.nmap_no_portscan(target)
        for i in range(0, len(aliveDict.keys()) - 2):
            aliveHosts.write(str(list(aliveDict.keys())[i]) + '\n')
        aliveHosts.close()

def portScan():
    if target == '':
        print('\nPlease specify hosts in target.txt\n')
    else:
        nmap = nmap3.NmapHostDiscovery()
        openPorts = open("open_ports.txt", "w+")
        openDict = nmap.nmap_portscan_only(target)
        for i in range(0, len(openDict.keys()['ports'])):
            openPorts.write(str(list(openDict.keys()[i])))
        openPorts.close()


def allOfTheAbove():
    if target == '':
        print('\nPlease specify hosts in target.txt\n')
    #else:



def fastScan():
    if target == '':
        print('\nPlease specify hosts in target.txt\n')
    #else:



def UDPScan():
    if target == '':
        print('\nPlease specify hosts in target.txt\n')
    #else:



def NSEScripts():
    if target == '':
        print('\nPlease specify hosts in target.txt\n')
    #else:



def versionOS():
    if target == '':
        print('\nPlease specify hosts in target.txt\n')
    #else:



def customOne():
    if target == '':
        print('\nPlease specify hosts in target.txt\n')
    #else:



def customTwo():
    if target == '':
        print('\nPlease specify hosts in target.txt\n')
    #else:



def customThree():
    if target == '':
        print('\nPlease specify hosts in target.txt\n')
    #else:



menu()
