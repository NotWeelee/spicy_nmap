"""
spicy_nmap (WIP), started by Willie Zhang on 12/21/2020

spicy_nmap was created to make it easier for people to run nmap scans. All you have to do
is put your targets into targets.txt and fire off the script. The script will do the rest,
including giving you an easy to read output. See README.md for more info!

"""

# IMPORTS
import nmap3
import re

def readFileLineByLine(file):
    food = []
    f = open(file, "r")
    lines = f.readlines()
    for line in lines:
        food.append(line)
    return food


# Reads the targets you want to scan from the provided targets.txt file located in the
# spicy_nmap directory.
target = readFileLineByLine('targets.txt')

# Prints the default options provided starting at 0 for funsies
print("""
What type of scan do you want to run? Decisions, decisions...

    0. Ping Scan
    1. Ping & Port Scan
    2. Fast Scan (Top 100 Ports)
    3. UDP Scan
    4. Version/OS Detection
    5. Default NSE Scripts
    6. Custom NSE Scripts
    7. Version/OS Detection, NSE, Traceroute, Port Scan
""")

# Reads the custom commands you want to use from the provided commands.txt file located
# in the spicy_nmap directory. Anything before the comma will be read as the name of the
# custom command and everything after will be the arguments of your custom nmap command.
# Blank lines are skipped to avoid empty commands.
customFile = open('commands.txt', 'r')
lines = customFile.readlines()
count = 7
for i in range(len(lines)):
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


# The main menu you see when you run the script. Options 1 - 6 are pre-provided nmap scans
# and options 7 - 9 are custom ones that can only be called if they exist in the options menu.
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


# nmap -sn (Used for host discovery but not look for open ports)
# The output will be a text file containing the IPs of all alive hosts that can be used
# as input in other scans.
def pingScan():
    if not target:
        print('\nPlease specify hosts in target.txt\n')
    else:
        for i in range(len(target)):
            nmap = nmap3.NmapScanTechniques()
            aliveHosts = open("alive_hosts.txt", "w")
            aliveDict = nmap.nmap_ping_scan(target[i])
            for i in range(len(aliveDict.keys()) - 2):
                aliveHosts.write(str(list(aliveDict.keys())[i]) + '\n')
        aliveHosts.close()


# nmap -Pn (Used for host discovery, as well as looking for open ports)
def portScan():
    if target == '':
        print('\nPlease specify hosts in target.txt\n')
    else:
        nmap = nmap3.NmapHostDiscovery()
        pingScan()
        aliveList = readFileLineByLine('alive_hosts.txt')
        openPorts = open("open_ports.txt", "w+")
        for i in range(len(aliveList)):
            openDict = nmap.nmap_portscan_only(aliveList[i])
            openPorts.write(str(openDict))
            #openPorts.write('Port : ' + str(openDict))
        openPorts.close()


#nmap -A (A surefire way to get most of the information you want from your target)
def allOfTheAbove():
    if target == '':
        print('\nPlease specify hosts in target.txt\n')
    #else:


# nmap -F (Scans the top 100 ports on each host; used for time efficiency)
def fastScan():
    if target == '':
        print('\nPlease specify hosts in target.txt\n')
    else:
        pingScan()
        aliveList = readFileLineByLine('alive_hosts.txt')
        nmap = nmap3.Nmap()
        fastScanFile = open("fast_scan.txt", "w")
        for i in range(len(aliveList)):
            fastDict = nmap.scan_top_ports(aliveList[i])
            fastScanFile.write(str(fastDict))
        fastScanFile.close()

# nmap -sU (Scans using UDP instead of the normal TCP Half-Connect)
def UDPScan():
    if target == '':
        print('\nPlease specify hosts in target.txt\n')
    #else:


# nmap -sC (Scans targets and uses default NSE scripts on the host if it applies)
def NSEScripts():
    if target == '':
        print('\nPlease specify hosts in target.txt\n')
    #else:


# nmap -O -sV (Detects OS and version of the services on a host)
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

# start the script
menu()
