#autopwn
import subprocess
import argparse
import netifaces
import pandas as pd
from tabulate import tabulate
import time
import nmap


parser = argparse.ArgumentParser()
parser.add_argument('-ip', '--ipaddress', type=str, help='ex: \'-ip 192.168.1.1\' -The IP Address which to start the search (ie. of your local machine)')
parser.add_argument('-r','--range', type=str, help='(small, big) ex: \'-r small\' - The IP range which to scan: \n small (defualt) = X.X.X.0/24 | big = X.X.0.0/16)')
parser.add_argument('-t','--scan-type', type=str, help='(ex: \'-r small\' - The IP range which to scan: \n small (defualt) = X.X.X.0/24 | big = X.X.0.0/16)')
args = parser.parse_args()


#Find Local ip
def getLocalIp():
    addresses = pd.DataFrame(columns=['Interface','IP'])
    addresseDict = {}

    #if user didn't provide an address
    if args.ipaddress is None:
        interfaces = netifaces.interfaces()
        #looping through interfaces
        for i in interfaces:
            #discarding local addresses
            if i == 'lo0' or i == 'lo':
                continue
            iface = netifaces.ifaddresses(i).get(netifaces.AF_INET)
            ipcounter = 0
            if iface != None:
                for j in iface:
                    addresses.loc[len(addresses.index)+1] = [i, j['addr']]
                    #addresseDict[i] = j['addr']

        #if more than one interface available
        if len(addresses.index) > 1:
            #user decides which interface they want to target
            print('\n' + 'Select the interface you would like to target:\n')
            print(tabulate(addresses) + "\n")
            #print(addresses.to_string(justify='center'))
            while True:
                try:
                    x = int(input('Number: '))
                    if x > 0 and x <= len(addresses.index):
                        return(addresses.iloc[x-1]['IP'])
                        break;
                    else:
                        print('Please input a valid interface...')
                except ValueError:
                    print("Please input a valid number")
                    continue

        if len(addresses.index) == 1:
            #user decides which interface they want to target
            print('\n' + 'Using the following interface:\n')
            print(tabulate(addresses) + "\n")
            return(addresses.iloc[0]['IP'])

        else:
            print('\n' + 'Unable to find any interfaces, try manually designating an IP Address')



        #if only one interface is available
        # if len(Addresses) == 1:
        #     print('Using detected interface:')
        #     for e, ip in Addresses.items():
        #         print("{} ({})".format(e, ip))
        #     return j['addr']
#Get range from ip
def getRange():
    range = ''
    ipAddress = str(getLocalIp())
    if args.range == None or args.r == 'small':
        range = '.'.join(ipAddress.split(".")[:-1]+["0/24"])
    if args.range == 'big':
        range = '.'.join(ipAddress.split(".")[:-2]+["0.0/16"])
    time.sleep(.5)
    return range
#Execute nmap scan on range

def scanner(Range):
    livehosts = []

    print('\n'+'Beginning scan on range: ' + Range)
    nm = nmap.PortScanner()
    nm.scan(hosts=Range, arguments='-n -sP -T5 --min-parallelism 100 --max-parallelism 256')
    hosts_list = [(x, nm[x]['status']['state']) for x in nm.all_hosts()]
    for host, status in hosts_list:
        if status == 'up':
            #livehosts += [host]
    #print('\n Found ' + len(livehosts) + ' live hosts...\n')
            print(host)


scanner(getRange())


#range16 =



#Argument Parser

#
#
#
# #print hello + user args
# print('Your IP Address is ', args.IP)
#
#
#
#
# bashCommand = "whoami"
# process = subprocess.Popen(bashCommand.split(), stdout=subprocess.PIPE, text=True)
# output, error = process.communicate()
#
# if error == None:
#     print(output)
# else:
#     print(error)
