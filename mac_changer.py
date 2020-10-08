#!/usr/bin/env python

import subprocess
import optparse
import re

def change_mac(interface,mac):
    subprocess.call(["ifconfig", interface, "down"])
    subprocess.call(["ifconfig", interface, "hw","ether",MAC])
    subprocess.call(["ifconfig", interface, "up"])

def prep_parser():
    parser = optparse.OptionParser()
    parser.add_option("-i","--interface",dest="interface",help="Interface to change MAC")
    parser.add_option("-m","--mac",dest="MAC",help="New MAC addr")
    return parser



parser = prep_parser()
(options,arguments)=parser.parse_args()

interface = options.interface
MAC = options.MAC

ifconfig_res = subprocess.check_output(["ifconfig",options.interface])
changedMAC = re.search(r"\w\w:\w\w:\w\w:\w\w:\w\w:\w\w",ifconfig_res)
change_mac(interface,MAC)

print(ifconfig_res)

print(changedMAC.group(0))
if changedMAC.group(0) != MAC:
    print("MAC changed succesfully")
else:
    print("MAC remains the same")
