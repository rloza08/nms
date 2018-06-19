#!/usr/bin/python3

import os, re
from pprint import pprint


class SNMPConfig:
    def __init__(self):
        self.snmp = {}
        cwd = os.getcwd()

        if 'nmspy_Russel' in cwd:
            self.configfile = cwd + "/common/config/clib.conf"
        else:
            self.configfile = cwd + "/nmspy_Russel/common/config/clib.conf"

        self.__Readconfig__()

    def __Readconfig__(self):
        snmp = {}

        if os.path.exists(self.configfile):
            pat = re.compile("^def")

            fh = open(self.configfile, "r")
            for line in fh:
                if pat.match(line):
                    if re.match("^defcommunity", line): 
                        var, snmp['c'] = line.split(",") 
                        snmp['c'] = snmp['c'].replace("\n", "")

                    if re.match("^defsecurityname", line): 
                        var, snmp['u'] = line.split(",")
                        snmp['u'] = snmp['u'].replace("\n", "")

                    if re.match("^defauthpassphrase", line): 
                        var, snmp['A'] = line.split(",") 
                        snmp['A'] = snmp['A'].replace("\n", "")

                    if re.match("^defsecuritylevel", line): 
                        var, snmp['l'] = line.split(",") 
                        snmp['l'] = snmp['l'].replace("\n", "")

                    if re.match("^defauthtype", line): 
                        var, snmp['a'] = line.split(",") 
                        snmp['a'] = snmp['a'].replace("\n", "")

                    if re.match("^defversion", line): 
                        var, snmp['v'] = line.split(",")
                        snmp['v'] = snmp['v'].replace("\n", "")
            fh.close()
        self.snmp = snmp

    def getconfig(self):
       return self.snmp

