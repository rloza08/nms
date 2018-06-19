#!/usr/bin/python3

import re, os, pdb, sys, copy
from pprint import pprint
import time, socket, pexpect, struct
from multiprocessing import Process, Queue

#sys.path.insert(0, os.getcwd())

from common.dbconnect import DbConnect
from common.yamlparser import yamlParser
from hpna.common.tmplparser import PageGenerator


class HpnaAclAsaCsv:
    def __init__(self):
        self.db = DbConnect('pidb')
        self.db.connect()

        # Data files..
        self.elist = dict()
        self.plist = dict()
        self.mask = dict()
        self.dmem = dict()
        self.hpna = dict()
        self.loop = dict()
        self.type = dict()
        self.divs = dict()

        #if 'nmspy' in os.getcwd():
        self.data_dir = os.getcwd() + "/data"
        #else:
        #    self.data_dir = os.getcwd() + "/nmspy/data"

    def getResultValues(self, sql):
        values = self.db.select_query(sql)
        return values

    def mainPage(self, formField=''):
        res = dict()
        params = dict()

        hpna, list, tftp = ('',) * 3

        if 'hpnagrp' in formField:
            hpna = formField['hpnagrp'].value
            params['hpna'] = hpna
 
        if 'list' in formField:
            list = formField['list'].value
            params['list'] = list

        if 'tftp' in formField:
            tftp = formField['tftp'].value
            params['tftp'] = tftp

        targ = list

        pat = re.compile("\d+")
        mat = pat.match(list)
        if mat is None:
            targ = hpna

        if 'Counts' in targ:
            params['count'] = self.mask
        elif not hpna:
            params['count'] = self.mask

        self.load_elist()
        self.load_plist()
        self.load_hpna()

        params['hpnagrp'] = self.divs

        genObj = PageGenerator('hpnaaclasacsv.tmpl')
        html = genObj.pageGenerate(None,
                                   values=res,
                                   resPage=res,
                                   params=params)

        return html

    def load_elist(self):
        pat = re.compile("^#")
        pat1 = re.compile("(\d{4})")

        filename = self.data_dir + "/excp-list.txt"
        if os.path.exists(filename):
            fh = open(filename, "r")

            for line in fh:
                mat = pat.match(line)
                if mat:
                    continue 

                arr = line.split(",")
                self.elist[arr[0]] = arr[1]

                mat1 = pat1.match(arr[0])
                if mat1:
                    site = mat1.group()
                    host = "fw%04da" % site
                    self.elist[host] = arr[1]

            fh.close()

    def load_plist(self):
        pat = re.compile("^#")

        filename = self.data_dir + "/pilot_stores"
        if os.path.exists(filename):
            fh = open(filename, "r")

            for line in fh:
                line = line.replace("\n", "")
                line = re.sub("\s+", " ", line)

                mat = pat.match(line)
                if mat:
                    continue

                arr = line.split(" ")
                if arr:
                    loc = arr[0]
                    del arr[0]

                    if loc in self.plist:
                        self.plist[loc].extend(arr)
                    elif loc:
                        self.plist[loc] = arr

            fh.close()

    def load_hpna(self):
        pat = re.compile('Dominicks')
        pat1 = re.compile('.*Retail,fw\d.*')
        pat2 = re.compile('Firewalls')
        pat3 = re.compile('^(\w{3})')

        filename = self.data_dir + "/hpna-group-mems.csv"
        if os.path.exists(filename):
            fh = open(filename, "r")

            for line in fh:
                line = line.strip()

                mat = pat.match(line)
                if mat:
                    continue  

                mat1 = pat1.match(line)
                if mat1 is None:
                    continue

                mat2 = pat2.match(line)
                if mat2:
                    continue

                arr = line.split(",")
                mat3 = pat3.match(arr[0])
                if not (mat3 is None):
                    self.divs[arr[0]] = str(mat3.group()).upper()

                if arr[0] in self.mask:
                    self.mask[arr[0]] = self.mask[arr[0]] + 1
                else:
                    self.mask[arr[0]] = 1
                self.dmem[arr[1]] = arr[0]

            self.divs["    -- All -- "] = "ALL"
            self.divs["   Primary Pilots"] = "PRI-P"
            self.divs[" Extended Pilots"] = "EXP-P"
            self.divs[" Labs"] = "LABS"
            self.divs["    Counts"] = 1 

            fh.close()

        pat = re.compile("^fw[0-9]\d{3}[ab],")

        filename = self.data_dir + "/hpna-inv.csv"
        if os.path.exists(filename):
            fh = open(filename, "r")

            for line in fh:
                line = line.strip()

                if 'Inactive' in line:
                    continue

                mat = pat.match(line)
                if mat is None:
                    continue 

                arr = line.split(",")
                self.hpna[arr[0]] = arr[1]
                self.type[arr[0]] = 0
                self.loop[arr[0]] = arr[1]

            fh.close()

