#!/usr/local/bin/python

import os, sys, re, pdb, hashlib

sys.path.insert(0, os.getcwd() + "/py")

from common.dbconnect import DbConnect
from portinv.common.tmplparser import PageGenerator

class ArpInvShow:
        def __init__(self):
                self.db = DbConnect('pidb')
                self.db.connect()
		
        def getStoreSubnet(self):
                self.StoreSubnets = ['a','b','c','d','e','f','g','h']
                return self.StoreSubnets

        def getSiteGroupValues(self):
                self.values = self.db.select_query("""select base,name from basexref where name <> 'unassigned';""")
                return self.values

        def mainPage(self, formField):
                siteGroupValues = []
                siteGroupValues.append([self.getStoreSubnet()])

                genObj = PageGenerator('arpinvshow.tmpl')
                html = genObj.pageGenerate('',siteGroupValues)
                return html
