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
        self.StoreSubnets = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h']
        return self.StoreSubnets

    def mainPage(self, formField):
        siteGroupValues = []
        siteGroupValues.append([self.getStoreSubnet()])
        restmpl = None
        resPage = None
        beg = None
        end = None
        params = {'beg': '', 'end': ''}

        genObj = PageGenerator('arpinvshow.tmpl')
        html = genObj.pageGenerate(restmpl, siteGroupValues, resPage, params)
        # html = genObj.pageGenerate('', siteGroupValues)
        return html
