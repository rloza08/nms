#!/usr/bin/python3

import cgi
import cgitb
import os, sys
cgitb.enable()

sys.path.insert(0, os.getcwd())

from portinv.qsel import QuickSelect
from portinv.bsportutil import BsPortUtil 
from portinv.macpidbsrch import MacPidbSrch 
from portinv.arpsitecomp import ArpSiteComp 
#from portinv.arpinvshow import arp-inv-show
from hpna.hpnaaclasacsv import HpnaAclAsaCsv 
from common.tmplparser import MainPageGenerator


def generateMainPage(menuContent=None):
    tmpl = MainPageGenerator('main', "menu.tmpl", "menu.yaml")

    print ("Content-Type: text/html\n")
    print (tmpl.menuGenerator(menuContent)) 


def generateSubMainPage(descr=None, submenu=None):
    yamlName = 'menu.yaml'

    if descr == 'submenu':
        yamlName = 'submenu.yaml'

    tmpl = MainPageGenerator('main', 'submenu.tmpl', yamlName) 

    print ("Content-Type: text/html\n")
    print (tmpl.submenuGenerator(submenu))


if __name__ == "__main__":
    formField = cgi.FieldStorage()

    if 'menuContents' in formField:
        if ':' in formField['menuContents'].value:
            (descr, submenu) = formField['menuContents'].value.split(':')
            generateSubMainPage(descr, submenu)
        else:
            generateSubMainPage('main', formField['menuContents'].value)
    elif 'param' in formField:
        value = formField['param'].value
        if 'qsel' in value:
            qobj = QuickSelect()
            html = qobj.mainPage(formField)

            print (html)
        elif 'bsport' in value:
            bsobj = BsPortUtil() 
            html = bsobj.mainPage(formField)

            print (html)
        elif 'mac_addr' in value:
            mac_addr_obj = MacPidbSrch()
            html = mac_addr_obj.mainPage(formField)

            print (html)
        elif 'arpsitecomp' in value:
            arp_obj = ArpSiteComp()
            html = arp_obj.mainPage(formField)

            print (html)
#	elif 'arp-inv-show' in value:
#            arp-inv-show_obj = arp-inv-show()
#            html = arp-inv-show_obj.mainPage(formField)
#
#            print (html)
        elif 'hpnaaclasacsv' in value:
            asa_acl_obj = HpnaAclAsaCsv()
            html = asa_acl_obj.mainPage(formField) 

            print (html)
    else:
        generateMainPage('Dashboard')

