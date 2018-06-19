
#!/usr/local/bin/python

import os, sys, re, pdb, hashlib

sys.path.insert(0, os.getcwd() + "/py")

from common.dbconnect import DbConnect
from portinv.common.tmplparser import PageGenerator

#for future use:
#VLAN = "/appl/nms/SNMSpidb/misc/st-vlanlist.dat"

class ARPInventory:
	def __init__(self):
		self.db = DbConnect('pidb')
		self.db.connect()

	def getDivisionValues(self):
		self.values = self.db.select_query("""select host, fac from sitexref where host rlike '^fw[0-4]';""")
		self.divisions = []
		for value in self.values:
			self.divisions.append(value[1])	
		
		return list(set(self.divisions)) 

	def getVlan(self):
		self.vlan_items = open("/appl/nms/SNMSpidb/misc/st-vlanlist.dat").read().splitlines()
		self.vlan_filtered = []
		
		for value in self.vlan_items:
			if re.findall("""10\.x\.(\w)\.(\d+):10\.x\.\w\.(\d+)""",str(value)):
				if '#' not in value: 
					self.vlan_filtered.append(value)

		#concatenated in one 	
		for value in self.vlan_items:
			if re.findall("""10\.x\.(\w)\.(\d+)""",str(value)) or re.findall("""\S+\.(\d+)1""",str(value)):
				if '#' not in value:
					self.vlan_filtered.append(value)	
		
		return self.vlan_filtered

	def scan_arp(self, dnam=None):
		sql = """select a.addr from arp_data a, sitexref b, portinfo c
                    where c.host rlike '^[rs][0-4]|^fw[0-4]' and c.host = b.host
                     and a.sidx = c.sidx and b.fac rlike '{}'""".format(str(dnam))
		self.sql_query = self.db.select_query(sql)
		list = []
		for value in sql:
			if re.findall("""\.safeway\.com""",str(value)):
				list.append(value)

		return list

	def mainPage(self, formField):
		siteGroupValues = []
		siteGroupValues.append([self.getVlan()])
		siteGroupValues.append([self.getDivisionValues()])
		restmpl = 'tabletmpl.tmpl'
		division = ''
		results = ''
		params = {'vlan': None, 'division': None}
		if 'vlan' in formField:
			vlan = formField['vlan'].value
			params['vlan'] = vlan

		if 'division' in formField:
			division = formField['division'].value
			params['division'] = division	
		else:
			division = 'Retail - Denver'		
		results = self.scan_arp(division)
		genObj = PageGenerator('arpinventory.tmpl')
		html = genObj.pageGenerate(restmpl,siteGroupValues,results,params)
		return html

