#!python3

import os, sys
#import MySQLdb
import mysql.connector as mariadb 
from pprint import pprint
from common.yamlparser import yamlParser


class DbConnect:

    def __init__(self, dbschema=None):
        cdir = os.getcwd()

        if 'nmspy_Russel' not in cdir:
            configfile = cdir + "/nmspy_Russel/common/config/dbconfig.yaml"
        elif 'common' in cdir: 
            configfile = cdir + "/config/dbconfig.yaml"
        else:
            configfile = cdir + "/common/config/dbconfig.yaml"

        dbconfig = yamlParser(configfile)
        self.configParam = dbconfig.parseFile()
        self.dbschema = dbschema

        if dbschema is None:
            return 

        if dbschema in self.configParam:
            self.dbuser = self.configParam[dbschema]['DBUSER']
            self.dbpass = self.configParam[dbschema]['DBPASS']
            self.dbhost = self.configParam[dbschema]['DBHOST']
            self.dbport = self.configParam[dbschema]['DBPORT']

    def connect(self, encoding=True):
        # self.dbobj = MySQLdb.connect(user=self.dbuser, passwd=self.dbpass,
        self.dbobj = mariadb.connect(user=self.dbuser, password=self.dbpass,
                                     host=self.dbhost, port=self.dbport,
                                     db=self.dbschema,
                                     use_unicode=encoding) 

    def select_query(self, query=None):
        if query is None:
            return

        cur = self.dbobj.cursor() 
        cur.execute(query)
        values = cur.fetchall()

        return values 

