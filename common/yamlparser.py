#!/usr/bin/python3

import os
import yaml
from pprint import pprint


class yamlParser:
    def __init__(self, yamlFile=None):
        self.file = yamlFile

    def parseFile(self):
        if os.path.exists(self.file):
            fh = open(self.file, "r")
            contents = yaml.load(fh.read()) 
            return contents 


#if __name__ == '__main__':
#    obj = yamlParser("dbconfig/dbconfig.yaml")
#    contents = obj.parseFile()
#    pprint (contents)

