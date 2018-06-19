#!/usr/bin/python3

import os, sys

cdir = os.getcwd()
os.chdir(cdir + "/..")
sys.path.append(os.getcwd())

# from common.dbconnect import DbConnect
from portinv.common.tmplparser import PageGenerator
