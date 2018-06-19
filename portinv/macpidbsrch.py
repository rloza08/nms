#!/usr/bin/python3

import re, os, pdb, sys, copy
from pprint import pprint
import time, socket

from common.dbconnect import DbConnect
from common.yamlparser import yamlParser
from portinv.common.tmplparser import PageGenerator


class MacPidbSrch:
    def __init__(self):
        self.contents = {} 
        self.db = DbConnect('pidb')
        self.db.connect()

    def getResultValues(self, sql):
        self.values = self.db.select_query(sql)
        return self.values

    def mainPage(self, formField):
        arr = []
        res = {}
        rad  = None 
        params = {}

        if 'type' in formField:
            rad = formField['type'].value
            params['type'] = rad 

        if 'srch' in formField:
            data = formField['srch'].value
            arr = data.split("\n")
            params['srch'] = data

        if 'file' in formField:
            datafile = formField['file']
            if datafile.file:
                params['file'] = datafile.file
                while 1:
                    line = str(datafile.file.readline(), 'utf-8')
                    if not line:
                        break
                    else:
                        line = re.sub("^\s+", "", line)
                        line = re.sub("\s+$", "", line)
                        arr.append(line)

        arr_str = ",".join(arr)
        srch_dict = self.prse_raw(arr_str)

        if len(srch_dict):
            base_dict, vend = self.load_xref()
            srch = copy.deepcopy(srch_dict)

            for seg in srch_dict:
                for type in srch_dict[seg]:
                    if type not in 'all':
                        if len(srch_dict[seg][type]):
                            result = None 
                            if rad == 'ARP':
                                result = self.srch_arp(seg, type, srch, base_dict, vend)

                            if rad == 'MAC':
                                result = self.srch_fdb(seg, type, srch, base_dict, vend)

                            if result:
                                if res:
                                    res.update(result)
                                else:
                                    res = result

        res = self.checkDuplicates(res)

        genObj = PageGenerator('macaddrsrch.tmpl')
        html = genObj.pageGenerate(None, values=self.contents, resPage=res, params=params)

        return html

    def checkDuplicates(self, res=None):
        res_dict = {}
        arr = list(res.keys())
        res_values = set(res.values())

        for index, value in enumerate(res_values):
            key = arr[index]
            res_dict[key] = value 

        return res_dict

    def prse_raw(self, data):
        segs, hits = (0,) * 2
        hostname = None
        srch = {}
        arr = data.split(",")

        for val in arr:
            if val is None or val == '':
                continue
 
            inner_dict = {'all': {}, 'mac': {}, 'addr': {}, 'name': {}}
            if val in inner_dict:
                inner_dict['all'][val] = inner_dict['all'][val] + 1
            else:
                inner_dict['all'][val] = 1

            pat = re.compile("^\s+|\s+$")
            val = pat.sub("", val)

            if val is None or val is '':
                continue

            if val in inner_dict['all']:
                inner_dict['all'][val] = inner_dict['all'][val] + 1
            else:
                inner_dict['all'][val] = 1

            pat = re.compile("(\w{2})[:,-](\w{2})[:,-](\w{2})[:,-](\w{2})[:,-](\w{2})[:,-](\w{2})")
            pat1 = re.compile("(\w{2})(\w{2})\.(\w{2})(\w{2})\.(\w{2})(\w{2})")
            pat2 = re.compile("^(\w{2})[:,-](\w{2})[:,-](\w{2})$")
            pat3 = re.compile("^(\w{2})(\w{2})\.(\w{2})$")
            ip_pat = re.compile("(\d+\.\d+\.\d+\.\d+)")

            mat = pat.match(val)
            mat1 = pat1.match(val)
            mat2 = pat2.match(val)
            mat3 = pat3.match(val)
            ip_mat = ip_pat.match(val)
            host_mat = re.match("([\w-]+)", val)

            if mat is not None:
                mac = "%02s-%02s-%02s-%02s-%02s-%02s" %\
                      (mat.group(1), mat.group(2), mat.group(3),
                       mat.group(4), mat.group(5), mat.group(6))
            
                if mac in inner_dict['mac']:
                    inner_dict['mac'][mac] = inner_dict['mac'][mac] + 1
                else:
                    inner_dict['mac'][mac] = 1

                if mac in inner_dict['all']:
                    inner_dict['all'][mac] = inner_dict['all'][mac] + 1
                else:
                    inner_dict['all'][mac] = 1
                hits = hits + 1
            elif mat1 is not None:
                mac = "%02s-%02s-%02s-%02s-%02s-%02s" %\
                      (mat1.group(1), mat1.group(2), mat1.group(3),
                       mat1.group(4), mat1.group(5), mat1.group(6))
                if mac in inner_dict['mac']:
                    inner_dict['mac'][mac] = inner_dict['mac'][mac] + 1
                else:
                    inner_dict['mac'][mac] = 1

                if mac in inner_dict['all']:
                    inner_dict['all'][mac] = inner_dict['all'][mac] + 1
                else:
                    inner_dict['all'][mac] = 1
                hits = hits + 1
            elif mat2 is not None:
                mac = "%02s-%02s-%02s" % \
                      (mat2.group(1), mat2.group(2), mat2.group(3))
                if mac in inner_dict['oui']:
                    inner_dict['oui'][mac] = inner_dict['oui'][mac] + 1
                else:
                    inner_dict['oui'][mac] = 1

                if mac in inner_dict['all']:
                    inner_dict['all'][mac] = inner_dict['all'][mac] + 1
                else:
                    inner_dict['all'][mac] = 1
                hits = hits + 1
            elif mat3 is not None:
                mac = "%02s-%02s-%02s" % \
                      (mat3.group(1), mat3.group(2), mat3.group(3))
                if mac in inner_dict['oui']:
                    inner_dict['oui'][mac] = inner_dict['oui'][mac] + 1
                else:
                    inner_dict['oui'][mac] = 1

                if mac in inner_dict['all']:
                    inner_dict['all'][mac] = inner_dict['all'][mac] + 1
                else:
                    inner_dict['all'][mac] = 1
                hits = hits + 1
            elif ip_mat is not None:
                addr = ip_mat.group(1)
                try:
                    value = socket.gethostbyaddr(addr)
                    hostname = value[0]
                except Exception as err:
                    hostname = 'Unknown Host'

                if 'safeway.com' in hostname:
                    hostname = hostname.replace('safeway.com', '')
                inner_dict['addr'][addr] = hostname
                inner_dict['all'][addr] = hostname
                hits = hits + 1

                if hostname:
                    inner_dict['name'][hostname] = addr
            elif host_mat is not None:
                hostaddr = None
                hostname = host_mat.group(1)
                try:
                    hostaddr = socket.gethostbyname(hostname)
                except Exception as err:
                    pass 

                if hostaddr:
                    mat = re.match("\d+\.\d+\.\d+\.\d+", hostaddr)
                    if mat:
                        inner_dict['name'][hostname] = hostaddr
                        inner_dict['addr'][hostaddr] = hostname
                        inner_dict['all'][hostaddr] = hostname
                    else:
                        inner_dict['name'][hostname] = hostname
                        inner_dict['all'][hostname] = hostname

            if inner_dict['all']:
                if segs in srch:
                    srch[segs]['all'].update(inner_dict['all'])
                    srch[segs]['mac'].update(inner_dict['mac'])
                    srch[segs]['name'].update(inner_dict['name'])
                    srch[segs]['addr'].update(inner_dict['addr'])
                else:
                    srch[segs] = inner_dict

                if hits >= 15:
                    hits = 0 
                    segs = segs + 1

        return srch

    def load_xref(self):
        vend = {}
        sql = """select * from oui_xref"""

        pat_arr = ["(\w+\s+\w+)\s+.+", "\s*internat\S+",
                   "\s*communica\S+", "\s*tech\S*", "\s*corp\S*",
                   "\s*inc\S*", "\w*ltd"]
        self.db.connect(False)
        values = self.getResultValues(sql)
        self.db.connect()

        for tup in values:
            oui = tup[0]
            vendor = tup[1]
            pat = re.compile(r"[\"\']")

            oui = str(tup[0])
            oui = re.sub('b\'|\'', '', oui)
            vendor = str(tup[1])
            vendor = re.sub('b\'|\'', '', vendor)
            vendor = pat.sub("", vendor)

            for regex in pat_arr:
                pat_sub = re.compile(regex, re.I)
                vendor = pat_sub.sub("", vendor)
                vend[oui] = vendor

        vend['00-00-5E-00-01'] = "VRRP MAC Address"
        sql = """select base, name from basexref"""
        values = self.getResultValues(sql)

        base_dict = {}
        for tup in values:
            base = tup[0]
            name = tup[1]
            base_dict[base] = name

        return base_dict, vend

    def type_mac(self, srch_dict):
        mac_list, sql = (None,) * 2
        seg = srch_dict['seg']

        for val in srch_dict[seg]['mac']:
            if mac_list is None:
                mac_list = val
            else:
                mac_list = mac_list + "','" + val

            sql = """select b.host, b.port, b.vlan, a.mac, c.addr,
                     d.host, b.name, date(b.date), c.base
                     from fdb_macs a
                     left join portinfo b on a.sidx=b.sidx
                     left join arp_data c on a.mac=c.mac
                     left join dns_xref d on c.addr=d.addr
                     where a.mac in ('{}')""".format(mac_list)

        return sql

    def type_oui(self, srch_dict):
        oui_list, sql = (None,) * 2
        seg = srch_dict['seg']

        for val in srch_dict[seg]['oui']:
            if oui_list is None:
                oui_list = val
            else:
                oui_list = oui_list + "|^" + val

            sql = """select b.host, b.port, b.vlan, a.mac, c.addr,
                     d.host, b.name, date(b.date), c.base
                     from fdb_macs a
                     left join portinfo b on a.sidx=b.sidx
                     left join arp_data c on a.mac=c.mac
                     left join dns_xref d on c.addr=d.addr
                     where a.mac rlike '^{}'""".format(oui_list)

        return sql

    def type_addr(self, chg, srch_dict):
        addr_list, sql = (None,) * 2
        seg = srch_dict['seg']

        for val in srch_dict[seg]['addr']:
            if addr_list is None:
                addr_list = val
            else:
                addr_list = addr_list + "','" + val

            if chg == '1':
                sql = """select b.host, b.port, b.vlan, a.mac,
                         c.addr, d.host, b.name, date(b.date), c.base
                         from arp_data c
                         left join fdb_macs a on a.mac=c.mac
                         left join portinfo b on a.sidx=b.sidx
                         left join dns_xref d on c.addr=d.addr
                         where c.addr in ('{}')""".format(addr_list)
            else:
                sql = """select b.host, b.port, b.vlan, c.mac, c.addr,
                        d.host, b.name, date(b.date), c.base
                        from arp_data c
                        left join portinfo b on b.sidx=c.sidx
                        left join dns_xref d on c.addr=d.addr
                        where c.addr in ('{}')""".format(addr_list)

        return sql

    def type_name(self, srch_dict):
        nlist, hlist, sql = (None,) * 3 
        seg = srch_dict['seg']

        for val in srch_dict[seg]['name']:
            if nlist:
                nlist = nlist + "','" + val
                hlist = hlist + "|" + val
            else:
                nlist = val
                hlist = val

        sql = """select b.host, b.port, b.vlan, c.mac, c.addr,
                   d.host, b.name, date(b.date), c.base
                   from dns_xref d
                   left join arp_data c on d.addr=c.addr
                   left join fdb_macs a on c.mac=a.mac
                   left join portinfo b on a.sidx=b.sidx
                   where d.host in ('{}')
                   union
                   select b.host,b.port,b.vlan,b.mac,b.addr,
                   b.name,a.name,b.base,date(b.date)
                   from portinfo a, snapshot b
                   where a.name rlike '{}'
                   and a.sidx=b.sidx""".format(nlist, hlist);

        return sql

    def compute(self, method='fdb', values=None, srch_dict=None, vend=None):
        data = {}
        hits = 0

        if srch_dict:
            seg = srch_dict['seg']

        if not values:
            return data

        pat = re.compile("^(\w{2}-\w{2}-\w{2})")
        pat1 = re.compile("^00-00-5e-00-01-(\w+)", re.I)
        pat2 = re.compile("\w+")

        for val in values:
            manf = ''
            hits = hits + 1
            string = ",".join(str(value) for value in val)
            host, port, vlan, mac, addr, name, desc, date, base = string.split(",") 

            mat = pat.match(mac)
            if mat is not None:
                oui = mat.group()
                if oui in vend:
                    manf = vend[oui]

            mat = pat1.match(mac)
            if mat is not None:
                vid = mat.group()
                manf = "VRRP ID %s MAC" % (vid)

            mat = pat2.match(name)
            if mat is None:
                if base in base_dict:
                    name = base_dict[base]

            if ":" in host:
                host, unknown = host.split(":")

            key = "a%03d-%s" % (hits, mac)
            value = "\t".join((mac, host, port, vlan,
                              addr, name, desc, manf, date))

            if method == 'fdb':
                data[mac] = value
            else:
                data[key] = value

            srch_dict[seg]['all'].pop(mac, None)
            srch_dict[seg]['all'].pop(addr, None)
            srch_dict[seg]['all'].pop(name, None)

        return data

    def srch_arp(self, seg, type, srch_dict, base_dict, vend):
        if type == 'name':
            return

        sql = ''

        if type == 'mac':
            srch_dict['seg'] = seg
            sql = self.type_mac(srch_dict)

        if type == 'addr':
            srch_dict['seg'] = seg
            sql = self.type_addr('0', srch_dict)

        if type == 'oui':
            srch_dict['seg'] = seg
            sql = self.type_oui(srch_dict)

        values = self.getResultValues(sql)
        data = self.compute('arp', values, srch_dict, vend)

        return data

    def srch_fdb(self, seg, type, srch_dict, base_dict, vend):
        sql = ''

        if type == 'mac':
            srch_dict['seg'] = seg
            sql = self.type_mac(srch_dict)

        if type == 'name':
            srch_dict['seg'] = seg
            sql = self.type_name(srch_dict)

        if type == 'oui':
            srch_dict['seg'] = seg
            sql = self.type_oui(srch_dict)

        if type == 'addr':
            srch_dict['seg'] = seg
            sql = self.type_addr('1', srch_dict)

        values = self.getResultValues(sql)
        data = self.compute('fdb', values, srch_dict, vend)

        return data
