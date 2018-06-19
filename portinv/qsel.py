#!/usr/bin/python3

import os, sys, re, pdb, hashlib
from pprint import pprint

#sys.path.insert(0, os.getcwd())

from common.dbconnect import DbConnect
from portinv.common.tmplparser import PageGenerator


class QuickSelect:
    def __init__(self):
        self.db = DbConnect('pidb')
        self.db.connect()

    def getSiteGroupValues(self):
        self.values = self.db.select_query("""select distinct fac from sitexref where
                                              host rlike '^r[0-4]' and fac > ' ' or
                                              host rlike '^r[a-z]' and fac > ' ';""")
        return self.values

    def getResultValues(self, sql):
        self.values = self.db.select_query(sql)
        return self.values

    def mainPage(self, formField):
        resPage = ''
        siteGroupValues = self.getSiteGroupValues()
        site, mask, vlan, restmpl = (None, ) * 4
        params = {'site': None, 'mask': '', 'vlan': ''}

        if 'site' in formField:
            site = formField['site'].value
            params['site'] = site

        if 'mask' in formField:
            mask = formField['mask'].value
            params['mask'] = mask

        if 'vlan' in formField:
            vlan = formField['vlan'].value
            params['vlan'] = vlan

        if 'site' in formField:
            if 'Retail' in formField['site'].value:
                resPage = self.show_retail(site, mask)
                restmpl = 'tabletmpl.tmpl'
            else:
                resPage = self.do_query(site, mask, vlan)
                restmpl = 'nontabletmpl.tmpl'

        show = ''
        if 'show' in formField:
            show = formField['show'].value

        if ('host' in formField or 'mask' in formField) and 'site' not in formField:
            if 'host' in formField:
                host = formField['host'].value

                restmpl = 'resultPage.tmpl'
                hd_det = {'hostname': host}

                return_val = self.load_xref(host, 0)

                if isinstance(return_val, dict):
                    res = self.view_host(host, vlan, return_val)
                    det, loc = ('',) * 2

                    if host in return_val['inv']:
                        det = " ".join(return_val['inv'][host][0])

                    if host in return_val['location']:
                        loc = return_val['location'][host]

                    hd_det = {'hostname': host, 'details': det, 'loc': loc}
                else:
                    res = return_val

                genObj = PageGenerator(restmpl)
                html = genObj.resPageGenerate(restmpl, res, hd_det)

                return html
            elif 'mask' in formField:
                restmpl = 'maskResult.tmpl'

                mask = formField['mask'].value
                return_val = self.load_xref(mask, 1)
                res = self.view_mask(mask, show, vlan, return_val)
 
                hd_det = {} 

                genObj = PageGenerator(restmpl)
                html = genObj.resPageGenerate(restmpl, res, hd_det)

                return html
            else:
                restmpl = 'usage.tmpl'
                genObj = PageGenerator('usage.tmpl')

                return (genObj.resPageGenerate(restmpl))

        genObj = PageGenerator('qsel.tmpl')
        html = genObj.pageGenerate(restmpl, siteGroupValues, resPage, params)

        return html

    def show_retail(self, site=None, mask=None):
        filt = '^r[0-4]'
        sql = None

        if mask is not None:
            filt = mask

        if 'Any' in site:
            sql = """select host from hostinfo where host rlike '{}' order by host""".format(filt)
        else:
            sql = """select b.host, b.divna, b.dstno, b.street, b.city, b.st, b.zip
                     from sitexref a, sitelist b where a.host = b.host 
                     and a.fac = '{}' and a.host rlike '{}'
                     order by a.host""".format(site, filt)

        values = self.getResultValues(sql)
        return values

    def do_query(self, site=None, mask=None, vlan=None):
        sql = None
        filter = None

        if mask:
            filter = mask
        else:
            if 'Retail' in site:
                filter= "^r[0-4]"
            else:
                filter = "^[rs][a-z]"
            vlan = None

        if vlan is not None:
            sql = """select host from portinfo where vlan = '{}'
                     and host rlike '{}' order by host""".format(vlan, filter)
        elif 'Any' in site:
            sql = """select host from hostinfo where host rlike '{}'
                     order by host""".format(filter)
        else:
            sql = """select host from sitexref where fac = '{}'
                     and host rlike '{}' order by host""".format(site, filter)

        values = self.getResultValues(sql)
        return values

    def load_xref(self, host=None, type=0):
        vend = {}
        # Disable encoding for database.
        self.db.connect(False)

        sql = "select * from oui_xref;"
        values = self.getResultValues(sql)
        self.db.connect()

        pat = re.compile(r"[\"\']")
        pat_arr = ["\s*internat\S+", "\s*communica\S+", "\s*tech\S*", "\s*corp\S*", "\s*inc\S*"]

        for tup in values:
            oui = str(tup[0])
            oui = re.sub('b\'|\'','',oui)
            vendor = str(tup[1])
            vendor = re.sub('b\'|\'','',vendor)

            vendor = pat.sub("", vendor)
            for regex in pat_arr:
                pat_sub = re.compile(regex, re.I)
                vendor = pat_sub.sub("", vendor) 
            vend[oui] = vendor

        if type == 0:
            sql = """select count(*) from hostinfo where host='{}'""".format(host)
            res = self.getResultValues(sql)
            host_cnt = res[0][0]

            if not host_cnt:
                return "No matches found for host '{}'".format(host)

        if type > 0:
            mask = host

        base_dict = {}

        if re.match(r"(\d{4})", host):
            mask = re.match(r"(\d{4})", host).group()

            sql = """select base, name from basexref"""
            values = self.getResultValues(sql)

            for tup in values:
                base = tup[0]
                name = tup[1]
                base_dict[base] = name.upper()
        else:
            mask = '^[a-z][a-z][a-z]|^d2' # Culpeper or d2 fix

        sql = """select a.host, a.addr, a.oid, a.loc, b.serialnumber
                 from hostinfo a
                 left join hpna.hpna b on a.host=b.name
                 where a.host rlike '{}'""".format(mask)

        values = self.getResultValues(sql)

        inv = {}
        mod = {}
        location = {}

        for tup in values:
            string = None

            for val in tup:
                if val is None:
                    val = ' '

                if string is None:
                    string = val
                else:
                    string = string + '::::' + val

            host, addr, oid, loc, snum = string.split("::::")

            oid = re.sub(".+MIB\.", "", str(oid))

            if re.match(r"\w+", snum):
                oid = oid + " -- SN: {}".format(snum)

            location[host] = loc

            if oid not in "Unknown":
                mod[host] = oid

            if host in inv:
                inv[host].append((addr, oid))
            else:
                inv[host] = [(addr, oid)]

        if re.match(r"\d{4}", host):
            sql = """select base, name from basexref"""
            values = self.getResultValues(sql)

            for tup in values:
                base = tup[0]
                name = tup[1]
                base_dict[base] = name.upper()

        return_dict = {'location': location, 'inv': inv, 'mod': mod, 'base': base_dict, 'vend': vend}
        return return_dict

    def view_host(self, host=None, Vlan=None, value_dict=None):
        inv = value_dict['inv']
        location = value_dict['location']
        mod = value_dict['mod']
        Base = value_dict['base']
        vnd = value_dict['vend']

        sql = "select sidx,pidx from pgrpinfo where sidx rlike '{}'".format(host)
        values = self.getResultValues(sql)

        pgrp = {}
        res = []

        for tup in values:
            sidx = tup[0]
            pidx = tup[1]

            pgrp[sidx] = pidx
            if pidx in pgrp:
                pgrp[pidx].append(sidx)
            else:
                pgrp[pidx] = [sidx]

        afix = {}
        pat = re.compile(r"(\d{4})")
        mat = pat.match(host)

        if mat is not None:
            val = re.match(r"(\d{4})", host).group()
            gate = "fw%sa" % (val)
            sql = """select a.mac,a.addr,b.host,a.base
                     from arp_data a left join dns_xref b on a.addr = b.addr
                     where a.sidx rlike '{}'""".format(gate)
            values = self.getResultValues(sql)

            for tup in values:
                mac = tup[0]
                addr = tup[1]
                host = tup[2]
                base = tup[3]

                if mac in afix:
                    afix[mac].append((addr, host, base))
                else:
                    afix[mac] = [(addr, host, base)]

        sql = """select a.sidx, a.port, a.vlan, b.mac, c.addr, d.host, c.base,
                 a.name as dscr, date(b.date)
                 from portinfo a
                 left join fdb_macs b on a.sidx=b.sidx
                 left join arp_data c on b.mac=c.mac
                 left join dns_xref d on c.addr=d.addr
                 where a.host = '{0}' and a.port not rlike 'vlan|trk[1-9]|snet'
                 and a.sidx not in (select sidx from cdp_neig)
                 and a.sidx not in (select sidx from portaddr)
                 # append CDP neighbors
                 union
                 select a.sidx,a.port,a.vlan,null as mac,b.addr,b.host as host,
                 null as base,null as dscr,date(b.date)
                 from portinfo a, cdp_neig b
                 where a.host = '{0}' and a.sidx = b.sidx
                 # get addressed ports
                 union
                 select a.sidx, a.port, a.vlan,null as mac, b.addr, null as host, null as base,
                 a.name as dscr, date(b.date)
                 from portinfo a, portaddr b
                 where a.host = '{0}' and a.sidx=b.sidx""".format(host)

        values = self.getResultValues(sql)

        pat_arr = ["^lo\d","^eo\d","^as\d","^n[ue]\d","^snet","^trk[1-9]","^inband","^s[cl]\d","^vlan/"]
        port_pat = re.compile("^vl\d", re.I)
        host_pat = re.compile("^s\d{4}")
        port_1_pat = re.compile("^po\d", re.I)
        host_1_pat = re.compile("^s\d{4}[a-vxyz]")

        show = {}
        neig = {}
        pkey_dict = {}

        for tup in values:
            string = None
            for val in tup:
                if string is None:
                    string = val
                else:
                    string = string + "::::" + str(val)
            string = re.sub("NULL", " ", string)

            pkey, port, vlan, mac, addr, host_name, base, name, date = string.split('::::')

            regex_match = 0
            for regex in pat_arr:
                desc_pat = re.compile(regex, re.I)
                if desc_pat.match(port) is not None:
                    regex_match = 1

            if regex_match == 1:
                continue

            if port_pat.match(port) is not None and host_pat.match(host_name) is not None:
                continue

            if port_1_pat.match(port) is not None and host_1_pat.match(host_name) is not None:
                continue

            kval = 0
            skey = None

            pat = re.compile(r":(\d+)")
            mat = pat.match(pkey)

            if mat:
                kval = mat.group(1)

            patt = re.compile(r"([A-Z])(\d+)")
            port1_pat = re.compile(r"\D*(\d+)\D(\d+)")

            mat0 = patt.match(port)
            mat1 = port1_pat.match(port)

            if mat0 is not None:
                snum = mat0.group(1)
                pnum = mat0.group(2)
                skey = "%-3s%03d.%05d." % (str(snum), int(pnum), int(kval))
            elif mat1 is not None:
                snum = mat1.group(1)
                pnum = mat1.group(2)
                skey = "%03i%03i%s%05i%s" % (int(snum), int(pnum), '.', int(kval), '.')
            else:
                val = 0
                if re.match(r"\D*(\d+)", port):
                    val = re.match(r"\D*(\d+)", port).group(1)
                skey = "%d%d.%d." % (999, int(val), int(kval))

            skey = skey + mac

            show[skey] = (pkey, port, vlan, mac, addr, host_name, base, name, date)
            pkey_dict[pkey] = port

            if host_name in inv:
                neig[skey] = host_name

        bgcolor_dict = {}
        for key in show:
            hyperlink = 1
            pkey, descr, vlan, mac, addr, hostname, base, desc, date = show[key]

            
            if len(bgcolor_dict) == 0:
                bgcolor_dict[vlan] = "ffffff" 
            elif vlan not in bgcolor_dict:
                md = hashlib.md5()
                md.update(str(vlan).encode('utf-8'))
                bgcolor = md.hexdigest()[1:7]
                bgcolor_dict[vlan] = bgcolor

            if mac == 'None':
                mac = ''

            if addr == 'None':
                addr = ''

            if hostname == 'None':
                hyperlink = 0
                hostname = ''

            if mac in afix:
                hyperlink = 0 
                addr, hostname, base = afix[mac]

            patt = re.compile(r"\w+")
            mat = patt.match(descr)
            if mat is None:
                continue

            host, val = pkey.split(":")

            pmem = []
            if pkey in pgrp:
                for value in pgrp[pkey]:
                    if value in pkey_dict:
                        pmem.append(pkey_dict[value])
                desc = "%s -- Port Group: %s" % (desc, ", ".join(pmem))

            patt = re.compile(r"^00-07-85")
            mat = patt.match(mac)
            if mat:
                hostname = "IP Phone"
                hyperlink = 0

            if Vlan is not None:
                if vlan != Vlan:
                    continue

            slot, Port = (0,) * 2
            patt = re.compile(r"^([A-Z])(\d+)")
            mat = patt.match(descr)

            pat1 = re.compile(r"^\s*\d+\s*$")
            mat1 = pat1.match(descr)

            pat2 = re.compile(r"[A-Za-z]*(\d+)\/(\d+)")
            mat2 = pat2.match(descr)

            if mat is not None:
                slot = (ord(mat.group(1)) - ord('A')) + 1
                Port = mat.group(2)
            elif mat1:
                slot = 0
                Port = descr
            elif mat2:
                slot = mat2.group(1)
                Port = mat2.group(2)

            if desc in inv:
                hostname = desc

            if key in neig:
                hostname = neig[key]
                hyperlink = 1 

            oui = None
            vend = ''

            if mac:
                oui = mac[0:8]

            if oui is not None:
                if oui in vnd:
                    vend = str(vnd[oui])
                else:
                    vend = ''

            if hostname in inv:
                if hostname in mod:
                    vend = mod[hostname]
                    desc = "uplink to {}".format(host)
            else:
                if not hostname and base in Base:
                    hostname = Base[base]
                    hyperlink = 0

            if base in Base:
                hostname = "%s %s" % (base, hostname)
                hyperlink = 0

            if desc is not None and hostname == '':
                hostname = desc
                hyperlink = 0

            if host == hostname:
                continue

            if date != 'None':
                pat_date = re.compile("^\d+-(\d+)-(\d+)")
                mat_date = pat_date.match(date)

                if mat_date:
                    date = "%02d/%02d" % (int(mat_date.group(1)), int(mat_date.group(2)))
            else:
                date = ''

            res.append([slot, Port, vlan, descr, mac, addr, hostname, vend, date, hyperlink, bgcolor_dict[vlan]])

        return res

    def view_mask(self, mask=None, Show=None, Vlan=None, value_dict=None):
        inv = value_dict['inv']
        location = value_dict['location']
        mod = value_dict['mod']
        Base = value_dict['base']
        vnd = value_dict['vend']

        sql = "select sidx,pidx from pgrpinfo where sidx rlike '{}'".format(mask)
        values = self.getResultValues(sql)

        pgrp = {}
        res = []

        for tup in values:
            sidx = tup[0]
            pidx = tup[1]

            pgrp[sidx] = pidx
            if pidx in pgrp:
                pgrp[pidx].append(sidx)
            else:
                pgrp[pidx] = [sidx]

        afix = {}
        pat = re.compile(r"(\d{4})")
        mat = pat.match(mask)

        if mat is not None:
            val = re.match(r"(\d{4})", mask).group()
            gate = "fw%04da" % (int(val))
            sql = """select a.mac,a.addr,b.host,a.base
                     from arp_data a left join dns_xref b on a.addr = b.addr
                     where a.sidx rlike '{}'""".format(gate)
            values = self.getResultValues(sql)

            for tup in values:
                mac = tup[0]
                addr = tup[1]
                host = tup[2]
                base = tup[3]

                if mac in afix:
                    afix[mac].append((addr, host, base))
                else:
                    afix[mac] = [(addr, host, base)]

        sql = """select a.sidx, a.port, a.vlan, b.mac, c.addr, d.host, c.base,
                 a.name as dscr,b.mac is not null as pcnt, date(b.date)
                 from portinfo a
                 left join fdb_macs b on a.sidx=b.sidx
                 left join arp_data c on b.mac=c.mac
                 left join dns_xref d on c.addr=d.addr
                 where a.host rlike '{0}' and a.port not rlike 'vlan|trk[1-9]|snet'
                 and a.sidx not in (select sidx from cdp_neig)
                 # append CDP neighbors
                 union
                 select a.sidx,a.port,a.vlan,null as mac,b.addr,b.host as host,
                 null as base,null as dscr, b.addr is not null as pcnt, date(b.date)
                 from portinfo a, cdp_neig b
                 where a.host rlike '{0}' and a.sidx = b.sidx""".format(mask)

        values = self.getResultValues(sql)

        desc_pat = re.compile("^lo\d|^eo\d|^as\d|^n[ue]\d|^snet|^trk[1-9]|^inband|^s[cl]\d|^vlan/", re.I)
        port_pat = re.compile("^vl\d", re.I)
        host_pat = re.compile("^s\d{4}")
        port_1_pat = re.compile("^po\d", re.I)
        host_1_pat = re.compile("^s\d{4}[a-vxyz]")

        show = {}
        neig = {}
        pkey_dict = {}

        for tup in values:
            string = None 
            for val in tup:
                if string:
                    string = string + "::::" + str(val)
                else:
                    string = str(val)
            string = re.sub("None", "", string)

            pkey, port, vlan, mac, addr, hostname, base, name, pcnt, date = string.split('::::')

            if desc_pat.match(port) is not None:
                continue

            if port_pat.match(port) is not None and host_pat.match(hostname) is not None:
                continue

            if port_1_pat.match(port) is not None and host_1_pat.match(hostname) is not None:
                continue

            kval = 0
            skey = None

            pat = re.compile(r":(\d+)")
            mat = pat.match(pkey)

            if mat:
                kval = mat.group(1)

            patt = re.compile(r"([A-Z])(\d+)")
            port1_pat = re.compile(r"\D*(\d+)\D(\d+)")

            mat0 = patt.match(port)
            mat1 = port1_pat.match(port)

            if mat0 is not None:
                snum = mat0.group(1)
                pnum = mat0.group(2)
                skey = "%s:%-3s%03d.%05d." % (host, str(snum), int(pnum), int(kval))
            elif mat1 is not None:
                snum = mat1.group(1)
                pnum = mat1.group(2)
                skey = "%s:%03d%03d.%05d." % (host, int(snum), int(pnum), int(kval))
            else:
                val = 0
                if re.match(r"\D*(\d+)", port):
                    val = re.match(r"\D*(\d+)", port).group(1)
                skey = "%s:%03d%03d.%05d." % (host, 999, int(val), int(kval))

            pat = re.compile(r"\d+:")
            mat = pat.match(skey)
            if mat:
                val = "%03d:" % (int(mat.group()))
                skey = re.sub("\d+:", val, skey)

            skey = skey + mac
            skey = re.sub(" ", "0", skey)

            show[skey] = (pkey, port, vlan, mac, addr, hostname, base, name, date, pcnt)
            pkey_dict[pkey] = port

            if hostname in inv:
                neig[skey] = hostname

        res = [] 
        tooltip = ''

        for skey in show:
            pkey, descr, vlan, mac, addr, hostname, base, desc, date, pcnt = show[skey]

            if mac == 'None':
                mac = ''

            if addr == 'None':
                addr = ''

            if hostname == 'None':
                hostname = ''

            if mac in afix:
                addr, host, base = afix[mac][0]

            if Show == 'open' and int(pcnt) > 0:
                continue

            if Show == 'used' and pcnt == 1:
                continue

            if Show == 'cdp':
                if hostname not in inv:
                    continue

            if Vlan is not None:
                if vlan != Vlan:
                    continue

            arr = pkey.split(":")
            host = arr[0]
            Port = ":".join((host, descr))

            pmem = []
            if pkey in pgrp:
                for val in pgrp[pkey]:
                    if val in pkey_dict:
                        pmem.append(pkey_dict[val])
                desc = "%s -- Port Group: %s" % (desc, ", ".join(pmem))

            patt = re.compile(r"^00-07-85")
            mat = patt.match(mac)
            if mat is not None:
                hostname = "IP Phone"

            oui = None
            vend = ''

            if mac:
                oui = mac[0:8]

            if oui is not None:
                if oui in vnd:
                    vend = str(vnd[oui])
                else:
                    vend = ''

            if hostname in mod:
                hostname = mod[hostname]

            if skey in neig:
                hostname = neig[skey]

            if 'Po1' in descr:
                if skey in neig:
                    if neig[skey] is None:
                        continue

            if desc in inv:
                host = desc

            if skey in neig:
                hostname = neig[skey]

            if hostname in inv:
                if hostname in mod:
                    vend = mod[hostname]
                    tooltip = "Browse to neighbor"
            else:
                if not hostname and base in Base:
                    hostname = Base[base]

            if base in Base:
                tooltip = base

            port = "%s:%s" % (host, descr)

            if host == hostname:
                continue

            if date != 'None':
                pat_date = re.compile("^\d+-(\d+)-(\d+)")
                mat_date = pat_date.match(date)

                if mat_date:
                    date = "%02d/%02d" % (int(mat_date.group(1)), int(mat_date.group(2)))
            else:
                date = ''

            res.append([port, vlan, mac, addr, hostname, vend, date, tooltip])

        return res
