#!/usr/bin/python3

import re, os, pdb, sys, copy
from pprint import pprint
import time, socket, pexpect, struct
from multiprocessing import Process, Queue

from common.dbconnect import DbConnect
from common.yamlparser import yamlParser
from common.snmpconfig import SNMPConfig
from portinv.common.tmplparser import PageGenerator
shellcmd = "ssh d2caqa01"

class ArpSiteComp:
    def __init__(self):
        self.msg = '' 

        self.snmp_dict = dict()
        self.site_dict = dict()
        self.arpt_dict = dict()
        self.neig_dict = dict()
        self.mact_dict = dict()
        self.port_dict = dict()
        self.hist_dict = dict()
        self.hits_dict = dict()
        self.vlan_dict = dict()
        self.caps_dict = dict()
        self.base_dict = dict()
        self.ping_dict = dict()
        self.snmpconfig = dict()
        self.descr_dict = dict()

        snmp_obj = SNMPConfig()
        self.snmpconfig = snmp_obj.getconfig()

        self.qping = "/appl/nms/bin/qping"
        self.db = DbConnect('pidb')
        self.db.connect()

    def getResultValues(self, sql):
        values = self.db.select_query(sql)
        return values

    def mainPage(self, formField=''):
        res = dict()
        params = dict()
        boot_dict = dict()

        site, ping, boot, filt = (None,) * 4

        if 'site' in formField:
            site = int(formField['site'].value)
            params['site'] = site
        #site = 107

        if 'ping' in formField:
            ping = formField['ping'].value
            params['ping'] = ping
        #ping = 'Poll'

        if 'boot' in formField:
            boot = formField['boot'].value
            params['boot'] = boot
        #boot = 'boot'

        if 'filt' in formField:
            filt = formField['filt'].value
            params['filt'] = filt
        #filt = 'none'

        res_list = list()
        if site:
            t1 = time.time()
            self.load_name()

            if boot:
                boot_dict = self.load_boot(site)

            self.load_real(site, ping)
            if filt:
                self.load_hist(site, filt)
            res_list = self.show_comp(ping, filt)

            t2 = time.time()
            t3 = t2-t1
            self.msg = self.msg + \
                       "<br/><br/>Total time: %d seconds" % t3

        res = {'boot': boot_dict,
               'msg': self.msg,
               'site': self.site_dict,
               'arp': self.arpt_dict,
               'res': res_list}

        genObj = PageGenerator('arpsitecomp.tmpl')
        html = genObj.pageGenerate(None,
                                   values=res,
                                   resPage=res,
                                   params=params)

        return html

    def load_name(self):
        sql = "select base, name from basexref"

        values = self.getResultValues(sql)
        for value in values:
            base = value[0]
            name = value[1]
            self.base_dict[base] = name

    def load_boot(self, site):
        poll = {}
        show = {}

        sql = """select host, addr, uptime from hostinfo
                 where mid(host, 2, 4) = {}""".format(site)

        values = self.getResultValues(sql)

        for value in values:
            host = value[0]
            addr = value[1]
            uptime = value[2]

            poll[host] = addr
            show[host] = ['unknown']

        pat = re.compile(".*sysUpTimeInstance (.*)")
        for host in poll:
            addr = poll[host]

            msg = """Current Network Device Uptimes for Store {}""" \
                .format(site)

            cmd = "{} snmpget {} sysUpTime.0 2>&1"\
                .format(shellcmd, addr)

            output = str(runSNMPCmd(cmd))
            output = output.replace('b\'', '')
            output = output.replace('\\r\\n\'', '')

            mat = pat.match(output)
            if mat is not None:
                uptime = mat.group(1)
                arr = uptime.split(":")
                show[host] = arr
        return show

    def load_real(self, site=None, ping=None):
        addr = '' 
        host = "r%04d" % (site)

        t1 = time.time()

        try:
            addr = str(socket.gethostbyname(host))
        except Exception as err:
            pass

        if re.match("^10\.\d+\.\d+\.\d+", addr) is None:
            self.msg = self.msg +\
                       "<br/><br/>Unable to resolve router address for store {}" \
                .format(site)
            return

        self.site_ping(site)
        t2 = time.time()
        t3 = t2 - t1

        self.msg = self.msg + \
                   ". . . Completed site ping in %d seconds . . ."\
                   % (int(t3))

        if ping:
            pat = re.compile("poll", re.I)
            mat = pat.match(ping)
            if mat is None:
                return

            self.msg = self.msg + "<br/><br/>Repolling FDB . . . "
            t1 = time.time()
            self.process() 
            t2 = time.time()
            t4 = t2 - t1
            self.msg = self.msg + \
                       "Completed repolling from device in %d seconds . . ."\
                       % (int(t4))

    def site_ping(self, site):
        sneta, snete, addr = (None,) * 3
        gate = "r%04d" % (site)

        try:
            addr = str(socket.gethostbyname(gate))
        except Exception as err:
            pass

        self.site_dict[gate] = addr
        pat = re.compile("10\.(\d+)\.(\d+)\.\d+")
        mat = pat.match(addr)

        if pat.match(addr):
            oct = int(mat.group(1))
            oct1 = int(mat.group(2))

            sneta = "10.%d.%d.0/22" % (oct, oct1)
            snete = "10.%d.%d.0/22" % (int(oct) - 64, oct1)

        self.msg = "Pinging {} {} and {}".format(site,
                                                 sneta,
                                                 snete)
        data = ''

        qping = self.qping

        cmd_snete = "{} {} -A -a -g {} 2>&1".format(shellcmd,
                                                    qping,
                                                    snete)
        cmd_sneta = "{} {} -A -a -g {} 2>&1".format(shellcmd,
                                                    qping,
                                                    sneta)

        q1 = Queue()
        q2 = Queue()
        q3 = Queue()

        p1 = Process(target=runSNMPCmd, args=(cmd_sneta, q1))
        p2 = Process(target=runSNMPCmd, args=(cmd_snete, q2))
        p3 = Process(target=func_gate, args=(gate, q3))

        p1.start()
        p2.start()
        p3.start()

        data = data + str(q1.get())
        data = data.replace("b'", "")
        data = data.replace("'", "")
        p1.join()

        data1 = str(q2.get())
        data1 = data1.replace("b'", "")
        data1 = data1.replace("'", "")
        data = data + data1
        p2.join()

        self.arpt_dict = q3.get()
        p3.join()

        arr = data.split("\\r\\n")
        for value in arr:
            pat = re.compile("^(1\S+)$")
            mat = pat.match(value)

            if mat:
                addr = mat.group()
                base = cal_base(addr)

                if addr in self.ping_dict:
                    self.ping_dict[addr] =\
                        self.ping_dict[addr] + 1
                else:
                    self.ping_dict[addr] = 1

                pat1 = re.compile("10.x.a.([34][0-9])")
                mat1 = pat1.match(base)

                if mat1:
                    offs = int(mat1.group(1))
                    if offs == 34:
                        host = "s%04dwl" % (int(site))
                        self.site_dict[host] = addr
                    elif offs > 34:
                        host = "s%04d%s" % (site, chr(97 + offs - 35))
                        self.site_dict[host] = addr

                if base == "10.x.a.196":
                    host = "fw%04da" % (site)
                    self.site_dict[host] = addr

    def process(self):
        q1 = Queue()
        q2 = Queue()
        q3 = Queue()

        for host in self.site_dict:
            descr_dict = dict()
            port_dict = dict()
            neig_dict = dict()
            arpt_dict = dict()

            ver = self.test_snmp(host)

            p1 = Process(target=slot_xref, args=(q1, host, ver,))
            p1.start()

            p2 = Process(target=dump_cdp, args=(q2, host, ver,))
            p2.start()

            p3 = Process(target=dump_arp, args=(q3, host, ver,))
            p3.start()

            arr = q1.get()
            if arr[0]:
                port_dict = arr[0]

            if arr[1]:
                descr_dict = arr[1]
            p1.join()

            neig_dict = q2.get()
            p2.join()

            arpt_dict = q3.get()
            p3.join()

            self.port_dict.update(port_dict)
            self.descr_dict.update(descr_dict)
            self.neig_dict.update(neig_dict)
            self.arpt_dict.update(arpt_dict)

            if re.match("^s", host):
                self.walk_vlans(host, ver,
                                port_dict,
                                descr_dict,
                                neig_dict,
                                arpt_dict)

    def test_snmp(self, host):
        self.snmp_dict[host] = self.snmpconfig['v']

        cmd = "{} snmpget -v {} {} system.sysName.0 2>&1" \
            .format(shellcmd, self.snmp_dict[host], host)
        resp = runSNMPCmd(cmd)

        pat = re.compile("sysName")
        mat = pat.match(str(resp))

        if mat is None:
            if self.snmpconfig['v'] == "3":
                self.snmp_dict[host] = '2c'
            else:
                self.snmp_dict[host] = '3'

            resp = "{} snmpget -v {} {} system.sysName.0 2>&1" \
                .format(shellcmd, self.snmp_dict[host], host)

        ver = "-v %s" % (self.snmp_dict[host])

        return ver

    def load_hist(self, site=None, filter=None):
        site_name = "%04d" % (site)
        gate = "r%04d" % (site)

        addr = '' 
        snetA, snetE = (None,) * 2

        try:
            addr = str(socket.gethostbyname(gate))
        except Exception as err:
            pass

        pat = re.compile("10\.(\d+)\.(\d+)\.\d+")
        mat = pat.match(addr)

        if mat is not None:
            oct2 = int(mat.group(1))
            oct3 = int(mat.group(2))
            snetA = "10.%d.%d.0" % (oct2, oct3)
            oct2 = oct2 - 64
            snetE = "10.%d.%d.0" % (oct2, oct3)

        qry = """select addr, host from cdp_else 
                 where host rlike '{}'""".format(site)
        values = self.getResultValues(qry)

        for value in values:
            ip_addr = value[0]
            hostname = value[1]
            self.caps_dict[ip_addr] = hostname

        qry = """select a.host, b.mac, a.port, a.vlan,
                   c.addr, d.host, c.base, b.date
                  from portinfo a
                  left join fdb_macs b on a.sidx=b.sidx
                  left join arp_data c on b.mac=c.mac
                  left join dns_xref d on c.addr=d.addr
                  where a.host rlike '{}'
                  and a.port not rlike 'vlan|trk[1-9]|snet'
                  and a.sidx not in (select sidx from cdp_neig
                     where host not rlike '^ap[0-9]')
                  union
                  select a.host, null as mac, a.port,
                    a.vlan, b.addr, b.host as host,
                    null as base, b.date
                  from portinfo a, cdp_neig b
                  where a.host rlike '{}' and a.sidx = b.sidx
                  and b.host not rlike '^ap[0-9]'""".format(site,
                                                            site)

        values = self.getResultValues(qry)

        pat = re.compile("^s\d{4}[a-vxyz]")
        pat1 = re.compile("^po\d", re.I)
        pat2 = re.compile("^\d+")
        pat3 = re.compile("^s\d+")
        pat4 = re.compile("\w+")
        pat5 = re.compile("^" + re.escape(filter))
        pat6 = re.compile("^([A-Za-z]+)\d+")

        test_dict = dict()
        pcnt_dict = dict()

        patt = None 
        if snetA and snetE:
            stri = re.escape(snetA) + r"|" + re.escape(snetE)
            patt = re.compile(stri)

        for value in values:
            host = value[0]
            mac = str(value[1])
            port = value[2]
            ip_addr = value[4]
            base = value[6]

            mat = pat.match(host)
            mat1 = pat1.match(port)

            if mat is not None and mat1 is not None:
                continue

            if ip_addr:
                mat2 = pat2.match(ip_addr)
                if mat2 is not None:
                    nettoa1 = ip_addr.split(".") 
                    nettoa2 = str("255.255.252.0").split(".")

                    oct0 = int(nettoa1[0]) & int(nettoa2[0])
                    oct1 = int(nettoa1[1]) & int(nettoa2[1])
                    oct2 = int(nettoa1[2]) & int(nettoa2[2])
                    oct3 = int(nettoa1[3]) & int(nettoa2[3])

                    soc_value = "%d.%d.%d.%d" % (oct0, oct1,
                                                 oct2, oct3)

                if patt: 
                    matt = patt.match(soc_value)
                    if matt is None:
                        continue

            mat3 = pat3.match(host)
            if mat3 is None:
                continue

            mat4 = pat4.match(mac)
            if mat4 is None:
                continue

            pkey = ''
            if port:
                arr = re.split("\D+", port)

                mat6 = pat6.match(port)
                if mat6:
                    arr[0] = mat6.group(1)

                if len(arr) == 4:
                    pkey = "%s:%s:%02d:%02d:%02d" % (host,
                                                     str(arr[0]),
                                                     int(arr[1]),
                                                     int(arr[2]),
                                                     int(arr[3]))
                elif len(arr) == 3:
                    pkey = "%s:%s:%02d:%02d" % (host,
                                                str(arr[0]),
                                                int(arr[1]),
                                                int(arr[2])) 

            if ip_addr:
                arr1 = ip_addr.split("\.")
                if len(arr1) >= 4:
                    ip_addr = "%03d.%03d.%03d.%03d" % (arr1[0],
                                                       arr1[1],
                                                       arr1[2],
                                                       arr1[3])

            # Test this line of code
            if base:
                mat5 = pat5.match(base)
                if filter not in 'none' \
                        and mat5 is None:
                    continue

            hkey = ''
            if ip_addr:
                stri = ''
                hkey = pkey + ',' + ip_addr
                for val in value:
                    stri = stri + "," + str(val)
                self.hist_dict[hkey] = pkey + stri

            if ip_addr in self.hits_dict:
                self.hits_dict[ip_addr] = \
                    self.hits_dict[ip_addr] + 1
            else:
                self.hits_dict[ip_addr] = 1

            test_dict[pkey] = hkey

            if pkey in pcnt_dict:
                pcnt_dict[pkey] =\
                    pcnt_dict[pkey] + 1
            else:
                pcnt_dict[pkey] = 1

        for hkey in self.hist_dict:
            arr = hkey.split(",")
            if arr[0] in pcnt_dict and arr[0] != '':
                if pcnt_dict[arr[0]] > 1:
                    self.hist_dict[hkey] = \
                        self.hist_dict[hkey] + ",o"

    def show_comp(self, ping=None, filt=None):
        neig_dict = self.neig_dict
        upl = dict()
        old = dict()

        for value in neig_dict:
            host = value.split(":")
            neig = neig_dict[value][0][0]
            addr = neig_dict[value][0][1]
            hkey = ''

            if value in self.descr_dict:
                hkey = host[0] + ":" + \
                       self.descr_dict[value]

            if hkey not in upl:
                upl[hkey] = neig

            if hkey not in self.hist_dict: 
                base = cal_base(addr)
                #self.hist_dict[hkey] = "{},{},{},,{},,{},{},{},,"\
                #    .format(host[0], self.descr_dict[value],
                #            addr, neig, base)

        for value in self.hist_dict:
            arr = self.hist_dict[value].split(",")
            if len(arr) >= 3:
                mac = arr[3]
                if mac in self.mact_dict:
                    if mac in old:
                        old[mac] = old[mac] + 1
                    else:
                        old[mac] = 1

        pat = re.compile(r"^s(\w+):\D+(\d+).(\d+)")

        for mac in self.mact_dict:
            if mac in old:
                if old[mac] >= 1:
                    mat = pat.match(self.mact_dict[mac])
                    if not (mat is None):
                        host = mat.group(1)
                        slot = int(mat.group(2))
                        port = int(mat.group(3))
                        pkey = "%s:%02d:%07.4f" % (host, slot, port)

                        key = pkey + "," + mac 
                        if pkey in self.vlan_dict:
                            if mac in self.arpt_dict:
                                val = "{},{},{},unknown,{},{},,{},,n"\
                                    .format(pkey, host, mac,
                                            self.vlan_dict[pkey],
                                            self.arpt_dict[mac][0],
                                            self.arpt_dict[mac][1])
                                self.hist_dict[key] = val 

        pat = re.compile("^s\d{4}(\w)")
        date_pat = re.compile("^\d{,4}-(.*):\d{,2}$")

        res = list()
        for value in self.hist_dict:
            bg = 'white'
            name = ''
            prev = ''
            curr = ''
            name_descr = ''

            arr = self.hist_dict[value].split(",")
            if arr[0] is None or arr[0] == '':
                continue

            addr = arr[5]
            base = arr[7]
            descr = arr[3]

            #if addr > "10" and base <= ' ':
            #    continue

            if base in self.base_dict:
                if 'Handheld' in self.base_dict[base]:
                    continue
                name_descr = self.base_dict[base]
   
            if 'none' not in filt: 
                pat1 = re.compile(re.escape(filt))
                mat1 = pat1.match(base)
                if mat1 is None:
                    continue

            if addr in self.caps_dict:
                name = self.caps_dict[addr]

            if name is None or name == '':
                name = arr[6]
                if name is None:
                    name = ''

            if ',o' in self.hist_dict[value]:
                bg = 'yellow'

            if ',n' in self.hist_dict[value]:
                bg = 'cyan'
                prev = descr
            else:
                prev = arr[1] + ':' + descr

            if arr[2] in self.mact_dict:
                if self.mact_dict[arr[2]] not in prev:
                    curr = self.mact_dict[arr[2]]

            if prev in upl:
                if upl[prev] not in name:
                    curr = upl[prev]

            mat = pat.match(name)
            if mat:
                suf = ord(mat.group(1))
                if suf == 119:
                    base = "10.x.a.%d" % (34)
                else:
                    suf = suf - 97 + 35 
                    base = "10.x.a.%d" % (int(suf))

            date_mat = date_pat.match(arr[8])
            if date_mat:
                date = date_mat.group(1)

            # arr[2] is the Mac address
            mac =  arr[2]
            fontcolor = 'black'

            if ping and addr not in self.ping_dict:
                fontcolor = 'red'
                bg = 'lightgray'

            res.append([addr, mac, prev, curr,
                        arr[4], name, name_descr,
                        date, bg, fontcolor])

        self.msg = self.msg + "<br/><br/> Total records: {}"\
            .format(str(len(res)))

        return res

    def walk_vlans(self, host=None, ver=None,
                   port_dict=None, descr_dict=None,
                   neig_dict=None, arpt_dict=None):
        pas = '' 
        pnum = list()

        vnum_dict = dict()
        xfdb_dict = dict()
        mact_dict = dict()

        cmd_1 = "{} snmpbulkwalk {} {} CISCO-VLAN-MEMBERSHIP-MIB::vmVlan 2>&1" \
            .format(shellcmd, ver, host)

        cmd_2 = "{} snmpbulkwalk {} {} ENTITY-MIB::entLogicalContextName 2>&1" \
            .format(shellcmd, ver, host)

        cmd_3 = "{} snmpbulkwalk {} {} BRIDGE-MIB::dot1dBasePortIfIndex 2>&1" \
            .format(shellcmd, ver, host)

        q1 = Queue()
        q2 = Queue()
        q3 = Queue()

        p1 = Process(target=runSNMPCmd, args=(cmd_1, q1,))
        p2 = Process(target=runSNMPCmd, args=(cmd_2, q2,))
        p3 = Process(target=runSNMPCmd, args=(cmd_3, q3,))

        p1.start()
        p2.start()
        p3.start()

        data_1 = str(q1.get())
        p1.join()

        data_2 = str(q2.get())
        p2.join()

        data_3 = str(q3.get())
        p3.join()

        pat = re.compile(".*::vmVlan\.(\d+) (\d+)")
        pat1 = re.compile("\D+")

        data_1 = data_1.replace("b'", "")
        data_1 = data_1.replace("'", "")

        arr = data_1.split("\\r\\n")
        for value in arr:
            pnum = list()

            mat = pat.match(value)
            if mat:
                sidx = mat.group(1)
                vlan = mat.group(2)

                if vlan in vnum_dict:
                    vnum_dict[vlan] = \
                        vnum_dict[vlan] + 1
                else:
                    vnum_dict[vlan] = 1

                if sidx in self.port_dict:
                    mat1 = pat1.match(port_dict[sidx])
                    if mat1:
                        pnum = port_dict[sidx].replace(mat1.group(), "") \
                            .split("/")

                    if len(pnum) >= 3:
                        pkey = "%s:%02d:%02d:%02d" % (host,
                                                      int(pnum[0]),
                                                      int(pnum[1]),
                                                      int(pnum[2]))
                        self.vlan_dict[pkey] = vlan

        pat = re.compile(".*::entLogicalContextName.+ vlan-(\d+)")

        data_2 = data_2.replace("b'", "")
        data_2 = data_2.replace("'", "")
        arr = data_2.split("\\r\\n")

        for value in arr:
            mat = pat.match(value)
            if mat is not None:
                if mat.group(1) in vnum_dict:
                    vnum_dict[mat.group(1)] = \
                        vnum_dict[mat.group(1)] + 1
                else:
                    vnum_dict[mat.group(1)] = 1

        pat = re.compile(".*dot1dBasePortIfIndex\.(\d+) (\d+)")
        pat1 = re.compile("^Po")

        data_3 = data_3.replace("b'", "")
        data_3 = data_3.replace("'", "")
        arr = data_3.split("\\r\\n")

        for value in arr:
            mat = pat.match(value)
            if mat is not None:
                sidx = mat.group(1)
                port = mat.group(2)

                if port in port_dict:
                    mat1 = pat1.match(port_dict[port])
                    if not (mat1 is None):
                        xfdb_dict[sidx] = port

        if vnum_dict:
            for vlan in vnum_dict:
                if host in self.snmp_dict:
                    if self.snmp_dict[host] == 3:
                        pas = "-n vlan-%d" % (vlan)
                    else:
                        if 'c' in self.snmpconfig:
                            pas = "-c %s@%d" % \
                                  (self.snmpconfig['c'], int(vlan))
                            mact_dict = dump_ports(host, ver, pas,
                                                   xfdb_dict, descr_dict,
                                                   port_dict, neig_dict)
        else:
            mact_dict = dump_ports(host, ver, pas,
                                   xfdb_dict, descr_dict,
                                   port_dict, neig_dict)

        self.mact_dict.update(mact_dict)


def dump_arp(q=None, host=None, ver=None):
    arpt_dict = dict()

    pat = re.compile("^fw[0-9]")
    mat = pat.match(host)

    if mat:
        cmd = "/appl/nms/SNMShpoo/bin/hpoo-headless.pl -f 1 -a {}" \
             .format(host)

        data = str(runSNMPCmd(cmd))
        data = data.replace("b'", "")
        data = data.replace("'", "")
        data = data.replace("\\t", "")

        arr = data.split("\\r\\n")

        pat1 = re.compile("(\w{2})(\w{2}).(\w{2})(\w{2}).(\w{2})(\w{2})")
        pat2 = re.compile("^10\.")

        for value in arr:
            if 'show' in value:
                continue

            if 'done' in value:
                continue
 
            if '---------' in value:
                continue

            try:
                arr1 = value.split(" ")

                if len(arr1) >= 3:
                    addr = arr1[1]
                    mac = arr1[2]

                    mat2 = pat2.match(addr)
                    if mat2 is None:
                        continue

                    mat1 = pat1.match(mac)
                    if mat1:
                        mac = "%s-%s-%s-%s-%s-%s" % (mat1.group(1),
                                                     mat1.group(2),
                                                     mat1.group(3),
                                                     mat1.group(4),
                                                     mat1.group(5),
                                                     mat1.group(6))
                    base = cal_base(addr)
                    mac = mac.upper()
                    arpt_dict[mac] = [addr, base]
            except Exception as err:
                pass
    else:
        cmd = "{} snmptable {} -CHi -Cf :: -O0x {} ipNetToMediaTable 2>&1" \
            .format(shellcmd, ver, host)

        data = str(runSNMPCmd(cmd))
        data = data.replace("b'", "")
        data = data.replace("'", "")
        arr = data.split("\\r\\n")

        for value in arr:
            mac, addr = (None,) * 2
            arr1 = str(value).split("::")

            if len(arr1) >= 4:
                mac = str(arr1[2])
                addr = str(arr1[3])

            if mac and addr:
                mac = mac.replace(":", "-")
                mac = mac.upper()

                base = cal_base(addr)
                arpt_dict[mac] = [addr, base]

    q.put(arpt_dict)


def dump_cdp(q=None, host=None, ver=None):
    neig_dict = dict()
    ifName = dict()
    n_addr = dict()
    n_name = dict()
    n_port = dict()
    n_type = dict()

    cmd = "{} snmpbulkwalk {} {} CISCO-CDP-MIB::cdpCache 2>&1"\
        .format(shellcmd, ver, host)

    pat = re.compile(".*cdpCacheAddress.(\d+)\.\d+ \"(.+)\"$")
    pat1 = re.compile("1.1.4.(\d+).\d+::(\W+)")
    pat2 = re.compile(".*cdpCacheDeviceId\.(\d+).\d+ (.+)$")
    pat3 = re.compile(".*cdpCacheDevicePort\.(\d+)\.\d+ (\S+)$")
    pat4 = re.compile(".*cdpCachePlatform\.(\d+)\.\d+ (.+)$")

    data = str(runSNMPCmd(cmd))
    data = data.replace('b\'', "")
    data = data.replace('\'', "")
    arr = data.split("\\r\\n")

    for value in arr:
        mat = pat.match(value)
        mat1 = pat1.match(value)
        mat2 = pat2.match(value)
        mat3 = pat3.match(value)
        mat4 = pat4.match(value)

        if mat:
            key = mat.group(1)
            val = mat.group(2)

            ifName[key] = key
            hex_arr = val.split(" ")
            hexa = list()

            for value in hex_arr:
                if value:
                    integ = int(value, 16)
                    hexa.append(integ)

            addr = "%s.%s.%s.%s" % (hexa[0],
                                    hexa[1],
                                    hexa[2],
                                    hexa[3])
            n_addr[key] = addr
        elif mat1:
            # IP address will be in the Hex format: 0x0aeb5822
            key = mat1.group(1)
            hexa_ip = mat1.group(2)

            ifName[key] = key

            addr_long = int(hexa_ip, 16)
            ip_addr = socket.inet_ntoa(struct.pack(">L", addr_long))
            n_addr[key] = ip_addr
        elif mat2:
            key = mat2.group(1)
            dat = mat2.group(2)

            ifName[key] = key

            pat5 = re.compile("\((\w+)\)")
            mat5 = pat5.match(dat)
            if mat5:
                dat = key

            dat = dat.replace(".safeway.com", "")
            n_name[key] = dat
        elif mat3:
            ifName[mat3.group(1)] = mat3.group(1)
            n_port[mat3.group(1)] = mat3.group(2)
        elif mat4:
            ifName[mat4.group(1)] = mat4.group(1)
            n_type[mat4.group(1)] = mat4.group(2)

    for value in ifName:
        if "air-cap" in n_type[value]\
                or "phone" in n_type[value]:
            continue

        key = host + ":" + ifName[value]
        if value in n_name and value in n_addr:
            neig_dict[key] = [(n_name[value], n_addr[value])]

    q.put(neig_dict)


def dump_ports(host=None, ver=None, pas=None,
               xfdb_dict=None, descr_dict=None,
               port_dict=None, neig_dict=None):

    mact_dict = dict()
    cmd = "{} snmpbulkwalk -OX {} {} {} BRIDGE-MIB::dot1dTpFdbPort 2>&1" \
        .format(shellcmd, ver, pas, host)

    data = str(runSNMPCmd(cmd))
    data = data.replace("b'", "")
    data = data.replace("'", "")
    arr = data.split("\\r\\n")

    pat = re.compile(".*dot1dTpFdbPort\[(\S+)\] (\d+)")
    for value in arr:
        mat = pat.match(value)
        if mat:
            mac = mat.group(1)
            idx = mat.group(2)
            mac = mac.upper()
            mac = mac.replace(":", "-")

            if xfdb_dict:
                if idx in xfdb_dict:
                    if xfdb_dict[idx] in port_dict:
                        nkey = host + ":" + xfdb_dict[idx]

                        if nkey not in neig_dict:
                            mact_dict[mac] = host + ":" +\
                                             descr_dict[nkey]
    return mact_dict


def runSNMPCmd(cmd=None, q=None):
    output = None

    if cmd:
        pexp_obj = pexpect.spawn("/bin/sh", ["-c", cmd])
        pexp_obj.expect(pexpect.EOF, timeout=None)
        output = pexp_obj.before

    if q:
        q.put(output)
    else:
        return output


def func_gate(gate=None, q=None):
    arpt_dict = dict()

    cmd = "{} snmpbulkwalk -O 0 {} IP-MIB::ipNetToMediaPhysAddress 2>&1" \
        .format(shellcmd, gate)

    data = str(runSNMPCmd(cmd))
    data = data.replace("b'", "")
    data = data.replace("'", "")
    arr = data.split("\\r\\n")

    for value in arr:
        pat = re.compile("IP-MIB::ipNetToMediaPhysAddress\.\d+\.(\S+) (\S+)")
        mat = pat.match(value)

        ip, mac = (None,) * 2
        if mat:
            ip = mat.group(1)
            mac = mat.group(2)
            mac = mac.upper()
            mac = mac.replace(":", "-")

        if ip is not None:
            base = cal_base(ip)
            arpt_dict[mac] = [ip, base]

    # return site_dict, arpt
    q.put(arpt_dict)


def slot_xref(q=None, host=None, ver=None):
    cmd = "{} snmpbulkwalk {} {} IF-MIB::ifName 2>&1" \
        .format(shellcmd, ver, host)

    data = str(runSNMPCmd(cmd))
    data = data.replace("b'", "")
    data = data.replace("'", "")
    arr = data.split("\\r\\n")

    port_dict = dict()
    descr_dict = dict()

    for value in arr:
        slot, sidx, name = (None,) * 3

        pat = re.compile(".*IF-MIB::ifName\.(\d+) (\S+)")
        mat = pat.match(str(value))

        if mat:
            sidx = mat.group(1)
            name = mat.group(2)

            port_dict[sidx] = name
            val = host + ":" + sidx
            descr_dict[val] = name

    q.put([port_dict, descr_dict])


def cal_base(addr):
    base = None

    pat = re.compile("^10\.(\d+)\.(\d+)\.(\d+)")
    mat = pat.match(addr)

    if mat:
        bnet = mat.group(1)
        snet = mat.group(2)
        offs = mat.group(3)

        snet = int(snet) % 4
        if int(bnet) >= 192:
            base = "10.x.%c.%d" % (ord("a") +
                                   snet, int(offs))
        elif int(bnet) >= 128:
            base = "10.y.%c.%d" % (ord("e") +
                                   snet, int(offs))

    return base
