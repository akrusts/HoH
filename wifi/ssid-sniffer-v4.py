#!/usr/bin/env python
# -*- coding: utf-8 -*-

from scapy.all import *


from threading import Thread
import subprocess,shlex,time
import threading
import time
import sys



import requests
import json

import sqlite3


db="sniffer.db"
interface="wlan0mon"
interfaceWifi="wlan0"


conn = sqlite3.connect(db)
c = conn.cursor()

c.execute("create table if not exists  manuf (prefix text, manuf text)")
c.execute("create table if not exists  ap (time int, ssid text,address text, capability text,signal int)")
c.execute("create table if not exists  probes (time int, ssid text,address text, signal int)")
c.execute("create table if not exists  log (time int, timestr text, log text)")

conn.commit()
conn.close()



def log(msg):
 global db
 tstr = time.strftime("%b %d %Y %H:%M:%S", time.gmtime())
 logmsg = "[*] %s: %s" % (tstr,msg)
 print logmsg
 conn = sqlite3.connect(db)
 ct = conn.cursor()
 ct.execute("insert into log values (?,?,?)", (tstr,time.time(),msg))
 conn.commit()
 conn.close()

def get_manuf(db,hw):
        prefix = hw[0:8] 
        conn = sqlite3.connect(db)
        ct = conn.cursor()
        ct.execute("select manuf from manuf where prefix = '%s'" % prefix)
        conn.commit()
        rows = ct.fetchall()
        if len(rows) > 0:
         rc = rows[0][0]
        else:
         rc = 'N/A'
        conn.close()
        return rc



locky = threading.Lock()


def Change_Freq_channel(channel_c):
        command = 'iwconfig ' + interface + ' channel '+str(channel_c)
        command = shlex.split(command)
        subprocess.Popen(command,shell=False) # To prevent shell injection attacks ! 

def Loop_Ch():
 while True:
       for channel_c in range(1,15):
          t = Thread(target=Change_Freq_channel,args=(channel_c,))
          t.daemon = True
          locky.acquire()
          t.start()
          time.sleep(0.1)
          locky.release()


log("Starting monitor mode for interface %s" % (interfaceWifi))
command = 'airmon-ng start ' + interfaceWifi
command = shlex.split(command)
try:
 subprocess.check_call(command,shell=False) # To prevent shell injection attacks ! 
except:
 log("Failed to enable monotor mode on %s interface" % (interfaceWifi))
 sys.exit(1)
log("Starting channel hopping")
ch=Thread(target=Loop_Ch)
ch.daemon = True
ch.start()

ap_list = []
def PacketHandler(pkt) :

    global db

    if pkt.haslayer(Dot11) :


        #pkt.show()


        try:
            sig_str = -(256 - ord(pkt.notdecoded[-4:-3]))
        except:
            sig_str = 0

        try:
          channel = int( ord(pkt[Dot11Elt:3].info))
        except:
          channel = -1


        try:
            capability = pkt.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}\
                                    {Dot11ProbeResp:%Dot11ProbeResp.cap%}")
        except:
            capability = ""

        if capability != "":
            if re.search("privacy", capability): 
                enc = '(encrypted)'
            else:
                enc  = '(open)'

        capability.replace(" ","")

        conn = sqlite3.connect(db)
        c = conn.cursor()
        tm=time.time()


        #c.execute("create table if not exists  manuf (prefix text, manuf text)")
        #c.execute("create table if not exists  ap (time int, ssid text,address text, capability text,signal int)")
        #c.execute("create table if not exists  probes (time int, ssid text,address text, signal int)")

        if pkt.type == 0 and pkt.subtype == 8 :
            if pkt.addr2 not in ap_list :
                                ap_list.append(pkt.addr2)
                                logmsg = "AP MAC: %s, SSID: '%s' %s, channel %d, signal: %ddBm, %s" %(pkt.addr2, pkt.info,enc,channel,sig_str,get_manuf(db,pkt.addr2))
                                try:
                                 log(logmsg)
                                except:
                                    print "[!] AP: Could not log"
                                try:
                                 #st="insert into ap values (%d, '%s', '%s', '%s', %d)" % (tm,pkt.info,pkt.addr2,capability,sig_str)
                                 c.execute("insert into ap values(?,?,?,?,?)",(tm,pkt.info,pkt.addr2,capability,sig_str))
                                 conn.commit()
                                except:
                                 print "[*] AP: could not insert"


        if pkt.type == 0 and pkt.subtype == 4 :
            try:
             log("Probe: SSID: '%s', MAC: %s, signal: %d, %s" % (pkt.info,pkt.addr2,sig_str,get_manuf(db,pkt.addr2)))
            except:
                print "[!] Probe: could not log"

            try:
             #st="insert into probes values (%d,'%s','%s',%d)" % (tm,pkt.info,pkt.addr2,sig_str)
             c.execute("insert into probes values (?,?,?,?)" , (tm,pkt.info,pkt.addr2,sig_str))
             conn.commit()
            except:
             print "[!] Probe: could not insert"

        conn.close()
sniff(iface=interface, prn = PacketHandler, store=0)

