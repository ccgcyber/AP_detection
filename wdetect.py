# John Lampe (C) 2002 ... finds wireless APs 

import SocketLib, sys, thread, time, re, string, math
from SocketLib import *
from types import *
from Tkinter import *
from tktools import *

def handle_error(msg="Unhandled Socket Error\n"):
    print msg
    text.insert('end', msg)
    if ("Socket" in msg):
        sys.exit()
    else:
        return (-1)



def match_generic(haystack):
    totalcounter = 0
    for i in range(0,GENSIGZ,1):
        if gensigs[i][0] in haystack:
            totalcounter = totalcounter + 1
    if (totalcounter >= 2):
        tstring = "Access Point : Matched " + str(totalcounter) + " out of " + str(GENSIGZ) + " generic signatures\n"
        #print tstring
        OUT.write(tstring)
        text.insert('end', tstring)
        sys.exit()

    return(-1)



def banner_match (haystack, bhost):
    for tu in range(0,NUMSIGZ,1):
        if sigs[tu][0] in haystack:
            return(tu)

    bret = match_generic(haystack)
    return(-1)


def check_snmp (myhost):
    snmpreq = "\x30\x26\x02\x01\x00\x04\x06" + "public" + "\xA0\x19\x02\x01\xDE\x02\x01\x00\x02\x01\x00\x30\x0E\x30\x0C\x06\x08\x2b\x06\x01\x02\x01\x01\x01\x00\x05\x00"
    

    soc = open_sock_udp (myhost, 161)
    if not soc:
        return (-1)
    try:
        soc.send(snmpreq)
    except socket.error:
        soc.close()
        return(-1)
    try:
        ret = soc.recv(4096)
    except socket.error, msg:
        soc.close()
        return(-1)
    
    soc.close()
    if ret:
        iswireless = banner_match(ret, myhost)
        if (iswireless >= 0):
            tstring = "Access point : " + sigs[iswireless][1] + " [SNMP]\n"
            text.insert('end', tstring)
            OUT.write(tstring)
            #print tstring
                


def default_accounts(dhost, dport):
    for philemon in range(0, DTOT, 1):
        dsoc = open_sock_tcp(dhost, dport)
        if not dsoc:
            return (-1)

        drequest = "GET /HTTP/1.1\r\nHost: localhost\r\nAuthorization: Basic %s\r\n\r\n" % dcounts[philemon][0]
        try:
            dsoc.send(drequest)
        except socket.error:
            dsoc.close()
            return(-1)
        try:
            muck = soc.recv(4096)
        except socket.error, msg:
            dsoc.close()
            return(-1)
        
        if "200 OK" in muck:
            muck = match_generic(mybanner)
            return(philemon)
        dsoc.close()

    return(-1)



def get_banner(bport, myhost):
    myerr = "ERROR"    
    frequest = "USER Anonymous\r\n"
    wrequest = "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"
    trequest = "cisco\n"
    soc = open_sock_tcp(myhost, bport)
    if not soc:
        if (DEBUG):
            print "Can't open a socket on ", myhost, " : ", str(bport), "\n"
        return myerr
    if (bport == 21):
        try:
            soc.send(frequest)
        except socket.error:
            soc.close()
            return myerr
        try:
            mu = soc.recv(1024)
        except socket.error, msg:
            soc.close()
            return myerr
        
        soc.close()
        if (len(mu) > 0):
            return(mu)
        
    if (bport == 23):
        try:
            mu = soc.recv(512)
        except socket.error, msg:
            soc.close()
            return myerr
        
        if "assword" in mu:
            try:
                soc.send(trequest)
            except socket.error:
                soc.close()
                return myerr
            try:
                mu = soc.recv(512)
            except socket.error, msg:
                soc.close()
                return myerr
            
            soc.close()
            if (len(mu) > 0):
                return(mu)

    if (bport == 80):
        badban = 0
        try:
            soc.send(wrequest)
        except socket.error:
            soc.close()
            return myerr
        try:
            mu = soc.recv(2048)
        except socket.error, msg:
            soc.close()
            if DEBUG:
                print "Socket recv() Error for ", myhost, " : ", str(bport), "\n"
            return myerr
        
        soc.close()
        if DEBUG:
            print "Banner returned was ", mu , "\n"
        badbanners = ("Server: Microsoft IIS", "Server: Apache", "Server: Netscape")
        for bad in badbanners:
            if bad in mu:
                badban = 1
        if not badban:
            return(mu)

    return(myerr)


def myscan (host):
    for i in range(0,TCPNUM + 1, 1):
        if (i == TCPNUM):
            check_snmp(host)
        else:
            banner = get_banner(tcp_ports[i], host)
            if "ERROR" not in banner:
                iswireless = banner_match(banner, host)
                if (iswireless >= 0) and sigs[iswireless][1]:
                    tstring = host + " : Access Point: " + sigs[iswireless][1] + " : " + str(tcp_ports[i]) + "\n"
                    text.insert('end', tstring)
                    #print tstring
                    OUT.write(tstring)
                    sys.exit()

                if (tcp_ports[i] == 80) and "401 Authorization" in banner:
                    iswireless = default_accounts(host, tcp_ports[i])
                    if (iswireless >= 0) and dcounts[iswireless][1]:
                        tstring = host + " : Access Point : " + dcounts[iswireless][1] + " : " + str(tcp_ports[i]) + " : " + dcounts[iswireless][2]
                        text.insert('end', tstring)
                        #print tstring
                        OUT.write(tstring)
                        sys.exit()



def parse_networks(netline):
    pattern = re.compile(
        "^network: [0-9]*\.[0-9]*\.[0-9]*\.[0-9]* - [0-9]*\.[0-9]*\.[0-9]*\.[0-9]*")

    result = pattern.match(netline)
    if (result):
        L = re.subn("^network: ([0-9]*\\.[0-9]*\\.[0-9]*\\.[0-9]*) - ([0-9]*\\.[0-9]*\\.[0-9]*\\.[0-9]*)", "\\1", netline)
        Z = re.subn("^network: ([0-9]*\\.[0-9]*\\.[0-9]*\\.[0-9]*) - ([0-9]*\\.[0-9]*\\.[0-9]*\\.[0-9]*)", "\\2", netline)
        if (L[1] > 0 and Z[1] > 0):
            myret = (L[0] , Z[0])
            return myret
        else:
            return("ERROR")
    else:
        return("ERROR")


        
        
DEBUG = 0

MAXSIGS = 1024

TCPNUM = 3

tcp_ports = (21, 23, 80)

dcounts = [
	("c3VwZXI6NTc3NzM2NA==", "NetGear AccessPoint", "super|5777364"),
	("OmFkbWlu", "3COM, Apple Airport, or Linksys Access Point", "NULL|admin"),
	("YWRtaW46Y29tY29tY29t","3COM wireless AP","admin|comcomcom"),
	("YWRtaW46QWRtaW4=","3COM wireless AP","admin|Admin"),
	("OjA=","Accton Access Point","NULL|0"),
	("cm9vdDpkZWZhdWx0","Micronet Access Point","root|default"),
	("YWRtaW46YWRtaW4=","Dell TrueMobile or Gateway Access Point","admin|admin"),
	("aW50ZWw6aW50ZWw=","Intel Wireless Gateway","intel|intel"),
	("OkludGVs","Intel 2011 Wireless Access Point","NULL|Intel"),
	("YWRtaW46","DLINK Access Point","admin|NULL"),                                  #10
	("YWRtaW46cGFzc3dvcmQ=","NetGear Access Point","admin|password"),
	("YWRtaW46MTIzNA==","NetGear Access Point","admin|1234"),
	("OnBhc3N3b3Jk","Airport Access Point","NULL|password"),
	("YWRtaW46c3lzdGVt","Cisco Access Point","admin|system"),
	("cm9vdDo=","Buffalo Access Point","root|NULL"),                                  #15
	("QWRtaW46NXVw","SMC Access Point","Admin|5up"),
	("OnB1YmxpYw==","Avaya Access Point","NULL|public"),
	("OnBhc3N3b3Jk","Enterasys RoamAbout Access Point","NULL|password"),
	("OkNpc2Nv","Cisco Wireless Access Point","NULL|Cisco"),
	("Q2lzY286Q2lzY28=","Cisco Wireless Access Point","Cisco|Cisco"),               #20
	("ZGVmYXVsdDo=","IBM Wireless Gateway","default|NULL"),
	("YWRtaW46bW90b3JvbGE=","Motorola Wireless Gateway","admin|motorola") ]


DTOT = 22

sigs = [
("BCM430","BCM430 Wireless Access Point"),
("BUFFALO WBR-G54","BUFFALO WBR-G54 Wireless Access Point"),
("CG814M","CG814M Wireless Access Point"),
("Cisco AP340","Cisco AP340 Wireless Access Point"),
("Cisco AP350","Cisco AP350 Wireless Access Point"),
("Cisco BR500","Cisco BR500 Wireless Access Point"),
("DG824M","DG824M Wireless Access Point"),
("DG834G","DG834G Wireless Access Point"),
("D-Link DI-1750","D-Link DI-1750 Wireless Access Point"),
("D-Link DI-514","D-Link DI-514 Wireless Access Point"),                 # 10
("D-Link DI-524","D-Link DI-524 Wireless Access Point"),
("D-Link DI-614","D-Link DI-614 Wireless Access Point"),
("D-Link DI-624","D-Link DI-624 Wireless Access Point"),
("D-Link DI-713","D-Link DI-713 Wireless Access Point"),
("D-Link DI-714","D-Link DI-714 Wireless Access Point"),
("D-Link DI-754","D-Link DI-754 Wireless Access Point"),
("D-Link DI-764","D-Link DI-764 Wireless Access Point"),
("D-Link DI-774","D-Link DI-774 Wireless Access Point"),
("D-Link DI-784","D-Link DI-784 Wireless Access Point"),
("D-Link DI-824","D-Link DI-824 Wireless Access Point"),                #20
("D-Link DSA-3100","D-Link DSA-3100 Wireless Access Point"),
("FM114P","FM114P Wireless Access Point"),
("FVM318","FVM318 Wireless Access Point"),
("FWAG114","FWAG114 Wireless Access Point"),
("HE102","HE102 Wireless Access Point"),
("HR314","HR314 Wireless Access Point"),
("Cisco 12000","Cisco 12000 Wireless Access Point"),
("Linksys BEFW","Linksys BEFW Wireless Access Point"),
("Linksys WAP","Linksys WAP Wireless Access Point"),
("Linksys WPG","Linksys WPG Wireless Access Point"),                      #30
("Linksys WRV","Linksys WRV Wireless Access Point"),
("MA101","MA101 Wireless Access Point"),
("ME102","ME102 Wireless Access Point"),
("ME103","ME103 Wireless Access Point"),
("MR314","MR314 Wireless Access Point"),
("MR814","MR814 Wireless Access Point"),
("PS111W","PS111W Wireless Access Point"),
("R2 Wireless Access Platform","R2 Wireless Access Platform Wireless Access Point"),
("SetExpress.shm","SetExpress.shm Wireless Access Point"),
("SOHO Version","SOHO Version Wireless Access Point"),                     #40
("WG101","WG101 Wireless Access Point"),
("WG302","WG302 Wireless Access Point"),
("WG602","WG602 Wireless Access Point"),
("WGR614","WGR614 Wireless Access Point"),
("WLAN","WLAN Wireless Access Point"),
("WLAN AP","WLAN AP Wireless Access Point"),
("220-****Welcome to WLAN AP****", "SMC EZ Connect Wireless Access Point"),
("ce03b8ee9dc06c1", "SMC EZ Connect Wireless Access Point"),
("AP-","Compaq Access Point"),
("Base Station","Base Station Access Point"),                              #50
("WaveLan","WaveLan Access Point"),
("WavePOINT-II","Orinoco WavePOINT II Wireless AP"),
("AP-1000","Orinoco AP-1000 Wireless AP"),
("Cisco BR500","Cisco Aironet Wireless Bridge"),
("Internet Gateway Device" , "D-Link Wireless Internet Gateway Device"),         #55
("Symbol Access Point","Symbol Wireless Access Point"),
("Linksys WAP51AB","Linksys WAP51AB Wireless Access Point"),
("Spectrum24 Access Point","Spectrum24 Wireless Access Point"),
("SMC2671W","SMC 2671W Wireless Access Point"),
("SMC2870W","SMC 2870W Wireless Access Point"),                                #60
("SMC2655W","SMC 2655W Wireless Access Point"),
("OfficePortal 1800HW","2WireOfficePortal 1800HW Home wireless gateway"),
("HomePortal 180HW","2Wire HomePortal 180HW"),
("Portal 1000HG","2Wire Wireless Portal"),
("Portal 1000HW","2Wire Wireless Portal"),                                    #65
("Portal 1000SW","2Wire Wireless Portal"),
("Portal 1700HG","2Wire Wireless Portal"),
("Portal 1700HW","2Wire Wireless Portal"),
("Portal 1700SG","2Wire Wireless Portal"),
("HomePortal 180HG","2Wire HomePortal 180HG"),                                #70
("HomePortal 2000","2Wire HomePortal 2000"),
("Wireless 11a/b/g Access Point","3COM OfficeConnect Wireless Access Point"),
("AT-WA1004G","Allied-Telesyn Wireless Access Point"),
("AT-WA7500","Allied-Telesyn Wireless Access Point"),
("AT-WL2411","Allied-Telesyn Wireless Access Point"),                      #75
("RTW020","ASKEY Access Point"),
("RTW026","ASKEY Access Point"),
("RTA040W","ASKEY Access Point"),
("RTA300W","ASKEY Access Point"),
("RTW010","ASKEY Access Point"),                                            #80
("RTW030","ASKEY Access Point"),
("The setup wizard will help you to configure the Wireless","AT&T Wireless Router"),
("realm=Access-Product","Avaya Access Point"),
("USR8054","US Robotics Wireless Access Point"),
("MR814","NetGear MR814"),                                               # 85
("WGR614","NetGear WGR614"),
("WGT624","NetGear WGT624"),
("AirPlus","D-Link AirPlus Wireless Access Point"),
("Linksys WET11","Linksys WET11 Access Point"),
("wireless/wireless_tab1.jpg","Belkin Wireless Internet Gateway"),     #90
("wireless/use_as_access_point_only_off","Linksys Access Point"),
("Gateway 11G Router","Gateway 802.11G Access Point"),
("Gateway 11B Router","Gateway 802.11B Access Point"),
("IBM High Rate Wireless LAN","IBM High Rate Wireless LAN Gateway"),
("MN-500","Microsoft Broadband Access Point"),                         # 95
("MN-700","Microsoft Broadband Access Point"),
("MN-510","Microsoft Broadband Access Point"),
("SBG900","Motorola Wireless Cable Modem Gateway"),
("SBG1000","Motorola Wireless Cable Modem Gateway"),
("WA840G","Motorola Wireless Cable Modem Gateway"),                 #100
("WR850G","Motorola Wireless Cable Modem Gateway"),
("WL1200-AB", "NEC Access Point"),
("WL5400AP","NEC Access Point"),
("Server: Cochise","TESTING TESTING TESTING") ]                                  # change this (testing)


NUMSIGZ = 104

gensigs = [
	("Wireless","GEN"),
	("wireless","GEN"),
	("AP","GEN"),
	("Access Point","GEN"),
	("access point","GEN"),
	("802.11","GEN"),
	("WEP","GEN"),
	("wep","GEN"),
	("SSID","GEN"),
	("Service Set ID","GEN"),
	("ssid","GEN"),
	("service set ID","GEN"),
	("Beacon","GEN"),
	("BEACON","GEN"),
	("beacon","GEN"),
	("RTS","GEN"),
	("CTS","GEN"),
	("TKIP","GEN"),
	("DHCP","GEN"),
	("54G","GEN"),                   #20
	("2.4GHz","GEN"),
	("54 Mbps","GEN"),
	("108 Mbps","GEN"),
	("11 Mbps","GEN"),
	("Ad Hoc","GEN"),                #25
	("Ad-Hoc","GEN"),
	("Wired Equivalent Privacy","GEN"),
	("ssid","GEN"),
	("Infrastructure Mode","GEN"),
	("Infrastructure mode","GEN"),      #30
	("infrastructure mode","GEN") ]

GENSIGZ = 31


    
        
# MAIN

start_time = time.time()
t = time.asctime()
t = re.subn("\\s+|:", ".", t)
outfile = "c:\\" + "wDetect." + t[0] + ".txt"
OUT = open(outfile, "w")

WdetectConf = "c:\\wdetect.conf"
try:
    tfile = open(WdetectConf, 'r')
except IOError:
    print "ERROR: can't open c:\\wdetect.conf\n"
    sys.exit()
    
z = tfile.readline()


nflag = 0
network = []
while (len(z) > 0):
    q = parse_networks(z)
    if ("ERROR" not in q):
        network.append(q)
        nflag += 1
    z = tfile.readline()

threadcount = 0
MAXTHREADS = 195

myclass = "wDetect AP Scanner - NetSecure Security Group"
root = Tk(className=myclass)
text, tframe = make_text_box(root)                          
text.insert('end', "Wdetect Scanner results:\n\n\n")
print "\n\n***** Don't close this Window ***\n\n"

if nflag > 0:
    for nets in range(0,nflag,1):
        currnet = network[nets][0]
        gtflag = 0
        tmpS = string.split(network[nets][0], sep=".")
        tmpE = string.split(network[nets][1], sep=".")
        if int(tmpS[0]) < int(tmpE[0]):
            gtflag = 1                                          
            Ainit,Aupper = int(tmpS[0]) , int(tmpE[0]) + 1
            Binit = Cinit = Dinit = 0
            Bupper = Cupper = Dupper = 255
        elif (int(tmpS[0]) > int(tmpE[0]) ) and ( not gtflag ):
            mesg = "There is an error with the network '",currnet," defined in wdetect.conf\n"
            handle_error(msg=mesg)
            continue
        elif int(tmpS[1]) < int(tmpE[1]):
            gtflag = 1
            Ainit,Aupper = int(tmpS[0]) , int(tmpE[0]) + 1
            Binit,Bupper = int(tmpS[1]) , int(tmpE[1]) + 1
            Cinit = Dinit = 0
            Cupper = Dupper = 255
        elif (int(tmpS[1]) > int(tmpE[1]) ) and ( not gtflag ):
            mesg = "There is an error with the network '",currnet," defined in wdetect.conf\n"
            handle_error(msg=mesg)
            continue
        elif int(tmpS[2]) < int(tmpE[2]):
            gtflag = 1
            Ainit,Aupper = int(tmpS[0]) , int(tmpE[0]) + 1
            Binit,Bupper = int(tmpS[1]) , int(tmpE[1]) + 1
            Cinit,Cupper = int(tmpS[2]) , int(tmpE[2]) + 1
            Dinit = 0
            Dupper = 255
        elif (int(tmpS[2]) > int(tmpE[2]) ) and ( not gtflag ):
            mesg = "There is an error with the network '",currnet," defined in wdetect.conf\n"
            handle_error(msg=mesg)
            continue
        elif int(tmpS[3]) < int(tmpE[3]):
            gtflag = 1
            Ainit,Aupper = int(tmpS[0]) , int(tmpE[0]) + 1
            Binit,Bupper = int(tmpS[1]) , int(tmpE[1]) + 1
            Cinit,Cupper = int(tmpS[2]) , int(tmpE[2]) + 1
            Dinit,Dupper = int(tmpS[3]) , int(tmpE[3]) + 1
        elif (int(tmpS[3]) > int(tmpE[3]) ) and ( not gtflag ):
            mesg = "There is an error with the network '",currnet," defined in wdetect.conf\n"
            handle_error(msg=mesg)
            continue
        else:
            mesg = "There is an error with the network '",currnet," defined in wdetect.conf\n"
            handle_error(msg=mesg)
            continue

        for A in range(Ainit,Aupper,1):
            for B in range(Binit,Bupper,1):
                for C in range(Cinit,Cupper,1):
                    for D in range(Dinit,Dupper,1):
                        thost = str(A) + "." + str(B) + "." + str(C) + "." + str(D)
                        threadcount += 1
                        if (threadcount % MAXTHREADS) == 0:
                            #print "Sleeping for 10 seconds\n"
                            time.sleep(20)
                        tmptuple = (thost,)
                        thread.start_new_thread(myscan,tmptuple)
                        if DEBUG:
                            text.insert('end' , "Testing ")
                            text.insert('end', thost)
                            text.insert('end', "\n")
                        

time.sleep(20)                          
text.insert('end' , "\n\n\nTest Complete\n")
end_time = time.time()
total_time = end_time - start_time
secs = total_time % 60
secs = math.floor(secs)
mins = total_time / 60
mins = math.floor(mins)
hours = mins / 60
hours = math.floor(hours)
timescanned = str(hours) + " Hours, " + str(mins) + " Minutes, " + str(secs) + " Seconds "

tstring = str(threadcount) + " hosts scanned in " + timescanned
text.insert('end', tstring)
text.insert('end' , "\n\n\nResults are also in " + outfile + "\n\n")

OUT.write(tstring)
OUT.close()
root.mainloop()
sys.exit(0)
    
     
