import time
from pathlib import Path
import os
from os import stat
import socket
import subprocess
from datetime import datetime
import logging
import logging.handlers
from tkinter import *
from threading import Thread
import queue
from stat import ST_SIZE
from tkinter.scrolledtext import *
from tkinter import ttk
from tkinter import messagebox
import itertools

def writeExtFile(self,message):

    filetest = Path(self.convertPath(self.ExFileLoc.get() + "WindowsLocalFWHistory.log","F"))

    if filetest.is_file():
        newlogfile = open(self.convertPath(self.ExFileLoc.get() + "WindowsLocalFWHistory.log","F"),"a")
    else:
        newlogfile = open(self.convertPath(self.ExFileLoc.get() + "WindowsLocalFWHistory.log","F"),"w")

    newlogfile.write(datetime.now().strftime('%Y-%m-%d %H:%M:%S') + " >> " + message)

    newlogfile.close()

    if stat(filetest)[ST_SIZE] > int(self.ExFile.get()) * 1000000:
        try:
            os.rename(self.convertPath(self.ExFileLoc.get() + "WindowsLocalFWHistory.log","F"),convertPath(self.ExFileLoc.get() + "WindowsLocalFWHistory" + datetime.now().strftime('%Y%m%d%H') + ".log","F"))
        except:
            time.sleep(1)
            os.rename(self.convertPath(self.ExFileLoc.get() + "WindowsLocalFWHistory.log","F"),convertPath(self.ExFileLoc.get() + "WindowsLocalFWHistory" + datetime.now().strftime('%Y%m%d%H') + ".log","F"))

def logsearch(self,msg):

    #self.StatusBar.set("Applying Search Criteria...")

    if self.FilVar2.get() == 1:

        try:
            msgItems = msg.split()

            sCount = 0

            #if len(self.SrchSysIP.get()) > 1:
                #sCount = sCount + 1

            if len(self.SrchAct.get()) > 2:
                sCount = sCount + 1

            if len(self.SrchProt.get()) > 2:
                sCount = sCount + 1

            if len(self.SrchSIP.get()) > 2:
                sCount = sCount + 1

            if len(self.SrchDIP.get()) > 2:
                sCount = sCount + 1

            if len(self.SrchSPrt.get()) > 1:
                sCount = sCount + 1

            if len(self.SrchDPrt.get()) > 1:
                sCount = sCount + 1

            #searchitems = self.SrchSysIP.get().split()

            #for sc in range(len(searchitems)):
                #if searchitems[sc] == msgItems[3].strip():
                    #sCount = sCount - 1

            if self.SrchAct.get().strip() == msgItems[7].strip():
                sCount = sCount - 1

            if self.SrchProt.get().strip() == msgItems[8].strip():
                sCount = sCount - 1

            searchitems = self.SrchSIP.get().split()

            for sc in range(len(searchitems)):
                if searchitems[sc] == msgItems[9].strip():
                    sCount = sCount - 1

            searchitems = self.SrchDIP.get().split()

            for sc in range(len(searchitems)):
                if searchitems[sc] == msgItems[10].strip():
                    sCount = sCount - 1

            searchitems = self.SrchSPrt.get().split()

            for sc in range(len(searchitems)):
                if searchitems[sc] == msgItems[11].strip():
                    sCount = sCount - 1

            searchitems = self.SrchDPrt.get().split()

            for sc in range(len(searchitems)):
                if searchitems[sc] == msgItems[12].strip():
                    sCount = sCount - 1

        except:
            pass

    else:
        sCount = -1

    return sCount

def FWLogProcess(self):

    prevmsg = ""

    while self.mqueue.qsize() > 0:
        try:

            logmsg = self.mqueue.get()

            msgtype = logmsg[43:44]
            #print(msgtype)
            FWAction = logmsg[65:72]
            #print(FWAction)
            ProgMsg = msgtype.isalpha()
            #print(ProgMsg)

            #self.StatusBar.set("Updating User Interface (message processing)...")
            #self.root.update_idletasks()

            #self.StatusBar.set("Writing log data to interface and DB...")

            if prevmsg == logmsg:
                #print('match')
                msgtype = '#'
                
            if logmsg.count(":") > 4:
                if self.IP6.get() == 1:
                    IPV6Msg = False
                else:
                    IPV6Msg = True
            else:
                IPV6Msg = True

            if msgtype != '#' and len(logmsg.strip()) > 42 and IPV6Msg == True:
                
                if self.LogTraf.get() != 1:
                    writeExtFile(self,logmsg)

                if ProgMsg == True and self.ShowPMsg.get() == 0:
                    if logmsg[23:29] == "SYSTEM":
                        self.LogApp.insert(3.0,logmsg,'dbwrite')
                        self.LogApp.tag_config('dbwrite',foreground='black')
                    else:
                        if "Error" not in logmsg:
                            self.LogApp.insert(3.0,logmsg,'progmsg')
                            self.LogApp.tag_config('progmsg',foreground='orange')
                        else:
                            self.LogApp.insert(3.0,logmsg,'errmsg')
                            self.LogApp.tag_config('errmsg',foreground='red')
                elif ProgMsg == False:
                    self.dbinfoqueue.put(logmsg)
                    if self.ShowTraf.get() == 0:
                        if self.fqueue.qsize() > 0:
                            Filter = self.fqueue.get()
                            self.fqueue.put(Filter)
                            msg = logmsg[23:39]
                            if Filter.strip() == msg.strip():
                               if FWAction.strip() == "ALLOW":
                                    if self.FilVar2.get() == 1:
                                        if logsearch(self,logmsg) == 0:
                                            self.LogWin.insert(3.0,logmsg,'allact')
                                            self.LogWin.tag_config('allact',foreground='green')
                                    else:
                                        self.LogWin.insert(3.0,logmsg,'allact')
                                        self.LogWin.tag_config('allact',foreground='green')
                               else:
                                   if FWAction.strip() == "DROP":
                                       if self.FilVar2.get() == 1:
                                           if logsearch(self,logmsg) == 0:
                                               self.LogWin.insert(3.0,logmsg,'dract')
                                               self.LogWin.tag_config('dract',foreground='red')
                                       else:
                                           self.LogWin.insert(3.0,logmsg,'dract')
                                           self.LogWin.tag_config('dract',foreground='red')
                                   else:
                                       self.LogWin.insert(3.0,logmsg)
                        else:
                            if FWAction.strip() == "ALLOW":
                                if self.FilVar2.get() == 1:
                                    if logsearch(self,logmsg) == 0:
                                        self.LogWin.insert(3.0,logmsg,'allact')
                                        self.LogWin.tag_config('allact',foreground='green')
                                else:
                                    self.LogWin.insert(3.0,logmsg,'allact')
                                    self.LogWin.tag_config('allact',foreground='green')
                            else:
                                if FWAction.strip() == "DROP":
                                    if self.FilVar2.get() == 1:
                                        if logsearch(self,logmsg) == 0:
                                            self.LogWin.insert(3.0,logmsg,'dract')
                                            self.LogWin.tag_config('dract',foreground='red')
                                    else:
                                        self.LogWin.insert(3.0,logmsg,'dract')
                                        self.LogWin.tag_config('dract',foreground='red')
                                else:
                                    if self.FilVar2.get() == 1:
                                        if logsearch(self,logmsg) == 0:
                                            self.LogWin.insert(3.0,logmsg)
                                    else:
                                        self.LogWin.insert(3.0,logmsg)
            prevmsg = logmsg

        except self.mqueue.Empty:
            pass

    return

def follow(self,thefile,WName,logfile):
    try:
        thefile.seek(0,2)
        where = thefile.tell()
        while True and self.cqueue.empty() == True:
            if thefile.closed == False:
                where = thefile.tell()
                line = thefile.readline()
                if not line:
                    if stat(logfile)[ST_SIZE] < where:
                        thefile.close
                        thefile = open(logfile,"r",1)
                        if abs(stat(logfile)[ST_SIZE] - where) > 1000:
                            thefile.seek(0,0)
                        else:
                            thefile.seek(where)
                        self.writeAppLog(datetime.now().strftime('%Y-%m-%d %H:%M:%S') + " >> " + WName + (15 - len(WName)) * ' ' + " >> Log file has been closed and reopened. File size: " + str(stat(logfile)[ST_SIZE]) + "\n")
                    else:
                        thefile.seek(where)
                        time.sleep(1)
                else:
                    yield line
            else:
                line = "File Error: File Closed.  Re-opening...\n"
    except IOError:
            line = "File Error: Readline Failed.  Retrying...\n"                

def FWMon(self,SIEMIPAddr,WinMachine,VT):

    sentinel = ""
    ConnRestore = ""
    FileError = ""
    LogCount = 0
    OutbCount = 0
    InbCount = 0
    UnkCount = 0
    TCPCount = 0
    UDPCount = 0
    ICMPCount = 0
    OtherCount = 0
    AllowCount = 0
    DropCount = 0
    PrevTimeDate = ""
    PrevMsg = ""
    PrevSIEMLogDef = ""
    DupLogMsg = ""
    DuplicateCount = 0
    LogCheckCount = 0
    StartTime = datetime.now()
    if VT != "Unlicensed":
        WinFWLogger = logging.getLogger('FWLogger')
        WinFWLogger.setLevel(logging.INFO)
        WinFWhandler = logging.handlers.SysLogHandler(address = (SIEMIPAddr,514))
        WinFWLogger.addHandler(WinFWhandler)

    logfilename = "//" + WinMachine + "/c$/Windows/System32/LogFiles/Firewall/pfirewall.log"
    logfile = open("//" + WinMachine + "/c$/Windows/System32/LogFiles/Firewall/pfirewall.log","r",1)

    while logfile.closed == False:
        loglines = follow(self,logfile,WinMachine,logfilename)
        for line in loglines:
            if len(line) > 10 and line[:1] != '#':
                ConnRestore = ""
                FileError = ""

                if line[:10] == "File Error":
                    try:
                        logfile.close()
                        logfile = open("//" + WinMachine + "/c$/Windows/System32/LogFiles/Firewall/pfirewall.log","r",1)
                        ConnRestore = WinMachine + " >> Connection Restored: " + datetime.now().strftime('%Y-%m-%d %H:%M:%S') + " File Open."
                        self.writeAppLog(datetime.now().strftime('%Y-%m-%d %H:%M:%S') + " >> " + WinMachine + (15 - len(WinMachine)) * ' ' + " ==> " + ConnRestore + '\n')
                        loglines = follow(self,logfile,WinMachine,logfilename)
                        break
                    except IOError:
                        FileError = WinMachine + " >> File Error: " + datetime.now().strftime('%Y-%m-%d %H:%M:%S') + " File not open."
                        self.writeAppLog(datetime.now().strftime('%Y-%m-%d %H:%M:%S') + " >> " + WinMachine + (15 - len(WinMachine)) * ' ' + " >> " + FileError + '\n')
                        self.writeAppLog(datetime.now().strftime('%Y-%m-%d %H:%M:%S') + " >> " + WinMachine + (15 - len(WinMachine)) * ' ' + " >> Waiting 10 seconds before retry...")
                        time.sleep(10)
                        Availability = LogAvail(self,WName)
                        if Availability == "UnAvailable":
                            logfile.close()
                        else:
                            logfile = open("//" + WName + "/c$/Windows/System32/LogFiles/Firewall/pfirewall.log","r",1)
                            loglines = follow(self,logfile,WinMachine,logfilename)
                        continue

                if len(FileError) == 0 and len(ConnRestore) == 0:
                    try:
                        LineList = line.split()
                        #print(LineList)

                        SIEMLogDef = LineList[0] + " " + LineList[1] + " Hostname:" + WinMachine + " EventName:WinFw" + LineList[2] + ": SrcIP:" + LineList[4] + \
                                     " SrcPrt:" + LineList[6] + " DstIP:" + LineList[5] + " DstPrt:" + LineList[7] + " Protocol:" + LineList[3] + "\n"
                        
                        LogMsg = LineList[0] + "  " + LineList[1] + "   " + LineList[2] + (5 - len(LineList[2])) * ' ' + "  " + LineList[3] + (4 - len(LineList[3])) * ' ' + \
                                 "  " + LineList[4] + (25 - len(LineList[4])) * ' ' + "  " + LineList[5] + (15 - len(LineList[5])) * ' ' + "  " + \
                                 LineList[6] + (5 - len(LineList[6])) * ' ' + "  " + LineList[7] + (5 - len(LineList[7])) * ' ' + "  " + \
                                 LineList[16] + (7 - len(LineList[16]))* ' ' + "    " + LineList[8] + " " + LineList[9] + " " + LineList[10] + " " + LineList[11] + " " + \
                                 LineList[12] + " " + LineList[13] + " " + LineList[14] + " " + LineList[15] + " " + "\n"

                        if (self.IP6.get() == 0) or ((LogMsg.count(":") < 5) and (self.IP6.get() == 1)):

                            self.dbinfoqueue.put(datetime.now().strftime('%Y-%m-%d %H:%M:%S') + " >> " + WinMachine + (15 - len(WinMachine)) * ' ' + " ==> " + LogMsg)

                            self.writeAppLog(datetime.now().strftime('%Y-%m-%d %H:%M:%S') + " >> " + WinMachine + (15 - len(WinMachine)) * ' ' + " ==> " + LogMsg)

                            FWLogProcess(self)

                            #if WinMachine == LineList[4]:
                            if LineList[16].strip() == 'SEND':
                                OutbCount = OutbCount + 1
                            else:
                                #if WinMachine == LineList[5]:
                                if LineList[16].strip() == 'RECEIVE':
                                    InbCount = InbCount + 1
                                else:
                                    UnkCount = UnkCount + 1

                            if LineList[3] == "TCP":
                                TCPCount = TCPCount + 1
                            else:
                                if LineList[3] == "UDP":
                                    UDPCount = UDPCount + 1
                                else:
                                    if LineList[3] == "ICMP":
                                        ICMPCount = ICMPCount + 1
                                    else:
                                        OtherCount = OtherCount + 1

                            if LineList[2] == "ALLOW":
                                AllowCount = AllowCount + 1
                            else:
                                if LineList[2] == "DROP":
                                    DropCount = DropCount + 1

                            LogCount = LogCount + 1

                            SIEMFlag = int(self.SIEMTraf.get())

                            if SIEMFlag == 1:
                                WinFWLogger.info(SIEMLogDef)

                            PrevSIEMLogDef = SIEMLogDef

                        #else:
                            #DuplicateCount = DuplicateCount + 1
                            #print(WinMachine + " Duplicates: " + str(DuplicateCount))

                    except:
                        self.writeAppLog(datetime.now().strftime('%Y-%m-%d %H:%M:%S') + " >> " + WinMachine + (15 - len(WinMachine)) * ' ' + " ==> " + line)
                        continue

            else:
                logfile.close()
                logfile = open("//" + WinMachine + "/c$/Windows/System32/LogFiles/Firewall/pfirewall.log","r",1)
                ConnRestore = WinMachine + " >> Connection Restored: " + datetime.now().strftime('%Y-%m-%d %H:%M:%S') + " File Open."
                self.writeAppLog(WinMachine + (15 - len(WinMachine)) * ' ' + " ==> " + ConnRestore)
                loglines = follow(self,logfile,WinMachine,logfilename)

            if PrevSIEMLogDef == SIEMLogDef:
                achar = 0

            timediff = (datetime.now() - StartTime)

            LogRate = int(LogCount / timediff.total_seconds()) + 1

            Stage1Msg = WinMachine + ": " + str(LogCount) + " lines ( Inbound: " + str(InbCount) + " + Outbound: " + str(OutbCount) + " + Other: " + str(UnkCount) + " ) < TCP: "
            Stage2Msg = Stage1Msg + str(TCPCount) + " + UDP: " + str(UDPCount) + " + ICMP: " + str(ICMPCount) + " + Other: " + str(OtherCount) + " > [ Allow: "
            Stage3Msg = Stage2Msg + str(AllowCount) + " + Drop: " + str(DropCount) + " ] "
            Stage4Msg = Stage3Msg + "Log Read Last @ " + datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            Stage5Msg = WinMachine + " " + str(LogCount) + " " + str(InbCount) + " " + str(OutbCount) + " " + str(UnkCount) + " " + str(TCPCount) + " " + str(UDPCount)
            Stage6Msg = Stage5Msg + " " + str(ICMPCount) + " " + str(OtherCount) + " " + str(AllowCount) + " " + str(DropCount) + " " + datetime.now().strftime('%Y-%m-%d %H:%M:%S') + " " + str(stat(logfilename)[ST_SIZE]) + " " + str(LogRate)

            LogCheckCount = LogCheckCount + 1
            #if datetime.now().strftime('%Y-%m-%d %H:%M:%S') > PrevTimeDate and LogCheckCount > (LogRate * 1):
            if datetime.now().strftime('%Y-%m-%d %H:%M:%S') > PrevTimeDate:
                self.queue.put(Stage6Msg)
                PrevTimeDate = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                LogCheckCount = 0
        
        try:
            if self.cqueue.empty() == False:
                sentinel = self.cqueue.get()
                if sentinel == WinMachine + "27":
                    self.writeAppLog(datetime.now().strftime('%Y-%m-%d %H:%M:%S') + " >> Exiting firewall log monitoring for " + WinMachine + "\n")
                    logfile.close()
                    #return
                else:
                    self.cqueue.put(sentinel)
        except:
            continue
    self.writeAppLog(datetime.now().strftime('%Y-%m-%d %H:%M:%S') + " >> Shutdown complete for monitor " + WinMachine + "\n")
    return

class Gui(object):
        
    def ClearFilter(self):
        self.StatusBar.set("Clearing all filters...")
        self.FilVar.set(-1)
        self.FilVar2.set(0)
        self.SrchAct.set("")
        self.SrchProt.set("")
        self.SrchSIP.set("")
        self.SrchDIP.set("")
        self.SrchSPrt.set("")
        self.SrchDPrt.set("")
        #self.SrchSysIP.set("")
        while self.fqueue.qsize() > 0:
            temp = self.fqueue.get()

    def monitoredsystems(self):

        columncount = 15
        maxperpage = 10
        padx_val = 5
        self.svars = []
        self.dispsvars = []
        self.labels = []

    #Monitored System Tabs

        if len(self.pages) > 0:
            pcount = len(self.pages) - 1
            while pcount >= 0:
                self.NB1.forget(self.pages[pcount])
                self.pages.remove(self.pages[pcount])
                pcount = pcount - 1

        if len(self.IPs2Mon) > maxperpage:
            if len(self.IPs2Mon) % maxperpage == 0:
                pagecount = len(self.IPs2Mon) // maxperpage
            else:
                pagecount = len(self.IPs2Mon) // maxperpage + 1
        else:
            pagecount = 1

        for p in range(pagecount):
            page = ttk.Frame(self.NB1)
            self.NB1.insert(p,page,text='Monitored Systems ' + str(p+1))
            self.pages.append(page)

    #Layout Monitored System metrics
        for p in range(pagecount):

            SysMonNumLabel = Label(self.pages[p],text="Monitoring " + str(len(self.IPs2Mon)) + " FW Logs",bg="lightsteelblue",relief=SUNKEN)
            SysMonNumLabel.grid(row=1,column=0,padx=padx_val,pady=5,ipadx=10,sticky=W+E,columnspan=2)

            DirLabel = Label(self.pages[p],text="Traffic Direction",bg="lightskyblue",relief=SUNKEN)
            DirLabel.grid(row=1,column=3,padx=padx_val,pady=5,ipadx=10,sticky=W+E,columnspan=3)

            ProtLabel = Label(self.pages[p],text="Protocol",bg="lightskyblue",relief=SUNKEN)
            ProtLabel.grid(row=1,column=6,padx=padx_val,pady=5,ipadx=10,sticky=W+E,columnspan=4)

            FWActionLabel = Label(self.pages[p],text="Firewall Action",bg="lightskyblue",relief=SUNKEN)
            FWActionLabel.grid(row=1,column=10,padx=padx_val,pady=5,ipadx=10,sticky=W+E,columnspan=2)

            FilterLabel = Label(self.pages[p],text="Search Log",bg="powderblue",relief=SUNKEN)
            FilterLabel.grid(row=2,column=0,padx=padx_val,pady=5,ipadx=3,sticky=W+E)

            SysLabel = Label(self.pages[p],text="System IP",bg="powderblue",relief=SUNKEN)
            SysLabel.grid(row=2,column=1,padx=padx_val,pady=5,ipadx=20,sticky=W+E)

            TotLabel = Label(self.pages[p],text="Total Traffic",bg="powderblue",relief=SUNKEN)
            TotLabel.grid(row=2,column=2,padx=padx_val,pady=5,ipadx=10,sticky=W+E)

            InbLabel = Label(self.pages[p],text="Inbound",bg="powderblue",relief=SUNKEN)
            InbLabel.grid(row=2,column=3,padx=padx_val,pady=5,ipadx=10,sticky=W+E)

            OutbLabel = Label(self.pages[p],text="Outbound",bg="powderblue",relief=SUNKEN)
            OutbLabel.grid(row=2,column=4,padx=padx_val,pady=5,ipadx=10,sticky=W+E)

            UnkbLabel = Label(self.pages[p],text="Unknown",bg="powderblue",relief=SUNKEN)
            UnkbLabel.grid(row=2,column=5,padx=padx_val,pady=5,ipadx=10,sticky=W+E)

            TCPLabel = Label(self.pages[p],text="TCP",bg="powderblue",relief=SUNKEN)
            TCPLabel.grid(row=2,column=6,padx=padx_val,pady=5,ipadx=10,sticky=W+E)

            UDPLabel = Label(self.pages[p],text="UDP",bg="powderblue",relief=SUNKEN)
            UDPLabel.grid(row=2,column=7,padx=padx_val,pady=5,ipadx=10,sticky=W+E)

            ICMPLabel = Label(self.pages[p],text="ICMP",bg="powderblue",relief=SUNKEN)
            ICMPLabel.grid(row=2,column=8,padx=padx_val,pady=5,ipadx=10,sticky=W+E)

            OthLabel = Label(self.pages[p],text="Other",bg="powderblue",relief=SUNKEN)
            OthLabel.grid(row=2,column=9,padx=padx_val,pady=5,ipadx=10,sticky=W+E)

            AllowLabel = Label(self.pages[p],text="Allow",bg="powderblue",relief=SUNKEN)
            AllowLabel.grid(row=2,column=10,padx=padx_val,pady=5,ipadx=10,sticky=W+E)

            DropLabel = Label(self.pages[p],text="Drop",bg="powderblue",relief=SUNKEN)
            DropLabel.grid(row=2,column=11,padx=padx_val,pady=5,ipadx=10,sticky=W+E)

            ReadLabel = Label(self.pages[p],text="Log Last Read",bg="powderblue",relief=SUNKEN)
            ReadLabel.grid(row=2,column=12,padx=padx_val,pady=5,ipadx=35,sticky=W+E,columnspan=2)

            FSizeLabel = Label(self.pages[p],text="Log File Size",bg="powderblue",relief=SUNKEN)
            FSizeLabel.grid(row=2,column=14,padx=padx_val,pady=5,ipadx=4,sticky=W+E)

            LogRateLabel = Label(self.pages[p],text="Log Rate (/sec)",bg="powderblue",relief=SUNKEN)
            LogRateLabel.grid(row=2,column=15,padx=padx_val,pady=5,ipadx=4,sticky=W+E)

            if len(self.IPs2Mon) > (maxperpage * (p + 1)):
                logcount = (maxperpage * (p + 1))
            else:
                logcount = len(self.IPs2Mon)

            for r in range(maxperpage*p,logcount):
                radiob = Radiobutton(self.pages[p],variable=self.FilVar,value=r,command=lambda:self.setfilter())
                radiob.grid(row=r+4,column=0)
                for c in range(columncount):
                    self.svar = StringVar()
                    self.dispsvar = StringVar()
                    self.svars.append(self.svar)
                    self.dispsvars.append(self.dispsvar)
                    label=Label(self.pages[p],textvariable=self.dispsvar,relief=SUNKEN)
                    label.grid(row=r+4,column=c+1,padx=padx_val,sticky=W+E)
                    self.labels.append(label)
        return r
    
    def readlicensefile(self,Dpath):

        licensefile = Path(self.convertPath(Dpath,"F") + "/licensefile.txt")

        if licensefile.is_file() == False:
            RegOwner = "Unlicensed"
            RegDate = "Unlicensed"
            LicType = "Unlicensed"
            LicKey = "Unlicensed"
            LicComp = "Unlicensed"
        else:
            licfile = open(licensefile,"r",1)
            RegOwner = licfile.readline().strip('\n')
            RegDate = licfile.readline().strip('\n')
            LicType = licfile.readline().strip('\n')
            LicKey = licfile.readline().strip('\n')
            if LicType == "Local":
                LicComp = LicKey[:5]
            if LicType == "Workgroup":
                LicComp = LicKey[:5] + LicKey[10:11] + LicKey[12:13] + LicKey[16:17] + LicKey[22:23]
            if LicType == "Enterprise":
                LicComp = LicKey[:5] + LicKey[16:17] + LicKey[22:23]
            licfile.close()

        return RegOwner,RegDate,LicType,LicKey,LicComp

    def writeAppLog(self,message):

        #message = datetime.now().strftime('%Y-%m-%d %H:%M:%S') + " >> " + message
        #print(message)
        msgtype = message[23:24]
        #print(msgtype)
        FWAction = message[45:52]
        #print(FWAction)
        ProgMsg = msgtype.isalpha()
        # print(ProgMsg)

        #self.StatusBar.set("Updating User Interface (message processing)...")
        #self.root.update_idletasks()

        #self.StatusBar.set("Writing log data to interface and DB...")

        if ProgMsg == True and self.ShowPMsg.get() == 0:
            if message[23:29] == "SYSTEM":
                self.LogApp.insert(3.0,message,'dbwrite')
                self.LogApp.tag_config('dbwrite',foreground='black')
            else:
                if "Error" not in message:
                    self.LogApp.insert(3.0,message,'progmsg')
                    self.LogApp.tag_config('progmsg',foreground='orange')
                else:
                    self.LogApp.insert(3.0,message,'errmsg')
                    self.LogApp.tag_config('errmsg',foreground='red')
        else:
            self.mqueue.put(message)

    def ReadIPs(self,IPs2MFile):
        with open(IPs2MFile,"r") as f:
            self.IPs2Mon = f.readlines()
        self.IPs2Mon = [x.strip('\n') for x in self.IPs2Mon]
        f.close()

    def WriteIPs(self,IPs2MFile,IP2Add):
        IPFile = open(IPs2MFile,"a")
        IPFile.seek(0,2)
        IPFile.write(IP2Add + "\n")
        IPFile.close()

    def log_startup_single(self,SysIP,VT,pcount):

            self.writeAppLog(datetime.now().strftime('%Y-%m-%d %H:%M:%S') + " >> Attempting to monitor Windows firewall log for " + SysIP + (15 - len(SysIP)) * ' ' + "...\n")
            t = Thread(target=FWMon, args=(self,self.SIEMIP.get(),SysIP,VT,))
            t.daemon = True
            t.start()
            self.Monitors[pcount] = (t,SysIP)
            self.writeAppLog(datetime.now().strftime('%Y-%m-%d %H:%M:%S') + " >> Monitoring Windows Firewall Log for " + SysIP + (15 - len(SysIP)) * ' ' + ".\n")
            AvailMsg = SysIP + " Available - - - - - - - - - " + datetime.now().strftime('%Y-%m-%d %H:%M:%S') + " - -"
            self.queue.put(AvailMsg)

    def log_startup_all(self,VerTp):

        if self.StartBtnText.get() == "Start":
            self.StatusBar.set("Starting monitor threads...")
            #procmonitor = {}
            proccount = 0

            for i in range(len(self.AvailIPs2Mon)):
                self.log_startup_single(self.AvailIPs2Mon[i],VerTp,proccount)
                proccount += 1
                
            self.StartBtnText.set("Stop")
            self.StartBtn.config(fg="red")
        else:
            self.StartBtnText.set("Start")
            self.StartBtn.config(fg="blue")
            for i in range(len(self.AvailIPs2Mon)):
                self.cqueue.put_nowait(27)
            self.ThreadMonitor(VerTp)

    def shutdown_monitors(self,VerType):

        self.StatusBar.set(datetime.now().strftime('%Y-%m-%d %H:%M:%S') + " >> Please Wait:  Shutting down...")
        self.ExitBtnText.set("Shutting Down")
        self.root.update_idletasks()

        self.cqueue.put_nowait(27)

        proccount = len(self.Monitors) - 1
        while proccount >= 0:
            (p,a) = self.Monitors[proccount]
            if not p.is_alive():
                del self.Monitors[proccount]
            proccount = proccount - 1
               
        self.ThreadMonitor(VerType)
        self.root.destroy()

    def ThreadMonitor(self,VerTp):
        #print("ThreadMonitor")
        achar = 0

        for proccount in self.Monitors.keys():
            (p, a) = self.Monitors[proccount]
            if not p.is_alive():
                self.writeAppLog(datetime.now().strftime('%Y-%m-%d %H:%M:%S') + " >> " + a + (15 - len(a)) * ' ' + " >> The process monitoring the Windows firewall log crashed! Restarting...\n")
                #r = Thread(target=FWMon, args=(self,self.SIEMIP.get(),a,))
                if VerTp == "MultiDB":
                    r = Thread(target=FWMon, args=(self,self.SIEMIP.get(),a,VerTP,))
                else:
                    r = Thread(target=FWMon, args=(self," ",a,VerTP,))

                r.daemon = True
                r.start()
                if r.is_alive():
                    self.writeAppLog(datetime.now().strftime('%Y-%m-%d %H:%M:%S') + " >> " + a + (15 - len(a)) * ' ' + " >> The process monitoring the Windows firewall log successfully restarted.\n")
                    self.Monitors[proccount] = (r,a)
        if self.cqueue.empty() == False:
            achar = self.cqueue.get_nowait()
            if achar == 27:
                #self.writeAppLog(datetime.now().strftime('%Y-%m-%d %H:%M:%S') + " >> Please Wait: FW Monitors are shutting down...\n")
                for procount in self.Monitors.keys():
                    (p, a) = self.Monitors[procount]
                    self.writeAppLog(datetime.now().strftime('%Y-%m-%d %H:%M:%S') + " >> Please Wait: Shutting down monitor for " + a + "\n")
                    self.cqueue.put_nowait(a + str(achar))
                #while self.cqueue.empty() == False:
                    #temp = self.cqueue.get
                    #time.sleep(0.05)
                    #del self.Monitors[procount]
                self.cqueue.put_nowait('Done')

    def convertPath(self,filePath,ConType):

        if ConType == "F":
            pythonfilePath = filePath.replace(chr(92), '/')
        else:
            pythonfilePath = filePath.replace('/', chr(92))

        return pythonfilePath

    def DetermineType(self,DPath):

        # Program Types
        #     No License - Local only - No Settings - No DB - Realtime Search Only
        #     License - Multiple Systems - Change Settings - No DB - Realtime Search Only
        #     License - Multiple Systems - Change Settings - DB - Historical and Realtime Search

        # Test for Database availablility

        RegO,RegD,LicT,LicK,LicC = self.readlicensefile(DPath)
        
        #TestString = subprocess.check_output(['wmic','product','get','name'])

        return RegO,RegD,LicT,LicK,LicC

    def LogAvail(self,IP,DFWPath):
        
        #print("Checking availability for IP " + IP + "...")
        logfilename = "//" + IP + self.convertPath(DFWPath,"F") + "/pfirewall.log"
        try:
            logfile = open("//" + IP + self.convertPath(DFWPath,"F") + "/pfirewall.log","r",1)
            Status = "Available"
            logfile.close()
            #print("Log available for IP " + IP)
            ErrMsg = "Log Available"
            self.writeAppLog(datetime.now().strftime('%Y-%m-%d %H:%M:%S') + " >> Log available for IP " + IP + "\n")

        except (OSError, IOError) as e:
            Status = "Unavailable"
            ErrMsg = "Error #" + str(e.errno) + ": " + str(e.strerror) + " - "+ IP + ": Log is unavailable.\n"
            #print(ErrMsg)
            self.writeAppLog(datetime.now().strftime('%Y-%m-%d %H:%M:%S') + " >> " + ErrMsg)

        return Status, ErrMsg

    def LogAvailCheck(self,DefFWPath):

        #print("Checking for log availability...")
        #self.writeAppLog(datetime.now().strftime('%Y-%m-%d %H:%M:%S') + " >> Checking for log availability...\n")
        #IPsAvail = []
        #IPsUnAvail = []
        #AvailFlags = []
        #AvailErrMsgs = []

        for i in range(len(self.IPs2Mon)):
            print("Checking availability for IP " + self.IPs2Mon[i] + "...")
            self.writeAppLog(datetime.now().strftime('%Y-%m-%d %H:%M:%S') + " >> Checking availability for IP " + self.IPs2Mon[i] + "...\n")
            AvailFlag, ErrMessage = self.LogAvail(self.IPs2Mon[i],DefFWPath)
            if AvailFlag == "Available":
                self.AvailIPs2Mon.append(self.IPs2Mon[i])
                self.Availability.append(AvailFlag)
            else:
                self.UnAvailIPs2Mon.append(self.IPs2Mon[i])
                self.AvailErrMsgs.append(ErrMessage)

    def FileLocDataChange(self):

        self.FLSaveButton.config(state="normal")

    def setfilter(self):
        while self.fqueue.qsize() > 0:
            temp = self.fqueue.get()
        self.fqueue.put(self.IPs2Mon[self.FilVar.get()])

    def LogUpdateCheck(self,logmsg,colcnt):
        #LCount = self.queue.get_nowait()
        try:
            for r in range(len(self.IPs2Mon)):
                teststring = str(logmsg)
                LabelList = teststring.split()
                dispmsg = self.svars[r*colcnt+11].get() + " " + self.svars[r*colcnt+12].get()

                if len(dispmsg) > 1:
                    disptimestr = dispmsg.strip()
                    disptime = datetime.strptime(disptimestr,'%Y-%m-%d %H:%M:%S')
                    timediff = (datetime.now() - disptime)

                    for c in range(colcnt):
                        if ((timediff.total_seconds()) / 60) < 3:
                            ##for c in range(colcnt):
                            self.labels[r*colcnt+c].config(bg="lightgrey")
                            self.svars[r*colcnt+c].set(LabelList[c])
                        else:
                            ##for c in range(colcnt):
                            self.labels[r*colcnt+c].config(bg="red")
                            self.svars[r*colcnt+c].set(LabelList[c])
                    
                if self.IPs2Mon[r] == LabelList[0]:
                    for c in range(colcnt):
                        self.labels[r*colcnt+c].config(bg="yellow")
                        self.svars[r*colcnt+c].set(LabelList[c])

        except:
                    pass

        #dcount = dcount + 1

    def updatecycle(self):

        StartTime = self.StartTime.get()[9:]
        LastUpdate = self.LastUpdate.get()[17:]

        StartTimeT = datetime.strptime(StartTime,'%Y-%m-%d %H:%M:%S')
        LastUpdateT = datetime.strptime(LastUpdate,'%Y-%m-%d %H:%M:%S')

        timediff = LastUpdateT - StartTimeT
        
        return timediff.total_seconds()
        
    def remIPsFromDB(self):

        values = [self.IPStatus.get(idx).split(' ') for idx in self.IPStatus.curselection()]
        IPs = [item[0] for item in values]

        for i in range(len(IPs)):
            RemSQL = "DELETE FROM ips2monitor where IPAddr = " + chr(34) + IPs[i] + chr(34)
            self.writeAppLog(datetime.now().strftime('%Y-%m-%d %H:%M:%S') + " >> " + IPs[i] + " successfully deleted.\n")
            dcr.execute(RemSQL)
        dcnn.commit()

        for idx in self.IPStatus.curselection():
            self.IPStatus.delete(self.IPStatus.curselection())
            
        self.StatusBar.set("Deleting IPs...")
        self.root.update_idletasks()

        return
    
    def addIPs2File(self,DFWPath):

        IPs2Test = self.IPMgt.get(1.0,"end-1c")

        IPs2Test = IPs2Test.split('\n')

        NoDuplicate = False
        
        for l in range(len(IPs2Test)):
            if len(IPs2Test[l]) > 3:
                octets = IPs2Test[l].split('.')
                if int(octets[0]) < 255 and int(octets[0]) > 0:
                    if int(octets[1]) < 255 and int(octets[1]) > 0:
                        if int(octets[2]) < 255 and int(octets[2]) > 0:
                            if int(octets[3]) < 255 and int(octets[3]) > 0:
                                #for n in range(len(self.IPs2Mon)):
                                if (IPs2Test[l] in self.IPs2Mon) == False:
                                    self.writeAppLog(datetime.now().strftime('%Y-%m-%d %H:%M:%S') + " >> " + IPs2Test[l] + " successfully added.\n")
                                    Availability, ErrMsg = self.LogAvail(IPs2Test[l],DFWPath)
                                    NoDuplicate = True
                                #self.IPStatus.configure(state="normal")
                                    if Availability == "Available":
                                        try:
                                            if IPs2Test[l] == socket.gethostbyname(socket.gethostname()):
                                                tempstr = subprocess.check_output(['netsh','advfirewall','show','all','state'])
                                            else:
                                                tempstr = subprocess.check_output(['netsh','-r',IPs2Test[l],'advfirewall','show','all','state'])
                                                
                                            FWProfileInfo = (''.join(ch for ch,_ in itertools.groupby(str(tempstr)))).split('\\r\\n')
                                            if FWProfileInfo[3][-2:] == 'OF':
                                                FWProfileInfo[3] = FWProfileInfo[3] + 'F'
                                            if FWProfileInfo[7][-2:] == 'OF':
                                                FWProfileInfo[7] = FWProfileInfo[7] + 'F'
                                            if FWProfileInfo[11][-2:] == 'OF':
                                                FWProfileInfo[11] = FWProfileInfo[11] + 'F'
                                            self.IPStatus.insert(0,(IPs2Test[l] + ((15 - len(IPs2Test[l])) * ' ') + " ==> " + Availability + "  >> Domain Profile: " + FWProfileInfo[3] + "  >> Private Profile: " + \
                                                                    FWProfileInfo[7] + "  >> Public Profile: " + FWProfileInfo[11] + "\n"))
                                        except:
                                            self.IPStatus.insert(0,(IPs2Test[l] + ((15 - len(IPs2Test[l])) * ' ') + " ==> " + Availability + "  >> Domain Profile: Unknown  >> Private Profile: Unknown  >> Public Profile: Unknown\n"))
                                            self.UnAvailIPs2Mon.append(IPs2Test[l])
                                            self.IPs2Mon.append(IPs2Test[l])
                                            self.WriteIPs(self.convertPath(self.IPs2M.get(),"F"),IPs2Test[l])
                                    else:
                                        #print(datetime.now().strftime('%Y-%m-%d %H:%M:%S') + " ==> " + ErrMsg)
                                        self.IPStatus.insert(0,(IPs2Test[l] + ((15 - len(IPs2Test[l])) * ' ') + " ==> " + Availability + "  >> Domain Profile: Unknown  >> Private Profile: Unknown  >> Public Profile: Unknown\n"))
                                        self.UnAvailIPs2Mon.append(IPs2Test[l])
                                        self.IPs2Mon.append(IPs2Test[l])
                                        self.WriteIPs(self.convertPath(self.IPs2M.get(),"F"),IPs2Test[l])
                                #self.IPStatus.configure(state="disabled")
                                self.IPMgt.delete(1.0,"end-1c")
                                if NoDuplicate == False:
                                    self.writeAppLog(datetime.now().strftime('%Y-%m-%d %H:%M:%S') + " >> Duplicate IP Error - " + IPs2Test[l] + " is a duplicate IP.\n")
                                    Availability = "Unavailable"
                                    ErrMsg = "Duplicate IP Error - " + IPs2Test[l] + " is a duplicate IP.\n"
                                else:
                                    if Availability == "Available":
                                        NoDuplicate = False
                                        self.IPs2Mon.append(IPs2Test[l])
                                        self.AvailIPs2Mon.append(IPs2Test[l])
                                        self.WriteIPs(self.convertPath(self.IPs2M.get(),"F"),IPs2Test[l])

            r = self.monitoredsystems()

        return

    def truncscrtxt(self):

        self.LogWin.configure(state='normal')
        self.LogWin.delete(self.RollB.get() + '.0',END)
        #LW.configure(state='disabled')

    def truncscrtxtA(self):

        self.LogApp.configure(state='normal')
        self.LogApp.delete(self.RollBA.get() + '.0',END)
        #LA.configure(state='disabled')

    def __init__(self, queue, mqueue, cqueue, fqueue, cfgqueue, dbinfoqueue):

    #Queue Declarations
        self.queue = queue
        self.mqueue = mqueue
        self.cqueue = cqueue
        self.fqueue = fqueue
        self.cfgqueue = cfgqueue
        self.dbinfoqueue = dbinfoqueue

    #Variable Declarations
        self.labels = []
        self.svars = []
        self.pages = []

        pmon = {}
        self.IPs2Mon = []
        self.AvailIPs2Mon = []
        self.UnAvailIPs2Mon = []
        self.Availability = []
        self.AvailErrMsgs = []

        #print(chr(34)) #"
        #print(chr(39)) #'
        #print(chr(92)) #\
        
    #Constant Declarations
        columncount = 15
        maxsysperpage = 10
        padx_val = 5
        UpdateCount = 1

    #File Location Determination
        dirPath = os.path.dirname(os.path.realpath(__file__))
        defFWPath = "/c$/Windows/System32/LogFiles/Firewall"

    #Determine version of Firewall Monitor - Local or Remote
        RegOwner,RegDate,LicType,LicKey,LicCmp = self.DetermineType(dirPath)

    #Based on version of Firewall Monitor, Determine IPs to Monitor & encryption
        if LicCmp == "MultiDB":
            fwenc, key = self.AccessCheck(dirPath)
            dconn,dcur,isopen = self.CreateDB(fwenc, key)
            self.IPs2Mon = self.ReadIPsDB(dcur)
            self.IPs2Mon.sort()
        else:
            dconn = 0
            dcur = 0
            isopen = False
            fwenc = 0
            key = 0
            self.IPs2Mon.append(str(socket.gethostbyname(socket.gethostname())))

    #Main Window Declaration
        self.root = Tk()
        self.root.wm_title("Windows Firewall Log Monitor")
        self.root.minsize(1100,300)

    #Setup initial values for display values
        self.FilVar = IntVar()
        self.FilVar.set(-1)

    #First Row - Start - Title - Last Update
        self.StartTime = StringVar()
        self.StartTime.set("Started: " + datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
        StartLabel = Label(self.root,textvariable=self.StartTime,bg="lightsteelblue",relief=SUNKEN)
        StartLabel.grid(row=0,column=0,padx=2,pady=2,ipadx=3,ipady=1,sticky=W+E,columnspan=2)
        
        title=Label(self.root, text="Windows Firewall Log Monitor",font=("Verdana 12 bold"),fg="yellow",bg="firebrick3",relief=SUNKEN)
        title.grid(row=0,column=5,sticky=W+E,columnspan=7)

        self.LastUpdate = StringVar()
        self.LastUpdate.set("Last Updated at: " + datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
        UpdateLabel = Label(self.root,textvariable=self.LastUpdate,bg="lightsteelblue",relief=SUNKEN)
        UpdateLabel.grid(row=0,column=13,pady=2,padx=2,ipadx=3,ipady=1,sticky=W+E,columnspan=2)

        self.NB1 = ttk.Notebook(self.root)
        self.NB1.grid(row=2,column=0,columnspan=14,padx=3,pady=3,sticky=W+E)

# ***** Build the Notebook Widget
                    
    #Application Log Tab
        AppLogPage = ttk.Frame(self.NB1)
        self.NB1.add(AppLogPage,text='Application Log')
        AppLogLabel = Label(AppLogPage,text="Application Log",font=("Verdana 12 bold"),bg="lightcyan2",relief=RAISED)
        AppLogLabel.grid(padx=10,pady=10,ipadx=10,ipady=10,sticky=W+E,columnspan=14)

        self.LogApp = ScrolledText(AppLogPage, width=153,height=12, padx=3, wrap='none',undo=False)
        self.LogApp.grid(padx=10,pady=2,columnspan=14)
        self.LogApp.insert(1.0,"Monitor Date & Time >> System IP       ==> Application Message\n")
        self.LogApp.insert(2.0,"=============================================================================================================================================================================\n")

        self.ShowPMsg = IntVar()
        ShowProgMsg = Checkbutton(AppLogPage,text="Stop Live Feed",variable=self.ShowPMsg)
        ShowProgMsg.grid(row=13,column=0,padx=5,pady=4,sticky=W)

        if LicCmp != "Unlicensed":
            ShowProgMsg.config(state="normal")
        else:
            ShowProgMsg.config(state="disabled")

        self.LineCountA = StringVar()
        self.LineCountA.set("App Log Line Count: " + str(self.LogApp.index('end-1c').split('.')[0]))
        LineLabelA = Label(AppLogPage,textvariable=self.LineCountA,bg="lightsteelblue",relief=SUNKEN)
        LineLabelA.grid(row=13,column=13,padx=8,pady=4,ipadx=10,ipady=3,sticky=E)

        self.writeAppLog(datetime.now().strftime('%Y-%m-%d %H:%M:%S') + " >> Starting the Windows Firewall Log Monitor...\n")

    #IP Management Tab
        IPMgtPage = ttk.Frame(self.NB1)
        self.NB1.add(IPMgtPage,text='IP Management')

        IPMgtLabel = Label(IPMgtPage,text="Monitored IP Management",font=("Verdana 12 bold"),bg="lightcyan2",relief=RAISED)
        IPMgtLabel.grid(row=1,column=1,padx=10,pady=10,ipadx=10,ipady=3,sticky=W+E,columnspan=3)

        self.IPMgt = ScrolledText(IPMgtPage,width=40,height=14, padx=3, wrap='none',undo=False)
        self.IPMgt.grid(row=2,column=1,padx=10,rowspan=4)

        self.AddIPText = StringVar()
        self.AddIPText.set("Add >>")
        self.AddIPButton = Button(IPMgtPage, textvariable=self.AddIPText, width=11, fg="Green", command=lambda:self.addIPs2File(defFWPath))
        self.AddIPButton.grid(row=3,column=2,pady=4)
        
        if LicCmp == "MultiDB" or LicCmp == "MultiNODB":
            self.AddIPButton.config(state="normal")
            self.IPMgt.config(state="normal")
        else:
            self.AddIPButton.config(state="disabled")
            self.IPMgt.config(state="disabled")

        self.RemIPText = StringVar()
        self.RemIPText.set("<< Remove")
        self.RemIPButton = Button(IPMgtPage, textvariable=self.RemIPText, width=11, fg="Green", command=lambda:self.remIPsFromFile(defFWPath))
        self.RemIPButton.grid(row=4,column=2,pady=4)
        
        if LicCmp == "MultiDB" or LicCmp == "MultiNODB":
            self.RemIPButton.config(state="normal")
        else:
            self.RemIPButton.config(state="disabled")

        #self.IPStatus = ScrolledText(IPMgtPage,width=120,height=14, padx=3, wrap='none',undo=False)
        self.IPStatus = Listbox(IPMgtPage,selectmode='multiple',width=132,height=14)
        self.IPStatus.grid(row=2,column=3,padx=10,rowspan=4)
        #self.IPStatus.configure(state="disabled")
 
    #File Location Tab

        FileLocationsPage = ttk.Frame(self.NB1)
        self.NB1.add(FileLocationsPage,text='File Information')

        FileLocSect = Label(FileLocationsPage,text="File Information",font=("Verdana 12 bold"),bg="lightcyan2",width=110,relief=SUNKEN)
        FileLocSect.grid(row=0,column=0,padx=7,ipadx=20,pady=2,sticky=W+E,columnspan=300)

        self.LogLoc = StringVar()

        LogLocation = Label(FileLocationsPage,text="Remote Firewall Log File Location and Filename:",relief=SUNKEN)
        LogLocation.grid(row=2,column=0,padx=7,ipadx=10,pady=2,sticky=E)
            
        VarLogLoc = Entry(FileLocationsPage,textvariable=self.LogLoc,width=75)
        VarLogLoc.grid(row=2,column=1,padx=7,sticky=W)

        if LicCmp == "MultiDB":
            dcur.execute("Select * FROM FileLocations WHERE FileSetting = 'FWLogLoc'")

            rows = dcur.fetchall()

            if len(rows) > 0:
                for row in rows:
                    settings = str(row).split()
                    temp = settings[3]
                    self.LogLoc.set(self.convertPath(temp[1:len(temp)-2],"B"))
            else:
                self.LogLoc.set(self.convertPath(DFWPath + "/pfirewall.log","B"))
                dcur.execute("INSERT INTO filelocations VALUES ('FWLogLoc'," + chr(39) + defFWPath + "/pfirewall.log" + chr(39) + ")")
                dconn.commit
        else:
            self.LogLoc.set(self.convertPath(defFWPath + "/pfirewall.log","B"))
            VarLogLoc.config(state="disabled")
            
        self.LogLoc.trace("w", lambda name, index, mode: self.FileLocDataChange())

        ExtFileLoc = Label(FileLocationsPage,text="File Location of External File:",relief=SUNKEN)
        ExtFileLoc.grid(row=3,column=0,padx=7,ipadx=10,pady=2,sticky=E)

        self.ExFileLoc = StringVar()

        VarEFileLoc = Entry(FileLocationsPage,textvariable=self.ExFileLoc,width=75)
        VarEFileLoc.grid(row=3,column=1,padx=7,sticky=W)

        if LicCmp == "MultiDB":
            dcur.execute("Select * FROM FileLocations WHERE FileSetting = 'ExtFileLoc'")

            rows = dcur.fetchall()

            if len(rows) > 0:
                for row in rows:
                    settings = str(row).split()
                    temp = settings[3]
                    self.ExFileLoc.set(self.convertPath(temp[1:len(temp)-2],"B"))
            else:
                self.ExFileLoc.set(self.convertPath(dirPath + "/","B"))
                dcur.execute("INSERT INTO filelocations VALUES ('ExtFileLoc','" + convertPath(dirPath,"F") + "/')")
                dconn.commit

            self.ExFileLoc.trace("w", lambda name, index, mode: self.FileLocDataChange())

        else:
            self.ExFileLoc.set(self.convertPath(dirPath + "/","B"))
            VarEFileLoc.config(state="disabled")

        IPsLocation = Label(FileLocationsPage,text="IPs to Monitor Location and Filename:",relief=SUNKEN)
        IPsLocation.grid(row=4,column=0,ipadx=10,pady=2,sticky=E)

        self.IPs2M = StringVar()
        self.IPs2M.set(dirPath + "\IPs2Monitor.txt")
        VarIPs2M = Entry(FileLocationsPage,textvariable=self.IPs2M,width=75)
        VarIPs2M.grid(row=4,column=1,padx=7,sticky=W)
        VarIPs2M.config(state="disabled")
            
        if LicCmp != "Unlicensed" and LicCmp != "Singl":
            self.FLSaveBtnText = StringVar()
            self.FLSaveBtnText.set("Save")
            self.FLSaveButton = Button(FileLocationsPage, textvariable=self.FLSaveBtnText, width=11, fg="Green", command=lambda:self.savefilesettings(dconn,dcur))
            self.FLSaveButton.grid(row=4,column=14,pady=4,sticky=E)
            self.FLSaveButton.config(state="disabled")

    #Determine IP Availability

        if LicCmp != "Unlicensed" and LicCmp != "Singl":

            filetest = Path(self.convertPath(self.IPs2M.get(),"F"))

            if filetest.is_file() and os.stat(self.convertPath(self.IPs2M.get(),"F")).st_size > 0:
                self.ReadIPs(self.convertPath(self.IPs2M.get(),"F"))
            else:
                self.WriteIPs(self.convertPath(self.IPs2M.get(),"F"),self.IPs2Mon[0])
        else:
            filetest = Path(self.convertPath(self.IPs2M.get(),"F"))
            if filetest.is_file():
                os.remove(self.convertPath(self.IPs2M.get(),"F"))
        
        self.LogAvailCheck(defFWPath)

        if len(self.UnAvailIPs2Mon) != 0:
            for i in range(len(self.UnAvailIPs2Mon)):
                UnAvailMsg = self.UnAvailIPs2Mon[i] + " Unavailable - - - - - - - - - " + datetime.now().strftime('%Y-%m-%d %H:%M:%S') + " - -"
                self.queue.put(UnAvailMsg)
                self.IPStatus.insert(0,(self.UnAvailIPs2Mon[i] + ((15 - len(self.UnAvailIPs2Mon[i])) * ' ') + " ==> " + self.AvailErrMsgs[i] + "  >> Domain Profile: Unknown  >> Private Profile: Unknown  >> Public Profile: Unknown\n"))

        for i in range(len(self.Availability)):
            self.IPStatus.configure(state="normal")
            try:
                if self.AvailIPs2Mon[i] == socket.gethostbyname(socket.gethostname()):
                    tempstr = subprocess.check_output(['netsh','advfirewall','show','all','state'])
                else:
                    tempstr = subprocess.check_output(['netsh','-r',self.AvailIPs2Mon[i],'advfirewall','show','all','state'])
                FWProfileInfo = (''.join(ch for ch,_ in itertools.groupby(str(tempstr)))).split('\\r\\n')
                if FWProfileInfo[3][-2:] == 'OF':
                    FWProfileInfo[3] = FWProfileInfo[3] + 'F'
                if FWProfileInfo[7][-2:] == 'OF':
                    FWProfileInfo[7] = FWProfileInfo[7] + 'F'
                if FWProfileInfo[11][-2:] == 'OF':
                    FWProfileInfo[11] = FWProfileInfo[11] + 'F'
                self.IPStatus.insert(0,(self.AvailIPs2Mon[i] + ((15 - len(self.AvailIPs2Mon[i])) * ' ') + " ==> " + self.Availability[i] + "  >> Domain Profile: " + FWProfileInfo[3] + "  >> Private Profile: " + \
                                        FWProfileInfo[7] + "  >> Public Profile: " + FWProfileInfo[11] + "\n"))
            except:
                self.IPStatus.insert(0,(self.AvailIPs2Mon[i] + ((15 - len(self.AvailIPs2Mon[i])) * ' ') + " ==> " + self.Availability[i] + "  >> Domain Profile: Unknown  >> Private Profile: Unknown  >> Public Profile: Unknown\n"))
 
        #for i in range(len(AvailErrMsgs)):
            #self.IPStatus.insert(0,AvailErrMsgs[i] + "\n")

    #Settings Tab

        SettingsPage = ttk.Frame(self.NB1)
        self.NB1.add(SettingsPage,text='Application Settings')

        SettingsSect = Label(SettingsPage,text="Application Settings",font=("Verdana 12 bold"),bg="lightcyan2",width=110,relief=SUNKEN)
        SettingsSect.grid(row=0,column=0,padx=7,ipadx=20,pady=2,sticky=W+E,columnspan=300)

        LogLineLimit = Label(SettingsPage,text="Maximum Number of Lines in Consolidated Firewall Log:",relief=SUNKEN)
        LogLineLimit.grid(row=1,column=0,padx=7,ipadx=10,pady=2,sticky=E)

        self.LineLim = StringVar()
        self.LineLim.set('200000')
        VarMaxLine = Entry(SettingsPage,textvariable=self.LineLim)
        VarMaxLine.grid(row=1,column=1,padx=7,sticky=W+E,columnspan=10)
        VarMaxLine.config(state="disabled")

        LogLineRollback = Label(SettingsPage,text="Number of lines to delete in Consolidated Firewall Log when limit is reached:",relief=SUNKEN)
        LogLineRollback.grid(row=2,column=0,padx=7,ipadx=10,pady=2,sticky=E)

        self.RollB = StringVar()
        self.RollB.set('50000')
        VarRollback = Entry(SettingsPage,textvariable=self.RollB)
        VarRollback.grid(row=2,column=1,padx=7,sticky=W+E,columnspan=10)
        VarRollback.config(state="disabled")

        LogLineLimit = Label(SettingsPage,text="Maximum Number of Lines in Application Log:",relief=SUNKEN)
        LogLineLimit.grid(row=3,column=0,ipadx=10,pady=2,sticky=E)

        self.LineLimA = StringVar()
        self.LineLimA.set('10000')
        VarMaxLineA = Entry(SettingsPage,textvariable=self.LineLimA)
        VarMaxLineA.grid(row=3,column=1,padx=7,sticky=W+E,columnspan=10)
        VarMaxLineA.config(state="disabled")

        LogLineRollbackA = Label(SettingsPage,text="Number of lines to delete in Application Log when limit is reached:",relief=SUNKEN)
        LogLineRollbackA.grid(row=4,column=0,padx=7,ipadx=10,pady=2,sticky=E)

        self.RollBA = StringVar()
        self.RollBA.set('5000')
        VarRollbackA = Entry(SettingsPage,textvariable=self.RollBA)
        VarRollbackA.grid(row=4,column=1,padx=7,sticky=W+E,columnspan=10)
        VarRollbackA.config(state="disabled")

        self.IP6 = IntVar()
        self.IP6.set(0)
        IP6Traffic = Checkbutton(SettingsPage,text="Do NOT log IPv6 Traffic",variable=self.IP6)
        IP6Traffic.grid(row=5,column=2,sticky=W)
        IP6Traffic.config(state="disabled")

        self.DeDup = IntVar()
        self.DeDup.set(0)
        DeDuplicate = Checkbutton(SettingsPage,text="Remove Duplicate Records",variable=self.DeDup)
        DeDuplicate.grid(row=6,column=2,sticky=W)
        DeDuplicate.config(state="disabled")

        ExtFileSize = Label(SettingsPage,text="File Size of External File (MB):",relief=SUNKEN)
        ExtFileSize.grid(row=8,column=0,padx=7,ipadx=10,pady=2,sticky=E)

        self.ExFile = StringVar()
        self.ExFile.set('25')
        VarEFileSize = Entry(SettingsPage,textvariable=self.ExFile)
        VarEFileSize.grid(row=8,column=1,padx=7,sticky=W+E,columnspan=10)
        VarEFileSize.config(state="disabled")

        self.LogTraf = IntVar()
        self.LogTraf.set(1)
        LogTraffic = Checkbutton(SettingsPage,text="Do NOT log traffic in external file",variable=self.LogTraf)
        LogTraffic.grid(row=8,column=20,columnspan=100,sticky=W)
        LogTraffic.config(state="disabled")

        SIEMIPAddr = Label(SettingsPage,text="SIEM IP Address:",relief=SUNKEN)
        SIEMIPAddr.grid(row=9,column=0,padx=7,ipadx=10,pady=2,sticky=E)

        self.SIEMIP = StringVar()
        SIEMIPAddr = Entry(SettingsPage,textvariable=self.SIEMIP)
        SIEMIPAddr.grid(row=9,column=1,padx=7,sticky=W+E,columnspan=10)
        SIEMIPAddr.config(state="disabled")

        self.SIEMTraf = IntVar()
        self.SIEMTraf.set(0)
        SIEMTraffic = Checkbutton(SettingsPage,text="Log traffic in SIEM",variable=self.SIEMTraf)
        SIEMTraffic.grid(row=9,column=20,sticky=W,columnspan=100)
        SIEMTraffic.config(state="disabled")

        if LicCmp == "Singl":
            LogTraffic.config(state="normal")
            VarEFileSize.config(state="normal")
            IP6Traffic.config(state="normal")
            VarRollbackA.config(state="normal")
            VarMaxLineA.config(state="normal")
            VarRollback.config(state="normal")
            VarMaxLine.config(state="normal")

        if LicCmp == "MultiNODB":
            LogTraffic.config(state="normal")
            VarEFileSize.config(state="normal")
            IP6Traffic.config(state="normal")
            VarRollbackA.config(state="normal")
            VarMaxLineA.config(state="normal")
            VarRollback.config(state="normal")
            VarMaxLine.config(state="normal")
            SIEMTraffic.config(state="normal")
            SIEMIPAddr.config(state="normal")
            
            UpdateFreq = Label(SettingsPage,text="Update Frequency (seconds):",relief=SUNKEN)
            UpdateFreq.grid(row=7,column=0,padx=7,ipadx=10,pady=2,sticky=E)

            self.UpdateFQ = StringVar()
            self.UpdateFQ.set('45')
            VarPerTab = Entry(SettingsPage,textvariable=self.UpdateFQ)
            VarPerTab.grid(row=7,column=1,padx=7,sticky=W+E,columnspan=10)

            #DBWriteSize = Label(SettingsPage,text="Number of Records to write to DB at one time:",relief=SUNKEN)
            #DBWriteSize.grid(row=10,column=0,padx=7,ipadx=10,pady=2,sticky=E)

            #self.DBWriteSize = StringVar()
            #self.DBWriteSize.set('250')
            #DBWriteSizeVar = Entry(SettingsPage,textvariable=self.DBWriteSize)
            #DBWriteSizeVar.grid(row=10,column=1,padx=7,sticky=W+E,columnspan=10)

    #License Tab
        
        LicensePage = ttk.Frame(self.NB1)
        self.NB1.add(LicensePage,text='Licensing')

        LicenseSect = Label(LicensePage,text="Licensing",font=("Verdana 12 bold"),bg="lightcyan2",width=110,relief=SUNKEN)
        LicenseSect.grid(row=0,column=0,padx=7,ipadx=20,pady=2,sticky=W+E,columnspan=300)

        RegOwnerlbl = Label(LicensePage,text="Registered Owner:",relief=SUNKEN)
        RegOwnerlbl.grid(row=1,column=0,padx=7,ipadx=10,pady=2,sticky=E)

        self.RegOwner = StringVar()
        RegOwnerE = Entry(LicensePage,textvariable=self.RegOwner)
        RegOwnerE.grid(row=1,column=1,padx=7,sticky=W+E,columnspan=100)
        RegOwnerE.config(state="disabled")

        RegDatelbl = Label(LicensePage,text="Registration Date:",relief=SUNKEN)
        RegDatelbl.grid(row=2,column=0,padx=7,ipadx=10,pady=2,sticky=E)

        self.RegDate = StringVar()
        RegDateE = Entry(LicensePage,textvariable=self.RegDate)
        RegDateE.grid(row=2,column=1,padx=7,sticky=W+E,columnspan=100)
        RegDateE.config(state="disabled")

        # License Types
        #    Local
        #    MultNoDB
        #    MultDB
        
        LicTypelbl = Label(LicensePage,text="License Type:",relief=SUNKEN)
        LicTypelbl.grid(row=3,column=0,padx=7,ipadx=10,pady=2,sticky=E)

        self.LicType = StringVar()
        LicTypeE = Entry(LicensePage,textvariable=self.LicType)
        LicTypeE.grid(row=3,column=1,padx=7,sticky=W+E,columnspan=100)
        LicTypeE.config(state="disabled")

        LicKeylbl = Label(LicensePage,text="License Key:",relief=SUNKEN)
        LicKeylbl.grid(row=4,column=0,padx=7,ipadx=10,pady=2,sticky=E)

        self.LicKey = StringVar()
        LicKeyE = Entry(LicensePage,textvariable=self.LicKey)
        LicKeyE.grid(row=4,column=1,padx=7,sticky=W+E,columnspan=100)
        LicKeyE.config(state="disabled")

        #NodeNumlbl = Label(LicensePage,text="Licensed Node Count:",relief=SUNKEN)
        #NodeNumlbl.grid(row=5,column=0,padx=7,ipadx=10,pady=2,sticky=E)

        #self.NodeNum = StringVar()
        #NodeNumE = Entry(LicensePage,textvariable=self.NodeNum)
        #NodeNumE.grid(row=5,column=1,padx=7,sticky=W+E,columnspan=100)
        #NodeNumE.config(state="disabled")

        self.RegOwner.set(RegOwner)
        self.RegDate.set(RegDate)
        self.LicType.set(LicType)
        self.LicKey.set(LicKey)

        self.Monitors = {}

        r = self.monitoredsystems()

    #Build Start Button
        self.StartBtnText = StringVar()
        self.StartBtnText.set("Start")
        self.StartBtn = Button(self.root, textvariable=self.StartBtnText, width=11, fg="blue", command=lambda:self.log_startup_all(LicCmp))
        self.StartBtn.grid(row=2,column=14,padx=padx_val,pady=5,ipadx=3,sticky=W+E)

# ***** Build the Search Criteria Area

        LogLabel = Label(self.root,text="Consolidated Firewall Log (includes local system date & time)",font=("Verdana 12 bold"),bg="lightcyan2",relief=RAISED)
        LogLabel.grid(padx=10,pady=10,ipadx=10,ipady=3,sticky=W+E,columnspan=15)

    #Set Filter Variable
        self.FilVar2 = IntVar()
        self.FilVar2.set(0)

        SearchCbox = Checkbutton(self.root,text="Enable Search",variable=self.FilVar2)
        SearchCbox.grid(row=r+6,column=14,sticky=W+E)

        SrchActLabel = Label(self.root,text="Search FW Action",bg="powderblue",relief=SUNKEN)
        SrchActLabel.grid(row=r+6,column=0,padx=padx_val,sticky=W+E)

        self.SrchAct = StringVar()
        SearchAct = OptionMenu(self.root,self.SrchAct,"","ALLOW","DROP","INFO-EVENTS-LOST")
        SearchAct.grid(row=r+7,column=0,padx=padx_val,sticky=W+E)

    
        SrchProtLabel = Label(self.root,text="Search Protocol",bg="powderblue",relief=SUNKEN)
        SrchProtLabel.grid(row=r+6,column=1,padx=padx_val,sticky=W+E)

        self.SrchProt = StringVar()
        SearchProt = OptionMenu(self.root,self.SrchProt,"","TCP","UDP","ICMP")
        SearchProt.grid(row=r+7,column=1,padx=padx_val,sticky=W+E)
        SearchProt.config(state="disabled")

        SrchSIPLabel = Label(self.root,text="Search Source IP",bg="powderblue",relief=SUNKEN)
        SrchSIPLabel.grid(row=r+6,column=2,padx=padx_val,sticky=W+E,columnspan=5)

        self.SrchSIP = StringVar()
        SearchSIP = Entry(self.root,textvariable=self.SrchSIP)
        SearchSIP.grid(row=r+7,column=2,padx=padx_val,sticky=W+E,columnspan=5)
        SearchSIP.config(state="disabled")

        SrchDIPLabel = Label(self.root,text="Search Dest IP",bg="powderblue",relief=SUNKEN)
        SrchDIPLabel.grid(row=r+6,column=7,padx=padx_val,sticky=W+E,columnspan=5)

        self.SrchDIP = StringVar()
        SearchDIP = Entry(self.root,textvariable=self.SrchDIP)
        SearchDIP.grid(row=r+7,column=7,padx=padx_val,sticky=W+E,columnspan=5)
        SearchDIP.config(state="disabled")

        SrchSPrtLabel = Label(self.root,text="Search Src Port",bg="powderblue",relief=SUNKEN)
        SrchSPrtLabel.grid(row=r+6,column=12,padx=padx_val,sticky=W+E,columnspan=1)

        self.SrchSPrt = StringVar()
        SearchSPrt = Entry(self.root,textvariable=self.SrchSPrt)
        SearchSPrt.grid(row=r+7,column=12,padx=padx_val,sticky=W+E,columnspan=1)
        SearchSPrt.config(state="disabled")

        SrchDPrtLabel = Label(self.root,text="Search Dst Port",bg="powderblue",relief=SUNKEN)
        SrchDPrtLabel.grid(row=r+6,column=13,padx=padx_val,sticky=W+E,columnspan=1)

        self.SrchDPrt = StringVar()
        SearchDPrt = Entry(self.root,textvariable=self.SrchDPrt)
        SearchDPrt.grid(row=r+7,column=13,padx=padx_val,sticky=W+E,columnspan=1)
        SearchDPrt.config(state="disabled")

        if LicCmp != "Unlicensed":
            SearchProt.config(state="normal")
            SearchSIP.config(state="normal")
            SearchDIP.config(state="normal")
            SearchSPrt.config(state="normal")
            SearchDPrt.config(state="normal")
        else:
            self.SrchProt.set("Unlicensed")
            self.SrchSIP.set("Unlicensed")
            self.SrchDIP.set("Unlicensed")
            self.SrchSPrt.set("Unlicensed")
            self.SrchDPrt.set("Unlicensed")

        button = Button(self.root, text='Clear Search', fg="green", command=lambda:self.ClearFilter())
        button.grid(row=r+7,column=14,padx=padx_val,pady=5,ipadx=3,sticky=W+E,columnspan=1)

# ***** Build the Firewall Log Area

        self.LogWin = ScrolledText(self.root, width=168, height=20, padx=3, wrap='none',undo=False)
        self.LogWin.grid(pady=2,columnspan=15)
        self.LogWin.insert(1.0,"Monitor Date & Time >> System IP       ==> Log Date    Log Time   Action Prot  Source IP                  Destination IP   SPort  DPort  Direction  Other\n")
        self.LogWin.insert(2.0,"=============================================================================================================================================================================\n")

# ***** Build Status Bar Area

        self.ShowTraf = IntVar()
        ShowTraffic = Checkbutton(self.root,text="Stop Live Feed",variable=self.ShowTraf)
        ShowTraffic.grid(row=r+28,column=0,sticky=W,columnspan=1)
        if LicCmp != "Unlicensed":
            ShowTraffic.config(state="normal")
        else:
            ShowTraffic.config(state="disabled")

        self.LineCount = StringVar()
        self.LineCount.set("FW Log Line Count: " + str(self.LogWin.index('end-1c').split('.')[0]))
        LineLabel = Label(self.root,textvariable=self.LineCount,bg="lightsteelblue",relief=SUNKEN)
        LineLabel.grid(row=r+28,column=13,padx=8,pady=4,ipadx=10,ipady=3,sticky=W,columnspan=3)

        self.UpdateStat = StringVar()
        self.UpdateStat.set("Update in " + str(int(self.UpdateFQ.get()) - int(self.updatecycle())) +" sec.")
        UpdateStatus = Label(self.root,textvariable = self.UpdateStat,bg="lightsteelblue",relief=SUNKEN)
        UpdateStatus.grid(row=r+28,column=12,padx=8,pady=4,ipadx=10,ipady=3,sticky=W+E)

        self.StatusBar = StringVar()
        if self.StartBtnText.get() == "Stop":
            self.StatusBar.set("Running...")
        else:
            self.StatusBar.set("Press Start to begin monitoring.")
        StatusBar = Label(self.root,textvariable=self.StatusBar,bg="lightsteelblue",relief=SUNKEN)
        StatusBar.grid(row=r+28,column=1,pady=4,ipadx=10,ipady=3,sticky=W+E,columnspan=3)

        if LicCmp == "MultiNODB":
            self.DBStatusBar = StringVar()
            self.DBStatusBar.set("Waiting to process logs...")
            StatusBar = Label(self.root,textvariable=self.DBStatusBar,bg="lightsteelblue",relief=SUNKEN)
            StatusBar.grid(row=r+28,column=4,pady=4,ipadx=10,ipady=3,sticky=W+E,columnspan=8)
            
        if LicCmp == "MultiDB":
            ShowTraffic.config(state="normal")
            self.DBStatBar1 = StringVar()
            if isopen == True:
                self.DBStatBar1.set("DB Status: Connected")
                DBStatBar = Label(self.root,textvariable=self.DBStatBar1,bg="lightgreen",relief=SUNKEN)
            else:
                self.DBStatBar1.set("DB Status: Not Present")
                DBStatBar = Label(self.root,text="DB Status: Not Present",bg="red",relief=SUNKEN)

            DBStatBar.grid(row=r+28,column=4,pady=4,ipadx=10,ipady=3,sticky=W+E)

            self.DBStatusBar = StringVar()
            if isopen == True:
                self.DBStatusBar.set("Waiting to process logs...")
            else:
                self.DBStatusBar.set("NOT Connected")
            StatusBar = Label(self.root,textvariable=self.DBStatusBar,bg="lightsteelblue",relief=SUNKEN)
            StatusBar.grid(row=r+28,column=4,pady=4,ipadx=10,ipady=3,sticky=W+E,columnspan=8)

        self.ExitBtnText = StringVar()
        self.ExitBtnText.set("Exit")
        button = Button(self.root, textvariable=self.ExitBtnText, width=11, fg="red", command=lambda:self.shutdown_monitors(LicCmp))
        button.grid(row=r+28,column=14,pady=4,sticky=E)

        Qcount = 0
        while self.mqueue.qsize() > 0 and Qcount < 10:
            logmsg = self.mqueue.get()
            if "Error" not in logmsg:
                self.LogApp.insert(3.0,logmsg,'progmsg')
                self.LogApp.tag_config('progmsg',foreground='orange')
            else:
                self.LogApp.insert(3.0,logmsg,'errmsg')
                self.LogApp.tag_config('errmsg',foreground='red')

            Qcount = Qcount + 1

        if len(self.AvailIPs2Mon) != 0:

            if self.StartBtnText.get() == "Stop":
                self.StatusBar.set("Connecting to Logs...")
                self.root.update_idletasks()
            if LicCmp == "MultiDB":
                readDB("fwlogs", self,dconn,dcur)
                # Schedule read_queue to run in the main thread in one second.
                self.root.after(1, self.read_queue,pmon,columncount,dconn,dcur,LicCmp,UpdateCount)
            else:
                self.root.after(1, self.read_queue,pmon,columncount,0,0,LicCmp,UpdateCount)

        else:
            self.StatusBar.set("No Logs Available.")
            self.NB1.select(IPMgtPage)
            if int(self.IPStatus.index('end-1c').split('.')[0]) == 0:
                messagebox.showinfo("Windows Firewall Monitor", "Please add an IP address to monitor.")
            self.root.update_idletasks()

    #else:
        #print("No logs are available to monitor.\nMonitor shutdown.")

    def read_queue(self,pm,colcount,DCN,DCUR,VType,UpCount):
        """ Check for updated temp data"""

        #temp = self.cfgqueue.get()

        #ConfigList = str(self.ShowPMsg.get()) + " " + str(self.ShowTraf.get()) + " " + str(self.SIEMTraf.get()) + " " + str(self.LogTraf.get()) + " " + str(self.FilVar.get()) + " " + str(self.IP6.get()) + " " + str(self.DeDup.get())

        #self.cfgqueue.put(ConfigList)

        dcount = 0
        CommitCounter = 0
        PrevLogmsg = ""

        while self.queue.qsize() > 0:
            try:
                if self.StartBtnText.get() == "Stop":
                    self.StatusBar.set("Checking for overdue logs...")
                self.root.update_idletasks()
                Logmsg = self.queue.get_nowait()
                Logmsgsplit = Logmsg.split()
                if Logmsgsplit[0] != PrevLogmsg:
                    #print(self.queue.qsize())
                    self.LogUpdateCheck(Logmsg,colcount)
                PrevLogmsg = Logmsgsplit[0]


            except queue.Empty:
                pass

        #print(int(self.UpdateFQ.get())*UpCount - int(self.updatecycle()))
        if int(self.UpdateFQ.get())*UpCount - int(self.updatecycle()) <= 1:
            for r in range(len(self.IPs2Mon)):
                for c in range(colcount):
                    self.labels[r*colcount+c].config(bg="yellow")
                    self.dispsvars[r*colcount+c].set(self.svars[r*colcount+c].get())
                    #print(self.dispsvars[r*colcount+c].get())

        if self.StartBtnText.get() == "Stop":
            self.StatusBar.set("Processing Logs...")
            self.root.update_idletasks()

        #t = Thread(target=FWLogProcess, args=(self,self.mqueue,self.dbinfoqueue,self.fqueue,self.ShowPMsg.get(),self.ShowTraf.get(),self.FilVar2.get(),LA,LW,))
        #t.daemon = True
        #t.start()

        if VType == "MultiDB":
            if (DCN):
                self.DBStatBar1.set("DB Status: Connected")
            else:
                self.DBStatBar1.set("DB Status: Failed")

        #if self.StartBtnText.get() == "Stop":
            #FWLogProcess(self)

        if VType == "MultiDB":
            if self.dbinfoqueue.qsize() > int(self.DBWriteSize.get()):
                self.StatusBar.set("Writing to Logs Database...")
                self.root.update_idletasks()
                #t = Thread(target=writeDB, args=(self,self.mqueue,self.fqueue,self.cfgqueue,self.dbinfoqueue,))
                #t.daemon = True
                #t.start()
                RecordsWritten = writeDB(self,DCN,DCUR)
                self.StatusBar.set("Reading Logs from Database...")
                self.root.update_idletasks()
                self.LogWin.configure(state='normal')
                BegLine = 3.0
                self.LogWin.delete(BegLine,END)
                readDB("fwlogs", self,DCN,DCUR)


        self.LineCount.set("FW Log Line Count: " + str(int(self.LogWin.index('end-1c').split('.')[0])-3))
        tempcount = int(self.LogWin.index('end-1c').split('.')[0])-3

        self.LineCountA.set("App Log Line Count: " + str(int(self.LogApp.index('end-1c').split('.')[0])-3))
        tempcountA = int(self.LogApp.index('end-1c').split('.')[0])-3

        if tempcount > int(self.LineLim.get()):
            self.StatusBar.set("Truncating FW Log...")
            self.truncscrtxt()
            self.writeAppLog(datetime.now().strftime('%Y-%m-%d %H:%M:%S') + " >> FW Log Truncated ==> The consolidated firewall log view was truncated by " + str(tempcount - int(self.RollB.get())) + " records.\n")

        if tempcountA > int(self.LineLimA.get()):
            self.StatusBar.set("Truncating App Log...")
            self.truncscrtxtA()
            self.writeAppLog(datetime.now().strftime('%Y-%m-%d %H:%M:%S') + " >> Application Log Truncated ==> The consolidated firewall log view was truncated by " + str(tempcountA - int(self.RollBA.get())) + " records.\n")

        if self.StartBtnText.get() == "Stop":
            self.StatusBar.set("Checking Log Connections...")
            self.ThreadMonitor(VType)

        self.LastUpdate.set("Last Updated at: " + datetime.now().strftime('%Y-%m-%d %H:%M:%S'))

        if int(self.UpdateFQ.get())*UpCount - int(self.updatecycle()) <= 0:
            UpCount = UpCount + 1

        self.UpdateStat.set("Update in " + str(int(self.UpdateFQ.get())*UpCount - int(self.updatecycle())) +" sec.")
        
        self.root.after(1, self.read_queue,pm,colcount,DCN,DCUR,VType,UpCount)

if __name__ == '__main__':

    CommQueue = queue.Queue()
    DataQueue = queue.Queue()
    MSGQueue = queue.Queue()
    FilQueue = queue.Queue()
    CfgQueue = queue.Queue()
    DBInfoQueue = queue.Queue()

    CfgQueue.put("0 0 0 0 -1")
    
    gui = Gui(DataQueue,MSGQueue,CommQueue,FilQueue,CfgQueue,DBInfoQueue)

    # Start mainloop
    try:
        gui.root.mainloop()
    except:
        pass

    exit
