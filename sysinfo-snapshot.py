'''

Created on Sep 24, 2012
Dependencies:
    Unix:
        cat
        gzip

    OFED:
    Windows:
    WinOF:


@author: luis
'''
from optparse import OptionParser
import subprocess
import shlex
import platform
import os


class System:
    '''
    Represents the state of the system in which the program is
    being executed. A wrapper for the platform module
    '''

    def __init__(self):
        #Any of these values upon retrieval failure will be NULL
        self.uname = platform.uname()
        self.system = self.uname[0]
        self.hostname = self.uname[1]
        self.kernel_version = self.uname[2]
        self.release = self.uname[3]
        self.CPU_architecture = self.uname[4]

        #OS environment variables in a dictionary
        self.env = os.environ

    def getPath(self):
        pass

    def getDate(self):
        pass

    def getHostname(self):
        return self.hostname

    def getRelease(self):
        return self.release

class Command:
    def __init__(self, cmd, name, TIMEOUT = 100):
        self.cmd = cmd
        self.name = name
        self.TIMEOUT = TIMEOUT
        self.lastout = ''

    def systemCall(self):
        '''
        non-implemented abstract function for subclassing
        '''
        pass

class UnixCommand(Command):
    def __init__(self, cmd, name):
        Command.__init__(cmd, name)

    def systemCall(self):
        '''
        Perform an OS CLI call on the Unix commandline and get the full output
        must use with commands that do not require interactivity
        returns both the output and the error in a tuple
        This is intentionally a blocking command, it will not return until the command has ended.
        '''
        proccess = subprocess.Popen(shlex.split(cmd))
        process.wait()
        out, err = process.communicate()
        self.lastout = out
        return out, err

class WindowsCommand(Command):
    def __init__(self, cmd, name):
        Command.__init__(cmd, name)


    def systemCall(self):
        '''
        Perform an OS CLI call on the Windows commandline and get the full output
        best used for one shot commands that do not involve interactivity
        '''
        #reserving for windows implementation
        pass

class IdentityService:
    def __init__(self, poolrange):
        self.pool = range(poolrange)
        self.used = []

    def createID(self):
        id = self.pool[0]
        self.pool.pop(id)
        self.used.append(id)
        return id

    def deleteID(self, id):
        self.used.pop(id)

    def getID(self, id):
        for i in self.used:
            if i == id:
                return id

        return None

class SysHTMLGenerator:
    def __init__(self, hostname, iterablecontent, sysinfoinstance, idservice):
        self.idservice = idservice
        self.sysinfo = sysinfoinstance
        self.hostname = hostname
        self.iterablecontent = iterablecontent


    def generateSectionFooter(self, previous, originsection, next):
        foot = """<small><a href=\"#{previoussection}\">[&lt;&lt;prev]</a></small> 
                          <small><a href=\"{index}\">[back to index]</a></small> 
                          <small><a href=\"{nextsection}">[next>>]</a></small>
               """.format(previoussection = previous,
                          index = originsection,
                          nextsection = next)
        return foot

    def generateTitle(self, hostname):
        return "<title>{hostn}'s Diagnostics</title>".format(hostn = hostname)

    #noinspection PyUnreachableCode,PyUnreachableCode,PyUnreachableCode,PyUnreachableCode,PyUnreachableCode
    def generateIndex(self):
        out = '''
<a name="index"></a>
<h1>Mellanox Technologies</h1>
<a name="index"></a>
<h2>System Information Snapshot Utility</h2>
<a name="index"></a>
<h2>Version: 0.1</h2>
<hr>
              '''
        return out

    def generateTableSection(self, sysinfo_data_structure):
        html += "<h2>{sectiontitle}\n</h2>".format(sectiontitle = sysinfo_data_structure.getTableTitle())
        c += 1
        if c >= section_split_delimiter:
            section_split_delimiter += section_split_delimiter
            html += "</tr>\n<tr>"
        html += '''
<td width="25%">
<a href="#{id}">{content}</a>
</td>
                '''.format(id = element.getId(), content = sysinfo_data_structure.getOutput())
        html += "</tbody>\n</table>"
        return html

    def generateTableSections(self, sysinfo_data_structure_list):
        '''
        This function generates one table based on the sysinfo datatype retrieved/constructed from the underlying os
        '''

        #Grab the amount of data structures in the list
        struct_count = len(sysinfo_data_structure_list)

        #set a delimiter to use for html <tr></tr> breaks
        section_split_delimiter = struct_count/4

        #initiate a count to keep track of when to break
        c = 0

        #start writing the tabled section...
        html = ''

        #Not exactly sure how HTML tables work, trying to figure out specifications for the entire table section here
        html += '''
        <table cols=\"{numofcols}\" border=\"{bordervalue}\" bgcolor=\"{bgcolor}\"width=\"{width}%\">\n<tbody>\n<tr>
        '''.format(
            numofcols = "4",
            bordervalue = "0",
            bgcolor = "#E0E0FF",
            width = "100",
            )
        #elements here are unpackaged sysinfostructs
        for element in sysinfo_data_structure_list:
            html += self.generateTableSection(element)
        html += self.generateSectionFooter(sysinfo_data_structure.getId() - 1, 'index', sysinfo_data_structure.getId() + 1)
        return html


    def generateOutputSection(self, sysinfo_data_structure):
        html = ''
        html += self.generateSectionFooter(sysinfo_data_structure.getId() - 1, 'index', sysinfo_data_structure.getId() + 1)


    def generateOutputSections(self, sysinfo_data_structure_list):
        for element in sysinfo_data_structure_list:
            self.generateOutputSection(element)

    def constructPage(self):
        page = '''
<html>
    <head>
    {title}
    </head>

    <body>
        <pre>
        {index}
        {ServerCommandTable}
        {NetworkCommandTable}
        {ServerFilesTable}

        {CommandsOutput}
        {FabricDiagnosticsOutput}
        {FilesOutput}
        </pre>
    </body>
</html>
               '''.format(title = self.generateTitle(self.hostname),

                          index = self.generateIndex(),

                          ServerCommandTable = self.generateTableSections(self.sysinfo.server_commands),

                          NetworkCommandTable = self.generateTableSections(self.sysinfo.fabric_diagnostics),

                          ServerFilesTable = self.generateTableSections(self.sysinfo.files),

                          CommandsOutput = self.generateOutputSections(self.sysinfo.server_commands),

                          FabricDiagnosticsOutput = self.generateOutputSections(self.sysinfo.fabric_diagnostics),

                          FilesOutput = self.generateOutputSections(self.sysinfo.files),
                          )
        return page

class SysinfoSnapshot:
    def __init__(self, system = None):
        self.factory = SysInfoDataFactory()
        self.system = system

class SysinfoSnapshotWin:
    def __init__(self):
        SysinfoSnapshot.__init__()

class SysinfoSnapshotUnix:
    def __init__(self):
        SysinfoSnapshot.__init__()
        self.APPOSTYPE = 'Unix'

        self.commandStrings = [
                                'arp -an',
                                #-n, --numeric
                                #shows numerical addresses instead of trying to determine symbolic host, port or user names.
                                #-a [hostname], --display [hostname]
                                #Shows the entries of the specified hosts. If the hostname parameter is not used, all entries will be displayed. The entries will be displayed in alternate (BSD) style
                                #Arp manipulates the kernel's ARP cache in various ways. The primary options are clearing an address mapping entry and manually setting up one. For debugging purposes, the arp program also allows a complete dump of the ARP cache.

                                'biosdecode',

                                #biosdecode parses the BIOS memory and prints information about all structures (or entry points) it knows of. Currently known entry point types are:

                                #List block devices on the system
                                'blkid -c /dev/null | sort',

                                #Grab the date, could probably be replaced by some Python library
                                'date',

                                #Show information about the file system on which each FILE resides, or all file systems by default.
                                #-h, --human-readable
                                #print sizes in human readable format (e.g., 1K 234M 2G)
                                'df -h',

                                #give us a snapshot of the current kernel output log, why this and /var/log/messages?
                                'dmesg',

                                #Older version of biosdecode for older systems
                                'dmidecode',

                                #-l
                                #List the partition tables for the specified devices and then exit. If no devices are given, those mentioned in /proc/partitions (if that exists) are used.
                                'fdisk -l',

                                #Provides information on unused memory and swap space.
                                'free',

                                #When used without argument retrieves current hostname
                                #Phased out in favor of Python cross platform library
                                #self.callCommand('hostname'),

                                #--netcard displays information specifically about communications devices
                                # lspci and hwinfo --pci are very similar for example
                                # hwinfo command is a generic large dump of hw information
                                'hwinfo --netcard',
                                'hwinfo',

                                #REQUIRES OFED
                                'ibstat',
                                'ibstatus',

                                'ibv_devinfo',
                                #v for verbose... why show regular version?
                                'ibv_devinfo -v',

                                #Show all Linux Network Interfaces regardless of up/down states
                                #For old systems were ip command is not depreciated
                                'ifconfig -a',

                                #ip - show / manipulate routing, devices, policy routing and tunnels
                                'ip a s',
                                'ip m s',
                                'ip n s',

                                #iptables commands require triggering of the iptables daemon
                                #iptables is listed here to explore various firewall rules on the system

                                #Removed for now because of customers complaints that this is intrusive
                                #Due to the fact that these commands trigger the iptables daemon to turn on

                                #'iptables -t filter -nvL',
                                #'iptables -t mangle -nvL',
                                #'iptables -t nat -nvL',
                                #'iptables-save -t filter',
                                #'iptables-save -t mangle',
                                #'iptables-save -t nat',

                                #NO LONGER MAINTAINED
                                #command returns a list of local locks on the system
                                #do we really need to recover this sort of information?
                                'lslk',

                                #lsmod - program to show the status of modules in the Linux Kernel
                                'lsmod',

                                #Lists open files on the system
                                'lsof',

                                #pci specific information gathering
                                'lspci',
                                'lspci -tv',
                                'lspci -tvvv',
                                'lspci -xxxx',

                                #Display low level nic information -vv also display raw MII register contents.
                                'mii-tool -vv',

                                #-s --syslog
                                #This option causes any error messages to go through the syslog mechanism (as LOG_DAEMON with level LOG_NOTICE) rather than to standard error. This is also automatically enabled when stderr is unavailable.
                                #This option is passed through install or remove commands to other modprobe commands in the MODPROBE_OPTIONS environment variable.
                                'modprobe sq',

                                #Display currently mounted filesystems, cat /etc/fstab is preferable...
                                'mount',

                                #-a	Displays all active connections and the TCP and UDP ports on which the computer is listening.
                                #-n	Displays active TCP connections, however, addresses and port numbers are expressed numerically and no attempt is made to determine names.
                                #p protocol (Windows and BSD)	Shows connections for the protocol specified by protocol. In this case, protocol can be tcp, udp, tcpv6, or udpv6. If this parameter is used with -s to display statistics by protocol, protocol can be tcp, udp, icmp, ip, tcpv6, udpv6, icmpv6, or ipv6.
                                #-p (Linux)	Show which processes are using which sockets (similar to -b under Windows) (you must be root to do this)
                                'netstat -anp',

                                #-i	Displays network interfaces and their statistics (not available under Windows)
                                'netstat -i'),
                                'netstat -nlp'),

                                #-r	Displays the contents of the IP routing table. (This is equivalent to the route print command under Windows.)
                                'netstat -nr'),

                                #
                                self.callCommand('numactl --hardware'),
                                self.callCommand('ofed_info'),
                                self.callCommand('ompi_info'),
                                self.callCommand('perfquery'),
                                self.callCommand('ps xfalw'),
                                self.callCommand('route -n'),
                                self.callCommand('sdpnetstat -anp'),
                                self.callCommand('sg_map -i -x'),
                                self.callCommand('sysctl -a'),
                                self.callCommand('ulimit -a'),
                                self.callCommand('uname -a'),
                                self.callCommand('uptime'),
                                self.callCommand('zcat /proc/config.gz'),
                                self.callMethod('zz_proc_net_bonding_files'), #implement as method
                                self.callMethod('zz_sys_class_net_files'), #implement as method
                               ]
        self.fabdiagStrings = []
        self.fileStrings = []

        #Methods listed here must exist in this class
        self.methodStrings = [

                                #Use the Python Platform library to retrieve OS hostname
                                'getHostname'

                                #Use the Python Platform library to retrieve OS release data in a cross platform manner
                                'getRelease',

                                #Get the output of ethtool <Interface> on every system interface
                                'eth-tool-all-interfaces',

                                #Pull the ini from each interface on the system
                                'fw-ini-dump',
                              ]

        self.allStrings = [self.commandStrings, self.methodStrings, self.fileStrings, self.fabdiagStrings]



    #Rogue and Orphan function implemented in order to satisfy dataset format for sysinfo
    #Also a good place for current implementations of Python libraries for those functions

    def getHostname(self):
        return self.system.getHostname()

    def getRelease(self):
        return self.system.getRelease()

    def eth_tool_all_interfaces():
        pass

    def Multicast_Information():
        pass

    def zz_proc_net_bonding_files():
        pass

    def zz_sys_class_net_files():
        pass

    def ib_find_bad_ports():
        pass

    def ib_mc_info_show():
        pass

    def ib_switches_FW_scan():
        pass
    def runDiscovery(self):
        self.server_commands = [
                           self.callCommand('arp -an'),
                           self.callCommand('biosdecode'),
                           self.callCommand('blkid -c /dev/nell | sort'),

                           #Phasing these out in favor of the Python implementation
                           #self.callCommand('cat /etc/SuSE-release'),
                           #self.callCommand('cat /etc/redhat-release','chkconfig --list | sort'),
                           self.callMethod('getRelease'),
                            self.callCommand('date'),
                           self.callCommand('df -h'),
                           self.callCommand('dmesg'),
                           self.callCommand('dmidecode'),
                           self.callMethod('eth-tool-all-interfaces'),#implemented as method
                           self.callCommand('fdisk -l'),
                           self.callCommand('free'),
                           self.callCommand('fw-ini-dump'),
                           self.callCommand('hostname'),
                           self.callCommand('hwinfo --netcard'),
                           self.callCommand('ibstat'),
                           self.callCommand('ibstatus'),
                           self.callCommand('ibv_devinfo'),
                           self.callCommand('ibv_devinfo -v'),
                           self.callCommand('ifconfig -a'),
                           self.callCommand('ip a s'),
                           self.callCommand('ip m s'),
                           self.callCommand('ip n s'),
                           self.callCommand('iptables -t filter -nvL'),
                           self.callCommand('iptables -t mangle -nvL'),
                           self.callCommand('iptables -t nat -nvL'),
                           self.callCommand('iptables-save -t filter'),
                           self.callCommand('iptables-save -t mangle'),
                           self.callCommand('iptables-save -t nat'),
                           self.callCommand('lslk'),
                           self.callCommand('lsmod'),
                           self.callCommand('lsof'),
                           self.callCommand('lspci'),
                           self.callCommand('lspci -tv'),
                           self.callCommand('lspci -tvvv'),
                           self.callCommand('lspci -xxxx'),
                           self.callCommand('mii-tool -vv'),
                           self.callCommand('modprobe sq'),
                           self.callCommand('mount'),
                           self.callCommand('netstat -anp'),
                           self.callCommand('netstat -i'),
                           self.callCommand('netstat -nlp'),
                           self.callCommand('netstat -nr'),
                           self.callCommand('numactl --hardware'),
                           self.callCommand('ofed_info'),
                           self.callCommand('ompi_info'),
                           self.callCommand('perfquery'),
                           self.callCommand('ps xfalw'),
                           self.callCommand('route -n'),
                           self.callCommand('sdpnetstat -anp'),
                           self.callCommand('sg_map -i -x'),
                           self.callCommand('sysctl -a'),
                           self.callCommand('ulimit -a'),
                           self.callCommand('uname -a'),
                           self.callCommand('uptime'),
                           self.callCommand('zcat /proc/config.gz'),
                           self.callMethod('zz_proc_net_bonding_files'), #implement as method
                           self.callMethod('zz_sys_class_net_files'), #implement as method
                           ]

        self.fabric_diagnostics = [
                            self.callMethod('Multicast_Information'),#implemented as method
                            #self.callCommand('ib-find-bad-ports'),
                            #self.callMethod('ib-find-disabled-ports'),
                            #self.callCommand('ib-mc-info-show'),
                            #self.callCommand('ib-topology-viewer'),
                            self.callCommand('ibdiagnet'),
                            self.callCommand('ib_switches_FW_scan'),
                            self.callCommand('ibcheckerrors -nocolor'),
                            self.callCommand('ibhosts'),
                            self.callCommand('ibnetdiscover'),
                            self.callCommand('ibnetdiscover -p'),
                            self.callCommand('ibswitches'),
                            self.callCommand('sm-status'),
                            self.callCommand('sm_master_is'),
                            self.callCommand('sminfo'),
                            ]

        self.files = [
                            self.getFileText('/etc/hosts'),
                            self.getFileText('/etc/hosts.allow'),
                            self.getFileText('/etc/hosts.deny'),
                            self.getFileText('/etc/issue'),
                            self.getFileText('/etc/modprobe.conf'),
                            self.getFileText('/etc/modprobe.d/blacklist-compat'),
                            self.getFileText('/etc/modprobe.d/blacklist-firewire'),
                            self.getFileText('/etc/modprobe.d/blacklist.conf'),
                            self.getFileText('/etc/modprobe.d/mlx4_en.conf'),
                            self.getFileText('/etc/modprobe.d/modprobe.conf.dist'),
                            self.getFileText('/etc/resolv.conf'),
                            self.getFileText('/etc/sysconfig/network-scripts/ifcfg-bond0'),
                            self.getFileText('/etc/sysconfig/network-scripts/ifcfg-eth0'),
                            self.getFileText('/etc/sysconfig/network-scripts/ifcfg-eth1'),
                            self.getFileText('/etc/sysconfig/network-scripts/ifcfg-ib0'),
                            self.getFileText('/etc/sysconfig/network-scripts/ifcfg-lo'),
                            self.getFileText('/proc/buddyinfo'),
                            self.getFileText('/proc/cmdline'),
                            self.getFileText('/proc/cpuinfo'),
                            self.getFileText('/proc/crypto'),
                            self.getFileText('/proc/devices'),
                            self.getFileText('/proc/deskstats'),
                            self.getFileText('/proc/dma'),
                            self.getFileText('/proc/execdomains'),
                            self.getFileText('/proc/scsi/scsi'),
                            self.getFileText('/proc/slabinfo'),
                            self.getFileText('/proc/stat'),
                            self.getFileText('/proc/swaps'),
                            self.getFileText('/proc/uptime'),
                            self.getFileText('/proc/vmstat'),
                            self.getFileText('/proc/zoneinfo'),
                            self.getFileText('/sys/class/infiniband/*/board_id'),
                            self.getFileText('/sys/class/infiniband/*/fw_ver'),
                            self.getFileText('/sys/class/infiniband/*/hca_type'),
                            self.getFileText('/sys/class/infiniband/*/hw_rev'),
                            self.getFileText('/sys/class/infiniband/*/node_desc'),
                            self.getFileText('/sys/class/infiniband/*/node_guid'),
                            self.getFileText('/sys/class/infiniband/*/node_type'),
                            self.getFileText('/sys/class/infiniband/*/sys_image_guid'),
                            self.getFileText('/sys/class/infiniband/*/uevent'),
                            self.getFileText('/var/log/messages'),
                            ]

    def getFileText(self, filename):
        '''
        returns a "SysInfoData" structure handled as a file type
        '''
        out = UnixCommand('cat {filename}'.format(fname = filename).systemCall()[0])
        FDStruct = self.factory.generateFileDataStruct(filename, out, 'file')
        return FDStruct

    def callMethod(self, methodname):
        '''
        returns a "SysInfoData" structure handled as a method type
        '''
        m = getattr(self, '{meth}'.format(meth = methodname))
        out = m()
        MStruct = self.factory.getMethodDataStruct(method, out, 'method')
        return MStruct

    def callCommand(self, command):
        '''
        returns a "SysInfoData" structure handled as a command type
        '''
        out = UnixCommand('{cmd}'.format(cmd = command)).systemCall()[0]
        CStruct = self.factory.generateCommandDataStruct(command, out, 'command')
        return CStruct

    #File output types, each version of the program will have to implement it's own way of packaging output


    def gzip(file, newfilename):
        f = open(file,r)
        result = UnixCommand('gzip {target} {destination}'.format(target = file, destination = newfilename))

    def dumpHTML(html, newfilename):
        f = open(newfilename+'.html', 'w')
        f.write(html)
        f.close()


class SysInfoDataFactory:
    def __init__(self):
        pass

    def generateMethodDataStruct(self, name, output, type, id, hrefname, tabletitle):
        return MethodData(name, output, type, id, hrefname, tabletitle)

    def generateFileDataStruct(self, name, output, type, id, hrefname, tabletitle):
        return FileData(name, output, type, id, hrefname, tabletitle)

    def generateCommandDataStruct(self, name, output, type, id, hrefname, tabletitle):
        return CommandData(name, output, type, id, hrefname, tabletitle)

class SysInfoData:
    def __init__(self, name, output, type, id, hrefname, tabletitle):

        self.name = name
        self.output = output
        self.type = type
        self.id = id

        #html attributes used to generate the html page
        self.hrefname = hrefname
        self.tabletitle = tabletitle


    def getName(self):
        return self.name

    def getOutput(self):
        return self.output

    def getType(self):
        return self.type

    def getId(self):
        return self.id

    def getHrefName(self):
        return self.hrefname

    def getTableTitle(self):
        return self.tabletitle

class MethodData(SysInfoData):
    def __init__(self, name, output, type, id, hrefname, tabletitle):
        SysInfoData.__init__(self, name, output, type, id, hrefname, tabletitle)

class FileData(SysInfoData):
    def __init__(self, name, output, type, id, hrefname, tabletitle):
        SysInfoData.__init__(self, name, output, type, id, hrefname, tabletitle)

class CommandData(SysInfoData):
    def __init__(self, name, output, type, id, hrefname, tabletitle):
        SysInfoData.__init__(self, name, output, type, id, hrefname, tabletitle)

class App:
    '''
        application interface specific stuff, CLI, GUI, etc
    '''
    def __init__(self):
        #initiate a few entities to help out the application...

        #application specific metadata
        self.metadata = {
        'Author': 'Luis De Siqueira',
        'Version': '0.1',
        'ProgramName': 'System Information Snapshot',
        }

        #identification generator for element control in HTML, assuming there won't be more than 5000 elements for now...
        self.identservice = IdentityService(5000)

        #Python command-line option/help generator http://docs.python.org/library/optparse.html
        self.parser = OptionParser()

        #System variables obtained, depending on the host system these variables can be very different
        self.system = System()

        #detect the OS and initiate the correct object representing the sysinfo-snapshot program capabilities
        if self.system.operating_system in ['Windows', 'Microsoft']:
            self.sysinfo = SysinfoSnapshotWin(self.system)

        else:
            self.sysinfo = SysinfoSnapshotUnix(self.system)

        self.__configureCLI__()

        #Get all application configuration parameters needed to execute the app, is it running in GUI mode? CLI with options?
        self.config = self.__getApplicationConfig__()

    def __configureCLI__(self):
        '''
        Add support and dispatch for all flags
        '''
        pass

    def __getApplicationConfig__(self):
        if self.sysinfo.APPOSTYPE == 'Unix':
            pass
        pass


class CLI:
    def __init__(self):
        self.validflags = []

    def addFlag(self):
        pass

    def removeFlag(self):
        pass









def testsysteminformation():
    s = System()
    print s.getRelease()
testsysteminformation()
