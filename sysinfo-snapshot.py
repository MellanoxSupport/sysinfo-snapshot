'''

Created on Sep 24, 2012
Dependencies:
    Unix:
        cat
        gzip

    OFED:
    Windows:
    WinOF:

    Python:
        netifaces - http://alastairs-place.net/projects/netifaces/ (pip install netifaces)

@author: luis
'''
from optparse import OptionParser
import subprocess
import shlex
import platform
import os

#non-standard libraries
import netifaces

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

        #Constants for grabbing network interfaces...
        self.SIOCGIFCONF = 0x8912  #define SIOCGIFCONF
        self.BYTES = 4096          # Simply define the byte size

        self.network_interfaces = netifaces.interfaces()
        #OS environment variables in a dictionary
        self.env = os.environ

    def getNetworkInterfaces(self):
        return self.network_interfaces

    def getSystem(self):
        return self.system

    def getHostname(self):
        return self.hostname

    def getKernelVersion(self):
        return self.kernel_version

    def getRelease(self):
        return self.release

    def getCPUArchitecture(self):
        return self.CPU_architecture



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
        proccess.wait()
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
    def __init__(self, hostname, iterablecontent, sysinfoinstance):
        self.sysinfo = sysinfoinstance
        self.hostname = hostname
        self.iterablecontent = iterablecontent

    def constructPage(self):
        page = '''
                <html>
                    <head>
                    {title}
                    </head>

                    <body>
                        <pre>
                        {index}
                        <h2>Server Commands:</h2>
                        {ServerCommandTable}
                        <h2>Network Information:</h2>
                        {NetworkCommandTable}
                        <h2>Files Information:</h2>
                        {ServerFilesTable}

                        <h2>Server Commands:</h2>
                        {CommandsOutput}
                        <h2>Network Information:</h2>
                        {FabricDiagnosticsOutput}
                        <h2>Files Information:</h2>
                        {FilesOutput}

                        </pre>
                    </body>
                </html>
               '''.format(
            title = self.generateTitle(self.hostname),
            index = self.generateIndex(),

            ServerCommandTable = self.generateTableSections(self.sysinfo.server_commands),
            NetworkCommandTable = self.generateTableSections(self.sysinfo.fabric_diagnostics),
            ServerFilesTable = self.generateTableSections(self.sysinfo.files),
            CommandsOutput = self.generateOutputSections(self.sysinfo.server_commands),

            FabricDiagnosticsOutput = self.generateOutputSections(self.sysinfo.fabric_diagnostics),
            FilesOutput = self.generateOutputSections(self.sysinfo.files),
        )
        return page

    def generateSectionFooter(self, previous, originsection, next):
        foot = '''
                <small><a href=\"#{previoussection}\">[&lt;&lt;prev]</a></small>
                <small><a href=\"#{index}\">[back to index]</a></small>
                <small><a href=\"#{nextsection}">[next>>]</a></small>
               '''.format(
            previoussection = previous,
            index = originsection,
            nextsection = next,
        )
        return foot

    def generateTitle(self, hostname):
        return "<title>{hostn}'s Diagnostics</title>".format(hostn = hostname)

    def generateIndex(self):
        out = '''
                <a name="index"></a>
                    <h1>
                    Mellanox Technologies
                    </h1>
                <a name="index"></a>
                    <h2>
                    System Information Snapshot Utility
                    </h2>
                <a name="index"></a>
                    <h2>
                    Version: 0.1
                    </h2>
                <hr>
              '''
        return out

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
            html += '''
                <td width = 25%>
                    <a href=#\"{secname}\">{elementname}</a>
                </td>
                    '''.format(
                secname = element.getSectionName(),
                elementname = element.getName(),
            )
            if c > 4:
                html += '''
                </tr>
                <tr>
                        '''
        return html

    def generateOutputSection(self):
        pass

class SysinfoSnapshot:
    def __init__(self, system = None):
        self.factory = SysInfoDataFactory()
        self.system = system
        self.idservice = IdentityService(5000)

class SysinfoSnapshotWin(SysinfoSnapshot):
    def __init__(self):
        SysinfoSnapshot.__init__()

class SysinfoSnapshotUnix(SysinfoSnapshot):
    def __init__(self):
        SysinfoSnapshot.__init__()

        self.commandStrings = [
                                'arp -an',
                                #-n, --numeric
                                #shows numerical addresses instead of trying to determine symbolic host, port or user
                                # names.
                                #-a [hostname], --display [hostname]
                                #Shows the entries of the specified hosts. If the hostname parameter is not used, all
                                # entries will be displayed. The entries will be displayed in alternate (BSD) style
                                #Arp manipulates the kernel's ARP cache in various ways. The primary options are
                                # clearing an address mapping entry and manually setting up one. For debugging
                                # purposes, the arp program also allows a complete dump of the ARP cache.

                                'biosdecode',

                                #biosdecode parses the BIOS memory and prints information about all structures
                                # (or entry points) it knows of.

                                #List block devices on the system
                                'blkid -c /dev/null | sort',

                                #Grab the date, could probably be replaced by some Python library
                                'date',

                                #Show information about the file system on which each FILE resides, or all file systems
                                # by default.
                                #-h, --human-readable
                                #print sizes in human readable format (e.g., 1K 234M 2G)
                                'df -h',

                                #give us a snapshot of the current kernel output log, why this and /var/log/messages?
                                'dmesg',

                                #Older version of biosdecode for older systems
                                'dmidecode',

                                #-l
                                #List the partition tables for the specified devices and then exit. If no devices are
                                # given, those mentioned in /proc/partitions (if that exists) are used.
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
                                'ofed_info',
                                'ibstat',
                                'ibstatus',
                                'ibv_devinfo',
                                'sminfo',

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
                                #This option causes any error messages to go through the syslog mechanism
                                # (as LOG_DAEMON with level LOG_NOTICE) rather than to standard error. This is also
                                # automatically enabled when stderr is unavailable.
                                #This option is passed through install or remove commands to other modprobe commands
                                # in the MODPROBE_OPTIONS environment variable.
                                'modprobe sq',

                                #Display currently mounted filesystems, cat /etc/fstab is preferable...
                                'mount',

                                #-a	Displays all active connections and the TCP and UDP ports on which the computer
                                # is listening.
                                #-n	Displays active TCP connections, however, addresses and port numbers are expressed
                                # numerically and no attempt is made to determine names.
                                #p protocol (Windows and BSD)	Shows connections for the protocol specified by
                                # protocol. In this case, protocol can be tcp, udp, tcpv6, or udpv6. If this parameter
                                # is used with -s to display statistics by protocol, protocol can be tcp, udp, icmp,
                                # ip, tcpv6, udpv6, icmpv6, or ipv6.
                                #-p (Linux)	Show which processes are using which sockets (similar to -b under Windows)
                                # (you must be root to do this)
                                'netstat -anp',

                                #-i	Displays network interfaces and their statistics (not available under Windows)
                                'netstat -i',
                                'netstat -nlp',#some random changes

                                #-r	Displays the contents of the IP routing table. (This is equivalent to the route
                                # print command under Windows.)
                                'netstat -nr',

                                #--hardware, -H
                                #Show inventory of available nodes on the system.
                                #Numactl can set up policy for a SYSV shared memory segment or a file
                                # in shmfs/hugetlbfs.
                                'numactl --hardware',

                                #ompi_info - Display information about the Open MPI installation
                                'ompi_info',

                                #perfquery uses PerfMgt GMPs to obtain the PortCounters (basic performance and error
                                # counters), PortExtendedCounters, PortXmitDataSL, or PortRcvDataSL from the PMA at
                                # the node/port specified. Optionally shows aggregated counters for all ports of node.
                                # Also, optionally, reset after read, or only reset counters.
                                #Note: In PortCounters, PortCountersExtended, PortXmitDataSL, and PortRcvDataSL,
                                # components that represent Data (e.g. PortXmitData and PortRcvData) indicate octets
                                # divided by 4 rather than just octets.
                                'perfquery',

                                #list process information...
                                'ps xfalw',

                                #list local routes without their hostnames
                                #-n
                                #show numerical addresses instead of trying to determine symbolic host names.
                                # This is useful if you are trying
                                #to determine why the route to your nameserver has vanished.
                                'route -n',

                                #netstat for sockets direct protocol
                                'sdpnetstat -anp',

                                #Sometimes it is difficult to determine which SCSI device a sg device name
                                # (e.g. /dev/sg0) refers to. This command loops through the sg devices and finds the
                                # corresponding SCSI disk, cdrom or tape device name (if any). Scanners are an example
                                # of SCSI devices that have no alternate SCSI device name apart from their sg device
                                # name.
                                'sg_map -i -x',

                                #sysctl - configure kernel parameters at runtime
                                #-a
                                #Display all values currently available.
                                'sysctl -a',

                                #User limits - limit the use of system-wide resources.
                                #-a report all limits available
                                'ulimit -a',

                                #displays information about the kernel version
                                'uname -a',

                                #displays time the system has been up
                                'uptime',

                                #???
                                'zcat /proc/config.gz'
                            ]
        self.fabdiagStrings = [

                                #utility for generic fabric sweep. gets counters only during run
                                'ibdiagnet',

                                #a lower level counter checker.
                                'ibcheckerrors -nocolor',

                                #detect all hosts inband on the fabric
                                'ibhosts',

                                #get a topology layout of all hosts on the fabric
                                'ibnetdiscover',

                                #Obtain a ports report which is a list of connected ports with relevant information
                                # (like LID, portnum, GUID, width, speed, and NodeDescription).
                                'ibnetdiscover -p',

                                #display all infiniband switches
                                'ibswitches',
                            ]
        self.fileStrings = [
                                #hosts files
                                '/etc/hosts',
                                '/etc/hosts.allow',
                                '/etc/hosts.deny',

                                #Same as System.getRelease()
                                # Phasing this out
                                # '/etc/issue',

                                #Kernel Module configurations
                                '/etc/modprobe.conf',
                                '/etc/modprobe.d/blacklist-compat',
                                '/etc/modprobe.d/blacklist-firewire',
                                '/etc/modprobe.d/blacklist.conf',
                                '/etc/modprobe.d/mlx4_en.conf',
                                '/etc/modprobe.d/modprobe.conf.dist',

                                #DNS configurations
                                '/etc/resolv.conf',

                                #config for Linux Interfaces, should grab all...
                                '/etc/sysconfig/network-scripts/ifcfg-bond0',
                                '/etc/sysconfig/network-scripts/ifcfg-eth0',
                                '/etc/sysconfig/network-scripts/ifcfg-eth1',
                                '/etc/sysconfig/network-scripts/ifcfg-ib0',
                                '/etc/sysconfig/network-scripts/ifcfg-lo',

                                #This file is used primarily for diagnosing memory fragmentation issues. Using the
                                # buddy algorithm, each column represents the number of pages of a certain order
                                # (a certain size) that are available at any given time. For example, for zone DMA
                                # (direct memory access), there are 90 of 2^(0*PAGE_SIZE) chunks of memory. Similarly,
                                # there are 6 of 2^(1*PAGE_SIZE) chunks, and 2 of 2^(2*PAGE_SIZE) chunks of memory
                                # available.
                                '/proc/buddyinfo',

                                #This file shows the parameters passed to the kernel at the time it is started.
                                # A sample /proc/cmdline file looks like the following:
                                # ro root=/dev/VolGroup00/LogVol00 rhgb quiet 3
                                #This tells us that the kernel is mounted read-only (signified by (ro)), located on the
                                # first logical volume (LogVol00) of the first volume group (/dev/VolGroup00). LogVol00
                                # is the equivalent of a disk partition in a non-LVM system (Logical Volume Management)
                                # , just as /dev/VolGroup00 is similar in concept to /dev/hda1, but much more extensible
                                # .
                                '/proc/cmdline',

                                #This virtual file identifies the type of processor used by your system.
                                '/proc/cpuinfo',

                                #This file lists all installed cryptographic ciphers used by the Linux kernel,
                                # including additional details for each
                                '/proc/crypto',

                                #This file displays the various character and block devices currently configured
                                # (not including devices whose modules are not loaded)
                                '/proc/devices',

                                #Field 1 -- # of reads issued
                                #Field 2 -- # of reads merged, field 6 -- # of writes merged
                                #Field 3 -- # of sectors read
                                #Field 4 -- # of milliseconds spent reading
                                #Field 5 -- # of writes completed
                                #Field 7 -- # of sectors written
                                #Field 8 -- # of milliseconds spent writing
                                #Field 9 -- # of I/Os currently in progress
                                #Field 10 -- # of milliseconds spent doing I/Os
                                #Field 11 -- weighted # of milliseconds spent doing I/Os
                                '/proc/diskstats',

                                #Looking at /proc/dma might not give you the information that you want, since it only
                                # contains currently assigned dma channels for isa devices.
                                #pci devices that are using dma are not listed in /proc/dma, in this case dmesg can be
                                # useful. The screenshot below shows that during boot the parallel port received dma
                                # channel 1, and the Infrared port received dma channel 3.
                                '/proc/dma',

                                #This file lists the execution domains currently supported by the Linux kernel,
                                # along with the range of personalities they support.
                                '/proc/execdomains',

                                # To display the SCSI devices currently attached (and recognized) by the SCSI subsystem
                                # use cat /proc/scsi/scsi/
                                '/proc/scsi/scsi',

                                #This file gives full information about memory usage on the slab level. Linux kernels
                                # greater than version 2.2 use slab pools to manage memory above the page level.
                                # Commonly used objects have their own slab pools.
                                # Instead of parsing the highly verbose /proc/slabinfo file manually, the
                                # /usr/bin/slabtop program displays kernel slab cache information in real time.
                                # This program allows for custom configurations, including column sorting and screen
                                # refreshing.
                                '/proc/slabinfo',

                                #The very first "cpu" line aggregates the numbers in all of the other "cpuN" lines.
                                #These numbers identify the amount of time the CPU has spent performing different
                                # kinds of work. Time units are in USER_HZ or Jiffies (typically hundredths of a second).
                                #The meanings of the columns are as follows, from left to right:
                                #user: normal processes executing in user mode
                                #nice: niced processes executing in user mode
                                #system: processes executing in kernel mode
                                #idle: twiddling thumbs
                                #iowait: waiting for I/O to complete
                                #irq: servicing interrupts
                                #softirq: servicing softirqs
                                '/proc/stat',
                                '/proc/swaps',
                                '/proc/uptime',
                                '/proc/vmstat',
                                '/proc/zoneinfo',
                                '/sys/class/infiniband/*/board_id',
                                '/sys/class/infiniband/*/fw_ver',
                                '/sys/class/infiniband/*/hca_type',
                                '/sys/class/infiniband/*/hw_rev',
                                '/sys/class/infiniband/*/node_desc',
                                '/sys/class/infiniband/*/node_guid',
                                '/sys/class/infiniband/*/node_type',
                                '/sys/class/infiniband/*/sys_image_guid',
                                '/sys/class/infiniband/*/uevent',
                                '/var/log/messages',
                            ]

        #Methods listed here must exist in this class
        self.methodStrings = [

                                #check whether sm is alive and what it is
                                'sm-status',

                                #check who the sm master is as opposed to any slave sm
                                'sm_master_is',

                                #scan the firmware for all inband infiniband switches
                                'ib_switches_FW_scan',

                                'Multicast_Information',

                                'ib_find_bad_ports',

                                'ib_find_disabled_ports',

                                'ib_mc_info_show',

                                'ib_topology_viewer',

                                'zz_sys_class_net_files',

                                'zz_proc_net_bonding_files',

                                #Use the Python Platform library to retrieve OS hostname
                                'getHostname'

                                #Use the Python Platform library to retrieve OS release data in a cross platform manner
                                'getRelease',

                                #Get the output of ethtool <Interface> on every system interface
                                'eth_tool_all_interfaces',

                                #Pull the ini from each interface on the system
                                'fw_ini_dump',
                              ]

        self.allStrings = self.commandStrings + self.methodStrings + self.fileStrings + self.fabdiagStrings



    #Rogue and Orphan function implemented in order to satisfy dataset format for sysinfo
    #Also a good place for current implementations of Python libraries for those functions

    def getHostname(self):
        return self.system.getHostname()

    def getRelease(self):
        return self.system.getRelease()

    def eth_tool_all_interfaces(self):
        pass

    def Multicast_Information(self):
        pass

    def zz_proc_net_bonding_files(self):
        pass

    def zz_sys_class_net_files(self):
        pass

    def ib_find_bad_ports(self):
        pass

    def ib_mc_info_show(self):
        pass

    def ib_switches_FW_scan(self):
        pass

    def sm_master_is(self):
        pass

    def fw_ini_dump(self):
        pass

    def ib_topology_viewer(self):
        pass

    def ib_mc_info_show(self):
        pass

    def sm_status(self):
        pass

    def runDiscovery(self):
        pass


    def getFileText(self, filename):
        with open(filename, 'r') as f:
            out = f.read()
        FDStruct = SysInfoData(filename, out, 'sysinfo-file', self.idservice.createID())
        return FDStruct

    def callMethod(self, methodname):
        m = getattr(self, '{meth}'.format(meth = methodname))
        out = m()
        MStruct = SysInfoData(methodname, out, 'sysinfo-method', self.idservice.createID())
        return MStruct

    def callCommand(self, command):
        out = UnixCommand('{cmd}'.format(cmd = command)).systemCall()[0]
        CStruct = SysInfoData(command, out, 'sysinfo-command', self.idservice.createID())
        return CStruct

    def gzip(self, file, newfilename):
        f = open(file,r)
        result = UnixCommand('gzip {target} {destination}'.format(target = file, destination = newfilename))

    def dumpHTML(self, html, newfilename):
        with open(newfilename+'.html', 'w') as f:
            f.write(html)

class SysInfoData:
    def __init__(self, name, output, type, id):
        self.name = name
        self.output = output
        self.type = type
        self.id = id
        self.section = self.name+str(self.id)

    def getName(self):
        return self.name

    def getOutput(self):
        return self.output

    def getType(self):
        return self.type

    def getId(self):
        return self.id

    def getSectionName(self):
        return self.section



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
        self.__configureCLI__()

        #System variables obtained, depending on the host system these variables can be very different
        self.system = System()

        #detect the OS and initiate the correct object representing the sysinfo-snapshot program capabilities
        if self.system.operating_system in ['Windows', 'Microsoft']:
            self.sysinfo = SysinfoSnapshotWin(self.system, self.configuration)

        else:
            self.sysinfo = SysinfoSnapshotUnix(self.system, self.configuration)


        #Get all application configuration parameters needed to execute the app, is it running in GUI mode? CLI with options?


    def __configureCLI__(self):
        '''
        Add support and dispatch for all flags
        '''
        self.parser.add_option("-m", "--minimal", action="store_true", dest="minimal")
