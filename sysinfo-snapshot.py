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
import getpass




class System:
    '''
    Represents the state of the system in which the program is
    being executed. A wrapper for the platform module
    '''

    def __init__(self):
        self.uname = platform.uname()
        self.system = self.uname[0]
        self.hostname = self.uname[1]
        self.kernel_version = self.uname[2]
        self.release = self.uname[3]
        self.CPU_architecture = self.uname[4]

        #OS environment variables in a dictionary
        self.env = os.environ

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

    def systemCall(self):
        '''
        non-implemented abstract function for subclassing
        '''
        pass

class fauxProcess:
    def __init__(self):
        pass

    def communicate(self):
        out = 'Process error, could not find program installed'
        err = 'Process error'
        return out, err

class UnixCommand(Command):
    def __init__(self, cmd, name):
        Command.__init__(self, cmd, name)

    def systemCall(self):
        '''
        Perform an OS CLI call on the Unix commandline and get the full output
        must use with commands that do not require interactivity
        returns both the output and the error in a tuple
        This is intentionally a blocking command, it will not return until the command has ended.
        '''
        try:
            process = subprocess.Popen(shlex.split(self.cmd), stderr = subprocess.STDOUT, stdout = subprocess.PIPE)
        #process.wait()
        except:
            process = fauxProcess()
        out, err = process.communicate()
        return out

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

class AdvancedSysHTMLGenerator:
    def __init__(self, system, sysinfo):
        self.sysinfo = sysinfo
        self.system = system

    def genSISCSS(self):
        css = '''
        * {
	    margin:0;
	    padding:0;
        }

        .MellanoxTitleContainer {
	    position:relative;
	    margin:0;
	    font-size:36px;
	    text-align:center;
        }

        .MenuTitle{
        font-weight:bold;
        font-size:22;
        }
        .MenuContainer{
        width:100%;
        height:300;
        text-align:center;

        }

        .Menu{
        float:left;
        margin:9.5%;
        }

        .MenuElement{
        }

        .Buttons{
	    font-family: Arial, Helvetica, sans-serif;
	    font-size: 14px;
	    color: #ffffff;
	    padding:5;
	    background: -moz-linear-gradient(
		top,
		#42aaff 0%,
		#003366);
	    background: -webkit-gradient(
		linear, left top, left bottom,
		from(#42aaff),
		to(#003366));
	    -moz-border-radius: 10px;
	    -webkit-border-radius: 10px;
	    border-radius: 10px;
	    border: 1px solid #003366;
	    -moz-box-shadow:
		0px 1px 3px rgba(000,000,000,0.5),
		inset 0px 0px 1px rgba(255,255,255,0.5);
	    -webkit-box-shadow:
		0px 1px 3px rgba(000,000,000,0.5),
		inset 0px 0px 1px rgba(255,255,255,0.5);
	    box-shadow:
		0px 1px 3px rgba(000,000,000,0.5),
		inset 0px 0px 1px rgba(255,255,255,0.5);
	    text-shadow:
		0px -1px 0px rgba(000,000,000,0.7),
		0px 1px 0px rgba(255,255,255,0.3);
        }

        .OutputContainer{
        width:70%;
        }

        .OutputSection{
        width-bottom;20;
        }
        .OutputHeader{
        font-weight:bold;
        font-size:150%;
        margin-bottom:10;
        margin-left:20;
        }

        .OutputBox{
        margin:100;
        }
        '''

        return css

    def genSISInterface(self, SISdatumsets):
        html = '''
        <html>
        <head>
        <script>
        function ToggleVisibility(id)
        {
        var e = document.getElementById(id);
        if(e.style.display == 'block')
          e.style.display = 'none';
          e.innerHTML = 'Show';
        else
          e.style.display = 'block';
          e.innerHTML = 'Hide';
        }

function myFunction()
{
alert("Hello World!");
}
        </script>
        '''

        html += '''
        <STYLE type="text/css">
        {thecss}
        </STYLE>
        </head>
        '''.format(thecss = self.genSISCSS())

        html += '''
        <body>
        <title>{hostn}'s SIS</title>
        '''.format(hostn = self.system.getHostname())

        html += '''
            <a name = 'index'>
            </a>
        	<div class = 'MellanoxTitleContainer'>
            Mellanox SIS
	        </div>
	        '''
        html += '''
        <div class = SuperLargBox style = "width:100%;height:100px;">
        </div>
        '''

        html += '<div class = MenuContainer>'

        html += self.genSISMenu(SISdatumsets['Commands'], 'Commands')

        html += self.genSISMenu(SISdatumsets['Network'], 'Network')

        html += self.genSISMenu(SISdatumsets['Files'], 'Files')



        html += '</div>'

        html += '''
        <div class = SuperLargBox style = "width:100%;height:1000;">
        </div>
        '''



        html += '<div class = OutputContainer>'

        html += self.genOutputSection(SISdatumsets['Commands'])
        html += self.genOutputSection(SISdatumsets['Network'])
        html += self.genOutputSection(SISdatumsets['Files'])

        html += '</div>'
        html += '</div>'
        html += '</div>'

        html += '</html>'
        return html

    def genSISMenu(self, SISdatums, datumsetname):
        html = '''
        <div class = Menu>
        <div class = MenuTitle>
        {i} Menu
        </div>
                '''.format(i = datumsetname
        )
        for d in SISdatums:
            html += self.genSISMenuElement(d)
        html += '</div>'
        return html



    def genSISMenuElement(self, SISdatum):
        html = '''
        <div class = MenuElement>
        <a href = "#{sectionid}">{linkname}</a>
        </div>
                '''.format(
        sectionid = SISdatum.getSectionName(),
        linkname = SISdatum.getName(),
)
        return html

    def genOutputBox(self, SISdatum):
        html = '<a name = "{sectionid}"></a>'.format(sectionid = SISdatum.getSectionName())

        html +='''

        <div class = OutputHeader>
        {header}
        </div>
        <button onclick="sayhi()">
        Show
        </button>
        <button onclick="myFunction()">Try it</button>
        '''.format(header = SISdatum.getName(),
                    ident = SISdatum.getName(),
        )

        html += '<a class = Buttons href = #index>Index</a>'

        html += '''
        <div id = {ident} class = OutputBox >
        {output}
        </div>
        '''.format(
            output = SISdatum.getOutput(),
            ident = SISdatum.getName(),
        )
        return html

    def genOutputSection(self, SISdatums):
        html ='''
        <div class = OutputSection>
        '''
        for SISdatum in SISdatums:
            html += self.genOutputBox(SISdatum)
        html +='''
        </div>
        '''
        return html

class SysinfoSnapshot:
    def __init__(self, system, config):
        self.system = system
        self.appconfig = config

class SysinfoSnapshotWin(SysinfoSnapshot):
    def __init__(self , system, config):
        SysinfoSnapshot.__init__(self, system, config)

    def amIRoot(self):
        if getpass.getuser() == 'administrator' or 'Administrator':
            return True
        else: return False

class SysinfoSnapshotUnix(SysinfoSnapshot):
    def __init__(self , system, config):
        SysinfoSnapshot.__init__(self, system, config)


        self.snapshotcmdstructs = []
        self.snapshotfilestructs = []
        self.snapshotfabstructs = []
        self.snapshotmethstructs = []

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
                                #'dmesg',

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

                                'Multicast_Information',

                                'zz_sys_class_net_files',

                                'zz_proc_net_bonding_files',

                                #Use the Python Platform library to retrieve OS hostname
                                'getHostname',

                                #Use the Python Platform library to retrieve OS release data in a cross platform manner
                                'getRelease',

                                #Get the output of ethtool <Interface> on every system interface
                                'eth_tool_all_interfaces',

                              ]

        self.allStrings = self.commandStrings + self.methodStrings + self.fileStrings + self.fabdiagStrings


    def amIRoot(self):
        if getpass.getuser() == 'root':
            return True
        else: return False

    def getHostname(self):
        return self.system.getHostname()

    def getRelease(self):
        return self.system.getRelease()

    def eth_tool_all_interfaces(self):
        out = ''
        regularEthtoolList = []
        driverEthtoolList = []
        #
            #Try to get the interfaces using ifconfig
        interfaces = [i for i in self.callCommand("ifconfig |grep encap|awk '{print $1'").getOutput().split('\n') if i != '']
        for interface in interfaces:
            regStruct = self.callCommand('ethtool {inter}'.format(inter = interface))
            regularEthtoolList.append(regStruct)
            driverStruct = self.callCommand('ethtool -i {inter}'.format(inter = interface))
            driverEthtoolList.append(driverStruct)

        out += "Ethtool for all interfaces\n"
        for struct in regularEthtoolList:
            out += struct.getOutput()+'\n'
        out += 'Ethtool -i showing driver for all interfaces\n'
        for struct in driverEthtoolList:
            out += struct.getOutput()+'\n'
        return out

    def Multicast_Information(self):
        out = ''
        out += "MLIDs list: \n"
        out += self.callCommand('/usr/sbin/saquery -g').getOutput()+'\n'
        out += "MLIDs members for each multicast group:" +'\n'
        MLIDS = self.callCommand("/usr/sbin/saquery -g |grep Mlid | sed 's/\./ /g'|awk '{print $2}'").getOutput() +'\n'

        for lid in MLIDS:
            out += "Members of MLID {gname} group".format(gname = lid) +'\n'
            out += self.callCommand("saquery -m {Lid}".format(Lid = lid)).getOutput() +'\n'
            out += "============================================================"
        return out

    def zz_proc_net_bonding_files(self):
        return self.callCommand("find /proc/net/bonding/ |xargs grep ^").getOutput()

    def zz_sys_class_net_files(self):
        return self.callCommand("find /sys/class/net/ |xargs grep ^").getOutput()

    def runDiscovery(self):

        if self.appconfig[0].minimal:
            print('hit appconfig minimal, exiting')
            pass

        else:
            print('starting cmd dump')
            for i in self.commandStrings:
                struct = self.callCommand(i)
                self.snapshotcmdstructs.append(struct)
            print('starting method dump')
            for i in self.methodStrings:
                struct = self.callMethod(i)
                self.snapshotmethstructs.append(struct)

            print('starting files dump')
            for i in self.fileStrings:
                struct = self.getFileText(i)
                self.snapshotfilestructs.append(struct)
            print('starting fabdiag dump')
            for i in self.fabdiagStrings:
                struct = self.callCommand(i)
                self.snapshotfabstructs.append(struct)




    def getFileText(self, filename):
        try:
            f = open(filename, 'r')
        except:
            return SysInfoData(filename, 'FILENOTFOUND', 'sysinfo-file')
        out = f.read()
        f.close()
        FDStruct = SysInfoData(filename, out, 'sysinfo-file')
        return FDStruct

    def callMethod(self, methodname):
        m = getattr(self, '{meth}'.format(meth = methodname))
        out = m()
        MStruct = SysInfoData(methodname, out, 'sysinfo-method')
        return MStruct

    def callCommand(self, command):
        out = UnixCommand('{cmd}'.format(cmd = command), command).systemCall()
        CStruct = SysInfoData(command, out, 'sysinfo-command')
        print CStruct
        return CStruct

    def gzip(self, file, newfilename):
        f = open(file,r)
        result = UnixCommand('gzip {target} {destination}'.format(target = file, destination = newfilename))

    def dumpHTML(self, html, filename):
        f = open('{fn}.html'.format(fn = filename), 'w')
        f.write(html)
        f.close()

    def getHTMLInterface(self):
        return self.htmlgen.constructPage()

class SysInfoData:
    def __init__(self, name, output, type):
        self.name = name
        self.output = output
        self.type = type
        self.id = id
        self.section = self.name+self.type

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

        #Python command-line option/help generator http://docs.python.org/library/optparse.html
        self.parser = OptionParser()
        self.configuration = self.__configureCLI__()

        #System variables obtained, depending on the host system these variables can be very different
        self.system = System()


        #detect the OS and initiate the correct object representing the sysinfo-snapshot program capabilities
        if self.system.getSystem() in ['Windows', 'Microsoft']:
            self.sysinfo = SysinfoSnapshotWin(self.system, self.configuration)

        else:
            self.sysinfo = SysinfoSnapshotUnix(self.system, self.configuration)

        #Initiate interface generator
        self.htmlgen = AdvancedSysHTMLGenerator(self.system, self.sysinfo)


    def __configureCLI__(self):
        '''
        Add support and dispatch for all flags
        '''
        self.parser.add_option("-m", "--minimal", action="store_true", dest="minimal")



        (opts, args) = self.parser.parse_args()
        configuration = [opts, args]
        return configuration

    def run(self):
        #if not self.sysinfo.amIRoot():
        #    print('You must run this program as root')
        #    print('exiting...')
        #    raise ValueError

        #Run all commands in accordance to flags passed from CLI
        print('Please wait, collecting...')
        self.sysinfo.runDiscovery()
        print('Discovery complete... generating interface')

        interface = self.htmlgen.genSISInterface({'Commands':self.sysinfo.snapshotcmdstructs + self.sysinfo.snapshotmethstructs,
                                                  'Network':self.sysinfo.snapshotfabstructs,
                                                  'Files':self.sysinfo.snapshotfilestructs})

        print('Dumping Interface at {location}'.format(location = os.getcwd()))
        self.sysinfo.dumpHTML(interface, '{hostname}Snapshot'.format(hostname = self.system.getHostname()))

a = App()
a.run()