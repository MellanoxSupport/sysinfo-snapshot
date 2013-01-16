# coding=utf-8
'''

Created on Sep 24, 2012
@author: luis
'''
from optparse import OptionParser
import subprocess
import shlex
import platform
import os
import getpass
import re




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

        ul li ul {
        display: none;
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
        width:1500;
        height:1000;
        }

        .Menu{
        float:left;
        width:33%;
        height:100%
        }

        .OutputHeader{
        font-weight:bold;
        font-size:150%;
        margin-bottom:10;
        margin-left:20;
        }
        '''
        return css

    def genSISInterface(self, SISdatumsets):
        html = '''
        <html>
        <head>
        '''
        html += '''
        <STYLE type="text/css">
        {thecss}
        </STYLE>
        </head>
        '''.format(thecss = self.genSISCSS())
        html += '''
        <body>
        <script>
        $('.list > li a').click(function () {
        $(this).parent().find('ul').toggle();
        });

        function findPos(obj) {
        var curtop = 0;
        if (obj.offsetParent) {
            do {
                curtop += obj.offsetTop;
            } while (obj = obj.offsetParent);
        return [curtop];
        }
        }

        function goToIndex(id){
        window.scroll(0,findPos(document.getElementById(id)));
        }

        function ToggleButtonVisibility(id){
        if (document.getElementById(id).style.visibility != "hidden"){
            document.getElementById(id).style.visibility = "hidden";
            document.getElementById(id).style.oldheight = document.getElementById(id).style.height;
            document.getElementById(id).style.oldwidth = document.getElementById(id).style.width;
            document.getElementById(id).style.height = "0%";
            document.getElementById(id).style.width = "0%";
            }
        else{
            document.getElementById(id).style.visibility = "visible";
            document.getElementById(id).style.height = document.getElementById(id).style.oldheight;
            document.getElementById(id).style.width = document.getElementById(id).style.oldwidth;
        }
        }
        </script>
        '''
        html += '''
        <title>{hostn} Diagnostics</title>
        '''.format(hostn = self.system.getHostname())
        html += '''
            <div name = 'index'></div>
            </button>
        	<div class = 'MellanoxTitleContainer'>
            Mellanox System Information Snapshot
	        </div>
	        <div id = "index"></div>
	        <hr width="100%" height="5"></hr>
	        '''
        html += '<div class = MenuContainer>'
        html += self.genSISMenu(SISdatumsets['Commands'], 'Commands')
        html += self.genSISMenu(SISdatumsets['Network'], 'Network')
        html += self.genSISMenu(SISdatumsets['Files'], 'Files')
        html += '</div>'
        html += '<div class = OutputContainer>'
        html += self.genOutputSection(SISdatumsets['Commands'])
        html += self.genOutputSection(SISdatumsets['Network'])
        html += self.genOutputSection(SISdatumsets['Files'])
        html += '</div>'
        html += '</html>'
        return html

    def genSISMenu(self, SISdatums, datumsetname):
        html = '''
        <div class = Menu>
        <h2 class = "MenuTitle">{i} Menu</h2>
        <button onclick="ToggleButtonVisibility('{ident}')">
        Show/Hide
        </button>
        <div id = "collapsemenu{ext}">

                '''.format(
            i = datumsetname,
            ident = 'collapsemenu'+datumsetname,
            ext = datumsetname,
        )
        for d in SISdatums:
            html += self.genSISMenuElement(d)
        html += '</div></div>'
        return html

    def genSISMenuElement(self, SISdatum):
        html = '''
        <li>
        <div class = MenuElement>
        <a href = "#{sectionid}">{linkname}</a>
        </div>
        </li>
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
        <button onclick="ToggleButtonVisibility('{ident}')">
        Show/Hide
        </button>
        '''.format(header = SISdatum.getName(),
                    ident = SISdatum.getName(),
        )
        html += '''
                <button onclick="goToIndex('index')">Index</button>
                                                  '''
        html += '''
        <div id = {ident} class = OutputBox>
        <code>
        <pre>
        {output}
        </pre>
        </code>
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
                                'biosdecode',
                                'blkid -c /dev/null | sort',
                                'date',
                                'df -h',
                                'dmidecode',
                                'fdisk -l',
                                'free',
                                'hwinfo --netcard',
                                'hwinfo',
                                'ofed_info',
                                'ibstat',
                                'ibstatus',
                                'ibv_devinfo',
                                'sminfo',
                                'ibv_devinfo -v',
                                'ifconfig -a',
                                'ip a s',
                                'ip m s',
                                'ip n s',
                                #'iptables -t filter -nvL',
                                #'iptables -t mangle -nvL',
                                #'iptables -t nat -nvL',
                                #'iptables-save -t filter',
                                #'iptables-save -t mangle',
                                #'iptables-save -t nat',
                                'lslk',
                                'lsmod',
                                'lsof',
                                'lspci',
                                'lspci -tv',
                                'lspci -tvvv',
                                'lspci -xxxx',
                                'mii-tool -vv',
                                'modprobe sq',
                                'mount',
                                'netstat -anp',
                                'netstat -i',
                                'netstat -nlp',
                                'netstat -nr',
                                'numactl --hardware',
                                'ompi_info',
                                'perfquery',
                                'ps xfalw',
                                'route -n',
                                'sdpnetstat -anp',
                                'sg_map -i -x',
                                'sysctl -a',
                                'ulimit -a',
                                'uname -a',
                                'uptime',
                                'zcat /proc/config.gz'
                            ]
        self.fabdiagStrings = [
                                'ibdiagnet',
                                'ibcheckerrors -nocolor',
                                'ibhosts',
                                'ibnetdiscover',
                                'ibnetdiscover -p',
                                'ibswitches',
                            ]
        self.fileStrings = [
                                '/etc/hosts',
                                '/etc/hosts.allow',
                                '/etc/hosts.deny',
                                '/etc/modprobe.conf',
                                '/etc/modprobe.d/blacklist-compat',
                                '/etc/modprobe.d/blacklist-firewire',
                                '/etc/modprobe.d/blacklist.conf',
                                '/etc/modprobe.d/mlx4_en.conf',
                                '/etc/modprobe.d/modprobe.conf.dist',
                                '/etc/resolv.conf',
                                '/etc/sysconfig/network-scripts/ifcfg-bond0',
                                '/etc/sysconfig/network-scripts/ifcfg-eth0',
                                '/etc/sysconfig/network-scripts/ifcfg-eth1',
                                '/etc/sysconfig/network-scripts/ifcfg-ib0',
                                '/etc/sysconfig/network-scripts/ifcfg-lo',
                                '/proc/buddyinfo',
                                '/proc/cmdline',
                                '/proc/cpuinfo',
                                '/proc/crypto',
                                '/proc/devices',
                                '/proc/diskstats',
                                '/proc/dma',
                                '/proc/execdomains',
                                '/proc/scsi/scsi',
                                '/proc/slabinfo',
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
        self.methodStrings = [
                                'Multicast_Information',
                                'zz_sys_class_net_files',
                                'zz_proc_net_bonding_files',
                                'getHostname',
                                'getRelease',
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
        self.section = self.name+'Section'

    def getName(self):
        #strip all spaces due to future HTML use
        return re.sub(r'\s+', '', self.name)

    def getOutput(self):
        return self.output

    def getType(self):
        return self.type

    def getId(self):
        return self.id

    def getSectionName(self):
        return self.section



class App:

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
        #Run all commands in accordance to flags passed from CLI
        print('Please wait, collecting...')
        self.sysinfo.runDiscovery()
        print('Discovery complete... generating interface')

        interface = self.htmlgen.genSISInterface({
            'Commands':self.sysinfo.snapshotcmdstructs + self.sysinfo.snapshotmethstructs,
            'Network':self.sysinfo.snapshotfabstructs,
            'Files':self.sysinfo.snapshotfilestructs,
            })
        print('Dumping Interface at {location}'.format(location = os.getcwd()))
        self.sysinfo.dumpHTML(interface, '{hostname}Snapshot'.format(hostname = self.system.getHostname()))
a = App()
a.run()