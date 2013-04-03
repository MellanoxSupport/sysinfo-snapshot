__author__ = 'luis'

from optparse import OptionParser
import subprocess
import shlex
import platform
import os

class App:
    def __init__(self):
        #Initialize all entities needed for the application to run
        self.system = System()
        self.sysinfo = self.__makeSysinfo__()
        self.opts, self.args = self.__initializeCLI__()
        self.file_name = self.system.getHostname() + ' ' + self.system.getCPUArchitecture() + \
            ' ' + self.system.getSystem()
        self.interfacebuilder = InterfaceBuilder()

    def __run__(self):
        if self.opts.minimal:
            sysinfodatums = self.sysinfo.__runMinimalDiscovery__()
        else:
            sysinfodatums = self.sysinfo.__runDiscovery__()

        html_interface = self.__buildInterface__(sysinfodatums)

        #Create output folder, dump files, and zip it up
        self.snapshot_directory = self.system.getHostname()+'_'+'SnapshotResults'
        os.mkdir(self.snapshot_directory)
        os.chdir(self.snapshot_directory)
        self.__dumpFile__(self.file_name, html_interface)
        os.chdir('../')
        self.__tarball__(self.file_name, self.snapshot_directory)

    def __dumpFile__(self, file_name, output):
        with open(file_name + '.html', 'w') as f:
            f.write(output)

    def __buildInterface__(self, sysinfodatums):
        return self.interfacebuilder.buildhtmlpage(sysinfodatums)

    def __tarball__(self, file_name, subdir):
        subprocess.call(shlex.split('tar -cvzf {file_name}.tgz {subdir}'.format(file_name=file_name, subdir=subdir)))

    def __makeSysinfo__(self):
        if self.system.getSystem() == self.system.LINUX_SYMBOL:
            sysinfo = LinuxSysinfo()
            return sysinfo
        if self.system.getSystem() == self.system.OSX_SYMBOL:
            sysinfo = OSXSysinfo()
            return sysinfo
        if self.system.getSystem() == self.system.WIN2000_SYMBOL:
            sysinfo = WIN2000Sysinfo()
            return sysinfo
        if self.system.getSystem() == self.system.WIN2008_SYMBOL:
            sysinfo = WIN2008Sysinfo()
            return sysinfo
        if self.system.getSystem() == self.system.WIN2012_SYMBOL:
            sysinfo = WIN2012Sysinfo()
            return sysinfo
        else:
            raise StandardError('No compatible operating system found')

    def __initializeCLI__(self):
        parser = OptionParser()
        #If -m is triggered options.minimal will be True
        parser.add_option('-m', '--minimal', dest='minimal', help='Run a less detailed version of sysinfo')
        #add more command-line options here...

        #Ibdiagnet related options
        parser.add_option('-s', '--speed', dest='speed', help='Input the speed for the ibdiagnet check')
        parser.add_option('-w', '--pciwidth', dest='width', help='Input the pci width check for the ibdiagnet check')
        parser.add_option('-t', '--timed', dest='timed', help='Time to sleep ibdiagnet')
        parser.add_option('-z', '--zipped', dest='zipped', action="store_true", help='Zip the output')

        options, args = parser.parse_args()
        return options, args

class System:
    '''
    Represents the state of the system in which the program is
    being executed. A wrapper for the platform module
    '''

    def __init__(self):
        self.uname = platform.uname()

        #Symbols will be the output of platform.system() for each platform
        self.WIN2008_SYMBOL = ''
        self.WIN2012_SYMBOL = ''
        self.WIN2000_SYMBOL = ''
        self.LINUX_SYMBOL = 'Linux'
        self.UNIX_SYMBOL = ''
        self.OSX_SYMBOL = ''

    def getSystem(self):
        '''
        Returns the Operating System Platform of the underlying system
        '''
        return self.uname[0]

    def getHostname(self):
        '''
        Returns the network hostname of the host
        '''
        return self.uname[1]

    def getKernelVersion(self):
        '''
        Returns the kernel version of the underlying system
        '''
        return self.uname[2]

    def getRelease(self):
        '''
        Returns the release version of the operating system
        '''
        return self.uname[3]

    def getCPUArchitecture(self):
        '''
        Returns the CPU architecture
        '''
        return self.uname[4]

    def getMachineType(self):
        '''
        Returns machine type
        '''
        return self.uname[5]

class fauxProcess:
    '''
    This class implements the communicate() interface just as subprocess.Popen does in order to intercept
    '''

    def __init__(self):
        pass

    def communicate(self):
        out = 'The program you are calling was not found in the underlying system.'
        err = 'Process error'
        return out, err

class Command:
    '''
    Implements the actions required for monitoring/executing shell commands on the underlying system
    '''
    def __init__(self, cmd, name):
        self.cmd = cmd
        self.name = name

    def systemCall(self):
        '''
        Perform an OS CLI call on the Unix commandline and get the full output
        must use with commands that do not require interactivity
        returns both the output and the error in a tuple
        This is intentionally a blocking command, it will not return until the command has ended.
        '''
        try:
            process = subprocess.Popen(shlex.split(self.cmd), stderr = subprocess.STDOUT, stdout = subprocess.PIPE)
        except:
            process = fauxProcess()
        out, err = process.communicate()
        return out

class SysInfoDatum:

    def __init__(self, name, output, tipe):
        self.name = name
        self.output = output
        self.tipe = tipe
        self.section = self.name+'_Section'

    def getName(self):
        #strip all spaces due to future HTML use
        return re.sub(r'\s+', '', self.name)

    def getOutput(self):
        return self.output

    def getType(self):
        return self.tipe

    def getSectionName(self):
        return self.section

class SysinfoSnapshotBase:
    def __init__(self):
        pass

class LinuxSysinfo(SysinfoSnapshotBase):
    def __init__(self):
        self.product_detector = ProductDetector()
        self.tuning_detector = TuningDetector()

        self.commands_to_run = [
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
            #'ps xfalw',
            'route -n',
            'sdpnetstat -anp',
            'sg_map -i -x',
            'sysctl -a',
            'ulimit -a',
            'uname -a',
            'uptime',
            'zcat /proc/config.gz',
            'SAquery -g',

            #Fabric Related Commands
            'ibdiagnet',
            'ibcheckerrors -nocolor',
            'ibhosts',
            'ibnetdiscover',
            'ibnetdiscover -p',
            'ibswitches',
        ]
        self.minimal_commands_to_run = []
        self.files_to_get = [
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

        self.minimal_files_to_get = []

    def __getNetworkInterfaces__(self):
        '''
        Return list of strings that will enumerate the Linux Network Interfaces using ifconfig
        '''
        return [i for i in Command('ifconfig |grep encap|awk {print $1}').systemCall().strip().split('\n') if i != '']

    def getCommand(self, cmdstr):
        return Command(cmdstr, cmdstr).systemCall()

    def getFile(self, file):
        return open(file, 'r').read()

    def __runDiscovery__(self):
        '''
        Run regular discovery for all information to be gathered on a Linux system
        '''
        sysinfodatums = []
        for command in self.commands_to_run:
            sysinfodatums.append(SysInfoDatum(command, self.getCommand(command), 'Command'))
        for file in self.files_to_get:
            sysinfodatums.append((SysInfoDatum(file, self.getFile(file), 'File')))
        return sysinfodatums

    def __runMinimalDiscovery__(self):
        '''
        Scan the system for only the minimal amount of information
        '''
        sysinfodatums = []
        for command in self.minimal_commands_to_run:
            sysinfodatums.append(SysInfoDatum(command, self.getCommand(command), 'Command'))
        for file in self.minimal_files_to_get:
            sysinfodatums.append((SysInfoDatum(file, self.getFile(file), 'File')))
        return sysinfodatums

    def __detectMellanoxProducts__(self):
        #Check for...
        pd = self.productdetector
        installed = []
        for product in pd.getSupportedProducts():
            if product in pd.getDetectedProducts():
                installed.append(product)
        return installed




class OSXSysinfo(SysinfoSnapshotBase):
    pass

class WIN2000Sysinfo(SysinfoSnapshotBase):
    def __init__(self):
        self.system = System()

    def amIRoot(self):
        if getpass.getuser() == 'administrator' or 'Administrator':
            return True
        else: return False

    #Discovery Methods

    def getSystemInformation(self):
        '''
        Return underlying system information
        '''
        return self.system.uname

    def getNetworkInformation(self):

class WIN2008Sysinfo(WIN2000Sysinfo):
    pass

class WIN2012Sysinfo(WIN2000Sysinfo):
    pass


class TuningDetector:
    def __init__(self, parameters):
        self.expected_parameters = parameters

class ProductDetector:
    def __init__(self, supported_products):
        self.supported_products = supported_products
        self.detected_products = self.getDetectedProducts()

    def detectUFM(self, ufm_root_dir):
        if os.path.isfile(ufm_root_dir):
            return True
        else:
            return False

    def detectVSA(self, vsa_root_dir):
        if os.path.isfile(vsa_root_dir):
            return True
        else:
            return False

    def detectVMA(self, vma_root_dir):
        if os.path.isfile(vsa_root_dir):
            return True
        else:
            return False

    def detectFCA(self, fca_root_dir):
        if os.path.isfile(fca_root_dir):
            return True
        else:
            return False

    def getDetectedProducts(self):
        detected = []
        if self.detectFCA():
            detected.append('FCA')
        if self.detectVSA():
            detected.append('VSA')
        if self.detectVMA():
            detected.append('VMA')
        if self.detectUFM():
            detected.append('UFM')

    def getSupportedProducts(self):
        return self.supported_products

class InterfaceBuilder:
    def __init__(self):
        pass

    def buildHtmlPage(self, sysinfodatums):
        files = []
        commands = []

        for datum in sysinfodatums:
            if datum.tipe == 'File':
                files.append(datum)
            if datum.tipe == 'Command':
                commands.append(datum)


