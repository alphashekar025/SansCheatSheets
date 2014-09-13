__author__ = 'shekarnh'

import  sys
import subprocess
import platform
import pexpect
import getpass


class IntrusionDiscovery(object):
    def __init__(self):
        self.OS = str(platform.dist()[0]).lower()

    def sudo(self, command, password=None, prompt="Enter password "):
        if not password:
            password = getpass.getpass(prompt)

        command = "sudo " + command
        child = pexpect.spawn(command)
        child.expect(['ssword', pexpect.EOF])
        child.sendline(password)
        child.expect(pexpect.EOF)
        child.close()
        return child.before

    ## ps, lsof, chkconfig
    def UnusualPs(self):
        ps = subprocess.Popen(['ps', 'aux'], stdout=subprocess.PIPE).communicate()[0]
        processes = ps.split('\n')
        # this specifies the number of splits, so the splitted lines
        # will have (nfields+1) elements
        nfields = len(processes[0].split()) - 1
        ps_list = []
        print(processes[0])
        for row in processes[1:]:
            if row:
                ps_list.append(row.split(None, nfields))

        #find root with uid = 0
        ps_root_0 = []
        for prs in ps_list:
            if str(prs[0]).lower() == "root" and prs[1] == "0":
                ps_root_0.append(prs)

        if ps_root_0:
            for ps_rt in ps_root_0:
                print"{***** ALERT:: Root User with UID 0 found::}"
                print"{0}".format(ps_rt)
        else:
            print">>>> INFO:: No Process found with Root User and UID 0"

        #TODO:: write ps_list to file
        #TODO:: Give a normal ps file to find anomaly (lsof -p [pid])

        # services enables at various runlevels
        chk_confg = ""
        checkconfig = []
        if self.OS == "ubuntu":
            # chk_confg = subprocess.Popen(['sudo', 'sysv-rc-conf', 'list'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            # out, err = chk_confg.communicate()
            # print out, err, chk_confg.returncode
            # #print chk_confg.communicate("password\n")

            out = self.sudo("sysv-rc-conf --list")
            checkconfig = out.split('\n')
        else:
            chk_confg = subprocess.Popen(['chkconfig', 'list'], stdout=subprocess.PIPE, shell=True).communicate()[0]
            checkconfig = chk_confg.split('\n')
        chkfields = len(checkconfig[0].split()) - 1
        srv_list = []
        for chk_row in checkconfig[1:]:
            if chk_row:
                srv_list.append(chk_row.split(None, chkfields))
        if srv_list:
            for srv in srv_list:
                print srv

    def UnusualFiles(self):
        pass

    def UnusualNwUsage(self):
        pass

    def UnusualScTasks(self):
        pass

    def UnusualAccounts(self):
        pass

    def UnusualLogEntries(self):
        pass

    def UnusualSysPerformance(self):
        pass


if __name__ == "__main__":
    IntrusionDiscovery().UnusualPs()