import platform
import subprocess
import psutil
import json


class Monitor:

    byte_to_gigabyte = 1073741824

    def cpu(self):

        cpu_list = {
            "cpu name": platform.processor(),
            "Cpu Cores": psutil.cpu_count(logical=False),
            "Cpu Stats": psutil.cpu_stats(),
            "Cpu Frequency": psutil.cpu_freq()
        }
        return cpu_list

    def ram(self):
        ram_list = {
            "Total Ram": round(psutil.virtual_memory()[0] / Monitor.byte_to_gigabyte, 2),
            "Avilable": round(psutil.virtual_memory()[1] / Monitor.byte_to_gigabyte, 2),
            "Used": round(psutil.virtual_memory()[3] / Monitor.byte_to_gigabyte, 2),
            "Percent": psutil.virtual_memory()[2]
        }
        return ram_list

    def disks(self):

        all_partitions = []
        total_space = []
        free_space = []
        used_space = []
        for disk in psutil.disk_partitions():
            if disk.fstype:
                all_partitions.append(disk[0])
                total_space.append((disk.device, round(psutil.disk_usage(
                    disk.mountpoint)[0] / Monitor.byte_to_gigabyte, 2)))
                free_space.append((disk.device, round(psutil.disk_usage(
                    disk.mountpoint)[2] / Monitor.byte_to_gigabyte, 2)))
                used_space.append((disk.device, round(psutil.disk_usage(
                    disk.mountpoint)[1] / Monitor.byte_to_gigabyte, 2)))

        hardDisk_list = {
            "All Partitions": all_partitions,
            "Total Space": total_space,
            "Free Space": free_space,
            "Used Space": used_space

        }
        return hardDisk_list

    def network(self):

        ifaces_with_mac = []
        for iface in psutil.net_io_counters(pernic=True):
            ifaces_with_mac.append(
                (iface, psutil.net_if_addrs().get(iface)[0].address))
        network_list = {
            "All Network Interfaces": ifaces_with_mac
        }
        return network_list

    def users(self):

        all_users = {
            "All Users": psutil.users()[0].name
        }

        return all_users

    def process_manager(self):

        all_process_list = []
        for pid in psutil.pids():
            all_process_list.append(psutil.Process(pid))

        process_list = {
            'All Process List': all_process_list,
        }
        return all_process_list
    
    def linux_services(self):
        return [(psutil.Process(p).name(), psutil.Process(p).status()) for p in psutil.pids()]

    def services(self):

        if platform.system() == "Windows":

            service_list = []
            for service in list(psutil.win_service_iter()):
                service_list.append(service)

            with open('windows_services.txt', 'w+') as file3:
                for line in service_list:
                    file3.writelines(str(line) + '\n')

        if platform.system() == "Linux":
            with open('linux_services.txt', 'w') as f:
                for service in self.linux_services():
                    if service[1] == 'running':
                        f.write(service[0] + '\n')

        else:
            return "no services found"

    def report_file(self):

        all_data = [
            self.cpu(),
            self.ram(),
            self.disks(),
            self.network(),
            self.users(),
        ]

        with open("report.txt", 'w') as file1:
            for i in all_data:
                file1.writelines((json.dumps(i)) + '\n')
            file1.close()

        with open('process_list.txt', 'w+') as file2:
            for i in self.process_manager():
                file2.writelines(str(i) + '\n')
            file2.close()

        print("all Data Saved in files")


Monitor().report_file()

