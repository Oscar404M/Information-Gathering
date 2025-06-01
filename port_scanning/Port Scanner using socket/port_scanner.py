import socket
import time

scan = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

target = input("enter your target: ")
target_ip = socket.gethostbyname(target)
print("start scanning on host: ", target_ip)

def port_scan(port):
    try:
        scan.connect((target_ip, port))
        return True
    except:
        return False
        
port_list = [21, 22, 23, 25, 53, 67, 80, 110, 443, 137, 138]

start = time.time()

for port in port_list:
    if port_scan(port) == True: # فحص البورت
        print(f'{socket.getservbyport(port)} {port} is open ')
    else:
        print(f'port {port} is closed')
        
end = time.time()
print(f'Time taken {round(end-start, 2)} seconds')