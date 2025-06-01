import argparse # تستخدم لتوضيح استخدامات الكود
import socket
import time # تستخدم لأنشاء الاتصال
from colorama import init, Fore # تستخدم لعرض النصوص بالألوان في موجه الاوامر
from threading import Thread, Lock # تستخدم للمسارات
from queue import Queue # تستخدم لإدارة المسارات

init()
GREEN = Fore.GREEN # ضبط اللون الاخضر
RESET = Fore.RESET # اعادة ضبط السطر في تيرمينال 
RED = Fore.RED # ضبط اللون الاحمر


THREADS_NUMBER = 200 # يمكنك تغيير او مضاعفىة ذلك العدد

Q = Queue()
print_lock = Lock()

def fast_scan(port):
    try:
        scan = socket.socket() # انشاء كائن من المكتبة سوكيت
        scan.connect((host, port)) # الاتصال بالهدف باستخدام الهوست والبورت
    except:
        with print_lock:
            print(f"{RED}{host}:{port} is closed  {RESET}", end='\r')
    else:
        with print_lock:
            print(f"{GREEN}{host}:{port} is open          {RESET}")
    finally:
        scan.close() # اغلاق الاتصال في النهاية مهما كانت حالة الاتصال

def scan_thread():
    global Q
    while True:
        bringer = Q.get() # الحصول علي رقم البورت من الكيو queue
        fast_scan(bringer) # فحص البورت الذي تم جلبه
        Q.task_done() # اخبار الكيو ان فحص المنفذ قد تم
        
def main(host, ports):
    global Q
    start = time.time()
    for t in range(THREADS_NUMBER): # البدء في تنفيذ كل مسار (100)
        t = Thread(target=scan_thread) # وضع الدالة السابقة في مسار لفحص المنقذ وهكذا
        t.daemon = True # نقوم بتفعيل ذلك الخيار للانتهاء من المسارات عن انتهاء الدالة الخاصة بنا main
        t.start() # البدء في تنفيذ المسار تلو الاخر

    for bringer in ports: # نقوم باستخراج كل بورت من قائمة البورتات التي سنمررها للدالة
        Q.put(bringer) # نضع كل بورت في الكيو حتي تقوم الدالة السابقة في استخراجه وبدء فحصه
    Q.join() # نقوم بانتظار المسارات حتي تنتهي
    end = time.time()
    print(f'Time taken {round(end-start, 2)} seconds')

if __name__ == "__main__": # نقطه استدعاء وتشغيل البرنامج

    parser = argparse.ArgumentParser(description="Simple port scanner") # اظهار معلومات حول استخدامات الاسكريبت
    parser.add_argument("--ports", "-p", dest="port_range", default="1-65535", help="Port range to scan, default is 1-65535 (all ports)")
    parser.add_argument("host", help="Host to scan.") # معلومات عن الهدف الذي يجب تضمينه
    args = parser.parse_args() # استخراج الهدف ومدي المنافذ من موجة الاوامر
    host, port_range = args.host, args.port_range # وضع الهوست او الهدف في متفير والبورت في متغير

    start_port, end_port = port_range.split("-") # استخراج بداية البورت ونهايته
    start_port, end_port = int(start_port), int(end_port) # تحويل الثيم الي integer

    ports = [ p for p in range(start_port, end_port)] # توليد قائمه البورتات

    main(host, ports) # تمرير الهوست وقائمة المنافذ الي الدالة main