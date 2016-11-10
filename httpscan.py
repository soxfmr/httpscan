#!/usr/bin/env python
#coding:utf-8
# Author: Zeroh

import re
import sys
import Queue
import codecs
import logging
import optparse
import requests
import threading
from IPy import IP
from os.path import basename
# from urllib3.exceptions import ConnectTimeoutError

printLock = threading.Semaphore(1)  #lock Screen print
TimeOut = 5  #request timeout

#User-Agent
header = {'User-Agent' : 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/44.0.2403.125 Safari/537.36','Connection':'close'}

class scan():

    def __init__(self,cidr,threads_num):
        self.threads_num = threads_num
        self.log_handler = None

        self.cidr, self.logfilename = self.load_target(cidr)
        self.cur_position = 1
        self.total = len(self.cidr)
        self.running = True

        #build ip queue
        self.IPs = Queue.Queue()
        self.msg_queue = Queue.Queue()
        for ip in self.cidr:
            self.IPs.put(ip)

    def load_target(self, target):
        targets = []
        logfilename = ''
        try:
            # try to open as file
            with open(target, 'r') as handle:
                for line in handle:
                    if line.strip():
                        targets.append(line.strip())
            logfilename = basename(target)
        except IOError, e:
            # treat as range of ip
            ips = IP(target)
            logfilename = ips.strNormal(3)
            targets = map(lambda x: str(x), ips)

        return (targets, './log/{}.log'.format(logfilename))

    def __record(self, log):
        if self.log_handler:
            self.log_handler.write(log + '\n')
        print log

    def request(self, log_handler):
        while self.IPs.qsize() > 0:
            ip = self.IPs.get()
            self.msg_queue.put('Current target: ' + ip)

            try:
                r = requests.Session().get('http://' + ip,headers=header,timeout=TimeOut)
                status = r.status_code
                title = re.search(r'<title>(.*)</title>', r.text) #get the title
                if title:
                    title = title.group(1).strip().strip("\r").strip("\n")[:30]
                else:
                    title = "None"
                banner = ''
                try:
                    banner += r.headers['Server'][:20] #get the server banner
                except:pass

                self.msg_queue.put("|%-16s|%-6s|%-20s|%-30s|" % (ip,status,banner,title))
                self.msg_queue.put("+----------------+------+--------------------+------------------------------+")
            except Exception:
                # timeout, nothing to do
                pass

    def __print_log_message(self):
        while self.running:
            try:
                msg = self.msg_queue.get(timeout=0.1)
            except:
                continue

            with printLock:
                if msg[0] in ('|', '+'):
                    self.__record(msg)
                else:
                    sys.stdout.write(' ' * 100 + '\r')
                    sys.stdout.flush()

                    if msg[:7] == 'Current':
                        msg = '%s (%d/%d)' % (msg, self.cur_position, self.total)
                        if self.cur_position < self.total:
                            self.cur_position += 1

                    sys.stdout.write(msg + '\r')
                    sys.stdout.flush()

    #Multi thread
    def run(self):
        threads = []

        with codecs.open(self.logfilename, 'w+', 'utf-8') as handle:
            try:
                self.log_handler = handle
                log_thread = threading.Thread(target=self.__print_log_message)
                log_thread.start()

                self.msg_queue.put("+----------------+------+--------------------+------------------------------+")
                self.msg_queue.put("|     IP         |Status|       Server       |            Title             |")
                self.msg_queue.put("+----------------+------+--------------------+------------------------------+")

                for i in range(self.threads_num):
                    threads.append(threading.Thread(target=self.request, args=(handle,)))
                    threads[i].setDaemon(True)
                    threads[i].start()

                for thread in threads:
                    thread.join(20000)
            except KeyboardInterrupt:
                self.msg_queue.put('[+] User aborted')
            finally:
                self.running = False

        self.msg_queue.put('done.')

if __name__ == "__main__":
    parser = optparse.OptionParser("Usage: %prog [options] <target|file>")
    parser.add_option("-t", "--thread", dest = "threads_num",
        default = 10, type = "int",
        help = "[optional]number of theads,default=10")
    (options, args) = parser.parse_args()

    if len(args) < 1:
        parser.print_help()
        sys.exit(0)

    s = scan(cidr = args[0], threads_num = options.threads_num)
    s.run()
