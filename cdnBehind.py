import json
import asyncio
import dns.resolver
import os
import socket
from urllib.parse import urlparse
import requests
import re
import IPy
from multiprocessing.pool import ThreadPool
import sys
import urllib3
import csv
import fofa
import configparser

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

loop = asyncio.get_event_loop()

class get_cdn(object):
    def __init__(self, target):
        self.target = target
        self.records = []
        self.ip_result = []
        self.cname_result = []

    async def query(self, dnsserver):
        try:
            Resolver = dns.resolver.Resolver()
            Resolver.lifetime = Resolver.timeout = 2.0
            Resolver.nameservers = dnsserver
            record = Resolver.resolve(self.target, "A")
            self.records.append(record)
        except Exception as e:
            # print(e)
            pass

    def check_cdn(self):
        dnsserver = [['114.114.114.114'], ['8.8.8.8'], ['223.6.6.6'], ['1.2.4.8'], ['208.67.222.222']]
        try:
            for i in dnsserver:
                loop.run_until_complete(self.query(i))
            for record in self.records:
                for m in record.response.answer:
                    for j in m.items:
                        if isinstance(j, dns.rdtypes.IN.A.A):
                            self.ip_result.append(j.address)
                        elif isinstance(j, dns.rdtypes.ANY.CNAME.CNAME):
                            self.cname_result.append(j.to_text())
        except Exception as e:
            print(e)

    def getrules(self):
        with open('cname', encoding='utf-8') as f:
            cname_rules = json.load(f)
            f.close()
        return cname_rules

    def run(self):
        cdn_flag = 0
        self.check_cdn()
        if len(list(set(self.ip_result))) > 1:
            cdn_flag = 1

        if cdn_flag == 1:
            cdn_name = 'Unknow'
            cname_rules = self.getrules()
            for i in self.cname_result:
                domain_spilt = i.split('.')
                cdn_domain = '.'.join(domain_spilt[-3:])[:-1]
                if cdn_domain in cname_rules.keys():
                    cdn_name = cname_rules[cdn_domain]['name']
                    break
        else:
            cdn_name = 'no cdn'
        return cdn_name


class bypass_cdn(object):
    def __init__(self, target):
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/48.0.2564.116 Safari/537.36',
        }
        self.target = target.rstrip('/')
        self.ips = set()
        self.cidr_set = set()
        self.Root_Path = os.path.dirname(os.path.abspath(__file__))
        parse = urlparse(target)
        self.scheme = str(parse.scheme)
        self.netloc = str(parse.netloc)
        self.ipList = []
        if self.scheme == "https":
            self.port = "443"
        else:
            self.port = "80"
        # 结果队列
        self.result = set()
        self.length = self.get_length(self.target)

    def get_length(self, target):
        times = 0
        while True:
            r = requests.get(target, headers=self.headers, timeout=5, verify=False)
            times = times + 1
            if len(r.content) != 0:
                return len(r.content)
            if times > 5:
                print("未能成功请求:" + target_url)
                return False

    def get_ip(self):
        myaddr = socket.getaddrinfo(self.netloc, 'http')
        return str(myaddr[0][4][0])

    def special_ping(self):
        if self.netloc.startswith('www.'):
            target_url = self.netloc[4:]
            name = get_cdn(target_url).run()
            if name == "no cdn":
                self.result.add(self.get_ip())


    def domain_history(self):
        # 读取config.ini
        config = configparser.ConfigParser()
        config.read('config.ini')
        apikey = config['DnsHistory']['apikey']

        url = 'https://api.viewdns.info/iphistory'
        # 去除WWW
        domain = self.netloc
        if self.netloc.startswith('www.'):
            target_url = self.netloc[4:]
            domain = target_url
        params = {'domain': domain , 'apikey': apikey, 'output': 'json'}

        try:
            response = requests.get(url, params=params)
            response.raise_for_status()  # 检查请求是否成功
            json_data = response.json()  # 解析 JSON 数据

            ipList1 = []
            # 提取 IP 地址
            ip_list = [record['ip'] for record in json_data['response']['records']]
            if len(ip_list) == 0:
                print("DNS历史解析无数据，可能是apikey查询次数已用尽，请注册新的apikey放入config.ini中")
            # 去重并保持顺序
            seen = set()
            for ip in ip_list:
                if ip not in seen:
                    self.ipList.append(ip)
                    ipList1.append(ip)
                    seen.add(ip)
            print("DNS历史解析的IP地址列表:", ipList1)

        except requests.RequestException as e:
            print(f"请求失败: {e}")

        except ValueError as e:
            print(f"JSON 解析失败: {e}")

    def fofa_ip(self):
        # 读取config.ini
        config = configparser.ConfigParser()
        config.read('config.ini')
        email = config['FOFA']['email']
        key = config['FOFA']['key']

        # 去除WWW
        domain = self.netloc
        if self.netloc.startswith('www.'):
            target_url = self.netloc[4:]
            domain = target_url
        email, key = (email, key)
        client = fofa.Client(email, key)
        query_str = 'domain={}'.format(domain)
        ip_list1 = []
        data = client.search(query_str, size=10000, page=1, fields="ip")
        for ip in data["results"]:
            ip_list1.append(ip)

        # 去重并保持顺序
        seen = set()
        for ip in ip_list1:
            if ip not in seen:
                self.ipList.append(ip)
                seen.add(ip)
        print("fofa收集到的ip列表:", self.ipList)

    def subscan(self):
        target = self.netloc
        if target.startswith('www.'):
            target = target[4:]

        def process_file(filename):
            # 读取原文件内容
            with open(filename, 'r') as file:
                lines = file.readlines()
            # 跳过第一行
            lines = lines[1:]
            # 使用集合来去除重复的行
            unique_lines = set()
            for line in lines:
                # 去除行尾的换行符，并拆分内容
                items = line.strip().split(',')
                # 将拆分后的每个项添加到集合中
                unique_lines.update(item for item in items)

            # 将集合中的内容转回到列表并排序（可选）
            processed_lines = sorted(unique_lines)
            # 写回文件
            with open(filename, 'w') as file:
                file.writelines(item + '\n' for item in processed_lines)

        os.chdir("OneForAll")
        cmdline = "python oneforall.py --target {} run".format(target)
        print(cmdline)
        os.system(cmdline)
        # print(sys.executable)
        os.chdir('../')
        # 处理表格数据
        path = "./OneForAll/results/{}.csv".format(target)
        with open(path, 'r') as csvfile:
            reader = csv.reader(csvfile)
            column = [row[8] for row in reader]

        with open('{}.txt'.format(target), 'w') as txtfile:
            txtfile.write('\n'.join(column))
        process_file('{}.txt'.format(target))

        sub_filename = "{}.txt".format(target)

        with open(sub_filename, 'r') as file:
            self.ips = set(line.strip() for line in file)

    def Cscan(self, target):
        patten = "[0-9]{1,}.[0-9]{1,}.[0-9]{1,}.[0-9]{1,}"
        ipadress = str(re.compile(patten).findall(target))[2:-2]
        headers_1 = {
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/48.0.2564.116 Safari/537.36',
        }
        headers_2 = {
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/48.0.2564.116 Safari/537.36',
            'Host': ''.format(self.netloc),
        }
        host_len = 0
        no_host_len = 0
        try:
            r = requests.get(target, headers=headers_1, timeout=5, verify=False)
            if r.status_code == 200:
                no_host_len = len(r.content)
        except Exception as e:
            no_host_len = 0
            pass
        try:
            r = requests.get(target, headers=headers_2, timeout=5, verify=False)
            if r.status_code == 200:
                host_len = len(r.content)
        except Exception as e:
            host_len = 0
            pass
        if host_len != 0 or no_host_len != 0:
            print("[*] %-15s\t%-6s\t%-6s" % (ipadress, no_host_len, host_len))
        if host_len == self.length or no_host_len == self.length:
            # print("找到真实ip地址")
            self.result.add(ipadress)

    def run(self):
        print("[+] fofa解析ip记录...")
        self.fofa_ip()
        print("[+] DNS解析历史记录...")
        self.domain_history()
        self.special_ping()
        print("[+] 子域名扫描...")
        self.subscan()

        if len(self.ipList) > 0:
            temp_list = []
            for ip in self.ipList:
                target = str(self.scheme) + "://" + str(ip) + ":" + str(self.port)
                temp_list.append(target)

        # onforall的ip扫C段
        while len(self.ips) != 0:
            target = self.ips.pop()
            # print('测试',target)
            cidr = IPy.IP(target).make_net('255.255.255.0')
            if not cidr in self.cidr_set:
                self.cidr_set.add(cidr)

        while len(self.cidr_set) != 0:
            cidr = self.cidr_set.pop()
            # 将每一个C段展开后放到列表里
            print("[+] 扫描C段: {}".format(cidr))
            for ip in cidr:
                target = str(self.scheme) + "://" + str(ip) + ":" + str(self.port)
                # fofa、DNS历史、子域名C段集合结果
                temp_list.append(target)


        # 多线程
        pools = 50
        pool = ThreadPool(pools)
        pool.map(self.Cscan, temp_list)
        pool.close()
        pool.join()

        if len(self.result) != 0:
            print("[+] 找到可能的IP地址")
            while len(self.result) != 0:
                print(self.result.pop())
        else:
            print("[-] 没有找到可能的ip地址")


def main():
    if len(sys.argv) < 2:
    	print("Usage: python3 scan.py http://domain.com")
    	return
    else:
    	target = sys.argv[1]
    parse = urlparse(target)
    netloc = str(parse.netloc)
    name = get_cdn(netloc).run()
    if name != "no cdn":
        print("[+] 目标存在CDN: " + name)
        bypass_cdn(target=target).run()
    else:
        print("[+] 目标不存在CDN")
        print("[+] " + bypass_cdn(target=target).get_ip())


if __name__ == '__main__':
    main()
