# Behind_cdn
![](https://img.shields.io/badge/python-3.8-blue)

绕过CDN查找网站背后的真实IP


## 简介
### 说明

 - 使用shmilylty的[oneforall](https://github.com/shmilylty/OneForAll)进行子域名收集
 - 对输入的域名进行fofa查询和dns历史查询
 - 根据HTTP响应包长度在扫出的地址范围内寻找真实IP
 - 输入的目标必须以`http/https`开头
## 项目架构

![项目架构](https://github.com/matias-a11y/Behind_cdn/blob/master/img/%E9%A1%B9%E7%9B%AE%E6%9E%B6%E6%9E%84.png)

## 准备

需要在config.ini文件填写dns解析网站 (https://viewdns.info/api/) 的api和fofa的email和key参数。

![config](https://github.com/matias-a11y/Behind_cdn/blob/master/img/config.png)
安装依赖
```
pip install -r requirements.txt
```

##  示例

```
PS C:\Users\yu\Desktop\Behind_cdn-master>python cdnBehind.py https://www.dfle.com.cn
[+] 目标不存在CDN
[+] 218.107.207.39
```
```
PS C:\Users\yu\Desktop\Behind_cdn-master>python cdnBehind.py https://test.com
[+] 目标存在CDN: Unknow
[+] fofa解析ip记录...
fofa收集到的ip列表: ['114.12.25.119'.............., '42.81.229.13']
[+] DNS解析历史记录...
DNS历史解析的IP地址列表: ['27.15.113.143'........., '184.22.154.21']
[+] 子域名扫描...
python oneforall.py --target test.com run

OneForAll is a powerful subdomain integration tool
[+] 扫描C段: 118.50.53.0/24
.....
.....
.....
[+] 扫描C段: 27.155.113.0/24
[*] 153.58.179.70       968     0
....
....
....
[*] 39.115.49.138       968     0
[+] 找到可能的IP地址
45.93.53.119
```
> 考虑到很多网站的真实IP所在主机为反向代理，会根据host头转发到后端的负载均衡服务器
> 上面输出中ip后面跟着的两个数字，就是有host和无host的响应包大小

