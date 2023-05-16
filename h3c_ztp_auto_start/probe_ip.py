from multiping import multi_ping
from netmiko import ConnectHandler
from re import search

#探测获取到IP地址的设备
def test_reachable_hosts():
    addr_list=[]
    for i in range(1,255):
        ip_str = '127.0.0.'+ str(i) #根据DHCP分配范围进行修改
        addr_list.append(ip_str)
    responses = multi_ping(addr_list, timeout=2, retry=1) #返回值是一个元组，内容为字典
#将设备IP写入文件中
    count = 0 #计数器
    for addr in responses[0].keys():
        # print(addr)
        with open('ip_addre.txt','a+') as ip:
            ip.write(addr + '\n')
        count += 1
    print(f'Reachable hosts are {count}')

#根据序列号下发对应配置
def connect_device(ip):
    dev = {'device_type':'hp_comware','ip':ip,'username':'python','password':'h3c@123456','session_log': str(ip) + '.log'}
    connect = ConnectHandler(**dev)
    content = connect.send_command('display device') 
    Device_SN = search(r'',content)
    connect.send_config_from_file(Device_SN + '.txt')
    print(f'{ip}---Configuration complete !')



# while True:
#     save_value = input('Do you want to save the configuration[yes/no]?')
#     if save_value == 'yes':
#         pass
#         break
#     elif save_value == 'no':
#         pass
#         break
#     else:
#         print('please try again!!')
       
if __name__ =='__main__':
     with open('ip_addre.txt','w') as dev_ip:
         for ip in dev_ip.readlines():
             con_ip = ip.strip()
             connect_device(con_ip)