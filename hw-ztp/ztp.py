#sha256sum="7eb57f7cf11d2bf481e544f333267e8dd43a532c12a60151d640d64872013a8b"
#!/usr/bin/env python
#
# Copyright (C) Huawei Technologies Co., Ltd. 2008-2013. All rights reserved.
# ----------------------------------------------------------------------------------------------------------------------
# History:
# Date                Author                      Modification
# 20130629            Author                      created file.
# ----------------------------------------------------------------------------------------------------------------------

"""
Zero Touch Provisioning (ZTP) enables devices to automatically load version files including system software,
patch files, configuration files when the device starts up, the devices to be configured must be new devices
or have no configuration files.

This is a sample of Zero Touch Provisioning user script. You can customize it to meet the requirements of
your network environment.
"""

import http.client
import urllib.request, urllib.parse, urllib.error
import string
import re
import xml.etree.ElementTree as etree
import os
import stat
import logging
import traceback
import hashlib
import sys
import ops

from urllib.parse import urlparse
from urllib.parse import urlunparse
from time import sleep

# error code
OK          = 0
ERR         = 1

slog = ops.ops()

g_sys_info = {'mac':'', 'esn':''}
g_ip_addr = None

# File server in which stores the necessary system software, configuration and patch files:
#   1) Specify the file server which supports the following format.
#      (hostname for IPv6 should be placed in brackets)
#      tftp://hostname
#      ftp://username:password@hostname
#      sftp://username:password@hostname[:port]
#      sftp-sha1://username:password@hostname[:port]
#      http://hostname[:port]
#   2) Do not add a trailing slash at the end of file server path.
FILE_SERVER = 'ftp://admin:hw12345@192.168.3.254'

# Remote file paths:
#   1) The path may include directory name and file name.
#   2) If file name is not specified, indicate the procedure can be skipped.
# File paths of system software on file server, filename extension is '.cc'.
REMOTE_PATH_IMAGE = {
    ''     :   '',
}
# File path of configuration file on file server, filename extension is '.cfg', '.zip' or '.dat'.
REMOTE_PATH_CONFIG = ''
# File path of patch file on file server, filename extension is '.pat'
REMOTE_PATH_PATCH = {
    ''     :   '',
}
# File path of stack member ID file on file server, filename extension is '.txt'
REMOTE_PATH_MEMID = ''
# File path of license list file, filename extension is '.xml'
REMOTE_PATH_LICLIST = ''
# File path of sha256 file, contains sha256 value of image / patch / memid / license file, file extension is '.txt'
REMOTE_PATH_SHA256 = ''
# File path of python file on file server, filename extension is '.py'
REMOTE_PATH_PYTHON = ''


# Max times to retry get startup when no query result
GET_STARTUP_INTERVAL = 15    # seconds
MAX_TIMES_GET_STARTUP = 120   # Max times to retry

# Max times to retry when download file faild
MAX_TIMES_RETRY_DOWNLOAD = 3


class OPSConnection(object):
    """Make an OPS connection instance."""

    def __init__(self, host, port = 80):
        self.host = host
        self.port = port
        self.headers = {
            "Content-type": "application/xml",
            "Accept":       "application/xml"
            }

        self.conn = http.client.HTTPConnection(self.host, self.port)

    def close(self):
        """Close the connection"""
        self.conn.close()

    def create(self, uri, req_data):
        """Create a resource on the server"""
        ret = self._rest_call("POST", uri, req_data)
        return ret

    def delete(self, uri, req_data):
        """Delete a resource on the server"""
        ret = self._rest_call("DELETE", uri, req_data)
        return ret

    def get(self, uri, req_data = None):
        """Retrieve a resource from the server"""
        ret = self._rest_call("GET", uri, req_data)
        return ret

    def set(self, uri, req_data):
        """Update a resource on the server"""
        ret = self._rest_call("PUT", uri, req_data)
        return ret

    def _rest_call(self, method, uri, req_data):
        """REST call"""
        if req_data == None:
            body = ""
        else:
            body = req_data

        logging.info('HTTP request: %s %s HTTP/1.1', method, uri)
        self.conn.request(method, uri, body, self.headers)
        response = self.conn.getresponse()
        ret = (response.status, response.reason, response.read())
        if response.status != http.client.OK:
            logging.info('%s', body)
            logging.error('HTTP response: HTTP/1.1 %s %s\n%s', ret[0], ret[1], ret[2])
        return ret

class OPIExecError(Exception):
    """OPI executes error."""
    pass

class ZTPErr(Exception):
    """ZTP error."""
    pass

def ztp_log(logStr, level):
    if g_ip_addr != None :
        slog.syslog(logStr, level, ops.SYSLOG)

def get_addr_by_hostname(ops_conn, host, addr_type = '1'):
    """Translate a host name to IPv4 address format. The IPv4 address is returned as a string."""
    logging.info("Get IP address by host name...")
    uri = "/dns/dnsNameResolution"
    root_elem = etree.Element('dnsNameResolution')
    etree.SubElement(root_elem, 'host').text = host
    etree.SubElement(root_elem, 'addrType').text = addr_type
    req_data = etree.tostring(root_elem, "UTF-8")
    ret, _, rsp_data = ops_conn.get(uri, req_data)
    if ret != http.client.OK:
        raise OPIExecError('Failed to get address by host name')

    root_elem = etree.fromstring(rsp_data)
    namespaces = {'vrp' : 'http://www.huawei.com/netconf/vrp'}
    uri = 'data' + uri.replace('/', '/vrp:') + '/vrp:'
    elem = root_elem.find(uri + "ipv4Addr", namespaces)
    if elem is None:
        raise OPIExecError('Failed to get IP address by host name')

    return elem.text

def _set_sshc_sha1_enable(ops_conn, switch):
    """Set SSH client attribute of authenticating user for the first time access"""
    if switch not in ["true", "false"]:
        return ERR

    logging.info('Set SSH client rsa public key enable switch = %s', switch)
    uri = "/sshc/sshCPubKeyAlg"
    str_temp = string.Template(
'''<?xml version="1.0" encoding="UTF-8"?>
<sshCPubKeyAlg>
    <rsa>$enable</rsa>
</sshCPubKeyAlg>
''')
    req_data = str_temp.substitute(enable = switch)
    ret, _, _ = ops_conn.set(uri, req_data)
    if ret != http.client.OK:
        if switch == 1:
            logging.info('Failed to enable SSH client rsa public key')
            logBuff = 'The device of system mac %s, ESN %s and IP %s fails to enable the SSH client rsa public key.' %(g_sys_info['mac'], g_sys_info['esn'], g_ip_addr)
        else:
            logging.info('Failed to disable SSH client rsa public key')
            logBuff = 'The device of system mac %s, ESN %s and IP %s fails to disable the SSH client rsa public key.' %(g_sys_info['mac'], g_sys_info['esn'], g_ip_addr)
        ztp_log(logBuff, ops.ERROR)
        return ERR
    logging.info('Success to set SSH client rsa public key')
    return OK

def get_addr_by_hostname_v6(ops_conn, host, addr_type = '2'):
    """Translate a host name to IPv6 address format. The IPv4 address is returned as a string."""
    uri = "/dns/dnsNameResMultiIp"
    str_temp = string.Template(
'''<?xml version="1.0" encoding="UTF-8"?>
<dnsNameResMultiIp>
    <host>$hostname</host>
    <addrType>$addtype</addrType>
    <ipv6Addr></ipv6Addr>
</dnsNameResMultiIp>
''')
    req_data = str_temp.substitute(addtype = addr_type, hostname = host)
    cmd = "ping ipv6 {}".format(host)
    _ops = ops.ops()
    handle, err_desp = _ops.cli.open()
    _ops.cli.execute(handle,cmd, None)
    _ops.cli.close(handle)
    ret, _, rsp_data = ops_conn.get(uri, req_data)
    if ret != http.client.OK:
        raise OPIExecError('Failed to get address by host name')
    root_elem = etree.fromstring(rsp_data)
    namespaces = {'vrp' : 'http://www.huawei.com/netconf/vrp'}
    uri = 'data' + uri.replace('/', '/vrp:') + '/vrp:'
    elem = root_elem.find(uri + "ipv6Addr", namespaces)
    if elem is None:
        raise OPIExecError('Failed to get IP address by host name')

    return elem.text

def get_v6_serverip_byurl(ops_conn, url):
    url_tuple = urlparse(url)
    if '[' in url:
        server_ip = url_tuple.hostname
    else:
        server_ip = get_addr_by_hostname_v6(ops_conn, url_tuple.hostname)
        logging.info('get_addr_by_hostname ,server_ip: %s', server_ip)
    return server_ip

def get_v6_userandpwd_byurl(url):
    url_tuple = urlparse(url)
    logging.info(type(url_tuple),url_tuple)
    if url_tuple.netloc == '':
        raise OPIExecError('Failed to get user and pwd by host name')

    serverinfo = url_tuple.netloc
    ipbeg = serverinfo.rfind("@")
    userinfo = serverinfo[0:ipbeg]

    str_list = [f for f in userinfo.split(":")]
    if len(str_list) != 2 or str_list[1] == '':
        raise OPIExecError('Failed to get address by host name')

    user = str_list[0]
    pwd = str_list[1]
    logging.info("ipv6 bootfile user is %s password is %s" % (user, pwd))
    return user, pwd


def _del_rsa_peer_key(ops_conn, key_name):
    """Delete RSA peer key configuration"""
    logging.info("Delete RSA peer key %s", key_name)
    uri = "/rsa/rsaPeerKeys/rsaPeerKey"
    root_elem = etree.Element('rsaPeerKey')
    etree.SubElement(root_elem, 'keyName').text = key_name
    req_data = etree.tostring(root_elem, "UTF-8")
    try:
        ret, _, _ = ops_conn.delete(uri, req_data)
        if ret != http.client.OK:
            raise OPIExecError('Failed to delete RSA peer key')

    except Exception as reason:
        logging.error(reason)

def _del_sshc_rsa_key(ops_conn, server_name, key_type = 'RSA'):
    """Delete SSH client RSA key configuration"""
    logging.debug("Delete SSH client RSA key for %s", server_name)
    uri = "/sshc/sshCliKeyCfgs/sshCliKeyCfg"
    root_elem = etree.Element('sshCliKeyCfg')
    etree.SubElement(root_elem, 'serverName').text = server_name
    etree.SubElement(root_elem, 'pubKeyType').text = key_type
    req_data = etree.tostring(root_elem, "UTF-8")
    try:
        ret, _, _ = ops_conn.delete(uri, req_data)
        if ret != http.client.OK:
            raise OPIExecError('Failed to delete SSH client RSA key')

    except Exception as reason:
        logging.error(reason)

    _del_rsa_peer_key(ops_conn, server_name)

def _set_sshc_first_time(ops_conn, switch):
    """Set SSH client attribute of authenticating user for the first time access"""
    if switch not in ['Enable', 'Disable']:
        return ERR

    logging.info('Set SSH client first-time enable switch = %s', switch)
    uri = "/sshc/sshClient"
    str_temp = string.Template(
'''<?xml version="1.0" encoding="UTF-8"?>
<sshClient>
    <firstTimeEnable>$enable</firstTimeEnable>
</sshClient>
''')
    req_data = str_temp.substitute(enable = switch)
    ret, _, _ = ops_conn.set(uri, req_data)
    if ret != http.client.OK:
        if switch == 'Enable':
            raise OPIExecError('Failed to enable SSH client first-time')
        else:
            raise OPIExecError('Failed to disable SSH client first-time')

    return OK

def _tftp_download_file(ops_conn, url, local_path):
    """Download file using TFTP."""
    logging.info('TFTP download "%s".', os.path.basename(url))
    uri = "/tftpc/tftpcTransferFiles/tftpcTransferFile"
    str_temp = string.Template(
'''<?xml version="1.0" encoding="UTF-8"?>
<tftpcTransferFile>
    <serverIpv4Address>$serverIp</serverIpv4Address>
    <commandType>get_cmd</commandType>
    <localFileName>$localPath</localFileName>
    <remoteFileName>$remotePath</remoteFileName>
</tftpcTransferFile>
''')
    url_tuple = urlparse(url)
    if re.match(r"\d+\.\d+\.\d+\.\d+", url_tuple.hostname):
        server_ip = url_tuple.hostname
    else:
        server_ip = get_addr_by_hostname(ops_conn, url_tuple.hostname)
    req_data = str_temp.substitute(serverIp = server_ip, remotePath = url_tuple.path[1:], localPath = local_path)
    ret, _, _ = ops_conn.create(uri, req_data)
    if ret != http.client.OK:
        print(('Failed to download file "%s" using TFTP' % os.path.basename(local_path)))
        logBuff = 'The device of system mac %s, ESN %s and IP %s fails to download the file using TFTP. (FileName=%s)' %(g_sys_info['mac'], g_sys_info['esn'], g_ip_addr, os.path.basename(local_path))
        ztp_log(logBuff, ops.ERROR)
        sys.stdout.flush()
        return ERR

    return OK

def _tftp_download_file_v6(ops_conn, url, local_path):
    """Download file using TFTP."""
    logging.info('TFTP download "%s".', os.path.basename(url))
    uri = "/tftpc/tftpcTransferFiles/tftpcTransferFile"
    str_temp = string.Template(
'''<?xml version="1.0" encoding="UTF-8"?>
<tftpcTransferFile>
    <serverIpv6Address>$serverIp</serverIpv6Address>
    <commandType>get_cmd</commandType>
    <localFileName>$localPath</localFileName>
    <remoteFileName>$remotePath</remoteFileName>
</tftpcTransferFile>
''')

    url_tuple = urlparse(url)
    server_ip = get_v6_serverip_byurl(ops_conn, url)
    req_data = str_temp.substitute(serverIp = server_ip, remotePath = url_tuple.path[1:], localPath = local_path)
    ret, _, _ = ops_conn.create(uri, req_data)
    if ret != http.client.OK:
        print(('Failed to download file "%s" using TFTP' % os.path.basename(local_path)))
        logBuff = 'The device of system mac %s, ESN %s and IP %s fails to download the file using TFTP. (FileName=%s)' %(g_sys_info['mac'], g_sys_info['esn'], g_ip_addr, os.path.basename(local_path))
        ztp_log(logBuff, ops.ERROR)
        sys.stdout.flush()
        return ERR

    return OK

def _ftp_download_file(ops_conn, url, local_path):
    """Download file using FTP."""
    logging.info('FTP download "%s".', os.path.basename(url))
    uri = "/ftpc/ftpcTransferFiles/ftpcTransferFile"
    str_temp = string.Template(
'''<?xml version="1.0" encoding="UTF-8"?>
<ftpcTransferFile>
    <serverIpv4Address>$serverIp</serverIpv4Address>
    <commandType>get</commandType>
    <userName>$username</userName>
    <password>$password</password>
    <localFileName>$localPath</localFileName>
    <remoteFileName>$remotePath</remoteFileName>
</ftpcTransferFile>
''')
    url_tuple = urlparse(url)
    if re.match(r"\d+\.\d+\.\d+\.\d+", url_tuple.hostname):
        server_ip = url_tuple.hostname
    else:
        server_ip = get_addr_by_hostname(ops_conn, url_tuple.hostname)
    req_data = str_temp.substitute(serverIp = server_ip, username = url_tuple.username, password = url_tuple.password,
                                   remotePath = url_tuple.path[1:], localPath = local_path)
    ret, _, _ = ops_conn.create(uri, req_data)
    if ret != http.client.OK:
        print(('Failed to download file "%s" using FTP' % os.path.basename(local_path)))
        logBuff = 'The device of system mac %s, ESN %s and IP %s fails to download the file using FTP. (FileName=%s)' %(g_sys_info['mac'], g_sys_info['esn'], g_ip_addr, os.path.basename(local_path))
        ztp_log(logBuff, ops.ERROR)
        sys.stdout.flush()
        return ERR

    return OK

def _ftp_download_file_v6(ops_conn, url, local_path):
    """Download file using FTP."""
    logging.info('FTP download "%s".', os.path.basename(url))
    uri = "/ftpc/ftpcTransferFiles/ftpcTransferFile"
    str_temp = string.Template(
'''<?xml version="1.0" encoding="UTF-8"?>
<ftpcTransferFile>
    <serverIpv6Address>$serverIp</serverIpv6Address>
    <commandType>get</commandType>
    <userName>$username</userName>
    <password>$password</password>
    <localFileName>$localPath</localFileName>
    <remoteFileName>$remotePath</remoteFileName>
</ftpcTransferFile>
''')
    url_tuple = urlparse(url)
    server_ip = get_v6_serverip_byurl(ops_conn, url)
    req_data = str_temp.substitute(serverIp = server_ip, username = url_tuple.username, password = url_tuple.password,
                                   remotePath = url_tuple.path[1:], localPath = local_path)
    logging.info(req_data)
    ret, _, res_data = ops_conn.create(uri, req_data)
    logging.info(res_data)
    if ret != http.client.OK:
        print(('Failed to download file "%s" using FTP' % os.path.basename(local_path)))
        logBuff = 'The device of system mac %s, ESN %s and IP %s fails to download the file using FTP. (FileName=%s)' %(g_sys_info['mac'], g_sys_info['esn'], g_ip_addr, os.path.basename(local_path))
        ztp_log(logBuff, ops.ERROR)
        sys.stdout.flush()
        return ERR

    return OK

def _sftp_download_file_v6(ops_conn, url, local_path):
    """Download file using SFTP."""
    _set_sshc_first_time(ops_conn, 'Enable')

    logging.info('SFTP download "%s".', os.path.basename(url))
    uri = "/sshc/sshcConnects/sshcConnect"
    str_temp = string.Template(
'''<?xml version="1.0" encoding="UTF-8"?>
<sshcConnect>
    <HostAddrIPv6>$serverIp</HostAddrIPv6>
    <commandType>get</commandType>
    <userName>$username</userName>
    <password>$password</password>
    <serverPort>$port</serverPort>
    <localFileName>$localPath</localFileName>
    <remoteFileName>$remotePath</remoteFileName>
    <identityKey>ssh-rsa</identityKey>
    <transferType>SFTP</transferType>
</sshcConnect>
''')
    url_tuple = urlparse(url)
    server_ip = get_v6_serverip_byurl(ops_conn, url)

    if url_tuple.port == None:
        server_port = '22'
    elif url_tuple.port > 1024 and url_tuple.port < 65536:
        server_port = url_tuple.port
    req_data = str_temp.substitute(serverIp = server_ip, username = url_tuple.username, password = url_tuple.password,
                                   remotePath = url_tuple.path[1:], localPath = local_path, port = server_port)
    ret, _, _ = ops_conn.create(uri, req_data)
    if ret != http.client.OK:
        print(('Failed to download file "%s" using SFTP' % os.path.basename(local_path)))
        logging.warning('fails to download the file using SFTP. (FileName=%s)', os.path.basename(local_path))
        ret = ERR
    else:
        ret = OK

    _del_sshc_rsa_key(ops_conn, server_ip)
    _set_sshc_first_time(ops_conn, 'Disable')
    return ret

def _sftp_sha1_download_file_v6(ops_conn, url, local_path):
    """Download file using SFTP-SHA1."""
    _set_sshc_sha1_enable(ops_conn, "true")
    ret = _sftp_download_file_v6(ops_conn, url, local_path)
    _set_sshc_sha1_enable(ops_conn, "false")
    return ret

def _sftp_download_file(ops_conn, url, local_path):
    """Download file using SFTP."""
    _set_sshc_first_time(ops_conn, 'Enable')

    logging.info('SFTP download "%s" to "%s".', url, local_path)
    uri = "/sshc/sshcConnects/sshcConnect"
    str_temp = string.Template(
'''<?xml version="1.0" encoding="UTF-8"?>
<sshcConnect>
    <HostAddrIPv4>$serverIp</HostAddrIPv4>
    <commandType>get</commandType>
    <userName>$username</userName>
    <password>$password</password>
    <localFileName>$localPath</localFileName>
    <remoteFileName>$remotePath</remoteFileName>
    <identityKey>ssh-rsa</identityKey>
    <transferType>SFTP</transferType>
</sshcConnect>
''')
    url_tuple = urlparse(url)
    if re.match(r"\d+\.\d+\.\d+\.\d+", url_tuple.hostname):
        server_ip = url_tuple.hostname
    else:
        server_ip = get_addr_by_hostname(ops_conn, url_tuple.hostname)
    req_data = str_temp.substitute(serverIp = server_ip, username = url_tuple.username, password = url_tuple.password,
                                   remotePath = url_tuple.path[1:], localPath = local_path)
    ret, _, _ = ops_conn.create(uri, req_data)
    if ret != http.client.OK:
        print(('Failed to download file "%s" using SFTP' % os.path.basename(local_path)))
        sys.stdout.flush()
        ret = ERR
    else:
        ret = OK

    _del_sshc_rsa_key(ops_conn, server_ip)
    _set_sshc_first_time(ops_conn, 'Disable')
    return ret

def _sftp_sha1_download_file(ops_conn, url, local_path):
    """Download file using SFTP-SHA1."""
    _set_sshc_sha1_enable(ops_conn, "true")
    ret = _sftp_download_file(ops_conn, url, local_path)
    _set_sshc_sha1_enable(ops_conn, "false")
    return ret

def _http_download_file(ops_conn, url, local_path):
    """Download file using HTTP."""
    logging.info('HTTP download "%s".', os.path.basename(url))
    uri = "/HTTPC/httpcTransFiles/httpcTransFile"
    str_temp = string.Template(
'''<?xml version="1.0" encoding="UTF-8"?>
<httpcTransFile>
    <OperationType>download</OperationType>
    <FileUrl>$fileUrl</FileUrl>
    <FileFullPath>$fileFullPath</FileFullPath>
    <IsOverSsl>false</IsOverSsl>
</httpcTransFile>
''')
    url_tuple = urlparse(url)
    if not re.match(r"\d+\.\d+\.\d+\.\d+", url_tuple.hostname):
        netloc = get_addr_by_hostname(ops_conn, url_tuple.hostname)
        if url_tuple.port:
            netloc += ':' + str(url_tuple.port)
        url = urlunparse((url_tuple.scheme, netloc, url_tuple.path, url_tuple.params, url_tuple.query,
                          url_tuple.fragment))
    dst_file_path = "%s/%s" % (os.getcwd(), os.path.basename(url))
    dst_file_path = os.path.abspath(dst_file_path)
    logging.info('HTTP download destination file=%s.', dst_file_path)
    req_data = str_temp.substitute(fileUrl = url, fileFullPath = local_path)
    ret, _, _ = ops_conn.create(uri, req_data)
    if ret != http.client.OK:
        logBuff = 'The device of system mac %s, ESN %s and IP %s fails to download the file using HTTP. (FileName=%s)' %(g_sys_info['mac'], g_sys_info['esn'], g_ip_addr, os.path.basename(local_path))
        ztp_log(logBuff, ops.ERROR)
        sys.stdout.flush()
        return ERR

    return OK

def _http_download_file_v6(ops_conn, url, local_path):
    """Download file using HTTP."""
    logging.info('HTTP download "%s".', os.path.basename(url))
    uri = "/HTTPC/httpcTransFiles/httpcTransFile"
    str_temp = string.Template(
'''<?xml version="1.0" encoding="UTF-8"?>
<httpcTransFile>
    <OperationType>download</OperationType>
    <FileUrl>$fileUrl</FileUrl>
    <FileFullPath>$fileFullPath</FileFullPath>
    <IsOverSsl>false</IsOverSsl>
</httpcTransFile>
''')
    url_tuple = urlparse(url)
    server_ip = get_v6_serverip_byurl(ops_conn, url)

    if url_tuple.port == None:
        server_port = '80'
    elif url_tuple.port > 1024 and url_tuple.port < 65536:
        server_port = url_tuple.port
    else :
        logging.error('DHCP server set the wrong value of http port : %s', url_tuple.port)
        server_port = url_tuple.port

    if "]" in server_ip:
        server_ip += ':' + str(server_port)
    else:
        server_ip = '[' + server_ip + ']' + ':' + str(server_port)
    url = urlunparse((url_tuple.scheme, server_ip, url_tuple.path, url_tuple.params, url_tuple.query,
                    url_tuple.fragment))
    dst_file_path = "%s/%s" % (os.getcwd(), os.path.basename(url))
    dst_file_path = os.path.abspath(dst_file_path)
    logging.info('HTTP download destination file=%s.', dst_file_path)
    req_data = str_temp.substitute(fileUrl = url, fileFullPath = local_path)
    ret, _, _ = ops_conn.create(uri, req_data)
    if ret != http.client.OK:
        logBuff = 'The device of system mac %s, ESN %s and IP %s fails to download the file using HTTP. (FileName=%s)' %(g_sys_info['mac'], g_sys_info['esn'], g_ip_addr, os.path.basename(local_path))
        ztp_log(logBuff, ops.ERROR)
        sys.stdout.flush()
        return ERR

    return OK

def _usb_download_file(ops_conn, url, local_path):
    """Download file using usb"""
    logging.info('USB download "%s" to "%s".', url, local_path)

    url_tuple = urlparse(url, allow_fragments=False)
    src_path = url_tuple.path[1:]
    try:
        copy_file(ops_conn, src_path, local_path)
    except:
        print(('Failed to download file "%s" using USB' % os.path.basename(local_path)))
        sys.stdout.flush()
        return ERR
    return OK

def download_file(ops_conn, url, local_path, retry_times = 0):
    """Download file, support SFTP.

    sftp://[username[:password]@]hostname[:port]/path

    Args:
      ops_conn: OPS connection instance
      url: URL of remote file
      local_path: local path to put the file

    Returns:
        A integer of return code
    """
    url_tuple = urlparse(url)
    print(("Info: Download %s to %s" % (url_tuple.path[1:], local_path)))
    sys.stdout.flush()
    is_ipv6 = check_is_ipv6_protocal(ops_conn)
    if is_ipv6 == True:
        func_dict = {'tftp': _tftp_download_file_v6,
                     'ftp':  _ftp_download_file_v6,
                    'sftp': _sftp_download_file_v6,
                    'http': _http_download_file_v6,
                    'file': _usb_download_file,
                    'sftp-sha1': _sftp_sha1_download_file_v6}
    else:
        func_dict = {'tftp': _tftp_download_file,
                     'ftp':  _ftp_download_file,
                    'sftp': _sftp_download_file,
                    'http': _http_download_file,
                    'file': _usb_download_file,
                    'sftp-sha1': _sftp_sha1_download_file}
    scheme = url_tuple.scheme
    if scheme not in list(func_dict.keys()):
        raise ZTPErr('Unknown file transfer scheme %s' % scheme)

    ret = OK
    cnt = 0
    while (cnt < 1 + retry_times):
        if cnt:
            print('Retry downloading...')
            sys.stdout.flush()
            logging.info('Retry downloading...')
        ret = func_dict[scheme](ops_conn, url, local_path)
        if ret is OK:
            break
        cnt += 1

    if ret is not OK:
        return ERR

    return OK


class StartupInfo(object):
    """Startup configuration information

    image: startup system software
    config: startup saved-configuration file
    patch: startup patch package
    """
    def __init__(self, image = None, config = None, patch = None):
        self.image = image
        self.config = config
        self.patch = patch

class Startup(object):
    """Startup configuration information

    current: current startup configuration
    next: current next startup configuration
    """
    def __init__(self, ops_conn):
        self.ops_conn = ops_conn
        self.current, self.next = self._get_startup_info()

    def _get_startup_info(self):
        """Get the startup information."""
        logging.info("Get the startup information...")
        uri = "/cfg/startupInfos/startupInfo"
        req_data = '''<?xml version="1.0" encoding="UTF-8"?>
<startupInfo>
    <position/>
    <configedSysSoft/>
    <curSysSoft/>
    <nextSysSoft/>
    <curStartupFile/>
    <nextStartupFile/>
    <curPatchFile/>
    <nextPatchFile/>
</startupInfo>'''

        cnt = 0
        while (cnt < MAX_TIMES_GET_STARTUP):
            ret, _, rsp_data = self.ops_conn.get(uri, req_data)
            if ret != http.client.OK or rsp_data == '':
                cnt += 1
                logging.warning('Failed to get the startup information')
                continue

            root_elem = etree.fromstring(rsp_data)
            namespaces = {'vrp' : 'http://www.huawei.com/netconf/vrp'}
            mpath = 'data' + uri.replace('/', '/vrp:')  # match path
            nslen = len(namespaces['vrp'])
            elem = root_elem.find(mpath, namespaces)
            if elem is not None:
                break
            logging.warning('No query result while getting startup info')
            sleep(GET_STARTUP_INTERVAL)     # sleep to wait for system ready when no query result
            cnt += 1

        if elem is None:
            raise OPIExecError('Failed to get the startup information')

        current = StartupInfo()     # current startup info
        curnext = StartupInfo()     # next startup info
        for child in elem:
            tag = child.tag[nslen + 2:]       # skip the namespace, '{namespace}text'
            if tag == 'curSysSoft':
                current.image = child.text
            elif tag == 'nextSysSoft':
                curnext.image = child.text
            elif tag == 'curStartupFile' and child.text != 'NULL':
                current.config = child.text
            elif tag == 'nextStartupFile' and child.text != 'NULL':
                curnext.config = child.text
            elif tag == 'curPatchFile' and child.text != 'NULL':
                current.patch = child.text
            elif tag == 'nextPatchFile' and child.text != 'NULL':
                curnext.patch = child.text
            else:
                continue

        return current, curnext

    def _set_startup_image_file(self, file_path):
        """Set the next startup system software"""
        logging.info("Set the next startup system software to %s...", file_path)
        uri = "/sum/startupbymode"
        str_temp = string.Template(
'''<?xml version="1.0" encoding="UTF-8"?>
<startupbymode>
    <softwareName>$fileName</softwareName>
    <mode>STARTUP_MODE_ALL</mode>
</startupbymode>
''')
        req_data = str_temp.substitute(fileName = file_path)
        # it is a action operation, so use create for HTTP POST
        ret, _, _ = self.ops_conn.create(uri, req_data)
        if ret != http.client.OK:
            raise OPIExecError("Failed to set startup system software")

    def _set_startup_config_file(self, file_path):
        """Set the next startup saved-configuration file"""
        logging.info("Set the next startup saved-configuration file to %s...", file_path)
        uri = "/cfg/setStartup"
        str_temp = string.Template(
'''<?xml version="1.0" encoding="UTF-8"?>
<setStartup>
    <fileName>$fileName</fileName>
</setStartup>
''')
        req_data = str_temp.substitute(fileName = file_path)
        # it is a action operation, so use create for HTTP POST
        ret, _, rsp_data = self.ops_conn.create(uri, req_data)
        if ret != http.client.OK:
            print("Set startup configfile failed.")
            root_elem = etree.fromstring(rsp_data)
            for rpc_error in root_elem.findall("rpc-error"):
                err_tag = rpc_error.find("error-app-tag").text
                err_msg = rpc_error.find("error-message").text
                print("%s" % (err_msg))
            raise OPIExecError(err_msg)

    def _del_startup_config_file(self):
        """Delete startup config file"""
        logging.info("Delete the next startup config file...")
        uri = "/cfg/clearStartup"
        req_data = '''<?xml version="1.0" encoding="UTF-8"?>
<clearStartup>
</clearStartup>
'''
        # it is a action operation, so use create for HTTP POST
        ret, _, _ = self.ops_conn.create(uri, req_data)
        if ret != http.client.OK:
            raise OPIExecError("Failed to delete startup configuration file")

    def _set_startup_patch_file(self, file_path):
        """Set the next startup patch file"""
        logging.info("Set the next startup patch file to %s...", file_path)
        uri = "/patch/startup"
        str_temp = string.Template(
'''<?xml version="1.0" encoding="UTF-8"?>
<startup>
    <packageName>$fileName</packageName>
</startup>
''')
        req_data = str_temp.substitute(fileName = file_path)
        # it is a action operation, so use create for HTTP POST
        ret, _, _ = self.ops_conn.create(uri, req_data)
        if ret != http.client.OK:
            raise OPIExecError("Failed to set startup patch file")

    def _check_patch_operation_schedule(self, patch_phase):
        uri = "/patch/patchOperationSchedule"
        str_temp = string.Template(
            '''<?xml version="1.0" encoding="UTF-8"?>
                <patchOperationSchedule>
                    <patchPhase>$patchPhase</patchPhase>
                    <curStatus/>
                    <schedule/>
                </patchOperationSchedule>
            ''')

        req_data = str_temp.substitute(patchPhase = patch_phase)
        ret, _, rsp_data = self.ops_conn.get(uri, req_data)
        logging.info(rsp_data)
        if ret != http.client.OK:
            raise OPIExecError('Failed to get patch operation schedule')
            logBuff = 'Failed to get patch operation schedule'
            ztp_log(logBuff, ops.ERROR)

        root_elem = etree.fromstring(rsp_data)
        namespaces = {'vrp' : 'http://www.huawei.com/netconf/vrp'}
        uri = 'data' + uri.replace('/', '/vrp:') + '/vrp:'
        elem = root_elem.find(uri + "schedule", namespaces)
        if elem is None:
            raise OPIExecError('Failed to get the current working directory for no "schedule" element')
            logBuff = 'Failed to obtain the working dictionary because the schedule field is not displayed.'
            ztp_log(logBuff, ops.ERROR)

        elem1 = root_elem.find(uri + "curStatus", namespaces)
        if elem1 is None:
            raise OPIExecError('Failed to get the current working directory for no "curStatus" element')
            logBuff = 'Failed to obtain the working dictionary because the curStatus field is not displayed.'
            ztp_log(logBuff, ops.ERROR)

        return elem.text, elem1.text

    def _check_patch_and_mod_load_schedule(self, file_type, patch_phase):
        if file_type == "patch":
            success_status = "patchOperationSuccess"
        elif file_type == "mod":
            success_status = "modOperationSuccess"

        check_times = 0
        while check_times < 30:
            schedule, cur_status = self._check_patch_operation_schedule(patch_phase)
            if int(schedule) == 100:
                break
            check_times += 1
            sleep(10)
        if int(schedule) != 100 or cur_status != success_status:
            raise OPIExecError('{} operation {} failed!'.format(file_type, patch_phase))
            logBuff = '%s operation {} failed, now end ztp proc.' %(file_type, patch_phase)
            ztp_log(logBuff, ops.ERROR)

    def _get_cur_stack_member_id(self):
        """rest api: Get current stack member id"""

        logging.info("Get current stack member ID...")
        uri = "/stack/stackMemberInfos/stackMemberInfo"
        req_data =  \
            '''<?xml version="1.0" encoding="UTF-8"?>
            <stackMemberInfo>
                    <memberID></memberID>
                </stackMemberInfo>
            '''
        ret, _, rsp_data = self.ops_conn.get(uri, req_data)
        if ret != http.client.OK or rsp_data == '':
            raise OPIExecError('Failed to get current stack member id, rsp not ok')

        root_elem = etree.fromstring(rsp_data)
        namespaces = {'vrp' : 'http://www.huawei.com/netconf/vrp'}
        uri = 'data' + uri.replace('/', '/vrp:') + '/vrp:'
        elem = root_elem.find(uri + "memberID", namespaces)
        if elem is None:
            raise OPIExecError('Failed to get the current stack member id for no "memberID" element')

        return elem.text

    def _set_stack_member_id(self, file_path, esn):
        """Set the next stack member ID"""

        def get_stackid_from_file(fname, esn):
            """parse esn_id.txt file and get stack id according to esn num
            format of esn_stackid file is like below:

            sn              Irf group              Irf number
            Sdddg              100                         1
            Sddde              100                         2
            """
            # fname must exist, guaranteed by caller
            fname = os.path.basename(fname)
            with open(fname, 'r') as item:
                for line in item:
                    token = line.strip('[\r\n]')
                    token = token.split()
                    if token[0] == esn:
                        return token[2]
            return None

        logging.info('Set the next stack member ID, filename %s', file_path)
        uri = "/stack/stackMemberInfos/stackMemberInfo"
        str_temp = string.Template(
            '''<?xml version="1.0" encoding="UTF-8"?>
                <stackMemberInfo>
                    <memberID>$curmemberid</memberID>
                    <nextMemberID>$memberid</nextMemberID>
                </stackMemberInfo>
            ''')

        cur_memid = self._get_cur_stack_member_id()
        next_memid = get_stackid_from_file(file_path, esn)
        if not next_memid:
            logging.error('Failed to get stack id from %s, esn %s', file_path, esn)
            return

        req_data = str_temp.substitute(curmemberid = cur_memid, memberid = next_memid)
        ret, _, _ = self.ops_conn.set(uri, req_data)
        if ret != http.client.OK:
            raise OPIExecError('Failed to set stack id {}'.format(next_memid))

        return OK

    def _reset_stack_member_id(self):
        """rest api: reset stack member id"""

        logging.info('Reset the next stack member ID')
        uri = "/stack/stackMemberInfos/stackMemberInfo"
        req_data = \
            '''<?xml version="1.0" encoding="UTF-8"?>
                <stackMemberInfo>
                    <memberID>1</memberID>
                    <nextMemberID>1</nextMemberID>
                </stackMemberInfo>
            '''

        ret, _, _ = self.ops_conn.set(uri, req_data)
        if ret != http.client.OK:
            raise OPIExecError('Failed to reset stack id ')

        return OK

    def _reset_startup_patch_file(self):
        """Rest patch file for system to startup"""
        logging.info("Reset the next startup patch file...")
        uri = "/patch/resetpatch"
        req_data = '''<?xml version="1.0" encoding="UTF-8"?>
<resetpatch>
</resetpatch>
'''
        # it is a action operation, so use create for HTTP POST
        ret, _, _ = self.ops_conn.create(uri, req_data)
        if ret != http.client.OK:
            raise OPIExecError('Failed to reset patch')

    def reset_startup_info(self, slave):
        """Reset startup info and delete the downloaded files"""
        logging.info("Reset the next startup information...")
        _, configured = self._get_startup_info()

        # 1. Reset next startup config file and delete it
        try:
            if configured.config != self.next.config:
                if self.next.config is None:
                    self._del_startup_config_file()
                else:
                    self._set_startup_config_file(self.next.config)
        except Exception as reason:
            logging.error(reason)

        # 2. reset stack member id
        try:
            self._reset_stack_member_id()
        except Exception as reason:
            logging.error(reason)

        # 3. Reset next startup patch file
        try:
            if configured.patch != self.next.patch:
                if self.next.patch is None:
                    self._reset_startup_patch_file()
                    self._check_patch_and_mod_load_schedule("patch", "patch-clrstartup")
                else:
                    self._set_startup_patch_file(self.next.patch)
                    self._check_patch_and_mod_load_schedule("patch", "patch-startup")
        except Exception as reason:
            logging.error(reason)

        # 4. Reset next startup system software and delete it
        try:
            if configured.image != self.next.image:
                self._set_startup_image_file(self.next.image)
        except Exception as reason:
            logging.error(reason)

    def set_startup_info(self, image_file, config_file, patch_file, memid_file, slave, esn_str):
        """Set the next startup information."""
        logging.info("Set the next startup information...")
        file_list = [image_file, config_file, patch_file, memid_file]
        # 1. Set next startup config file
        if config_file is not None:
            try:
                self._set_startup_config_file(config_file)
            except Exception as reason:
                logging.error(reason)
                self.reset_startup_info(slave)
                del_file_list_all(self.ops_conn, file_list, slave)
                raise

        # 2. Set next member id
        if memid_file is not None:
            try:
                self._set_stack_member_id(memid_file, esn_str)
            except Exception as reason:
                logging.error(reason)
                self.reset_startup_info(slave)
                del_file_list_all(self.ops_conn, file_list, slave)
                raise

        # 3. Set next startup patch file
        if patch_file is not None:
            try:
                self._set_startup_patch_file(patch_file)
                self._check_patch_and_mod_load_schedule("patch", "patch-startup")
            except Exception as reason:
                logging.error(reason)
                self.reset_startup_info(slave)
                del_file_list_all(self.ops_conn, file_list, slave)
                raise

        # 4. Set next startup system software
        if image_file is not None:
            try:
                self._set_startup_image_file(image_file)
            except Exception as reason:
                logging.error(reason)
                self.reset_startup_info(slave)
                del_file_list_all(self.ops_conn, file_list, slave)
                raise

def get_cwd(ops_conn):
    """Get the full filename of the current working directory"""
    logging.info("Get the current working directory...")
    uri = "/vfm/pwds/pwd"
    req_data =  \
'''<?xml version="1.0" encoding="UTF-8"?>
<pwd>
    <dictionaryName/>
</pwd>
'''
    ret, _, rsp_data = ops_conn.get(uri, req_data)
    if ret != http.client.OK or rsp_data == '':
        raise OPIExecError('Failed to get the current working directory')

    root_elem = etree.fromstring(rsp_data)
    namespaces = {'vrp' : 'http://www.huawei.com/netconf/vrp'}
    uri = 'data' + uri.replace('/', '/vrp:') + '/vrp:'
    elem = root_elem.find(uri + "dictionaryName", namespaces)
    if elem is None:
        raise OPIExecError('Failed to get the current working directory for no "directoryName" element')

    return elem.text

def file_exist(ops_conn, file_path):
    """Returns True if file_path refers to an existing file, otherwise returns False"""
    uri = "/vfm/dirs/dir"
    str_temp = string.Template(
'''<?xml version="1.0" encoding="UTF-8"?>
<dir>
    <fileName>$fileName</fileName>
</dir>
''')
    req_data = str_temp.substitute(fileName = file_path)
    ret, _, rsp_data = ops_conn.get(uri, req_data)
    if ret != http.client.OK or rsp_data == '':
        raise OPIExecError('Failed to list information about the file "%s"' % file_path)

    root_elem = etree.fromstring(rsp_data)
    namespaces = {'vrp' : 'http://www.huawei.com/netconf/vrp'}
    uri = 'data' + uri.replace('/', '/vrp:') + '/vrp:'
    elem = root_elem.find(uri + "fileName", namespaces)
    if elem is None:
        return False

    return True

def del_file(ops_conn, file_path):
    """Delete a file permanently"""
    if file_path is None or file_path == '':
        return

    logging.info("Delete file %s permanently", file_path)
    uri = "/vfm/deleteFileUnRes"
    str_temp = string.Template(
'''<?xml version="1.0" encoding="UTF-8"?>
<deleteFileUnRes>
    <fileName>$filePath</fileName>
</deleteFileUnRes>
''')
    req_data = str_temp.substitute(filePath = file_path)
    try:
        # it is a action operation, so use create for HTTP POST
        ret, _, _ = ops_conn.create(uri, req_data)
        if ret != http.client.OK:
            raise OPIExecError('Failed to delete the file "%s" permanently' % file_path)

    except Exception as reason:
        logging.error(reason)

def del_file_noerror(ops_conn, file_path):
    """Delete a file permanently"""
    if file_path is None or file_path == '':
        return

    logging.info("Delete file %s permanently", file_path)
    uri = "/vfm/deleteFileUnRes"
    str_temp = string.Template(
'''<?xml version="1.0" encoding="UTF-8"?>
<deleteFileUnRes>
    <fileName>$filePath</fileName>
</deleteFileUnRes>
''')
    req_data = str_temp.substitute(filePath = file_path)
    try:
        # it is a action operation, so use create for HTTP POST
        ret, _, _ = ops_conn.create(uri, req_data)
        if ret != http.client.OK:
            logging.info("file not exist")

    except Exception as reason:
        logging.error(reason)        

def del_file_all(ops_conn, file_path, slave):
    """Delete a file permanently on all main boards"""
    if file_path:
        del_file(ops_conn, file_path)
        if slave:
            del_file(ops_conn, 'slave#' + file_path)

def del_file_list_all(ops_conn, file_list, slave):
    for file in file_list:
        del_file_all(ops_conn, file, slave)

def del_file_all_noerror(ops_conn, file_path, slave):
    """Delete a file permanently on all main boards"""
    if file_path:
        del_file_noerror(ops_conn, file_path)
        if slave:
            del_file_noerror(ops_conn, 'slave#' + file_path)

def del_file_list_all_noerror(ops_conn, file_list, slave):
    for file in file_list:
        del_file_all_noerror(ops_conn, file, slave)

def copy_file(ops_conn, src_path, dest_path):
    """Copy a file"""
    print(('Info: Copy file %s to %s...' % (src_path, dest_path)))
    sys.stdout.flush()
    logging.info('Copy file %s to %s...', src_path, dest_path)
    uri = "/vfm/copyFile"
    str_temp = string.Template(
'''<?xml version="1.0" encoding="UTF-8"?>
<copyFile>
    <srcFileName>$src</srcFileName>
    <desFileName>$dest</desFileName>
</copyFile>
''')
    req_data = str_temp.substitute(src = src_path, dest = dest_path)

    # it is a action operation, so use create for HTTP POST
    ret, _, _ = ops_conn.create(uri, req_data)
    if ret != http.client.OK:
        raise OPIExecError('Failed to copy "%s" to "%s"' % (src_path, dest_path))

def has_slave_mpu(ops_conn):
    """Whether device has slave MPU, returns a bool value"""
    logging.info("Test whether device has slave MPU...")
    uri = "/devm/phyEntitys"
    req_data =  \
'''<?xml version="1.0" encoding="UTF-8"?>
<phyEntitys>
    <phyEntity>
        <entClass>mpuModule</entClass>
        <entStandbyState/>
        <position/>
    </phyEntity>
</phyEntitys>
'''
    ret, _, rsp_data = ops_conn.get(uri, req_data)
    if ret != http.client.OK or rsp_data == '':
        raise OPIExecError('Failed to get the device slave information')

    root_elem = etree.fromstring(rsp_data)
    namespaces = {'vrp' : 'http://www.huawei.com/netconf/vrp'}
    uri = 'data' + uri.replace('/', '/vrp:') + '/vrp:'
    for entity in root_elem.findall(uri + 'phyEntity', namespaces):
        elem = entity.find("vrp:entStandbyState", namespaces)
        if elem is not None and elem.text == 'slave':
            return True

    return False

def get_system_info(ops_conn):
    """Get system info, returns a dict"""
    logging.info("Get the system information...")
    uri = "/system/systemInfo"
    req_data =  \
'''<?xml version="1.0" encoding="UTF-8"?>
<systemInfo>
    <productName/>
    <esn/>
    <mac/>
</systemInfo>
'''
    ret, _, rsp_data = ops_conn.get(uri, req_data)
    if ret != http.client.OK or rsp_data == '':
        raise OPIExecError('Failed to get the system information')

    sys_info = {}.fromkeys(('productName', 'esn', 'mac'))
    root_elem = etree.fromstring(rsp_data)
    namespaces = {'vrp' : 'http://www.huawei.com/netconf/vrp'}
    uri = 'data' + uri.replace('/', '/vrp:')
    nslen = len(namespaces['vrp'])
    elem = root_elem.find(uri, namespaces)
    if elem is not None:
        for child in elem:
            tag = child.tag[nslen + 2:]       # skip the namespace, '{namespace}esn'
            if tag in list(sys_info.keys()):
                sys_info[tag] = child.text

    return sys_info

def test_file_paths(image, config, patch, stack_memid, sha256_file, license_list_file):
    """Test whether argument paths are valid."""
    logging.info("Test whether argument paths are valid...")
    # check image file path
    file_name = os.path.basename(image)
    if file_name != '' and not file_name.lower().endswith('.cc'):
        print('Error: Invalid filename extension of system software')
        sys.stdout.flush()
        return False

    # check config file path
    file_name = os.path.basename(config)
    file_name = file_name.lower()
    _, ext = os.path.splitext(file_name)
    if file_name != '' and ext not in ['.cfg', '.zip', '.dat']:
        print('Error: Invalid filename extension of configuration file')
        sys.stdout.flush()
        return False

    # check patch file path
    file_name = os.path.basename(patch)
    if file_name != '' and not file_name.lower().endswith('.pat'):
        print('Error: Invalid filename extension of patch file')
        sys.stdout.flush()
        return False

    # check stack member id file path
    file_name = os.path.basename(stack_memid)
    if file_name != '' and not file_name.lower().endswith('.txt'):
        print('Error: Invalid filename extension of stack member ID file')
        sys.stdout.flush()
        return False

    # check sha256 file path
    file_name = os.path.basename(sha256_file)
    if file_name != '' and not file_name.lower().endswith('.txt'):
        print('Error: Invalid filename extension of sha256 file')
        sys.stdout.flush()
        return False

    # check license list file path
    file_name = os.path.basename(license_list_file)
    if file_name != '' and not file_name.lower().endswith('.xml'):
        print('Error: Invalid filename extension of license list file')
        sys.stdout.flush()
        return False

    return True

def sha256sum(fname, need_skip_first_line = False):
    """
    Calculate sha256 num for this file.
    """

    def read_chunks(fhdl):
        '''read chunks'''
        chunk = fhdl.read(8096)
        while chunk:
            yield chunk
            chunk = fhdl.read(8096)
        else:
            fhdl.seek(0)

    sha256_obj = hashlib.sha256()
    if isinstance(fname, str) and os.path.exists(fname):
        with open(fname, "rb") as fhdl:
            #skip the first line
            fhdl.seek(0)
            if need_skip_first_line:
                fhdl.readline()
            for chunk in read_chunks(fhdl):
                sha256_obj.update(chunk)
    elif fname.__class__.__name__ in ["StringIO", "StringO"] or isinstance(fname, file):
        for chunk in read_chunks(fname):
            sha256_obj.update(chunk)
    else:
        pass
    return sha256_obj.hexdigest()

def sha256_get_from_file(fname):
    """Get sha256 num form file, stored in first line"""

    with open(fname, "r") as fhdl:
        fhdl.seek(0)
        line_first = fhdl.readline()

    # if not match pattern, the format of this file is not supported
    if not re.match('^#sha256sum="[\\w]{64}"[\r\n]+$', line_first):
        return 'None'

    return line_first[12:76]

def sha256_check_with_first_line(fname):
    """Validate sha256 for this file"""

    fname = os.path.basename(fname)
    sha256_calc = sha256sum(fname, True)
    sha256_file = sha256_get_from_file(fname)

    if sha256_file.lower() != sha256_calc:
        logging.warning('sha256 check failed, file %s', fname)
        print(('sha256 checksum of the file "%s" is %s' % (fname, sha256_calc)))
        sys.stdout.flush()
        logging.warning('sha256 checksum of the file "%s" is %s', fname, sha256_calc)
        print(('sha256 checksum received from the file "%s" is %s' % (fname, sha256_file)))
        sys.stdout.flush()
        logging.warning('sha256 checksum received from the file "%s" is %s', fname, sha256_file)
        return False

    return True

def sha256_check_with_dic(sha256_dic, fname):
    """sha256 check with dic"""
    if fname not in sha256_dic:
        logging.info('sha256_dic does not has key %s, no need to do sha256 verification', fname)
        return True

    sha256sum_result = sha256sum(fname, False)
    if sha256_dic[fname] == sha256sum_result:
        return True

    print(('sha256 checksum of the file "%s" is %s' % (fname, sha256sum_result)))
    sys.stdout.flush()
    print(('sha256 checksum received for the file "%s" is %s' % (fname, sha256_dic[fname])))
    sys.stdout.flush()
    logging.warning('sha256 check failed, file %s', fname)
    logging.warning('sha256 checksum of the file "%s" is %s', fname, sha256sum_result)
    logging.warning('sha256 checksum received for the file "%s" is %s', fname, sha256_dic[fname])

    return False

def parse_sha256_file(fname):
    """parse sha256 file"""

    def read_line(fhdl):
        """read a line by loop"""
        line = fhdl.readline()
        while line:
            yield line
            line = fhdl.readline()
        else:
            fhdl.seek(0)

    sha256_dic = {}
    with open(fname, "r") as fhdl:
        for line in read_line(fhdl):
            line_spilt = line.split()
            if 2 != len(line_spilt):
                continue
            dic_tmp = {line_spilt[0]: line_spilt[1]}
            sha256_dic.update(dic_tmp)
    return sha256_dic

def verify_and_parse_sha256_file(fname):
    """
    vefiry data integrity of sha256 file and parse this file

    format of this file is like:
    ------------------------------------------------------------------
    #sha256sum="517cf194e2e1960429c6aedc0e4dba37"

    file-name              sha256
    conf_5618642831132.cfg c0ace0f0542950beaacb39cd1c3b5716
    ------------------------------------------------------------------
    """
    if not sha256_check_with_first_line(fname):
        return ERR, None
    return OK, parse_sha256_file(fname)

def check_parameter(aset):
    seq = ['&', '>', '<', '"', "'"]
    if aset:
        for c in seq:
             if c in aset:
                    return True
    return False

def check_filename(ops_conn):
    sys_info = get_system_info(ops_conn)
    url_tuple = urlparse(FILE_SERVER)
    if check_parameter(url_tuple.username) or check_parameter(url_tuple.password):
        raise ZTPErr('Invalid username or password, the name should not contain: '+'&'+' >'+' <'+' "'+" '.")
    file_name = os.path.basename(REMOTE_PATH_IMAGE.get(sys_info['productName'], ''))
    if file_name != '' and check_parameter(file_name):
       raise ZTPErr('Invalid filename of system software, the name should not contain: '+'&'+' >'+' <'+' "'+" '.")
    file_name = os.path.basename(REMOTE_PATH_CONFIG)
    if file_name != '' and check_parameter(file_name):
       raise ZTPErr('Invalid filename of configuration file, the name should not contain: '+'&'+' >'+' <'+' "'+" '.")
    file_name = os.path.basename(REMOTE_PATH_PATCH.get(sys_info['productName'], ''))
    if file_name != '' and check_parameter(file_name):
       raise ZTPErr('Invalid filename of patch file, the name should not contain: '+'&'+' >'+' <'+' "'+" '.")
    file_name = os.path.basename(REMOTE_PATH_MEMID)
    if file_name != '' and check_parameter(file_name):
       raise ZTPErr('Invalid filename of member ID file, the name should not contain: '+'&'+' >'+' <'+' "'+" '.")
    file_name = os.path.basename(REMOTE_PATH_SHA256)
    if file_name != '' and check_parameter(file_name):
       raise ZTPErr('Invalid filename of sha256 file, the name should not contain: '+'&'+' >'+' <'+' "'+" '.")
    file_name = os.path.basename(REMOTE_PATH_LICLIST)
    if file_name != '' and check_parameter(file_name):
       raise ZTPErr('Invalid filename of license list file, the name should not contain: '+'&'+' >'+' <'+' "'+" '.")
    return OK

def active_license(ops_conn, license_name):
    if license_name:
        uri = "/lcs/lcsActive"
        str_temp = string.Template(
'''<?xml version="1.0" encoding="UTF-8"?>
<lcsActive>
    <lcsFileName>$lcsFileName</lcsFileName>
</lcsActive>
''')
        req_data = str_temp.substitute(lcsFileName = license_name)
        ret, _, _ = ops_conn.create(uri, req_data)
        if ret != http.client.OK:
            logging.error('Error: Failed to active license.')
            return ERR
    return OK

def main_proc(ops_conn):
    """Main processing"""
    sys_info = get_system_info(ops_conn)    # Get system info, such as esn and system mac
    cwd = get_cwd(ops_conn)                 # Get the current working directory
    startup = Startup(ops_conn)
    slave = has_slave_mpu(ops_conn)         # Check whether slave MPU board exists or not
    chg_flag = False

    check_filename(ops_conn)

    # check remote file paths
    if not test_file_paths(REMOTE_PATH_IMAGE.get(sys_info['productName'], ''), REMOTE_PATH_CONFIG,
                           REMOTE_PATH_PATCH.get(sys_info['productName'], ''), REMOTE_PATH_MEMID, REMOTE_PATH_SHA256,
                           REMOTE_PATH_LICLIST):
        return ERR

    # download sha256 file first, used to verify data integrity of files which will be downloaded next
    local_path_sha256 = None
    file_path = REMOTE_PATH_SHA256
    if not file_path.startswith('/'):
        file_path = '/' + file_path
    file_name = os.path.basename(file_path)
    if file_name != '':
        url = FILE_SERVER + file_path
        local_path_sha256 = cwd + file_name
        ret = download_file(ops_conn, url, local_path_sha256, MAX_TIMES_RETRY_DOWNLOAD)
        if ret is ERR or not file_exist(ops_conn, file_name):
            print(('Error: Failed to download sha256 file "%s"' % file_name))
            sys.stdout.flush()
            raise ZTPErr('Failed to download file "%s"' % os.path.basename(url))
        print('Info: Download sha256 file successfully')
        sys.stdout.flush()
        ret, sha256_dic = verify_and_parse_sha256_file(file_name)
        # delete the file immediately
        del_file_all(ops_conn, local_path_sha256, None)
        if ret is ERR:
            print(('Error: sha256 check failed, file "%s"' % file_name))
            sys.stdout.flush()
            return ERR
    else:
        sha256_dic = {}

    # download configuration file
    local_path_config = None
    file_path = REMOTE_PATH_CONFIG
    if "%s" in file_path:
        file_path = REMOTE_PATH_CONFIG % sys_info['esn']
    if not file_path.startswith('/'):
        file_path = '/' + file_path
    file_name = os.path.basename(file_path)
    if file_name != '':
        url = FILE_SERVER + file_path
        local_path_config = cwd + file_name
        del_file_noerror(ops_conn, local_path_config)
        ret = download_file(ops_conn, url, local_path_config, MAX_TIMES_RETRY_DOWNLOAD)
        if ret is ERR or not file_exist(ops_conn, file_name):
            print(('Error: Failed to download configuration file "%s"' % file_name))
            sys.stdout.flush()
            raise ZTPErr('Failed to download file "%s"' % os.path.basename(url))
        print('Info: Download configuration file successfully')
        sys.stdout.flush()
        if not sha256_check_with_dic(sha256_dic, file_name):
            print(('Error: sha256 check failed, file "%s"' % file_name))
            sys.stdout.flush()
            del_file_all(ops_conn, local_path_config, slave)
            return ERR
        if slave:
            del_file_noerror(ops_conn, 'slave#' + local_path_config)
            copy_file(ops_conn, local_path_config, 'slave#' + local_path_config)
        chg_flag = True

    # download patch file
    local_path_patch = None
    file_path = REMOTE_PATH_PATCH.get(sys_info['productName'], '')
    if not file_path.startswith('/'):
        file_path = '/' + file_path
    file_name = os.path.basename(file_path)
    if startup.current.patch:
        cur_pat = os.path.basename(startup.current.patch).lower()
    else:
        cur_pat = ''
    if file_name != '' and file_name.lower() != cur_pat:
        url  = FILE_SERVER + file_path
        local_path_patch = cwd + file_name
        del_file_noerror(ops_conn, local_path_patch)
        ret = download_file(ops_conn, url, local_path_patch, MAX_TIMES_RETRY_DOWNLOAD)
        if ret is ERR or not file_exist(ops_conn, file_name):
            print(('Error: Failed to download patch file "%s"' % file_name))
            sys.stdout.flush()
            del_file_all(ops_conn, local_path_config, slave)
            raise ZTPErr('Failed to download file "%s"' % os.path.basename(url))
        print('Info: Download patch file successfully')
        sys.stdout.flush()
        if not sha256_check_with_dic(sha256_dic, file_name):
            print(('Error: sha256 check failed, file "%s"' % file_name))
            sys.stdout.flush()
            del_file_all(ops_conn, local_path_config, slave)
            del_file_all(ops_conn, local_path_patch, slave)
            return ERR
        if slave:
            del_file_noerror(ops_conn, 'slave#' + local_path_patch)
            copy_file(ops_conn, local_path_patch, 'slave#' + local_path_patch)
        chg_flag = True

    # download stack member ID file
    local_path_memid = None
    file_path = REMOTE_PATH_MEMID
    if not file_path.startswith('/'):
        file_path = '/' + file_path
    file_name = os.path.basename(file_path)
    if file_name != '':
        url = FILE_SERVER + file_path
        local_path_memid = cwd + file_name
        del_file_noerror(ops_conn,local_path_memid)
        ret = download_file(ops_conn, url, local_path_memid, MAX_TIMES_RETRY_DOWNLOAD)
        if ret is ERR or not file_exist(ops_conn, file_name):
            print(('Error: Failed to download system software "%s"' % file_name))
            sys.stdout.flush()
            file_list = [local_path_config, local_path_patch]
            del_file_list_all(ops_conn, file_list, slave)
            raise ZTPErr('Failed to download file "%s"' % os.path.basename(url))
        print('Info: Download stack member ID file successfully')
        sys.stdout.flush()
        if not sha256_check_with_dic(sha256_dic, file_name):
            print(('Error: sha256 check failed, file "%s"' % file_name))
            sys.stdout.flush()
            file_list = [local_path_config, local_path_patch, local_path_memid]
            del_file_list_all(ops_conn, file_list, slave)
            return ERR
        chg_flag = True
        #no need copy to slave board

    # download system software
    local_path_image = None
    file_path = REMOTE_PATH_IMAGE.get(sys_info['productName'], '')
    if not file_path.startswith('/'):
        file_path = '/' + file_path
    file_name = os.path.basename(file_path)
    if startup.current.image:
        cur_image = os.path.basename(startup.current.image).lower()
    else:
        cur_image = ''
    if file_name != '' and file_name.lower() != cur_image:
        url  = FILE_SERVER + file_path
        local_path_image = cwd + file_name
        del_file_noerror(ops_conn, local_path_image)
        ret = download_file(ops_conn, url, local_path_image, MAX_TIMES_RETRY_DOWNLOAD)
        if ret is ERR or not file_exist(ops_conn, file_name):
            if file_exist(ops_conn, file_name):
                del_file_all(ops_conn, local_path_image, slave)
            print(('Error: Failed to download system software "%s"' % file_name))
            sys.stdout.flush()
            file_list = [local_path_config, local_path_patch, local_path_memid]
            del_file_list_all(ops_conn, file_list, slave)
            raise ZTPErr('Failed to download file "%s"' % os.path.basename(url))
        print('Info: Download system software file successfully')
        sys.stdout.flush()
        if not sha256_check_with_dic(sha256_dic, file_name):
            print(('Error: sha256 check failed, file "%s"' % file_name))
            sys.stdout.flush()
            file_list = [local_path_config, local_path_patch, local_path_memid, local_path_image]
            del_file_list_all(ops_conn, file_list, slave)
            return ERR
        if slave:
            del_file_noerror(ops_conn, 'slave#' + local_path_image)
            copy_file(ops_conn, local_path_image, 'slave#' + local_path_image)
        chg_flag = True
        
    # download license list file
    local_path_liclist = None
    file_path = REMOTE_PATH_LICLIST
    if not file_path.startswith('/'):
        file_path = '/' + file_path
    file_name = os.path.basename(file_path)
    download_space = os.path.dirname(file_path)
    if file_name != '':
        url = FILE_SERVER + file_path
        local_path_liclist = cwd + file_name
        del_file_noerror(ops_conn, local_path_liclist)
        ret = download_file(ops_conn, url, local_path_liclist, MAX_TIMES_RETRY_DOWNLOAD)
        if ret is ERR or not file_exist(ops_conn, file_name):
            print(('Error: Failed to download license list file "%s"' % file_name))
            sys.stdout.flush()
            raise ZTPErr('Failed to download file "%s"' % os.path.basename(url))
        print('Info: Download license list file successfully')
        sys.stdout.flush()
        if not sha256_check_with_dic(sha256_dic, file_name):
            print(('Error: sha256 check failed, file "%s"' % file_name))
            sys.stdout.flush()
            file_list = [local_path_config, local_path_patch, local_path_memid, local_path_image,
                         local_path_liclist]
            del_file_list_all(ops_conn, file_list, slave)
            return ERR
        chg_flag = True

    #execute license list file to get license file name which end with .dat
    license_name = None
    if local_path_liclist is not None:
        tree = etree.parse(file_name)
        root = tree.getroot()
        for child in root.findall('Lic'):
            name = child.get('name')
            esn = child.find('Esn').text 
            if sys_info['esn'] in esn:
                license_name = name
                print(('Info: License file name is "%s"' % license_name))
                sys.stdout.flush()
                break
        if license_name == None :
            print('Warning: Esn of this device is not in the license list file')
            sys.stdout.flush()
            #del_file_all(ops_conn, local_path_config, slave)
            #del_file_all(ops_conn, local_path_patch, slave)
            #del_file_all(ops_conn, local_path_memid, slave)
            #del_file_all(ops_conn, local_path_image, slave)
            #del_file_all(ops_conn, local_path_liclist, slave)
            #return ERR        

    # download license file
    local_path_license = None
    file_path = license_name
    if file_path is not None:
        if not file_path.startswith('/'):
            file_path = '/' + file_path
        if download_space != "/":
            file_path = download_space + file_path
        file_name = os.path.basename(file_path)
        if file_name != '':
            url = FILE_SERVER + file_path
            local_path_license = cwd + file_name
            ret = download_file(ops_conn, url, local_path_license, MAX_TIMES_RETRY_DOWNLOAD)
            if ret is ERR or not file_exist(ops_conn, file_name):
                print(('Error: Failed to download license file "%s"' % file_name))
                sys.stdout.flush()
                file_list = [local_path_config, local_path_patch, local_path_memid, local_path_image,
                             local_path_liclist]
                del_file_list_all(ops_conn, file_list, slave)
                raise ZTPErr('Failed to download file "%s"' % os.path.basename(url))
            print('Info: Download license file successfully')
            sys.stdout.flush()
            if not sha256_check_with_dic(sha256_dic, file_name):
                print(('Error: sha256 check failed, file "%s"' % file_name))
                sys.stdout.flush()
                file_list = [local_path_config, local_path_patch, local_path_memid, local_path_image,
                             local_path_liclist, local_path_license]
                del_file_list_all(ops_conn, file_list, slave)
                return ERR
            chg_flag = True
            #no need copy to slave board

    # download python file
    local_path_python = None
    file_path = REMOTE_PATH_PYTHON
    if not file_path.startswith('/'):
        file_path = '/' + file_path
    file_name = os.path.basename(file_path)
    if file_name != '':
        url = FILE_SERVER + file_path
        local_path_python = cwd + file_name
        del_file_noerror(ops_conn, local_path_python)
        ret = download_file(ops_conn, url, local_path_python, MAX_TIMES_RETRY_DOWNLOAD)
        if ret is ERR or not file_exist(ops_conn, file_name):
            print(('Error: Failed to download python file "%s"' % file_name))
            sys.stdout.flush()
            file_list = [local_path_config, local_path_patch, local_path_memid, local_path_image,
                         local_path_liclist, local_path_license]
            del_file_list_all(ops_conn, file_list, slave)
            raise ZTPErr('Failed to download file "%s"' % os.path.basename(url))
        print('Info: Download python file successfully')
        sys.stdout.flush()
        if not sha256_check_with_dic(sha256_dic, file_name):
            print(('Error: sha256 check failed, file "%s"' % file_name))
            sys.stdout.flush()
            file_list = [local_path_config, local_path_patch, local_path_memid, local_path_image,
                         local_path_liclist, local_path_license, local_path_python]
            del_file_list_all(ops_conn, file_list, slave)
            return ERR
        if slave:
            del_file_noerror(ops_conn, 'slave#' + local_path_python)
            copy_file(ops_conn, local_path_python, 'slave#' + local_path_python)
        chg_flag = True

    if chg_flag is False:
        return ERR

    # active license file
    if local_path_license is not None:
        ret = active_license(ops_conn, local_path_license)
        if ret is ERR:
            print('Info: Active license failed')
            sys.stdout.flush()
            file_list = [local_path_config, local_path_patch, local_path_memid, local_path_image,
                         local_path_liclist, local_path_license, local_path_python]
            del_file_list_all(ops_conn, file_list, slave)
            return ERR
        print(('Info: Active license sucessfully, name: %s' % local_path_license))
        sys.stdout.flush()
    sleep(10)
    # set startup info
    try:
        startup.set_startup_info(local_path_image, local_path_config, local_path_patch,
                             local_path_memid, slave, sys_info['esn'])
    except Exception as reason:
        logging.error(reason)
        raise
    finally:
        # delete stack member ID file and license list file after used
        del_file_all(ops_conn, local_path_memid, None)
        del_file_all(ops_conn, local_path_liclist, None)

    return OK

def get_interfaces_by_if_type(ops_conn, if_type):
    """Get interfaces with specified interface type."""
    logging.info('Get all %s interfaces', if_type)
    uri = "/ifm/interfaces"
    str_temp = string.Template(
'''<?xml version="1.0" encoding="UTF-8"?>
<interfaces>
    <interface>
        <ifName/>
        <ifPhyType>$ifPhyType</ifPhyType>
    </interface>
</interfaces>
''')
    req_data = str_temp.substitute(ifPhyType = if_type)
    ret, _, rsp_data = ops_conn.get(uri, req_data)
    if ret != http.client.OK or rsp_data == '':
        raise OPIExecError('Failed to get the information of interfaces')
        logging.warning('fails to obtain the interface information.')

    if_name_list = []
    root_elem = etree.fromstring(rsp_data)
    namespaces = {'vrp' : 'http://www.huawei.com/netconf/vrp'}
    uri = 'data' + uri.replace('/', '/vrp:') + '/vrp:'
    for interface in root_elem.findall(uri + 'interface', namespaces):
        elem = interface.find("vrp:ifName", namespaces)
        if elem is None:
            break

        if_name_list.append(elem.text)

    return if_name_list

def get_interface_ipv6_enable(ops_conn, interface):
    uri = "/ifm/interfaces/interface"
    str_temp = string.Template(
'''<?xml version="1.0" encoding="UTF-8"?>
<interface>
    <ifName>$interName</ifName>
    <ifmAm6>
        <enableFlag></enableFlag>
    </ifmAm6>
</interface>
''')
    req_data = str_temp.substitute(interName = interface)
    ret, _, rsp_data = ops_conn.get(uri, req_data)
    if ret != http.client.OK or rsp_data == '':
        logging.info('try get ipv6 enable failed')
        return ERR, "false"

    logging.info(rsp_data)

    root_elem = etree.fromstring(rsp_data)
    logging.info(root_elem)
    namespaces = {'vrp' : 'http://www.huawei.com/netconf/vrp'}
    uri = 'data' + uri.replace('/', '/vrp:') + '/vrp:ifmAm6' + '/vrp:enableFlag'
    elem = root_elem.find(uri, namespaces)
    if elem is None:
        logging.info('try get ipv6 enable failed elem is null')
        return ERR, "false"
    return OK, elem.text

def check_is_ipv6_protocal(ops_conn):
    iftype_list = ['MEth']
    ifnames = []    # all the interface names existing on device
    for iftype in iftype_list:
        namelist = get_interfaces_by_if_type(ops_conn, iftype)
        if len(namelist) > 0:
            ifnames += namelist

    if len(ifnames) > 0:
        for ifname in ifnames:
            ret, ipv6_proto = get_interface_ipv6_enable(ops_conn, ifname)
            if ipv6_proto == 'true' :
                logging.info('current ip protocal is ipv6')
                return True
    logging.info('current ip protocal is ipv4')
    return False

def test_config(ops_conn):
    uri = "/ifm/interfaces/interface"
    req_data = \
'''<?xml version="1.0" encoding="UTF-8"?>
<interface operation="merge">
    <ifName>G0/0/1</ifName>
    <ifmAm4>
        <am4CfgAddrs>
            <am4CfgAddr operation="create">
                <ifIpAddr>1.1.1.1</ifIpAddr>
                <subnetMask>255.255.255.0</subnetMask>
                <addrType>main</addrType>
            </am4CfgAddr>
        </am4CfgAddrs>
    </ifmAm4>
</interface>
'''
    ret, _, rsp_data = ops_conn.create(uri, req_data)
    return rsp_data

def main(usb_path = ''):
    """The main function of user script. It is called by ZTP frame, so do not remove or change this function.

    Args:
    Raises:
    Returns: user script processing result
    """
    host = "localhost"
    if usb_path and len(usb_path):
        logging.info('ztp_script usb_path: %s', usb_path)
        global FILE_SERVER
        FILE_SERVER = 'file:///' + usb_path
    try:
        # Make an OPS connection instance.
        ops_conn = OPSConnection(host)
        ret = main_proc(ops_conn)
        test_config(ops_conn)
        print('---test_config exec Successfully---')

    except OPIExecError as reason:
        logging.error('OPI execute error: %s', reason)
        print(("Error: %s" % reason))
        sys.stdout.flush()
        ret = ERR

    except ZTPErr as reason:
        logging.error('ZTP error: %s', reason)
        print(("Error: %s" % reason))
        sys.stdout.flush()
        ret = ERR

    except IOError as reason:
        print(("Error: %s" % reason))
        sys.stdout.flush()
        ret = ERR

    except Exception as reason:
        logging.error(reason)
        traceinfo = traceback.format_exc()
        logging.debug(traceinfo)
        ret = ERR

    finally:
        # Close the OPS connection
        ops_conn.close()

    return ret

if __name__ == "__main__":
    main()