import traceback
import httplib
import string


class OPSConnection(object):
    """Make an OPS connection instance."""

    def __init__(self, host, port = 80):
        self.host = host
        self.port = port
        self.headers = {
            "Content-type": "text/xml",
            "Accept":       "text/xml"
            }
        self.conn = None

    def close(self):
        """Close the connection"""
        self.conn.close()

    def create(self, uri, req_data):
        """Create operation"""
        ret = self.rest_call("POST", uri, req_data)
        return ret

    def delete(self, uri, req_data):
        """Delete operation"""
        ret = self.rest_call("DELETE", uri, req_data)
        return ret

    def get(self, uri, req_data = None):
        """Get operation"""
        ret = self.rest_call("GET", uri, req_data)
        return ret

    def set(self, uri, req_data):
        """Set operation"""
        ret = self.rest_call("PUT", uri, req_data)
        return ret

    def rest_call(self, method, uri, req_data):
        """REST call"""
        print('|---------------------------------- request: ----------------------------------|')
        print('%s %s HTTP/1.1\n' % (method, uri))
        if req_data == None:
            body = ""
        else:
            body = req_data
            print(body)
        if self.conn:
            self.conn.close()
        self.conn = httplib.HTTPConnection(self.host, self.port)

        self.conn.request(method, uri, body, self.headers)
        response = self.conn.getresponse()
        response.status = httplib.OK    # stub code
        ret = (response.status, response.reason, response.read())
        print('|---------------------------------- response: ---------------------------------|')
        print('HTTP/1.1 %s %s\n\n%s' % ret)
        print('|------------------------------------------------------------------------------|')
        return ret
       
def upload_cfg_ftp(ops_conn):
    """upload device config file use ftp """

    uri = "/ftpc/ftpcTransferFiles/ftpcTransferFile"
    req_data = \
'''<?xml version="1.0" encoding="UTF-8"?> 
<ftpcTransferFile> 
<serverIpv4Address>192.168.3.254</serverIpv4Address> 
<commandType>put</commandType> 
<userName>admin</userName> 
<password>hw@123</password> 
<localFileName>vrpcfg.cfg</localFileName> 
<remoteFileName>vrpcfg.cfg</remoteFileName> 
</ftpcTransferFile>
'''
    ret, _, rsp_data = ops_conn.create(uri, req_data) 
    if ret != httplib.OK:
        return None

    return rsp_data   
    
    
def main():
    """The main function."""

    host = "localhost"
    try:
        ops_conn = OPSConnection(host)
        print('+-------------------------- Open a OPS connection. ----------------------------+')
        rsp_data = upload_cfg_ftp(ops_conn)
        # if rsp_data is not None:
        #     cfgFileName = rsp_data[rsp_data.find("curStartupFile")+15 : rsp_data.find("/curStartupFile")-1]
        #     backup_file(ops_conn,cfgFileName)
        ops_conn.close()
        print('+-------------------------- Close a OPS connection. ---------------------------+')
        return
    except:
        errinfo = traceback.format_exc()
        print(errinfo)
        return

if __name__ == "__main__":
    main()

    