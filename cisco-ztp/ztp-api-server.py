from flask import  Flask,request,send_from_directory
import json

ztp_app=Flask(__name__)

@ztp_app.route('/ztp',methods=['GET'])
def ztp_file():
    return send_from_directory('.','h3c_ztp_conf.py')

@ztp_app.route('/devcfg/<dev_sn>',methods=['POST'])
def ztp_data(dev_sn):
    if dev_sn == 'test':
        config ={'int l0':'ip address 192.168.1.1 255.255.255.0'}
        return config



ztp_app.run(host='0.0.0.0',port=80)