from .request import Request, DBController
from .classifier import ThreatClassifier
import urllib
from flask import request ,jsonify
import requests

db = DBController()
threat_clf = ThreatClassifier()
req = Request()


class WAF(object):
     def __init__(self):
          pass
     
     def test():
        print('*' * 100)
        haders= dict(request.headers)
#         origen = request.environ['REMOTE_ADDR'] #sor ip
        host = urllib.parse.unquote(request.headers.get('Host'))
        path_request = urllib.parse.unquote(request.full_path)
        method = request.method
        body=[]
        for i in list(request.form.values()):
            body.append(urllib.parse.unquote(i))

        ip =request.headers.get('Cf-Connecting-Ip') #sor ip
#         ip='85.208.109.158'
        geo_location = requests.get(f'https://api.ip2location.io/?key=020EAE9E5E1881E1EBB56A074AC7CB4F&ip={ip}', headers={'Accept': 'application/json'})
        

        req.origin= ip
        req.host = host
        req.request = path_request
        req.method = method
        req.headers = haders
        req.threat_type = 'None'
        req.body = body
        src_port = request.environ.get('REMOTE_PORT')

        
        threat_clf.classify_request(req)
        print(req.threats)
        db.save(req)
     #    threat_state = 0
        geo_location = geo_location.json()
        if list(req.threats.keys())[0] == 'valid':
            threat_state_valid=1
            geo_location['threat_state_valid'] = threat_state_valid
            req.geo_location = {}
        else:
            threat_state_unvalid=1
            geo_location['threat_state_unvalid'] = threat_state_unvalid
            geo_location['payload'] = req.body
            geo_location['threat_type'] = req.threats

            req.geo_location = geo_location
               

        if list(req.threats.keys())[0] != 'valid':


                    from twilio.rest import Client

                    account_sid = 'AC024199e13f740adbf6d37186098e0b42'
                    auth_token = '34c7ce0d2bbc9e27cd2cc4876a30e3ae'
                    client = Client(account_sid, auth_token)

                    message = client.messages.create(
                      from_='whatsapp:+14155238886',
                      body=f"Your website is under threat by ip={ip} , and threat is:\n{list(req.threats.keys())[0]}\nFor more info visit: \n https://veto.grafana.net/d/fe54402a-0814-4dd1-bdfb-4c7c7d6edd14/waf?orgId=1&refresh=5s",
                      to='whatsapp:+201099394113'
                    )

                    print(message.sid)
       
        print(req.headers)
        print('*' * 100)
        print(request.environ['REMOTE_ADDR'])
        print('*' * 100)
        print(jsonify({'ip': request.remote_addr}), 200)
        print('*' * 100)
        print('host is ' , request.headers.get('Host'))
        print('*' * 100)
        print('url is ' ,  request.full_path)
        print('*' * 100)
        print('Method is' ,  request.method)
        print('*' * 100)
        print('form  is' ,  body)
        print('*' * 100)
        print('port  is' ,  request.environ.get('REMOTE_PORT'))
        print(list(req.threats.keys())[0])
        print('*' * 100)
        print('port is' ,  src_port)
        print('*' * 100)
        print('ip is' , ip)
        return req.threats
     
       
