#!/usr/bin/env python3
# encoding: utf-8
from cortexutils.responder import Responder
import requests
import base64
import hashlib
import hmac
import uuid
import datetime

class MimecastBlacklister(Responder):
    def __init__(self):
        Responder.__init__(self)
        self.base_url = self.get_param('config.base_url', None, "Base URL Missing")
        self.access_key = self.get_param('config.access_key', None, "Integration access key Missing")
        self.secret_key = self.get_param('config.secret_key', None, "Base secret key Missing")
        self.app_id  = self.get_param('config.app_id', None, "Integration application id Missing")
        self.app_key = self.get_param('config.app_key', None, "Integration application key Missing")
        self.uri = self.get_param('config.uri', None, "Integration application key Missing")

    def run(self):
        Responder.run(self)

        if self.get_param('data.dataType') == 'url':

            url = self.get_param('data.data', None, 'No artifacts available')
        
            self.urljoin = self.base_url + self.uri
            delimiter = ":"
            self.request_id = str(uuid.uuid4())
            hdr_date = datetime.datetime.utcnow().strftime("%a, %d %b %Y %H:%M:%S") + " UTC"                                   
            acc = bytes(self.access_key, 'UTF-8')
            app = bytes(self.app_key, 'UTF-8')
            u = bytes(self.uri, 'UTF-8')
            req = bytes(self.request_id, 'UTF-8')
            hdr = bytes(hdr_date, 'UTF-8')
            key = bytes(self.secret_key, 'UTF-8')
            delim = bytes(delimiter, 'UTF-8')
            code = base64.b64decode(key)
            hmac_sha1 = hmac.new(code, delim.join([hdr, req, u, app]), hashlib.sha1).digest()
            sig = base64.encodebytes(hmac_sha1).rstrip()


            headers = {
                'Authorization': b'MC ' + acc + b':' + sig,
                'x-mc-app-id': self.app_id,
                'x-mc-date': 	hdr_date,
                'x-mc-req-id': self.request_id,
                'Content-Type': 'application/json'
            }

            payload = {
                'data': [
                    {
                    'action': 'block',
                    'url' : url
                    }                                        
                ]
            }

            r = requests.post(self.urljoin, json=payload, headers=headers)
            if r.status_code == 200:
                self.report({'message': 'Blacklisted in Mimecast.'})
            else:
                self.error(r.text)

    def operations(self, raw):
        return [self.build_operation('AddTagToArtifact', tag='Mimecast:blocked')]

if __name__ == '__main__':
        MimecastBlacklister().run()
