from flask import Flask, current_app, request, jsonify, redirect, url_for
import logging
import sys
import os
import base64
import json

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

logging.basicConfig(stream=sys.stdout,level=logging.DEBUG, format=f'%(asctime)s %(levelname)s %(name)s %(funcName)15s() line=%(lineno)3s: %(message)s')

app = Flask(__name__)


def current_cmd():
    # with this response, the C&C does not instruct the bot to do anything :)
    response = { "success" : "true" }
    return response


@app.route('/api/v1/device', methods=['GET', 'POST'])
@app.route('/api/v1/device/check')
@app.route('/api/v1/device/lock', methods=['GET', 'POST'])
@app.route('/api/v1/device/server-log', methods=['GET','POST'])
@app.route('/api/v1/device/screen', methods=['GET','POST'])
def answer():
    if b'data:image' in request.data[0:30]:
        # write screencast to a file
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
        quit()
    else:
        current_app.logger.debug(f"Request: {request} Received Data: {request.data}")
        
    return jsonify(current_cmd())

@app.route('/payload')
def payload():
    # thepayload.apk refers to BianLian's utility apk com.fbdev.payload
    # either use that (not malicious) or another placeholder apk
    return redirect( url_for('static', filename='thepayload.apk'), code=301)


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=9999, debug=True)

