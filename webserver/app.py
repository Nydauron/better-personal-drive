import os
from flask import Flask, render_template, request, jsonify, redirect, send_file, make_response
from markupsafe import escape
from werkzeug.utils import secure_filename
import requests
from io import BytesIO
import re
import base64
from dotenv import load_dotenv

load_dotenv()

FILE_SERVER_HOST = os.getenv('FILE_SERVER_HOST')
SFTP_IP = os.getenv('SFTP_IP')
SFTP_PORT = int(os.getenv('SFTP_PORT'))
SFTP_USERNAME = os.getenv('SFTP_USERNAME')

APP = Flask(__name__)

@APP.route('/favicon.ico')
def site_icon():
    try:
        return make_response(send_file(f"assets/favicon.ico"))
    except FileNotFoundError:
        return jsonify(success=False), 404
@APP.route('/assets/<file>')
def get_assets(file):
    return make_response(send_file(f"assets/{file}"))

@APP.route('/')
@APP.route('/<dir_id>')
def frontend_upload(dir_id=""):
    r = requests.post(FILE_SERVER_HOST + "/" + dir_id)
    if r.status_code != 200:
        return jsonify(success=False), r.status_code
    print(r.headers)
    if r.headers['Query-Type'] == "folder":
        items = r.json()
        return render_template('upload.html', files = items)
    if r.headers['Query-Type'] == "file":
        # Here, I would like this to replace the /view domain, where it will look
        #  at the mimetypes in the header and be able to decide if it can display
        #  such media or not
        # TODO: Do this ^^^
        print(r.headers['Content-Type'][:6])
        if r.headers['Content-Type'][:6] == "image/":
            data = BytesIO(r.content)
            encoded_img_data = base64.b64encode(data.getvalue())
            return render_template('res.html', type=r.headers['Content-Type'], img_data=encoded_img_data.decode('utf-8'))
            
        if r.headers['Content-Type'][:6] == "video/":
            return render_template('res.html', type=r.headers['Content-Type'], server_host = FILE_SERVER_HOST, video = escape(dir_id))
        
        filename = re.findall(r"filename=(.+)", r.headers['Content-Disposition'])[0]
        return send_file(BytesIO(r.content), download_name=filename, as_attachment=True)
        
    return jsonify(success=False), 404

# @APP.route('/<path:vid_name>/view')
# def website(vid_name):
#     # vid_path = os.path.join(MEDIA_PATH, vid_name)
#     # resp = make_response(send_file(vid_path, 'video/mp4'))
#     # resp.headers['Content-Disposition'] = 'inline'
#     return render_template('res.html', server_host = FILE_SERVER_HOST, video = escape(vid_name))

@APP.route('/<dir>/mkdir', methods=['POST'])
@APP.route('/mkdir', methods=['POST'])
def backend_mkdir(dir = None):
    # it would just be better to use sftp
    print(request.form)
    parent_uuid = 0
    if dir != None:
        parent_uuid = int(dir)
    r = requests.post(f"{FILE_SERVER_HOST}/mkdir", data={'parent_uuid': parent_uuid, "name": request.form['name']})
    return r.json(), r.status_code
    
@APP.route('/<dir>/upload', methods=['POST'])
@APP.route('/upload', methods=['POST'])
def backend_upload(dir = None):
    # it would just be better to use sftp
    actual_path = None
    if dir != None:
        r = requests.post(f"{FILE_SERVER_HOST}/folder", data={'uuid': int(dir)})
        if r.status_code != 200:
            return jsonify(success=False), 400
        actual_path = r.json()['path']
    else:
        actual_path = dir
    
    f = request.files['file']
    
    import paramiko
    host, port = SFTP_IP, SFTP_PORT
    transport = paramiko.Transport((host,port))
    
    username, pkey = SFTP_USERNAME, paramiko.rsakey.RSAKey.from_private_key_file("id_rsa")
    transport.connect(None, username, pkey=pkey)
    
    with paramiko.SFTPClient.from_transport(transport) as sftp:
        sftp.chdir('Drive')
        try:
            sftp.stat(actual_path)
        except IOError as e:
            import errno
            if e.errno == errno.ENOENT:
                print("Directory doesnt exist")
                return jsonify(success=False), 400
            else:
                print("other err tf")
                return jsonify(success=False), 500
        sftp.chdir(actual_path) # shouldnt fail
        sftp.putfo(f, secure_filename(f.filename))
    
    # import requests
    # r = requests.post(FILE_SERVER_HOST + '/process', data={'filepath': dir + secure_filename(f.filename)})
    # print(r.json())
    # res_json = r.json()
    # if 'id' in res_json:
    #     return redirect('/' + str(res_json['id']) + "/view", code=302)
    return jsonify(success=True), 200
    

if __name__ == '__main__':
    APP.run("0.0.0.0", port=os.getenv('FLASK_PORT'), )