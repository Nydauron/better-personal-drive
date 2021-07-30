import os
from flask import Flask, render_template, request, session, jsonify, redirect, send_file, make_response, url_for, flash, abort, Response
from flask_migrate import Migrate
from flask_wtf.csrf import CSRFProtect
from flask_bcrypt import Bcrypt
from models import db, Account, ShareLink
from markupsafe import escape
from werkzeug.utils import secure_filename
from werkzeug.urls import url_fix
import requests
from io import BytesIO
import re
import base64
from dotenv import load_dotenv
import jwt
import datetime
import dateutil.parser
import pytz
from functools import update_wrapper
import inspect
from keys import JWT_PRIV_KEY, JWT_PUB_KEY, JWT_STOR_KEY
import uuid
import json

load_dotenv()

from config import SECRET_KEY, DATABASE_URI

FILE_SERVER_HOST = os.getenv('FILE_SERVER_HOST')
WEBSERVER_HOST = ""
SFTP_IP = os.getenv('SFTP_IP')
SFTP_PORT = int(os.getenv('SFTP_PORT'))
SFTP_USERNAME = os.getenv('SFTP_USERNAME')

app = Flask(__name__)
app.secret_key = SECRET_KEY
app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URI
csrf = CSRFProtect(app)
db.init_app(app)

migrate = Migrate(app, db)

bcrypt = Bcrypt(app)

def check_auth(tok_name, users_allowed):
    def decorator(f):
        def wrapper(*args, **kwargs):
            dir = kwargs.get('dir_id')
            
            (is_valid, tok_data) = is_valid_token(session[tok_name], users_allowed) if tok_name in session else (False, None)
            if is_valid:
                if 'tok_data' in inspect.getfullargspec(f).args:
                    return f(tok_data=tok_data, *args, **kwargs)
                return f(*args, **kwargs)
            else:
                session['auth_redirect'] = request.full_path
                return redirect('/login')
        return update_wrapper(wrapper, f)
    return decorator
    
@app.route('/favicon.ico')
def site_icon():
    try:
        return app.send_static_file("favicon.ico")
    except FileNotFoundError:
        return jsonify(success=False), 404

@app.route('/assets/<file>')
def get_assets(file):
    return app.send_static_file(file)

@app.route('/profile')
@check_auth('userToken', ['jareth'])
def profile():
    return render_template('profile.html')
        
@app.route('/update-password', methods=['POST'])
@check_auth('userToken', ['jareth'])
def update_password(tok_data = None):
    user = tok_data['aud']
    
    if (request.form['new-pass0'] != request.form['new-pass1']):
        flash("New passwords do not match.")
        return redirect("/profile")
    
    account = Account.query.filter_by(username=user).first()
    if bcrypt.check_password_hash(account.hashed_pass, str(request.form['cur-pass'])):
        new_pass_hash = bcrypt.generate_password_hash(request.form['new-pass0']).decode('utf-8')
        account.hashed_pass = new_pass_hash
        with app.app_context():
            db.session.add(account)
            db.session.commit()
            flash("New password set successfully.")
            return redirect("/profile")
    flash("Old password does not match expected.")
    return redirect("/profile")

@app.route('/login', methods=['GET', 'POST'])
def login():
    # On GET, give login page
    
    # On POST, process user and password
    # If we find these values (hashed password ofc), then we give a jwt token valid
    #  for 1 hour
    
    if request.method == 'GET':
        return render_template('login.html')
    elif request.method == 'POST':
        account = Account.query.filter_by(username=str(request.form['user'])).first()
        print(f"{request.form['user']}: {account}")
        if account and bcrypt.check_password_hash(account.hashed_pass, str(request.form['pass'])):
            session['userToken'] = generate_JWT_token(account.username)
            return redirect(session.get('auth_redirect', '/'))
        flash("Incorrect user credentials.")
        return redirect('.')
    else:
        return jsonify(success=False), 404
        
@app.route('/logout', methods=['GET'])
def logout():
    if 'userToken' in session:
        session.pop('userToken')
        flash('You were logged out')
        return redirect('/login')
    flash('You were not even logged in!')
    return redirect('/login')
    
def generate_JWT_token(user = "guest", duration = datetime.timedelta(hours=1), path = '.'):
    if user == 'guest' and path == '.':
        print('''Please note you are giving a guest user full access to your drive.
                They won\'t be able to add, edit, or delete any files but it might 
                not be something you would want to do.''')
    curr_time = datetime.datetime.utcnow()
    
    data = {'drive_path': path, 'nbf': curr_time, 'exp': curr_time + duration, 'iat': curr_time, 'iss': 'webserver-admin', 'aud': user, 'alg': "RS256"}
    
    return jwt.encode(data, key=JWT_PRIV_KEY, algorithm="RS256")
    
def generate_JWT_storage_token(duration = datetime.timedelta(seconds=5)):
    global JWT_STOR_KEY
    curr_time = datetime.datetime.utcnow()
    
    data = {'nbf': curr_time, 'exp': curr_time + duration, 'iat': curr_time, 'iss': 'webserver-admin', 'aud': 'webserver-admin', 'alg': "RS256"}
    
    return jwt.encode(data, key=JWT_STOR_KEY, algorithm="RS256")

def is_valid_token(tok, users_allowed = ['jareth']):
    '''
    Return True if token is valid for given user, directory (if guest), and duration
    Return False otherwise
    '''
    decoded_tok = None
    try:
        decoded_tok = jwt.decode(tok, key=JWT_PUB_KEY, algorithms=["RS256"], audience=users_allowed)
    except jwt.ExpiredSignatureError:
        print("The token has expired")
        flash('Token has expired.')
        return (False, None)
    except jwt.InvalidAudienceError:
        print("The token is invalid for this user")
        return (False, None)
    account = Account.query.filter_by(username=str(decoded_tok['aud'])).first()
    if account:
        return (True, decoded_tok)
    return (False, None)

@app.route('/dir/')
@app.route('/dir/<dir_id>')
@check_auth('userToken', ['jareth'])
def get_folder_directory(dir_id=""):
    try:
        admin_tok = generate_JWT_storage_token()
        r = requests.head(f"{FILE_SERVER_HOST}/{dir_id}?t={url_fix(admin_tok)}", data={'only_get_dir': True})
    except requests.exceptions.ConnectionError:
        print("Failed to connect to storage server. Is the server down?")
        return jsonify(success=False), 500
    
    if r.status_code == 204 and r.headers['Query-Type'] == "folder":
        try:
            data_r = requests.get(f"{FILE_SERVER_HOST}/{dir_id}?t={url_fix(admin_tok)}", data={'only_get_dir': True})
        except requests.exceptions.ConnectionError:
            print("Failed to connect to storage server. Is the server down?")
            return jsonify(success=False), 500
        return jsonify(items=data_r.json()), data_r.status_code
    else:
        return jsonify(success=False), 404

@app.route('/')
@app.route('/<dir_id>')
@check_auth('userToken', ['jareth'])
def frontend_upload(dir_id=""):
    return get_file_dir(dir_id)

def get_file_dir(dir_id="", is_sharing=False, share_id = ""):
    try:
        admin_tok = generate_JWT_storage_token()
        r = requests.head(f"{FILE_SERVER_HOST}/{dir_id}?t={url_fix(admin_tok)}")
    except requests.exceptions.ConnectionError:
        print("Failed to connect to storage server. Is the server down?")
        return jsonify(success=False), 500
    if not r.status_code in [200, 204]:
        return jsonify(success=False), r.status_code
    
    if r.headers['Query-Type'] == "folder":
        return render_template('upload.html') # files will not be parsed by server now
    if r.headers['Query-Type'] == "file":
        if r.headers['Content-Type'][:6] == "image/":
            return render_template('res.html', type=r.headers['Content-Type'], server_host = WEBSERVER_HOST, file_id = escape(dir_id), sharing = is_sharing, share_id=share_id)
            
        if r.headers['Content-Type'][:6] == "video/":
            return render_template('res.html', type=r.headers['Content-Type'], server_host = WEBSERVER_HOST, file_id = escape(dir_id), sharing = is_sharing, share_id=share_id)
        
        try:
            data_r = requests.get(f"{FILE_SERVER_HOST}/{dir_id}?t={url_fix(admin_tok)}")
        except requests.exceptions.ConnectionError:
            print("Failed to connect to storage server. Is the server down?")
            return jsonify(success=False), 500
            
        filename = re.findall(r"filename=(.+)", data_r.headers['Content-Disposition'])[0]
        return send_file(BytesIO(data_r.content), download_name=filename, as_attachment=True)
        
    return jsonify(success=False), 404

@app.route('/<dir_id>/view')
@check_auth('userToken', ['jareth'])
def file_view(dir_id):
    return view_file(dir_id)
    
def view_file(dir_id):
    try:
        r = requests.request(
        method=request.method,
        url=f"{FILE_SERVER_HOST}/{dir_id}?t={url_fix(generate_JWT_storage_token())}",
        headers={key: value for (key, value) in request.headers if key != 'Host'},
        data=request.get_data(),
        cookies=request.cookies,
        allow_redirects=False)
    except requests.exceptions.ConnectionError:
        print("Failed to connect to storage server. Is the server down?")
        return jsonify(success=False), 500
    if not r.status_code in [200, 206]:
        return jsonify(success=False), r.status_code
    if r.headers['Query-Type'] == "folder":
        return jsonify(success=False), 404
    if r.headers['Query-Type'] == "file":
        excluded_headers = ['content-encoding', 'content-length', 'transfer-encoding', 'connection']
        headers = [(name, value) for (name, value) in r.raw.headers.items() if name.lower() not in excluded_headers]
        response = Response(r.content, r.status_code, r.raw.headers.items())
        return response
    return jsonify(success=False), 404

@app.route('/<dir>/mkdir', methods=['POST'])
@app.route('/mkdir', methods=['POST'])
@check_auth('userToken', ['jareth'])
def mkdir_handler(dir = None):
    parent_uuid = 0
    if dir != None:
        parent_uuid = int(dir)
    r = requests.post(f"{FILE_SERVER_HOST}/mkdir?t={url_fix(generate_JWT_storage_token())}", data={'parent_uuid': parent_uuid, "name": request.form['name']})
    return r.json(), r.status_code

@app.route('/delete', methods=['POST'])
@check_auth('userToken', ['jareth'])
def delete_handler():
    r = requests.post(f"{FILE_SERVER_HOST}/delete?t={url_fix(generate_JWT_storage_token())}", data={"id": request.form['id']})
    return r.json(), r.status_code

@app.route('/get-share-urls/<file_id>', methods=['POST'])
@check_auth('userToken', ['jareth'])
def get_all_share_links(file_id):
    item_id = uuid.UUID(int=int(file_id))
    if not item_id:
        return abort(404)
    share_urls = ShareLink.query.filter_by(item_id=item_id).all()
    
    valid_links = []
    for s in share_urls:
        cur_time = datetime.datetime.utcnow()
        if not s.expires_at:
            valid_links.append({"id": s.share_id.hex, "url": f"/sharing/{s.share_id.hex}", "expires_delta": None})
        elif s.expires_at < cur_time:
            db.session.delete(s)
        else:
            valid_links.append({"id": s.share_id.hex, "url": f"/sharing/{s.share_id.hex}", "expires_delta": (s.expires_at - cur_time).total_seconds()})
    
    db.session.commit()
    
    return jsonify(urls=valid_links), 200
    
@app.route('/delete-share-url/<share_id_str>', methods=['POST'])
@check_auth('userToken', ['jareth'])
def delete_share_url(share_id_str):
    share_id = uuid.UUID(hex=share_id_str)
    if not share_id:
        return abort(404)
    share_url = ShareLink.query.filter_by(share_id=share_id).first()
    if not share_url:
        return jsonify(success=False), 404
    
    db.session.delete(share_url)
    db.session.commit()
    return jsonify(success=True), 200

@app.route('/create-share-url/<file_id>', methods=['POST'])
@check_auth('userToken', ['jareth'])
def generate_share_url(file_id):
    current_time = datetime.datetime.now(tz=pytz.utc)
    if 'expire_in' in request.form:
        timedelta_info = json.loads(request.form['expire_in'])
        
        if timedelta_info:
            duration = datetime.timedelta(**timedelta_info)
        else:
            return jsonify(sucess=False), 400
        
        expires_datetime = current_time + duration
        if expires_datetime <= current_time:
            return jsonify(sucess=False), 404
        share_url = ShareLink(item_id = uuid.UUID(int=int(file_id)), generated_at = current_time, expires_at = expires_datetime)
        
    elif 'expire_at' in request.form:
        iso_info = json.loads(request.form['expire_at'])
        expires_datetime = dateutil.parser.isoparse(iso_info['datetime'])
        print(expires_datetime)
        if not expires_datetime or expires_datetime <= current_time:
            return jsonify(sucess=False), 404
        share_url = ShareLink(item_id = uuid.UUID(int=int(file_id)), generated_at = current_time, expires_at = expires_datetime)
    else:
        share_url = ShareLink(item_id = uuid.UUID(int=int(file_id)), generated_at = current_time, expires_at = None)
    
    db.session.add(share_url)
    db.session.commit()
    
    return jsonify(share_url=f"/sharing/{share_url.share_id.hex}"), 200
    
@app.route('/sharing/<share_id_str>', methods=['GET'])
def get_share_view_page(share_id_str):
    is_valid, file_id = is_valid_share_link(share_id_str)
    if not is_valid:
        return abort(404)
    return get_file_dir(file_id, True, share_id_str) # having share_id_str is kinda sus ngl, but the validation does seem to provide some form of sanitation

@app.route('/sharing/<share_id_str>/view', methods=['GET'])
def get_share_content(share_id_str):
    is_valid, file_id = is_valid_share_link(share_id_str)
    if not is_valid:
        return abort(404)
    return view_file(file_id)
    
def is_valid_share_link(share_id_str):
    share_uuid = uuid.UUID(hex=share_id_str)
    if not share_uuid:
        return False, None
    res = ShareLink.query.filter_by(share_id=share_uuid).first()
    if not res or res.expires_at < datetime.datetime.utcnow():
        if res:
            print("Shared link is expired. Deleting ...")
            db.session.delete(res)
            db.session.commit()
        return False, None
    return True, res.item_id.int

@app.route('/<dir>/upload', methods=['POST'])
@app.route('/upload', methods=['POST'])
@check_auth('userToken', ['jareth'])
def backend_upload(dir = None):
    f = request.files['file']
    
    url = f"{FILE_SERVER_HOST}/upload"
    if dir:
        url += f"/{dir}"
    r = requests.post(f"{url}?t={url_fix(generate_JWT_storage_token())}", files={f"{f.filename}": f}, data={'modified_at': request.form['modified_at']})
    print(r)
    return r.json(), r.status_code
    

if __name__ == '__main__':
    app.run("0.0.0.0", port=os.getenv('FLASK_PORT'), )