import os
import flask
from flask import Flask, send_file, request, make_response, jsonify, Response, abort
from werkzeug.utils import secure_filename
import subprocess
import pickle
import uuid
import mimetypes
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import re
import io
from dotenv import load_dotenv
from functools import update_wrapper
import jwt
import inspect
from models import db, DirectoryFile
from flask_migrate import Migrate
from config import JWT_PUB_FILE, DATABASE_URI
import datetime
import dateutil.parser

def load_jwt_public_key():
    # Should create some error if it cant find private key file
    global JWT_PUB_KEY
    with open(JWT_PUB_FILE, 'r') as f:
        JWT_PUB_KEY = f.read()
        print("loaded pub key")

def check_req_auth(tok_name, users_allowed = ['webserver-admin']):
    def decorator(f):
        def wrapper(*args, **kwargs):
            tok = request.args.get(tok_name)
            (is_valid, tok_data) = is_valid_token(tok, users_allowed)
            if is_valid:
                if 'tok_data' in inspect.getfullargspec(f).args:
                    return f(tok_data=tok_data, *args, **kwargs)
                return f(*args, **kwargs)
            else:
                return abort(403)
        return update_wrapper(wrapper, f)
    return decorator

def is_valid_token(tok, users_allowed = ['webserver-admin']):
    '''
    Return True if token is valid for given user, directory (if guest), and duration
    Return False otherwise
    '''
    decoded_tok = None
    try:
        decoded_tok = jwt.decode(tok, key=JWT_PUB_KEY, algorithms=["RS256"], audience=users_allowed)
    except jwt.ExpiredSignatureError:
        print("The token has expired")
        return (False, None)
    except jwt.InvalidAudienceError:
        print("The token is invalid for this user")
        return (False, None)
    return (True, decoded_tok)
    
load_dotenv()

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URI
db.init_app(app)

migrate = Migrate(app, db)

# def model_exists(model_class):
#     engine = db.get_engine(bind=model_class.__bind_key__)
#     return model_class.metadata.tables[model_class.__tablename__].exists(engine)
# 
# if model_exists(DirectoryFile):
#     print("DirectoryFile exists")

MEDIA_PATH = os.getenv('STORAGE_ABS_PATH')
PROCESSED_VIDS_PATH = os.getenv('PROCESSED_VIDS_PATH')
DIRECTORY_PKL = os.getenv('DIRECTORY_PKL_PATH')
load_jwt_public_key()
# directory = {}
'''
directory -> {names:[Union[str, List]], attr: {"uuid": {"name": <file name>, "type": <file type returned from mimetypes>}, "uuid_folder": {"name": "folder name", "type"}}}

'''

class DriveHandler(FileSystemEventHandler):
    def on_any_event(self, event):
        print(event.event_type, event.src_path)

    def on_created(self, event):
        # I stg Synology u stoopid piece of shit
        if '@eaDir' in event.src_path:
            return
        # print("on_created", event.src_path)
        
        if os.path.isdir(event.src_path):
            type = "folder"
        else:
            type = 'video/x-matroska' if os.path.splitext(event.src_path)[1] == '.mkv' else mimetypes.guess_type(event.src_path)[0]
        id = uuid.uuid1()
        new_path = os.path.join(os.path.dirname(event.src_path), str(id.int))
        os.rename(event.src_path, new_path)
        
        dir_item = DirectoryFile(uuid=id, name=os.path.basename(event.src_path), mimetype=type, path=os.path.relpath(new_path, MEDIA_PATH))
        
        with app.app_context():
            db.session.add(dir_item)
            db.session.commit()

    def on_deleted(self, event):
        if '@eaDir' in event.src_path:
            return
        # print("on_deleted", event.src_path)

    def on_modified(self, event):
        if '@eaDir' in event.src_path:
            return
        # print("on_modified", event.src_path)

    def on_moved(self, event):
        if '@eaDir' in event.src_path:
            return
        # print("on_moved", event.src_path)

BLACKLISTED_DIRS = ["#recycle", "@eaDir"]

@app.after_request
def after_request(response):
    response.headers.add('Accept-Ranges', 'bytes')
    return response

@app.route('/mkdir', methods=['POST'])
@check_req_auth('t')
def get_folder_path():
    raw_uuid_int = int(request.form['parent_uuid'])
    given_uuid = uuid.UUID(int=raw_uuid_int)
    
    dir_item = DirectoryFile.query.filter_by(uuid=given_uuid).first()
    parent_path = MEDIA_PATH
    if raw_uuid_int != 0 and not dir_item:
        return jsonify(success=False), 400
    if dir_item:
        parent_path = os.path.join(MEDIA_PATH, dir_item.path)
    
    id = uuid.uuid1()
    mkdir_path = os.path.join(parent_path, str(id.int))
    dir_item = DirectoryFile(uuid=id, name=request.form['name'], mimetype="folder", path=os.path.relpath(mkdir_path, MEDIA_PATH), drive_creation_date=datetime.datetime.now(tz = datetime.timezone.utc))
    os.mkdir(mkdir_path)
    db.session.add(dir_item)
    db.session.commit()
    return jsonify(success=True), 200
    
@app.route('/delete', methods=['POST'])
@check_req_auth('t')
def delete_file():
    raw_uuid_int = int(request.form['id'])
    given_uuid = uuid.UUID(int=raw_uuid_int)
    
    dir_item = DirectoryFile.query.filter_by(uuid=given_uuid).first()
    if not dir_item:
        return jsonify(success=False), 400
    path_to_delete = dir_item.path
    
    if dir_item.mimetype == "folder":
        sub_files = DirectoryFile.filter(DirectoryFile.path.startswith(path_to_delete)).all()
        
        for file in sub_files:
            db.session.delete(file)
    
    db.session.delete(dir_item)
    db.session.commit()
    
    return jsonify(success=True), 200
    
@app.route('/folder', methods=['POST'])
@check_req_auth('t')
def get_drive_folder_path():
    folder_uuid = uuid.UUID(int=int(request.form['uuid']))
    
    if int(request.form['uuid']) == 0:
        return jsonify(path="."), 200
    
    dir_item = DirectoryFile.query.filter_by(uuid=folder_uuid).first()
    
    if dir_item and dir_item.mimetype == 'folder':
        return jsonify(path=dir_item.path), 200
    
    # parent_path = MEDIA_PATH
    # if folder_uuid != 0 and directory[folder_uuid]['type'] == 'folder':
    #     # parent_path = os.path.join(MEDIA_PATH, directory[folder_uuid]['path'])
    #     return jsonify(path=directory[folder_uuid]['path']), 200
    # elif folder_uuid == 0:
    #     return jsonify(path="."), 200
    
    return jsonify(success=False), 400


def get_chunk(path, byte1=None, byte2=None):
    full_path = path
    file_size = os.stat(full_path).st_size
    start = 0
    
    if byte1 < file_size:
        start = byte1
    if byte2:
        length = byte2 + 1 - byte1
    else:
        length = min(file_size - start, 4 * 1024 * 1024) # 4MB buffer

    with open(full_path, 'rb') as f:
        f.seek(start)
        chunk = f.read(length)
    return chunk, start, length, file_size

def get_folder_directory_response(file_path):
    '''
    Returns JSON for HTTP response
    '''
    with os.scandir(file_path) as entries:
        item_names = [uuid.UUID(int=int(entry.name)) for entry in entries]
        # for entry in entries:
        #     if not entry.name in BLACKLISTED_DIRS: # ehhh ubuntu doesnt put shit unlike DSM
        #         item_names.append(uuid.UUID(int=int(entry.name)))
                # file_id = int(entry.name)
                # resp_data.append({'name': directory[file_id]['name'], 'type': directory[file_id]['type'], 'uuid': file_id})
        
        
        if not item_names:
            return []
        
        dir_items = DirectoryFile.query.filter(DirectoryFile.uuid.in_(tuple(item_names))).all()
        
        if not dir_items:
            return []
        
        def gen_metadata(db_item):
            file_stat = os.stat(os.path.join(MEDIA_PATH, db_item.path))
            return {
                'name': db_item.name,
                'type': db_item.mimetype,
                'uuid': str(db_item.uuid.int),
                'created_at': db_item.drive_creation_date,
                'last_modified_at': datetime.datetime.fromtimestamp(file_stat.st_mtime, tz=datetime.timezone.utc),
                'last_accessed_at': datetime.datetime.fromtimestamp(file_stat.st_atime, tz=datetime.timezone.utc),
                'size': file_stat.st_size
            }
        return [gen_metadata(item) for item in dir_items]
    return None
    
# For authetication, the plan is to have the webserver create a token that can be verified by this nas-server
# This should apply when the webserver makes a request for a folder/file from this server alongside
#  when the end-user makes a request for a folder/file from this server

# Feature: JWT Verification
#  Will have set expiry datetime
#  Will mention user authenticated as ['webserver/admin', 'jareth', 'guestlink']
#  Directory that the token is valid for (applies more towards if user is 'guestlink')

# Turn this to using GET and HEAD
@app.route('/', methods=['GET', 'HEAD'])
@app.route('/<str_id>', methods=['GET', 'HEAD'])
@check_req_auth('t')
def serve_file(str_id=None):
    if str_id == None:
        file_path = os.path.join(MEDIA_PATH)
        resp_data = get_folder_directory_response(file_path)
        if resp_data == None:
            return jsonify(success=False), 500
            # print(resp_data)
        resp = make_response(jsonify(resp_data))
        resp.headers['Query-Type'] = 'folder'
        if request.method == 'HEAD':
            resp.status_code = 204
        return resp
    
    id = uuid.UUID(int=int(str_id))
    file_data = DirectoryFile.query.filter_by(uuid=id).first()
    
    if file_data:
        file_path = os.path.join(MEDIA_PATH, file_data.path)
        if file_data.mimetype == "folder":
            
            resp_data = get_folder_directory_response(file_path)
            if resp_data == None:
                return jsonify(success=False), 500
            
            resp = make_response(jsonify(resp_data))
            resp.headers['Query-Type'] = 'folder'
            if request.method == 'HEAD':
                resp.status_code = 204
            return resp
        elif not request.form.get('only_get_dir', False):
            resp = None
            if request.method == 'HEAD':
                empty_file = io.BytesIO()
                resp = send_file(empty_file, mimetype=file_data.mimetype, as_attachment=False, download_name=file_data.name)
                resp.status_code = 204
            else:
                range_header = request.headers.get('Range', None)
                byte1, byte2 = 0, None
                if range_header:
                    match = re.search(r'(\d+)-(\d*)', range_header)
                    groups = match.groups()
                
                    if groups[0]:
                        byte1 = int(groups[0])
                    if groups[1]:
                        byte2 = int(groups[1])
                # else:
                #     byte1 = 0
                #     byte2 = 1024 * 1024
                
                chunk, start, length, file_size = get_chunk(file_path, byte1, byte2)
                resp = Response(chunk, 206, mimetype=file_data.mimetype,
                                  content_type=file_data.mimetype, direct_passthrough=True)
                resp.headers.add('Content-Range', 'bytes {0}-{1}/{2}'.format(start, start + length - 1, file_size))
                resp.headers.add('Content-Disposition', f"filename={file_data.name}")
                resp.headers['Query-Type'] = 'file'
                return resp
            
            resp.headers['Query-Type'] = 'file'
            return resp
    return jsonify(success=False), 404

# @app.route('/process', methods=['POST'])
# @check_req_auth('t')
# def process():
#     pass
#     type = ('video/x-matroska', None) if os.path.splitext(request.form['filepath'])[1] == '.mkv' else mimetypes.guess_type(request.form['filepath'])
# 
#     id = uuid.uuid1().int
#     directory[id] = {'name': os.path.basename(request.form['filepath']), 'type': type[0], 'path': request.form['filepath']}
# 
#     # print(directory)
# 
#     with open(DIRECTORY_PKL, "w+b") as f:
#         pickle.dump(directory, f)
# 
#     if type[0][:6] == "video/":
#         # honestly, processing video here is fine, but making this async would be the *much better* option
# 
#         f = open(os.path.join(MEDIA_PATH, request.form['filepath']), "rb")
#         command = ['ffmpeg', '-y', '-i', '-', '-vcodec', 'copy', '-acodec', 'copy', '-f', 'mp4', os.path.join(PROCESSED_VIDS_PATH, str(id) + ".mp4")]
#         process = subprocess.Popen(command, stdin=subprocess.PIPE)
#         print("parent process is going")
#         recording_ogg, errordata = process.communicate(f.read())
#         f.close()
#         print(errordata)
#         print(recording_ogg)
# 
#         return jsonify(success=True, id=id), 200
# 
#     # file_path = os.path.join(MEDIA_PATH, request.form['filepath'])
#     # with open(file_path, "w+b") as f:
#     #     f.write(request.form['file_data'])
# 
#     return jsonify(success=True), 200

@app.route('/upload', methods=['POST'])
@app.route('/upload/<dir_id>', methods=['POST'])
@check_req_auth('t')
def upload_handler(dir_id=None):
    print(dir_id)
    actual_parent_path = "."
    if dir_id:
        folder = DirectoryFile.query.filter_by(uuid=dir_id, mimetype="folder").first()
        if not folder:
            return jsonify(success=False), 404
        actual_parent_path = folder.path
    for filename in request.files.keys():
        f = request.files[filename]
        if os.path.isdir(filename):
            type = "folder"
        else:
            type = 'video/x-matroska' if os.path.splitext(filename)[1] == '.mkv' else mimetypes.guess_type(filename)[0]
        id = uuid.uuid1()
        new_path = os.path.join(MEDIA_PATH, actual_parent_path, str(id.int))
        last_modified = dateutil.parser.isoparse(request.form['modified_at'])
        dir_item = DirectoryFile(uuid=id, name=filename, mimetype=type, path=os.path.relpath(new_path, MEDIA_PATH), drive_creation_date=last_modified)
        # path = os.path.join(MEDIA_PATH, actual_parent_path, secure_filename(filename))
        print(new_path)
        f.save(new_path)
        os.utime(new_path, (last_modified.timestamp(), last_modified.timestamp()))
        db.session.add(dir_item)
    db.session.commit()
    
    return jsonify(success=True), 200
    
# def on_created(self, event):
#     # I stg Synology u stoopid piece of shit
#     if '@eaDir' in event.src_path:
#         return
#     # print("on_created", event.src_path)
# 
#     if os.path.isdir(event.src_path):
#         type = "folder"
#     else:
#         type = 'video/x-matroska' if os.path.splitext(event.src_path)[1] == '.mkv' else mimetypes.guess_type(event.src_path)[0]
#     id = uuid.uuid1()
#     new_path = os.path.join(os.path.dirname(event.src_path), str(id.int))
#     os.rename(event.src_path, new_path)
# 
#     dir_item = DirectoryFile(uuid=id, name=os.path.basename(event.src_path), mimetype=type, path=os.path.relpath(new_path, MEDIA_PATH))
# 
#     with app.app_context():
#         db.session.add(dir_item)
#         db.session.commit()

# file_handler = DriveHandler()
# observer = Observer()
# observer.schedule(file_handler, path=MEDIA_PATH, recursive=True)
print(f"Storage is located at {MEDIA_PATH}")
# observer.start()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=os.getenv('FLASK_PORT'), threaded=True)
    # observer.stop()
    # observer.join()