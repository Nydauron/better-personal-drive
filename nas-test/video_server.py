import os
import flask
from flask import Flask, send_file, request, make_response, jsonify
import subprocess
import pickle
import uuid
import mimetypes
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import re
import io
from dotenv import load_dotenv

load_dotenv()

APP = Flask(__name__)
MEDIA_PATH = os.getenv('STORAGE_ABS_PATH')
PROCESSED_VIDS_PATH = os.getenv('PROCESSED_VIDS_PATH')
DIRECTORY_PKL = os.getenv('DIRECTORY_PKL_PATH')
directory = {}
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
        print("on_created", event.src_path)
        
        type = 'video/x-matroska' if os.path.splitext(event.src_path)[1] == '.mkv' else mimetypes.guess_type(event.src_path)[0]
        if type == None:
            type = "folder"
        id = uuid.uuid1().int
        
        new_path = f"{os.path.dirname(event.src_path)}/{str(id)}" # should use os.path.join
        os.rename(event.src_path, new_path)
        
        directory[id] = {'name': os.path.basename(event.src_path), 'type': type, 'path': new_path[len(MEDIA_PATH):]}
        
        print(id)
        print(directory[id])
        with open(DIRECTORY_PKL, "w+b") as f:
            pickle.dump(directory, f)

    def on_deleted(self, event):
        if '@eaDir' in event.src_path:
            return
        print("on_deleted", event.src_path)

    def on_modified(self, event):
        if '@eaDir' in event.src_path:
            return
        print("on_modified", event.src_path)

    def on_moved(self, event):
        if '@eaDir' in event.src_path:
            return
        print("on_moved", event.src_path)

BLACKLISTED_DIRS = ["#recycle", "@eaDir"]

@APP.route('/mkdir', methods=['POST'])
def get_folder_path():
    parent_uuid = int(request.form['parent_uuid'])
    parent_path = MEDIA_PATH
    if parent_uuid != 0 and directory[parent_uuid]['type'] == 'folder':
        parent_path = os.path.join(MEDIA_PATH, directory[parent_uuid]['path'])
    elif parent_uuid != 0:
        return jsonify(success=False), 400
    
    mkdir_path = os.path.join(parent_path, request.form['name'])
    os.mkdir(mkdir_path)
    return jsonify(success=True), 200
    
@APP.route('/folder', methods=['POST'])
def get_drive_folder_path():
    folder_uuid = int(request.form['uuid'])
    parent_path = MEDIA_PATH
    if folder_uuid != 0 and directory[folder_uuid]['type'] == 'folder':
        # parent_path = os.path.join(MEDIA_PATH, directory[folder_uuid]['path'])
        return jsonify(path=directory[folder_uuid]['path']), 200
    elif parent_uuid == 0:
        return jsonify(path="."), 200
    
    return jsonify(success=False), 400

@APP.route('/', methods=['GET', 'POST'])
@APP.route('/<str_id>', methods=['GET', 'POST'])
def serve_file(str_id=None):
    if str_id == None:
        file_path = os.path.join(MEDIA_PATH)
        with os.scandir(file_path) as entries:
            resp_data = []
            directory
            for entry in entries:
                if not entry.name in BLACKLISTED_DIRS:
                    file_id = int(entry.name)
                    resp_data.append({'name': directory[file_id]['name'], 'type': directory[file_id]['type'], 'uuid': file_id})
            print(resp_data)
            resp = make_response(jsonify(resp_data))
            resp.headers['Query-Type'] = 'folder'
            return resp
        
        return jsonify(success=False), 500
    
    id = int(str_id)
    if id in directory:
        file_path = os.path.join(MEDIA_PATH, directory[id]['path'])
        if directory[id]['type'] == "folder":
            with os.scandir(file_path) as entries:
                resp_data = []
                for entry in entries:
                    if not entry.name in BLACKLISTED_DIRS:
                        file_id = int(entry.name)
                        resp_data.append({'name': directory[file_id]['name'], 'type': directory[file_id]['type'], 'uuid': file_id})
                        # resp_data.append({'name': directory[file_id]['name'], 'is_folder': entry.is_dir(), 'uuid': file_id})
                print(resp_data)
                resp = make_response(jsonify(resp_data))
                resp.headers['Query-Type'] = 'folder'
                return resp # jsonify(resp), 200
            
            return jsonify(success=False), 500
        else:
            resp = None
            if directory[id]['type'][:6] == "video/" and request.method == 'POST':
                empty_file = io.BytesIO()
                resp = send_file(empty_file, mimetype=directory[id]['type'], as_attachment=False, download_name=directory[id]['name'])
                # resp = flask.Response(status=200,content_type=directory[id]['type'][:6]) # This is just wrong
                # resp.headers['Content-Disposition'] += f"filename=\"{directory[id]['name']}\""
            else:
                resp = send_file(file_path, mimetype=directory[id]['type'], as_attachment=True, download_name=directory[id]['name'])
            resp.headers['Query-Type'] = 'file'
            return resp
    else:
        return jsonify(success=False), 404

@APP.route('/process', methods=['POST'])
def process():
    pass
    type = ('video/x-matroska', None) if os.path.splitext(request.form['filepath'])[1] == '.mkv' else mimetypes.guess_type(request.form['filepath'])
    
    id = uuid.uuid1().int
    directory[id] = {'name': os.path.basename(request.form['filepath']), 'type': type[0], 'path': request.form['filepath']}
    
    print(directory)
    
    with open(DIRECTORY_PKL, "w+b") as f:
        pickle.dump(directory, f)
    
    if type[0][:6] == "video/":
        # honestly, processing video here is fine, but making this async would be the *much better* option
        
        f = open(os.path.join(MEDIA_PATH, request.form['filepath']), "rb")
        command = ['ffmpeg', '-y', '-i', '-', '-vcodec', 'copy', '-acodec', 'copy', '-f', 'mp4', os.path.join(PROCESSED_VIDS_PATH, str(id) + ".mp4")]
        process = subprocess.Popen(command, stdin=subprocess.PIPE)
        print("parent process is going")
        recording_ogg, errordata = process.communicate(f.read())
        f.close()
        print(errordata)
        print(recording_ogg)
        
        return jsonify(success=True, id=id), 200
    
    # file_path = os.path.join(MEDIA_PATH, request.form['filepath'])
    # with open(file_path, "w+b") as f:
    #     f.write(request.form['file_data'])
    
    return jsonify(success=True), 200
    
if __name__ == '__main__':
    if not os.path.isfile(DIRECTORY_PKL):
        with open(DIRECTORY_PKL, "w+b") as f:
            pickle.dump(directory, f)
    else:
        with open(DIRECTORY_PKL, "rb") as f:
            directory = pickle.load(f)
    
    file_handler = DriveHandler()
    observer = Observer()
    observer.schedule(file_handler, path=MEDIA_PATH, recursive=True)
    observer.start()
    APP.run(host='0.0.0.0', port=os.getenv('FLASK_PORT'))
    observer.stop()
    observer.join()