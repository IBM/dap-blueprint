import os, json
from flask import request, Response
from flask_restx import Resource, Namespace, fields
from .signing_service import SigningService
import dap_consts

PREPARED_DIR = '/data/prepared'
SIGNED_DIR = '/data/signed'
os.makedirs(PREPARED_DIR, exist_ok=True)
os.makedirs(SIGNED_DIR, exist_ok=True)

ss = SigningService(dap_consts.reboot)

api = Namespace('feed', description='Feed APIs for IBM Bridge')

##### Upload response model #####
upload_response_model = api.model('UploadResponse', {
    'msg': fields.String(description='msg'),
})

##### Status response model #####
status_response_model = api.model('StatusResponse', {
    'status': fields.String(description='satus message'),
})

##### Download response model #####
download_response_model = api.model('DownloadResponse', {
    'binary': fields.String(description='Contents of a downloaded file')
})

@api.route('/upload')
class Upload(Resource):

    @api.response(code=200, description='Success', model=upload_response_model)
    @api.doc(description='This API uploads a prepared file.')
    def post(self):
        if 'files' not in request.files:
            return {'msg': 'files is required'}, 200

        file = request.files['files']
        filename = file.filename
        if '' == filename:
            return {'msg': 'filename must not be empty'}, 200

        prepared_file_path = os.path.join(PREPARED_DIR, filename)
        file.save(prepared_file_path)

        doc = None
        with open(prepared_file_path, 'rb') as f:
            doc = json.load(f)
        
        if doc is None:
            return {'msg': 'Failed to load {}'.format(prepared_file_path)}
        
        doc = ss.process(doc, no_enqueue=True)
        os.remove(prepared_file_path)

        signed_file_path = os.path.join(SIGNED_DIR, filename)
        with open(signed_file_path, 'w') as f:
            json.dump(doc, f)

        return {'msg': 'Saved to {}'.format(signed_file_path)}

@api.route('/download')
class Download(Resource):

    @api.response(code=200, description='Success', model=download_response_model)
    @api.doc(description='This API downloads a signed file.')
    def get(self):
        for file_name in os.listdir(SIGNED_DIR):
            file_path = os.path.join(SIGNED_DIR, file_name)
            with open(file_path, 'rb') as f:
                contents = f.read()
                os.remove(file_path)
                return Response(contents,
                                mimetype='application/zip',
                                headers={'Content-Disposition': 'attachment; filename={}'.format(file_name)})
        return {'file_path': None}

@api.route('/status')
class Status(Resource):

    @api.response(code=200, description='Success', model=status_response_model)
    @api.doc(description='This API returns a signing status.')
    def get(self):
        return {'status': 'done'}
