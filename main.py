from starlette.applications import Starlette as API
from starlette.requests import Request
from starlette.responses import Response
from functools import wraps
from marshmallow import Schema, fields, validate
from starlette.datastructures import UploadFile
from starlette.exceptions import HTTPException

from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy import Column, Integer, String

import uvicorn
import inspect
import tracemalloc
import json
import asyncio
import jwt
import hashlib

JWT_KEY = 'authorization'


class BaseException(Exception):

    def __init__(self, msg="", *args: object) -> None:
        super().__init__(*args)
        self.msg = msg


class BadRequest(BaseException):
    def __init__(self, msg="Bad request", errors={}, *args: object) -> None:
        super().__init__(msg, *args)
        self.errors = errors


class Forbidden(BaseException):
    def __init__(self, msg="Forbidden", errors={}, *args: object) -> None:
        super().__init__(msg, *args)
        self.errors = errors


class NotFound(BaseException):
    def __init__(self, msg="NotFound", errors={}, *args: object) -> None:
        super().__init__(msg, *args)
        self.error = errors


class InternalAPI(API):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        async def exc_method_not_allow(request: Request, exc: HTTPException):
            return Response(
                content=json.dumps({
                    'data': '',
                    'msg': 'Method not allow',
                    'error': {}
                }),
                status_code=405,
                headers={'Content-type': 'application/json'}
            )

        async def exc_not_found(request: Request, exc: HTTPException):
            return Response(
                content=json.dumps({
                    'data': '',
                    'msg': 'Not found',
                    'error': {}
                }),
                status_code=404,
                headers={'Content-type': 'application/json'}
            )

        _excs = self.exception_handlers
        self.exception_handlers = {
            **_excs,
            405: exc_method_not_allow,
            404: exc_not_found
        }

    def add_api(
        self,
        path: str,
        api
    ):
        _meths = inspect.getmembers(api, predicate=inspect.ismethod)
        for (method, func) in _meths:
            if method.upper() in ['GET', 'POST', 'PUT', 'DELETE']:
                self.add_route(path, func, methods=[method.upper()])


def http(
    is_login=False,
    query_params: Schema = None,
    form_data: Schema = None,
    path_params: Schema = None,
):

    def validate_authen(request: Request):
        try:
            _authorization = request.headers.get('authorization')
            if not _authorization:
                raise
            _type, _token = _authorization.split()
            if _type.lower() != 'bearer':
                raise
            _decode = jwt.decode(_token, key=JWT_KEY, algorithms=['HS256'])
            return _decode
        except:
            raise Forbidden(errors={'user': 'User invalid'})

    def http_internal(f):
        @wraps(f)
        async def decorated(*args, **kwargs):
            tracemalloc.start()

            _res = {
                'data': '',
                'msg': '',
                'errors': {},
            }
            try:
                _kwargs = {}
                _request: Request = args[1]
                _self = args[0]
                if is_login:
                    _payload = validate_authen(_request)
                    _kwargs['user'] = _payload

                if query_params:
                    _params_data = _request.query_params._dict
                    _validate = query_params.validate(_params_data)
                    if _validate:
                        raise BadRequest(errors=_validate)
                    _data = json.loads(query_params.dumps(_params_data))
                    _kwargs['query_params'] = _data

                if path_params:
                    _path_data = _request.path_params
                    _validate = path_params.validate(_path_data)
                    if _validate:
                        raise BadRequest(errors=_validate)
                    _data = json.loads(path_params.dumps(_path_data))
                    _kwargs['path_params'] = _data

                if form_data:
                    _content_type = _request.headers.get('content-type')
                    if _content_type is None:
                        raise BadRequest(errors=form_data.validate({}))

                    if _content_type == 'application/json':
                        _form_data = await _request.json()
                        _validate = form_data.validate(_form_data)
                        if _validate:
                            raise BadRequest(errors=_validate)
                        _kwargs['form_data'] = json.loads(
                            form_data.dumps(_form_data))

                    elif _content_type.startswith('multipart/form-data'):
                        async with _request.form() as form:
                            _data = {}
                            for k, v in form._dict.items():
                                if isinstance(v, UploadFile):
                                    _data[k] = await v.read()
                                else:
                                    _data[k] = v
                            _validate = form_data.validate(_data)
                            if _validate:
                                raise BadRequest(errors=_validate)
                            _kwargs['form_data'] = json.loads(
                                form_data.dumps(_data))
                if asyncio.iscoroutinefunction(f):
                    _response = await f(_self, **_kwargs)
                else:
                    _response = f(_self, **_kwargs)
                if isinstance(_response, Response):
                    return _response
                else:
                    _res['data'] = _response
                return Response(
                    content=json.dumps(_res),
                    status_code=200,
                    headers={'Content-type': 'application/json'}
                )
            except Exception as e:
                _exc_header = {'Content-type': 'application/json'}
                _status = 400
                if isinstance(e, BadRequest):
                    _res['errors'] = e.errors
                    _res['msg'] = e.msg
                    _status = 400
                elif isinstance(e, Forbidden):
                    _res['errors'] = e.errors
                    _res['msg'] = e.msg
                    _status = 403
                elif isinstance(e, NotFound):
                    _status = 404
                    _res['msg'] = e.msg
                else:
                    _res['errors'] = str(e)
                    _status = 400
                tracemalloc.stop()
                return Response(json.dumps(_res), status_code=_status, headers=_exc_header)
        return decorated
    return http_internal


"""
======================================================================================
======================================================================================
======================================================================================
======================================================================================
"""
SQLALCHEMY_DATABASE_URL = "sqlite:///./sql_app.db"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False}
)
Session = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


class Model(Base):
    __abstract__ = True
    __table_args__ = {'extend_existing': True}

    @property
    def as_dict(self):
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}


class UserModel(Model):
    __tablename__ = "user"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    username = Column(String, unique=True, index=True)
    password = Column(String)
    age = Column(Integer)
    role = Column(String)


class UserSchema(Schema):
    username = fields.Str(required=True)
    password = fields.Str(required=True)
    age = fields.Integer(required=False, validate=validate.Range(min=1))
    role = fields.Str(required=False, validate=validate.OneOf(
        ['admin', 'user']), default='user')


class LoginSchema(Schema):
    username = fields.Str(required=True)
    password = fields.Str(required=True)


class UpdateSchema(Schema):
    password = fields.Str(required=False)
    age = fields.Integer(required=False, validate=validate.Range(min=1))


class DeleteSchema(Schema):
    username = fields.Str(required=True)


class User:

    @http(is_login=True)
    def get(self, user):
        with Session() as sess:
            _user = sess.query(UserModel).filter_by(**user).first()
        if not _user:
            raise BadRequest(errors={'user': 'Not have user'})
        return _user.as_dict

    @http(form_data=UserSchema())
    def post(self, form_data):
        with Session() as sess:
            _user = sess.query(UserModel).filter(
                UserModel.username == form_data.get('username'))
            if _user.count() > 0:
                raise BadRequest(errors={'info': 'User existed'})
            _password = form_data.get('password')
            form_data['password'] = hashlib.md5(_password.encode()).hexdigest()
            user = UserModel(**form_data)
            sess.add(user)
            sess.commit()
        return True

    @http(form_data=UpdateSchema(), is_login=True)
    def put(self, form_data, user):
        if form_data.get('password'):
            form_data['password'] = hashlib.md5(
                form_data.get('password').encode()).hexdigest()
        with Session() as sess:
            _user = sess.query(UserModel).filter_by(**user)
            _user.update(form_data)
            sess.commit()
        return True

    @http(form_data=DeleteSchema(), is_login=True)
    def delete(self, form_data, user):
        with Session() as sess:
            _user = sess.query(UserModel).filter_by(**user).first()
            if not _user:
                raise BadRequest(errors={'user': 'Not have user'})
            if _user.role != 'admin':
                raise Forbidden(errors={'user': 'Permission denined'})
            sess.query(UserModel).filter_by(**form_data).delete()
            sess.commit()
        return True


class Login:

    @http(form_data=LoginSchema())
    def post(self, form_data):
        with Session() as sess:
            _password = form_data.get('password')
            _password = hashlib.md5(_password.encode()).hexdigest()
            _user = sess.query(UserModel).filter(
                UserModel.username == form_data.get('username'),
                UserModel.password == _password
            )
            if _user.count() == 0:
                raise BadRequest(errors={'info': 'User not existed'})
            _userInfo = _user.all()
            _userInfo = [i.as_dict for i in _userInfo]
        _access_token = jwt.encode(
            {'username': _userInfo[0].get('username')}, key=JWT_KEY)
        return {'access_token': _access_token}


app = InternalAPI()
app.add_api('/user', User())
app.add_api('/login', Login())

if __name__ == '__main__':
    Model.metadata.create_all(engine)
    uvicorn.run("main:app", port=5005, reload=True, log_level='debug')
