import os

class Config:
    SECRET_KEY = 'b\x83\xd8\x11\xa5^\xdbPeP\xd2\xf5\xd0{\x1a^\xbd\xfd0\xcb?z{(\xa1'
    SQLALCHEMY_DATABASE_URI = 'sqlite:///cloud_storage.db'
    UPLOAD_FOLDER = 'uploads/'
    MAX_CONTENT_LENGTH = 100 * 1024 * 1024  # Максимальный размер файла (100 МБ)
