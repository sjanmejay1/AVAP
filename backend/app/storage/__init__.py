"""Object storage for raw scanner output (local directory or S3).

Business logic depends only on the ObjectStorage interface; which backend
is used is decided by configuration in `factory.build_object_storage`.
"""
