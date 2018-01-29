#!/usr/bin/env python
from setuptools import setup, find_packages
from distutils.util import convert_path

main_ns = {}
ver_path = convert_path('web/version.py')
with open(ver_path) as ver_file:
    exec(ver_file.read(), main_ns)

setup(
    name='ocloud-base-flask',
    description='Base flask template',
    version=main_ns['__version__'],
    url='https://github.com/jorgensoares/ocloud-flask-base',
    author='Jorge Soares',
    packages=find_packages(exclude=['tests']),
    entry_points={
        'console_scripts': [
            'ocloud-server = app:main'
        ]
    },
    install_requires=['flask',
                      'python-crontab',
                      'flask_sqlalchemy',
                      'MySQL-python',
                      'flask-login',
                      'flask-restful',
                      'requests',
                      'werkzeug',
                      'itsdangerous',
                      'Flask-Mail',
                      'Flask-WTF',
                      'Flask-Principal',
                      'psutil',
                      'pytz',
                      'wtforms'],

    include_package_data=True,
    zip_safe=False,
)
