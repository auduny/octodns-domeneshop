#!/usr/bin/env python

from setuptools import find_packages, setup


def descriptions():
    with open('README.md') as fh:
        ret = fh.read()
        first = ret.split('\n', 1)[0].replace('#', '')
        return first, ret


def version():
    with open('octodns_domeneshop/__init__.py') as fh:
        for line in fh:
            if line.startswith('__version__'):
                return line.split("'")[1]
    raise Exception('Failed to find version')


description, long_description = descriptions()

tests_require = ('pytest', 'pytest-cov', 'pytest-network', 'requests_mock')

setup(
    author='Audun Ytterdal',
    author_email='audun@ytterdal.net',
    description=description,
    extras_require={
        'dev': tests_require
        + (
            'black>=24.3.0,<25.0.0',
            'build>=0.7.0',
            'isort>=5.11.5',
            'pyflakes>=2.2.0',
            'readme_renderer[md]>=26.0',
            'twine>=3.4.2',
        ),
        'test': tests_require,
    },
    install_requires=('octodns>=1.5.0', 'requests>=2.27.0'),
    license='MIT',
    long_description=long_description,
    long_description_content_type='text/markdown',
    name='octodns-domeneshop',
    packages=find_packages(),
    python_requires='>=3.8',
    url='https://github.com/auduny/octodns-domeneshop',
    version=version(),
)
