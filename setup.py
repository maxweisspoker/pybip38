from setuptools import setup, find_packages

setup(
    name='pybip38',
    version='0.9',
    install_requires=['pycrypto','scrypt','simplebitcoinfuncs'],
    description='My python implementation of the full BIP0038 spec',
    url='https://github.com/maxweisspoker/pybip38',
    keywords='bitcoin bip38 bip0038 bip BIP 38 BIP38 BIP0038 password encryption casascius private key',
    author='Maximilian Weiss',
    author_email='MaxWeiss@hotmail.com',
    license='MIT',
    packages=find_packages(),
    classifiers=[
        'Development Status :: 4 - Beta',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.2',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5'
    ],
)

