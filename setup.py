from setuptools import setup, find_packages

setup(
    name='Bluto',
    version='1.1.5',
    author='Darryl lane',
    author_email='DarrylLane101@gmail.com',
    url='https://github.com/RandomStorm/Bluto',
    packages=find_packages() + ['Bluto'],
    include_package_data=True,
    license='LICENSE.txt',
    description='DNS recon, brutfocing, DNS transfers.',
    long_description=open('README.md').read(),
    scripts=['Bluto/bluto.py'],
    install_requires=[
        "dnspython",
        "termcolor",
        "BeautifulSoup4",
    ],
)

