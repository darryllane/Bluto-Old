from setuptools import setup, find_packages

setup(
    name='Bluto',
    version='1.0.0',
    author='Darryl lane',
    author_email='DarrylLane101@gmail.com',
    url='https://github.com/RandomStormProjects/Bluto',
    packages=find_packages() + ['Bluto'],
    include_package_data=True,
    license='LICENSE.txt',
    description='DNS recon, brutfocing, DNS transfers.',
    long_description=open('Bluto/doc/README.txt').read(),
    package_data={
    'netcraft': ['Bluto/NetcraftAPI.py'],
},
    scripts=['Bluto/bluto.py'],
    install_requires=[
        "dnspython",
        "termcolor",
        "BeautifulSoup4",
    ],
)

