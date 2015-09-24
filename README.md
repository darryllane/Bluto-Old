**BLUTO**
-----
**DNS recon | Brute forcer | DNS Zone Transfer**
 
>Author: Darryl Lane  |  Twitter: @darryllane101

>https://github.com/RandomStorm/Bluto


The target domain is queried for MX and NS records. SubDomains are passively gathered via NetCraft. The target domain NS servers are each queried for potential Zone Transfers. If none of them gives up their spinach, Bluto will brute force subdomains using parallel sub processing on the top 20000 of the The Alexa Top 1 Million subdomains. NetCraft results are presented individually and are then compared to the brute force results, duplication's are removed and particularly interesting results are highlighted.
         
Bluto requires various other dependencies. So to make things as easy as possible `pip` is used for the installation. This does mean you will need to have pip installed prior to attempting the Bluto install.

**Install Instructions**
Note: To test if pip is already installed execute;

`pip -V`

1. Mac and Kali users can simply use the following command to download and install `pip`;

`curl https://bootstrap.pypa.io/get-pip.py -o - | python`

2. Once `pip` has successfully downloaded and installed, we can install Bluto:
 
`pip install git+git://github.com/RandomStorm/Bluto`

3. You should now be able to execute 'bluto.py' from any working directory in any terminal.
 
`bluto.py`

**Upgrade Instructions**

1. The upgrade process is as simple as;

`pip install git+git://github.com/RandomStorm/Bluto --upgrade`
