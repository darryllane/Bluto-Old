**BLUTO**
-----
**DNS recon | Brute forcer | DNS Zone Transfer**
 
>Author: Darryl Lane  |  Twitter: @darryllane101

>https://github.com/RandomStorm/Bluto


The target domain is queried for MX and NS records. Sub-domains are passively gathered via NetCraft. The target domain NS records are each queried for potential Zone Transfers. If none of them gives up their spinach, Bluto will brute force sub-sdomains using parallel sub processing on the top 200000 sub-domains. Running on my MAC with an i5 core, I hit all 200000 subs in less than a second. The sub-domain list `masslist.txt` is a combination of the 'Zone Transfers on The Alexa Top 1 Million' list from Ryan's blog <http://tinyurl.com/DewhurstSecurityBlog> and various other sub-domains gathered from the far corners of the Web. NetCraft results are presented individually and are then compared to the brute force results, any duplications are removed and particularly interesting results are highlighted.
         
Bluto requires various other dependencies. So to make things as easy as possible, `pip` is used for the installation. This does mean you will need to have pip installed prior to attempting the Bluto install.

**Pip Install Instructions**

Note: To test if pip is already installed execute.

`pip -V`

(1) Mac and Kali users can simply use the following command to download and install `pip`.

`curl https://bootstrap.pypa.io/get-pip.py -o - | python`

**Bluto Install Instructions**

(1) Once `pip` has successfully downloaded and installed, we can install Bluto:

`pip install git+git://github.com/RandomStorm/Bluto`

(2) You should now be able to execute 'bluto.py' from any working directory in any terminal.
 
`bluto.py`

**Upgrade Instructions**

(1) The upgrade process is as simple as;

`pip install git+git://github.com/RandomStorm/Bluto --upgrade`

