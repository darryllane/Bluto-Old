                                                                                
                                                                                
BBBBBBBBBBBBBBBBB  lllllll                       tttt                          
B::::::::::::::::B l:::::l                     ttt:::t                          
B::::::BBBBBB:::::Bl:::::l                     t:::::t                          
BB:::::B     B:::::l:::::l                     t:::::t                          
  B::::B     B:::::Bl::::luuuuuu    uuuuuttttttt:::::ttttttt      ooooooooooo   
  B::::B     B:::::Bl::::lu::::u    u::::t:::::::::::::::::t    oo:::::::::::oo 
  B::::BBBBBB:::::B l::::lu::::u    u::::t:::::::::::::::::t   o:::::::::::::::o
  B:::::::::::::BB  l::::lu::::u    u::::tttttt:::::::tttttt   o:::::ooooo:::::o
  B::::BBBBBB:::::B l::::lu::::u    u::::u     t:::::t         o::::o     o::::o
  B::::B     B:::::Bl::::lu::::u    u::::u     t:::::t         o::::o     o::::o
  B::::B     B:::::Bl::::lu::::u    u::::u     t:::::t         o::::o     o::::o
  B::::B     B:::::Bl::::lu:::::uuuu:::::u     t:::::t    ttttto::::o     o::::o
BB:::::BBBBBB::::::l::::::u:::::::::::::::uu   t::::::tttt:::::o:::::ooooo:::::o
B:::::::::::::::::Bl::::::lu:::::::::::::::u   tt::::::::::::::o:::::::::::::::o
B::::::::::::::::B l::::::l uu::::::::uu:::u     tt:::::::::::ttoo:::::::::::oo 
BBBBBBBBBBBBBBBBB  llllllll   uuuuuuuu  uuuu       ttttttttttt    ooooooooooo   
                                                            
 
Bluto: DNS recon | Brute forcer | DNS Zone Transfer,.

 The target domain is queried for MX and NS records. SubDomains are passively gathered via NetCraft. The target domain then
 queries each NS server for potential Zone Transfers.
 If none of them gives up their spinach, Bluto will brute force subdomains using parallel sub processing on the top 20000 of the
 The Alexa Top 1 Million subdomains. NetCraft results are presented individually and are then compared to the brute force
 results, duplications are removed and particularly interesting results are highlighted.

             Author: Darryl Lane  |  Twitter: @darryllane101
               https://github.com/RandomStormProjects/Bluto


 Install Instructions
 ====================
 All you need to use Bluto is the distribution file.
 
 Bluto requires various other dependencies. So to make things as easy as possible I
 have created a distribution package to install the relevant dependents during the
 install. For the install to work correctly please install 'easy_install'.

 You can find instructions for installing easy_install/setuptools from here 
 https://pypi.python.org/pypi/setuptools.


1.Mac and Unix users can simply use the following command; 

>sudo curl https://bootstrap.pypa.io/ez_setup.py -o - | python


2.Once the setuptools/easy_install, install is completed download the distro from here: 
  https://github.com/RandomStormProjects/Bluto/blob/master/Bluto-1.0.0.tar.gz (right click the link and save)
  and execute the following.

>sudo easy_install Bluto-1.0.0.tar.gz

 Note: You can use pip to install aswell (if you already have this installed, to check if it is installed type ‘pip’. pip
       install Bluto-1.0.0.tar.gz.

3.You should now be able to execute the script from any working dir in a terminal (may
  need to close and reopen if in the same terminal as the one used to run the setup
  initially). 

>bluto.py



