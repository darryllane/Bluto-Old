                                                                                
                                                                                
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
               https://github.com/RandomStorm/Bluto

Install Instructions
====================
 All you need to use Bluto is the distribution file.
 
 Bluto requires various other dependencies. So to make things as easy as possible I
 have created a distribution package to install the relevant dependents during the
 install. For the install to work correctly please install 'pip'.

Note: To test if pip is already installed execute;

  >pip -V

  Example:
  root@pentest:~# pip -V
  pip 7.1.2 from /usr/local/lib/python2.7/dist-packages (python 2.7)
  root@pentest:~# 

1.Mac and Kali users can simply use the following command to download and install pip; 

  >sudo curl https://bootstrap.pypa.io/get-pip.py -o - | python

  Example:
  root@pentest:~# sudo curl https://bootstrap.pypa.io/get-pip.py -o - | python
  
    % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                   Dload  Upload   Total   Spent    Left  Speed
  100 1379k  100 1379k    0     0  2323k      0 --:--:-- --:--:-- --:--:-- 2450k
  Requirement already up-to-date: pip in /usr/local/lib/python2.7/dist-packages
  root@pentest:~# 

2.Once pip has successfully downloaded and installed, we can install Bluto:

  Example:
  root@pentest:~ git clone https://github.com/RandomStorm/Bluto.git
  
  Cloning into 'Bluto'...
  remote: Counting objects: 112, done.
  remote: Compressing objects: 100% (7/7), done.
  remote: Total 112 (delta 2), reused 0 (delta 0), pack-reused 105
  Receiving objects: 100% (112/112), 1.25 MiB | 926.00 KiB/s, done.
  Resolving deltas: 100% (37/37), done.
  Checking connectivity... done.
  root@pentest:~ 
  

  >sudo pip install Bluto-1.1.0.tar.gz

  Example:
  root@pentest:~/Desktop# pip install Bluto-1.1.0.tar.gz 
  
  Processing ./Bluto-1.1.0.tar.gz
  Requirement already satisfied (use --upgrade to upgrade): 
  dnspython in /usr/local/lib/python2.7/dist-packages (from Bluto==1.1.0)
  Requirement already satisfied (use --upgrade to upgrade): 
  termcolor in /usr/local/lib/python2.7/dist-packages/termcolor-1.1.0-py2.7.egg (from Bluto==1.1.0)
  Requirement already satisfied (use --upgrade to upgrade): 
  BeautifulSoup4 in /usr/local/lib/python2.7/dist-packages (from Bluto==1.1.0)
  Installing collected packages: Bluto
  Running setup.py install for Bluto
  Successfully installed Bluto-1.1.0
  root@pentest:~/Desktop#

3.You should now be able to execute 'bluto.py' from any working directory in any terminal ( you may
  need to close and reopen if in the same terminal as the one used to run the setup initially). 

  >bluto.py

  Example:
  root@pentest:~/Desktop# bluto.py 

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
                                                            
 
              DNS recon | Brute forcer | DNS Zone Transfers

              Author: Darryl Lane  |  Twitter: @darryllane101
             
               https://github.com/RandomStorm/Bluto
               
  Target Domain:

Upgrade Instructions
====================

1. Simply use the upgrade switch once the new updated distibution has been downloaded:
  
  Example:
  root@pentest:/ pip install Bluto-1.1.2.tar.gz  --upgrade
  Processing ./Bluto-1.1.2.tar.gz
  Requirement already up-to-date: dnspython in /usr/local/lib/python2.7/dist-packages (from Bluto==1.1.2)
  Requirement already up-to-date: termcolor in /usr/local/lib/python2.7/dist-packages/termcolor-1.1.2-py2.7.egg 
  (from Bluto==1.1.2)
  Requirement already up-to-date: BeautifulSoup4 in /usr/local/lib/python2.7/dist-packages (from Bluto==1.1.2)
  
  Installing collected packages: Bluto
    Found existing installation: Bluto 1.1.2
      Uninstalling Bluto-1.1.2:
      Successfully uninstalled Bluto-1.1.2
    Running setup.py install for Bluto
  Successfully installed Bluto-1.1.2
  root@pentest:/
