#!/usr/local/bin/python

from multiprocessing.dummy import Pool as ThreadPool 
import dns.resolver, dns.query, dns.zone
import sys, time, datetime, socket, os, math
from termcolor import colored
import requests, re, collections
from bs4 import BeautifulSoup
import urllib2, hashlib, json, site

def output_data(target_dict, sub_intrest):
    print "Bluto Results: \n"
    for item in target_dict:
        if item in sub_intrest:
            print colored(item + "\t", 'red'), colored(target_dict[item], 'red')
        else:
            print item + "\t",target_dict[item]

    time_spent = time.time() - start_time
    print "\nRequests executed:", str(check_count) + " in " + str(datetime.timedelta(seconds=(time_spent))) + " seconds"
                
def zone_trans(zn_list, domain):
    print "\nAttempting Zone Transfers"
    zn_list.sort()
    vuln = True
    vulnerable_listT = []
    vulnerable_listF = []
    dump_list = []
    for ns in zn_list:
        try:
            z = dns.zone.from_xfr(dns.query.xfr(ns, domain))
            names = z.nodes.keys()
            names.sort()
            if vuln == True:
                vulnerable_listT.append(ns)
                            
        except Exception as e:
            error = str(e)
            if error == "[Errno 54] Connection reset by peer" or "No answer or RRset not for qname":
                vuln = False
                vulnerable_listF.append(ns)
            else:
                print """An unexpected error has occured. Please report the error and its context to https://github.com/RandomStormProjects/Bluto/issues, thank you.
                """            
                
    
    if vulnerable_listF:
        print "\nNot Vulnerable:\n"
        for ns in vulnerable_listF:
            print colored(ns, 'green')
    
    if vulnerable_listT:
        print "\nVulnerable:\n"
        for ns in vulnerable_listT:
            print colored(ns,'red'), colored("\t" + "TCP/53", 'red')

   
        z = dns.zone.from_xfr(dns.query.xfr(vulnerable_listT[0], domain))
        names = z.nodes.keys()
        names.sort()
        print "\nRaw Zone Dump\n"
        for n in names:
            data1 = "{}.{}" .format(n,domain)
            try:
                addr = socket.gethostbyname(data1)
                dump_list.append("{}.{} {}" .format(n, domain, addr))
            
            except Exception as e:
                error = str(e)
                if error == "[Errno -5] No address associated with hostname":
                    pass
                else:
                    print """An unexpected error has occured. Please report the error and its context to https://github.com/RandomStormProjects/Bluto/issues, thank you.
                    """
            print z[n].to_text(n)

        clean_dump = sorted(set(dump_list))
        target_dict = dict((x.split(' ') for x in clean_dump))
        clean_target = collections.OrderedDict(sorted(target_dict.items()))
        print "\nProcessed Dump\n"
        for item in clean_target:
            if item in sub_intrest:
                print colored(item, 'red'), colored("\t" + clean_target[item], 'red')
            else:
                print item, "\t" + target_dict[item]
    
    
    return vulnerable_listT


def get_details(domain):
    ns_list = []
    zn_list =[]
    mx_list = []        
    try:
        print "\nName Server:\n"
        myAnswers = myResolver.query(domain, "NS")
        for data in myAnswers.rrset:
            data1 = str(data)
            data2 = (data1.rstrip('.'))
            addr = socket.gethostbyname(data2)
            ns_list.append(data2 + '\t' + addr)
            zn_list.append(data2)
            list(set(ns_list))
            ns_list.sort()
        for i in ns_list:
            print colored(i, 'green')
    except:
        e = str(sys.exc_info()[0])
        print "\nCheck The Target Domain Is Correct!\n\nQuitting.."
        sys.exit()
        
    try:    
        print "\nMail Server:\n"
        myAnswers = myResolver.query(domain, "MX")
        for data in myAnswers:
            data1 = str(data)
            data2 = (data1.split(' ',1)[1].rstrip('.'))
            addr = socket.gethostbyname(data2)
            mx_list.append(data2 + '\t' + addr)
            list(set(mx_list))
            mx_list.sort()
        for i in mx_list:
            print colored(i, 'green')
    except:
        e = str(sys.exc_info()[0])
        print "\tNo Mail Servers"   
       
        
    return zn_list

def line_count(filename):
    lines = 0
    for line in open(filename):
        lines += 1
    return lines

def get_brutes(subdomain):
    try:
        myAnswers = myResolver.query(subdomain)
        for data in myAnswers:
            targets.append(subdomain + ' ' + str(data))
            
    except Exception as e:
        pass
    
def get_subs(filename):
    full_list = []
    try:    
        subs = [line.rstrip('\n') for line in open(filename)]
        for sub in subs:
            full_list.append(str(sub.lower() + "." + domain))
    except Exception as e:
        print """\n\tBluto can't find its Subdomain list. Please make sure 'subdomains-top1mil-20000.txt' is {}.""". format (str(path) + "/Bluto/doc/subdomains-top1mil-20000.txt")
        sys.exit()
        
    return full_list    
        
def get_sub_interest(filename):
    full_list = []
    try:
        subs = [line.rstrip('\n') for line in open(filename)]
        for sub in subs:
            full_list.append(str(sub.lower() + "." + domain))
    
    except Exception as e:
        print """\n\tBluto can't find its Sub_Interest list. Please make sure 'sub_interest.txt' is in Bludo's root directory."""
        sys.exit()
        
    return full_list


def get_netcraft(domain):
    netcraft_list = []
    print "\nPassive Gatherings From NetCraft\n"
    res = NetcraftAPI({'verbose': True}).search(domain)
    
    for item in res:
        data1 = str(item + "." + domain)
        try:
            addr = socket.gethostbyname(data1)
            netcraft_list.append(item + "." + domain + " " + addr)
        except Exception as e:
            error = str(e)
            print """An unexpected error has occured. Please report the error and its context to https://github.com/RandomStormProjects/Bluto/issues, thank you."""
            print error
            continue
            
    netcraft_list.sort()
        
    for item in netcraft_list:
            print colored(item, 'red')
            
    return netcraft_list    
        
class NetcraftAPI(object):
    """
    This is the (unofficial) Python API for netcraft.com Website.
    Using this code, you can retrieve subdomains. This has been modified
    from its original state that can be found on the following url. 
    https://github.com/PaulSec/API-netcraft.com
    
    """    

    """
        NetcraftAPI Main Handler
    """

    _instance = None
    _verbose = False

    def __init__(self, arg=None):
        pass

    def __new__(cls, *args, **kwargs):
        """
            __new__ builtin
        """
        if not cls._instance:
            cls._instance = super(NetcraftAPI, cls).__new__(
                cls, *args, **kwargs)
            if (args and args[0] and args[0]['verbose']):
                cls._verbose = True
        return cls._instance

    def display_message(self, s):
        if (self._verbose):
            print '%s' % s

    def search(self, domain):
        res = []
        url = "http://searchdns.netcraft.com/?restriction=site+contains&host=*.%s&lookup=wait..&position=limited" % domain
        s = requests.session()
        s.get('http://searchdns.netcraft.com/')
        req = s.get(url)

        challenge_cookie = req.headers['set-cookie'].split('=')[1].split(';')[0]
        string = urllib2.unquote(challenge_cookie)
        challenge_cookie_value = hashlib.sha1(string).hexdigest()
        cookies = {'netcraft_js_verification_response': challenge_cookie_value}

        req = s.get(url, cookies = cookies)
        soup = BeautifulSoup(req.content, "lxml")

        pattern = 'Found (\d+) site'
        number_results = re.findall(pattern, req.content)

        if (len(number_results) > 0 and number_results[0] != '0'):
            number_results = int(number_results[0])
            number_pages = int(math.ceil(number_results / 20)) + 1

            pattern = 'rel="nofollow">([a-z\.\-A-Z0-9]+)<FONT COLOR="#ff0000">'
            subdomains = re.findall(pattern, req.content)
            res.extend(subdomains)
            last_result = subdomains[-1]
            # "Last result: %s" % last_result

            for index_page in xrange(1, number_pages):
                url = "http://searchdns.netcraft.com/?host=*.%s&last=%s.%s&from=%s&restriction=site contains&position=limited" % (domain, last_result, domain, (index_page * 20 + 1))
                req = s.get(url, cookies = cookies)
                pattern = 'rel="nofollow">([a-z\-\.A-Z0-9]+)<FONT COLOR="#ff0000">'
                subdomains = re.findall(pattern, req.content)
                # print req.content
                res.extend(subdomains)
                try:
                    for subdomain in subdomains:
                        hostname = ('{}.{}' .format (subdomain, domain))
                        addr = socket.gethostbyname(hostname)                    
                        #self.display_message('{}.{} {}' .format (subdomain, domain, addr))
                except Exception as e:
                    pass
                last_result = subdomains[-1]
            return res
        else:
            self.display_message("\tNo results found for %s" % domain)
            return res



print """
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
BBBBBBBBBBBBBBBBB  llllllll   uuuuuuuu  uuuu       ttttttttttt    ooooooooooo"""
print """
                {2} | {3} | {4}
               {0}  |  {1}
                 {5}
""" . format (colored("Author: Darryl Lane", 'blue'),colored("Twitter: @darryllane101", 'blue'),colored("DNS Recon", 'green'),colored("Brute forcer", 'green'),colored("DNS Zone Transfers", 'green'),colored("https://github.com/RandomStormProjects/Bluto", 'green'))

domain = raw_input("\nTarget Domain: ")
path = str(site.getsitepackages()[0])
filename1 = path + "/Bluto/doc/subdomains-top1mil-20000.txt"
filename2 = path + "/Bluto/doc/sub_interest.txt"
targets = []

myResolver = dns.resolver.Resolver()
myResolver.nameservers = ['8.8.8.8']

if __name__ == "__main__":
#Detail Call
    sub_intrest = get_sub_interest(filename2)
    zn_list = get_details(domain)
#NetCraft Call
    netcraft_list = get_netcraft(domain)
#ZoneTrans Call    
    vulnerable_list = zone_trans(zn_list, domain)
    if vulnerable_list == []:
        print "\nNone of the Name Servers are vulnerable to Zone Transfers\n"
#Bruting
        check_count = line_count(filename1)
        subs = get_subs(filename1)
        pool = ThreadPool(12)
        print """\tNote:\n                                                                        
        Bluto is attempting to brute force the target domain.
        Newly found targets will be aded to the already identified
        targets from Netcraft. They will be sorted for duplications
        and printed back to the screen                                                                                     
        """
        start_time = time.time()
        pool.map(get_brutes, subs)
        pool.close() 
        pool.join()
        if targets == []:
            targets.append("temp-enter")
        
        domains = list(set(targets + netcraft_list))
        domains.sort()
        if "temp-enter" in domains: domains.remove("temp-enter")
        target_dict = dict((x.split(' ') for x in domains))
#Outputing Brute data
        output_data(target_dict, sub_intrest)
        