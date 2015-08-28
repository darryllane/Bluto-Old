from multiprocessing.dummy import Pool as ThreadPool 
import dns.resolver, dns.query, dns.zone
import sys, time, datetime, socket, os
from termcolor import colored
netcraftapi = '~/lib/NetcraftAPI.py'
sys.path.append(os.path.dirname(os.path.expanduser(netcraftapi)))
from NetcraftAPI import NetcraftAPI

domain = raw_input("\nTarget Domain: ")

#filename1 = "dns.txt"
filename1 = "subdomains-top1mil-20000.txt"

filename2 = "sub_interest.txt"

targets = []
myResolver = dns.resolver.Resolver()
myResolver.nameservers = ['8.8.8.8']

def zone_trans(zn_list, domain):
    print "\nAttemping Zone Transfers"
    zn_list.sort()
    vuln = True
    vulnerable_listT = []
    vulnerable_listF = []
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
                
    
    for ns in vulnerable_listF:
        print colored("\n\t", 'green'), colored(ns, 'green'), colored("Not Vulnerable", 'green')
    
    for ns in vulnerable_listT:
        print colored("\n\t", 'red'), colored(ns,'red'), colored("Is Vulnerable\n", 'red')
        z = dns.zone.from_xfr(dns.query.xfr(ns, domain))
        names = z.nodes.keys()
        names.sort()        
        for n in names:
            print z[n].to_text(n)
            
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
            ns_list.append(data2 + ' ' + addr)
            zn_list.append(data2)
            list(set(ns_list))
            ns_list.sort()
        for i in ns_list:
            print "\t", colored(i, 'red')
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
            mx_list.append(data2 + ' ' + addr)
            list(set(mx_list))
            mx_list.sort()
        for i in mx_list:
            print "\t", colored(i, 'red')
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
        print """\n\tBluto can't find its Subdomain list. Please make sure 'subdomains-top1mil-20000.txt' is in Bludo's root directory."""
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
        addr = socket.gethostbyname(data1)
        netcraft_list.append(item + "." + domain + " " + addr)
    
    netcraft_list.sort()
        
    for item in netcraft_list:
            print "\t", colored(item, 'red')
            
    return netcraft_list    



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
        
        print "\nBluto Results: \n"
        
        target_dict = dict((x.split(' ') for x in domains))
        for item in target_dict:
            if item in sub_intrest:
                print "\t", colored(item, 'red'), colored(target_dict[item], 'red')
            else:
                print "\t", item, target_dict[item]
    
        time_spent = time.time() - start_time
        print "\nRequests executed:", str(check_count) + " in " + str(datetime.timedelta(seconds=(time_spent))) + " seconds"