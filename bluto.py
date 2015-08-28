from multiprocessing.dummy import Pool as ThreadPool 
import dns.resolver, dns.query, dns.zone
import sys, time, datetime, socket
from NetcraftAPI import NetcraftAPI

domain = raw_input("\nTarget Domain: ")

filename = "subdomains-top1mil-20000.txt"
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
        print "\n", ns, "Not Vulnerable"
    
    for ns in vulnerable_listT:
        print "\n", ns, "Is Vulnerable\n"
        z = dns.zone.from_xfr(dns.query.xfr(ns, domain))
        names = z.nodes.keys()
        names.sort()        
        for n in names:
            print z[n].to_text(n)
            
    return vulnerable_listT


def get_details(domain):
    try:
        ns_list = []
        zn_list =[]
        mx_list = []        
        myAnswers = myResolver.query(domain, "NS")
        print "\nName Server:\n"
        for data in myAnswers.rrset:
            data1 = str(data)
            data2 = (data1.rstrip('.'))
            addr = socket.gethostbyname(data2)
            ns_list.append(data2 + ' ' + addr)
            zn_list.append(data2)
            list(set(ns_list))
            ns_list.sort()
        for i in ns_list:
            print i    
        myAnswers = myResolver.query(domain, "MX")
        print "\nMail Server:\n\n",
        for data in myAnswers:
            data1 = str(data)
            data2 = (data1.split(' ',1)[1].rstrip('.'))
            addr = socket.gethostbyname(data2)
            mx_list.append(data2 + ' ' + addr)
            list(set(mx_list))
            mx_list.sort()
        for i in mx_list:
            print i
    except:
        e = str(sys.exc_info()[0])
        print "\nCheck The Target Domain Is Correct!\n\nQuitting.."
        sys.exit()
       
        
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
    
def get_subs():
    full_list = []
    subs = [line.rstrip('\n') for line in open(filename)]
    for sub in subs:
        full_list.append(str(sub + "." + domain))
    
    return full_list


def get_netcraft(domain):
    netcraft_list = []
    print "\nPassive Gatherings From NetCraft\n"
    res = NetcraftAPI({'verbose': True}).search(domain)
    
    for item in res:
        data1 = str(item + "." + domain)
        addr = socket.gethostbyname(data1)
        netcraft_list.append(item + "." + domain + " " + addr)
        #print str(item + "." + domain + " " + addr)
    
    netcraft_list.sort()
        
    for item in netcraft_list:
            print item
            
    return netcraft_list    



if __name__ == "__main__":
#Detail Call
    zn_list = get_details(domain)
#NetCraft Call
    netcraft_list = get_netcraft(domain)
#ZoneTrans Call    
    vulnerable_list = zone_trans(zn_list, domain)
    
    if vulnerable_list == []:
        print "\nNone of the Name Servers are vulnerable to Zone Transfers"
#Bruting
        check_count = line_count(filename)
        subs = get_subs()
        
        pool = ThreadPool(12)
    
        print """
        Note:                                                                        
        Bluto is attempting to brute force the target domain. Newly found 
        targets will be aded to the already identified targets from Netcraft.
        They will be sorted for duplications and printed back to the screen                                                                                      
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
        for item in domains:
            print item
    
        time_spent = time.time() - start_time
    
        print "\nRequests executed:", str(check_count) + " in " + str(datetime.timedelta(seconds=(time_spent))) + " seconds"