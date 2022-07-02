import scapy.all as scapy
import argparse

def get_arguments():
    parser = argparse.OptionParser()
    parser.add_option("-t", "--target", dest="target", help="Target IP / IP range")
    options = parser.parse_args()
    return options
   
def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    success_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    

    target_list = []
    for elements in success_list:
        target_dict = {"ip": elements[1].psrc, "mac": elements[1].hwsrc}
        target_list.append(target_dict)
    return target_list
    
def show_result(result_list):
    print("IP\t\t\tMAC Adress\n--------------------------------")
    for target in result_list:
        print(target["ip"] + "\t\t" + target["mac"])
        
options = get_arguments()
scan_result = scan(options.target)
show_result(scan_result)





