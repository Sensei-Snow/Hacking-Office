# ---------------------------------------------------------------------------------- Importer les bibliothèques
import pyfiglet
import time
from plyer import notification
from scapy.all import sniff, ARP, Ether, srp

# ---------------------------------------------------------------------------------- Créer et afficher la fonction pour le logo
def show_logo():
    ascii_banner = pyfiglet.figlet_format("IntruSpotter")
    print(ascii_banner)
show_logo()

# ---------------------------------------------------------------------------------- Presser la touche entrée
while True:
    confirmation = str(input("Press the Enter key "))
    if confirmation =="":
        break
    else:
        print("[Warning] -- Wrong command")
        continue
print("")

# ---------------------------------------------------------------------------------- Afficher les règles et demander l'accord
print("This tool has been created for learning purposes. The developer is not responsible for any misuse of the software.")
print("Don't hesitate to check the python code :-)")
while True:
    acceptation = str(input("Do you accept the rules (Y/n) : "))
    if acceptation =="Y":
        break
    elif acceptation =="n":
        print("")
        print("Bro, why ?!?!")
        exit()
    else:
        print("[Warning] -- Wrong command")
        continue
print("")

# ---------------------------------------------------------------------------------- Afficher le développeur
print("Lead developer : $now_")
print("")

# ---------------------------------------------------------------------------------- Fonction pour afficher l'heure
def show_time():
    actual_time = time.strftime("%H:%M:%S")
    print("[" + actual_time + "]", end="")

# ---------------------------------------------------------------------------------- Fonction pour obtenir le nom du protocole
def get_protocol(protocol):
    with open("protocol.txt", "r") as file:
        numbers = []
        services = []
        for line in file:
            line = line.strip()
            parts = line.split('\t')
            number = int(parts[0])
            numbers.append(number)
            service = str(parts[1])
            services.append(service)
        if protocol in numbers:
            index = numbers.index(protocol)
            return services[index]
        else:
            return "[CRITICAL] -- Protocol not found, maybe a suspicious package"

# ---------------------------------------------------------------------------------- Initialisation variables
presence_ip_safe = False
presence_ip_black = False

# ---------------------------------------------------------------------------------- Demander la commande
while True:
    command = str(input("Enter the command you want to execute (you can use the \"Help\" command) : "))
    # ---------------------------------------------------------------------------------- Commande "Sniff -All"
    if command == "Sniff -All":
        packets_captured = 0

        def monitor_packet(packet):
            if packet.haslayer("IP"):
                global packets_captured
                ip_src = packet["IP"].src
                ip_rec = packet["IP"].dst
                protocol_num = packet["IP"].proto
                if presence_ip_black == True:
                    if ip_src in ip_black:
                        print(f"[CRITICAL] -- The device with IP address : {ip_src} send a package on this network")
                        notification.notify(title="Security Alert", message=f"Device with IP address : {ip_src} send a package on this network", timeout=7, app_icon="danger_ico.ico")
                        packets_captured += 1
                    elif ip_rec in ip_black:
                        print(f"[CRITICAL] -- The device with the black IP address : {ip_rec} received a package on this network")
                        notification.notify(title="Security Alert", message=f"Device with IP address : {ip_rec} received a package on this network", timeout=7, app_icon="danger_ico.ico")
                        packets_captured += 1
                    else:
                        show_time() ; print(f" -- Captured package : {ip_src} -> {ip_rec} (Protocol : {protocol_num} -> {get_protocol(protocol_num)})")
                        packets_captured += 1
                else:
                    show_time() ; print(f" -- Captured package : {ip_src} -> {ip_rec} (Protocol : {protocol_num} -> {get_protocol(protocol_num)})")
                    packets_captured += 1

        number_capture = int(input("Enter the number of packages you want to sniff : "))
        print("")

        while packets_captured < number_capture:
            sniff(prn=monitor_packet, count=1)
            time.sleep(0.1)

        print("")
        print("Capture complete")
        print("")
        continue
    # ---------------------------------------------------------------------------------- Commande "Sniff -Src"
    elif command == "Sniff -Src":
        packets_captured = 0
        sniff_src = str(input("Enter the source you want to sniff : "))

        def monitor_packet(packet):
            if packet.haslayer("IP"):
                global packets_captured
                ip_src = sniff_src
                ip_rec = packet["IP"].dst
                protocol_num = packet["IP"].proto
                if presence_ip_black == True:
                    if ip_src in ip_black:
                        print(f"[CRITICAL] -- The device with IP address : {ip_src} send a package on this network")
                        notification.notify(title="Security Alert",
                                            message=f"Device with IP address : {ip_src} send a package on this network",
                                            timeout=7, app_icon="danger_ico.ico")
                        packets_captured += 1
                    elif ip_rec in ip_black:
                        print(
                            f"[CRITICAL] -- The device with the black IP address : {ip_rec} received a package on this network")
                        notification.notify(title="Security Alert",
                                            message=f"Device with IP address : {ip_rec} received a package on this network",
                                            timeout=7, app_icon="danger_ico.ico")
                        packets_captured += 1
                    else:
                        show_time() ; print(f" -- Captured package : {ip_src} -> {ip_rec} (Protocol : {protocol_num} -> {get_protocol(protocol_num)})")
                        packets_captured += 1
                else:
                    show_time() ; print(f" -- Captured package : {ip_src} -> {ip_rec} (Protocol : {protocol_num} -> {get_protocol(protocol_num)})")
                    packets_captured += 1

        number_capture = int(input("Enter the number of packages you want to sniff : "))
        print("")

        while packets_captured < number_capture:
            sniff(prn=monitor_packet, count=1)
            time.sleep(0.1)

        print("")
        print("Capture complete")
        print("")
        continue
    # ---------------------------------------------------------------------------------- Commande "Sniff -Rec"
    elif command == "Sniff -Rec":
        packets_captured = 0
        sniff_rec = str(input("Enter the recipient you want to sniff :  "))

        def monitor_packet(packet):
            if packet.haslayer("IP"):
                global packets_captured
                ip_src = packet["IP"].src
                ip_rec = sniff_rec
                protocol_num = packet["IP"].proto
                if presence_ip_black == True:
                    if ip_src in ip_black:
                        print(f"[CRITICAL] -- The device with IP address : {ip_src} send a package on this network")
                        notification.notify(title="Security Alert",
                                            message=f"Device with IP address : {ip_src} send a package on this network",
                                            timeout=7, app_icon="danger_ico.ico")
                        packets_captured += 1
                    elif ip_rec in ip_black:
                        print(
                            f"[CRITICAL] -- The device with the black IP address : {ip_rec} received a package on this network")
                        notification.notify(title="Security Alert",
                                            message=f"Device with IP address : {ip_rec} received a package on this network",
                                            timeout=7, app_icon="danger_ico.ico")
                        packets_captured += 1
                    else:
                        show_time() ; print(f" -- Captured package : {ip_src} -> {ip_rec} (Protocol : {protocol_num} -> {get_protocol(protocol_num)})")
                        packets_captured += 1
                else:
                    show_time() ; print(f" -- Captured package : {ip_src} -> {ip_rec} (Protocol : {protocol_num} -> {get_protocol(protocol_num)})")
                    packets_captured += 1

        number_capture = int(input("Enter the number of packages you want to sniff : "))
        print("")

        while packets_captured < number_capture:
            sniff(prn=monitor_packet, count=1)
            time.sleep(0.1)

        print("")
        print("Capture complete")
        print("")
        continue
    # ---------------------------------------------------------------------------------- Commande "Sniff -Src -Rec"
    elif command == "Sniff -Src -Rec":
        packets_captured = 0
        sniff_src = str(input("Enter the source you want to sniff : "))
        sniff_rec = str(input("Enter the recipient you want to sniff :  "))

        def monitor_packet(packet):
            if packet.haslayer("IP"):
                global packets_captured
                ip_src = sniff_src
                ip_rec = sniff_rec
                protocol_num = packet["IP"].proto
                if presence_ip_black == True:
                    if ip_src in ip_black:
                        print(f"[CRITICAL] -- The device with IP address : {ip_src} send a package on this network")
                        notification.notify(title="Security Alert",
                                            message=f"Device with IP address : {ip_src} send a package on this network",
                                            timeout=7, app_icon="danger_ico.ico")
                        packets_captured += 1
                    elif ip_rec in ip_black:
                        print(
                            f"[CRITICAL] -- The device with the black IP address : {ip_rec} received a package on this network")
                        notification.notify(title="Security Alert",
                                            message=f"Device with IP address : {ip_rec} received a package on this network",
                                            timeout=7, app_icon="danger_ico.ico")
                        packets_captured += 1
                    else:
                        show_time() ; print(f" -- Captured package : {ip_src} -> {ip_rec} (Protocol : {protocol_num} -> {get_protocol(protocol_num)})")
                        packets_captured += 1
                else:
                    show_time() ; print(f" -- Captured package : {ip_src} -> {ip_rec} (Protocol : {protocol_num} -> {get_protocol(protocol_num)})")
                    packets_captured += 1

        number_capture = int(input("Enter the number of packages you want to sniff : "))
        print("")

        while packets_captured < number_capture:
            sniff(prn=monitor_packet, count=1)
            time.sleep(0.1)

        print("")
        print("Capture complete")
        print("")
        continue
    # ---------------------------------------------------------------------------------- Commande Devices -Find
    elif command == "Devices -Find":
        def scan_network(ip_range):
            arp_request = ARP(pdst=ip_range)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether / arp_request

            result = srp(packet, timeout=2, verbose=False)[0]

            devices = []
            for sent, received in result:
                devices.append({'ip': received.psrc, 'mac': received.hwsrc})

            return devices

        if __name__ == "__main__":
            ip_range = "192.168.1.0/24"  # Remplacez par le sous-réseau de votre réseau
            devices = scan_network(ip_range)
            print("")
            print("Appareils connectés :")
            for device in devices:
                if presence_ip_black == True:
                    if device['ip'] in ip_black:
                        print(f"[CRITICAL] -- the device with the IP address : {device['ip']} and the Mac address : {device['mac']} is connected to the network")
                        notification.notify(title="Security Alert", message=f"Device with IP address : {device['ip']} and Mac address : {device['mac']} is connected on the network",timeout=7, app_icon="danger_ico.ico")
                    else:
                        print(f"IP: {device['ip']}, Mac: {device['mac']}")
                        continue
                else:
                    print(f"IP: {device['ip']}, Mac: {device['mac']}")
                    continue
            print("")
        continue
    # ---------------------------------------------------------------------------------- Commande Mac -Find
    elif command == "Mac -Find":
        mac_address = str(input("Enter the Mac address with the unknown manufacturer : "))

        def find_mac_info(mac_address):
            mac_prefix = mac_address[:8].upper().replace(":", "-")
            with open("oui.txt", "r", encoding="utf-8") as file:  # Encodage UTF-8
                for line in file:
                    if mac_prefix in line:
                        manufacturer = line.split("\t")[-1].strip()
                        print("")
                        print(f"Fabricant trouvé : {manufacturer}")
                        print("")
                        return

            print("Aucune information trouvée pour cette adresse MAC.")
            print("")

        find_mac_info(mac_address)
    # ---------------------------------------------------------------------------------- Commande "Import -IP -Safe"
    elif command == "Import -IP -Safe":
        while True:
            ip_safe = []
            presence_ip_safe = True

            ip_safe_file = str(input("Enter the path to the file with the safe IP : "))

            with open(ip_safe_file, "r", encoding="utf-8") as file:
                for line in file:
                    ip_safe.append(line.strip())

            len_ip_safe = len(ip_safe)

            print("")
            print("Here is the list of safe IP you want to import :")
            for i in range(len_ip_safe):
                print(ip_safe[i])
            print("")

            problematic_ip_safe = []
            if presence_ip_black == True:
                for ip in ip_safe:
                    if ip in ip_black:
                        problematic_ip_safe.append(ip)

            if problematic_ip_safe:
                for ip in problematic_ip_safe:
                    print(f"[ERROR] -- IP adress : {ip} is already in the black IP adresses list")
                print("")
                continue

            while True:
                confirmation_ip_safe = str(input("Is it correct? (Y/n) : "))
                if confirmation_ip_safe == "Y":
                    break
                elif confirmation_ip_safe == "n":
                    break
                else:
                    print("[Warning] -- Wrong command")

            if confirmation_ip_safe == "Y":
                break
        print("")
        continue
    # ---------------------------------------------------------------------------------- Commande "Import -IP -Black"
    elif command == "Import -IP -Black":
        while True:
            ip_black = []
            presence_ip_black = True

            ip_black_file = str(input("Enter the path to the file with the black IP : "))

            with open(ip_black_file, "r", encoding="utf-8") as file:
                for line in file:
                    ip_black.append(line.strip())

            len_ip_black = len(ip_black)

            print("")
            print("Here is the list of black IP you want to import :")
            for i in range(len_ip_black):
                print(ip_black[i])
            print("")

            problematic_ip_black = []
            if presence_ip_safe == True:
                for ip in ip_black:
                    if ip in ip_safe:
                        problematic_ip_black.append(ip)

            if problematic_ip_black:
                for ip in problematic_ip_black:
                    print(f"[ERROR] -- IP adress : {ip} is already in the safe IP adresses list")
                print("")
                continue

            while True:
                confirmation_ip_black = str(input("Is it correct? (Y/n) : "))
                if confirmation_ip_black == "Y":
                    break
                elif confirmation_ip_black == "n":
                    break
                else:
                    print("[Warning] -- Wrong command")

            if confirmation_ip_black == "Y":
                break
        print("")
        continue
    # ---------------------------------------------------------------------------------- Commande "Display -IP -Safe"
    elif command == "Display -IP -Safe":
        if presence_ip_safe == True:
            print("")
            print("Here is the list of all the safe IP adresses :")
            for i in range(len_ip_safe):
                print(ip_safe[i])
            print("")
        else:
            print("")
            print("[WARNING] -- No IP safe list imported")
            print("")
        continue
    # ---------------------------------------------------------------------------------- Commande "Display -IP -Black"
    elif command == "Display -IP -Black":
        if presence_ip_black == True:
            print("")
            print("Here is the list of all the black IP adresses :")
            for i in range(len_ip_black):
                print(ip_black[i])
            print("")
        else:
            print("")
            print("[WARNING] -- No IP black list imported")
            print("")
        continue
    # ---------------------------------------------------------------------------------- Commande "Exit"
    elif command == "Exit":
        exit()
    # ---------------------------------------------------------------------------------- Commande "Help"
    elif command == "Help":
        print("")
        print("Here are all the commands that you can use")
        print("\"Sniff -All\" : Sniff a number of packages on the local network")
        print("\"Sniff -Src\" : Sniff a number of packages on a local network but with a special source")
        print("\"Sniff -Rec\" : Sniff a number of packages on a local network but with a special recipient")
        print("\"Sniff -Src -Rec\" : Sniff a number of packages on a local network but with a special source and recipient")
        print("\"Devices -Find\" : Find the IP and the Mac addresses of all the devices connected on a local network")
        print("\"Mac -Find\" : Find the manufacturer of a network card with its Mac address")
        print("\"Import -IP -Safe\" : Import in the software a list of safe IP addresses")
        print("\"Import -IP -Black\" : Import in the software a list of black IP addresses")
        print("\"Display -IP -Safe\" : Display the list of all the safe IP addresses")
        print("\"Display -IP -Black\" : Display the list of all the black IP addresses")
        print("\"Exit\" : Exit the software")
        print("")
    # ---------------------------------------------------------------------------------- Commande non valide
    else:
        print("[Warning] -- Wrong command")
        continue