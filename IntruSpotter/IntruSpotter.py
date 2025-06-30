# ---------------------------------------------------------------------------------- Importing libraries :
# pyfiglet for logos creation
# time : to add timeouts
# plyer : to show notifications on the desk
# scapy.all : to sniff network packages
from asyncio import timeout

import pyfiglet
import time
from plyer import notification
from scapy.all import sniff, ARP, Ether, srp

# ---------------------------------------------------------------------------------- Create a function to display the logo and display it
def show_logo():
    ascii_banner = pyfiglet.figlet_format("IntruSpotter")
    print(ascii_banner)
show_logo()

# ---------------------------------------------------------------------------------- Creation of a loop to start the software once the “enter” key has been pressed
while True:
    confirmation = str(input("Press the Enter key "))
    if confirmation =="":
        break
    else:
        print("[Warning] -- Wrong command")
        continue
print("")

# ---------------------------------------------------------------------------------- Display of rules and instructions for use
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

# ---------------------------------------------------------------------------------- Display software developer
print("Lead developer : $now_")
print("")

# ---------------------------------------------------------------------------------- Create a function to display time as [Hours:Minutes:Seconds]
def show_time():
    actual_time = time.strftime("%H:%M:%S")
    print("[" + actual_time + "]", end="")

# ---------------------------------------------------------------------------------- Create a function to display the name of the network protocol found for a sniffed network package
def get_protocol(protocol):
    # Open the "protocol.txt" file
    with open("protocol.txt", "r") as file:
        # Create a list to store all the numbers of the network protocols
        numbers = []
        # Create a list to store all the names of the network protocols
        services = []
        # Read each lines
        for line in file:
            line = line.strip()
            # Split each lines in two parts when there is a tabulation
            parts = line.split('\t')
            # Add the first part (numbers) in the numbers list
            number = int(parts[0])
            numbers.append(number)
            # Add the second part (protocols) in the protocols list
            service = str(parts[1])
            services.append(service)
        # Return the name of the protocol which goes with the number of the sniffed network package
        if protocol in numbers:
            index = numbers.index(protocol)
            return services[index]
        else:
            return "[CRITICAL] -- Protocol not found, maybe a suspicious package"

# ---------------------------------------------------------------------------------- Set variables

# By default, there are no MAC addresses safe and black lists imported
presence_mac_safe = False
presence_mac_black = False
# Set the variables which will be useful to ask if we want a quantity of sniffed network packages or a sniff period
use_quantity = False
use_period = False
hide_safe = False

# ---------------------------------------------------------------------------------- Ask the main command
while True:
    command = str(input("Enter the command you want to execute (you can use the \"Help\" command) : "))
    # ---------------------------------------------------------------------------------- Command "Sniff -All"
    if command == "Sniff -All":
        # Set the numbers of network packages sniffed and time at 0
        packets_captured = 0
        start_time = None

        # Create a function to sniff the network packages
        def monitor_packet(packet):
            # Include the last variables in this function
            global packets_captured, start_time

            # Name all the different part of a network package if an IP address is written
            if packet.haslayer("IP"):
                # Name the IP and Mac source addresses
                ip_src = packet["IP"].src
                mac_src = packet["Ether"].src
                # Name the IP and Mac recipient addresses
                ip_rec = packet["IP"].dst
                mac_rec = packet["Ether"].dst
                # Name the protocol which is used with his nummer
                protocol_num = packet["IP"].proto

                # Hide the safe Mac addresses in the list of captured packages if the user ask it
                if presence_mac_safe == True and hide_safe == True:
                    if mac_src in mac_safe:
                        return
                    elif mac_rec in mac_safe:
                        return

                # Verify if there is a list of black listed Mac address to check
                if presence_mac_black:
                    # Send an alert with a notification if a device with a black listed Mac address send a package on the network
                    if mac_src in mac_black:
                        show_time() ; print(f" -- [CRITICAL] -- The device with IP address : {ip_src} and Mac address : {mac_src} send a package on this network")
                        packets_captured += 1
                        notification.notify(title="Security Alert", message=f"Device with IP address : {ip_src} and Mac address : {mac_src} send a package on this network", timeout=7, app_icon="danger_ico.ico")
                        # If a quantity of packages is asked by the user, stop the capture if the correct number of captured packages has been reached
                        if ask_number_time == "Q":
                            if packets_captured >= number_capture:
                                raise KeyboardInterrupt
                        else:
                            if time.time() - start_time > time_capture:
                                raise KeyboardInterrupt

                    # Send an alert with a notification if a device with a black listed Mac address received a package on the network
                    elif mac_rec in mac_black:
                        show_time() ; print(f" -- [CRITICAL] -- The device with IP address : {ip_rec} and Mac address : {mac_rec} received a package on this network")
                        packets_captured += 1
                        notification.notify(title="Security Alert", message=f"Device with IP address : {ip_rec} and Mac address : {mac_rec} received a package on this network", timeout=7, app_icon="danger_ico.ico")
                        # If a quantity of packages is asked by the user, stop the capture if the correct number of captured packages has been reached
                        if ask_number_time == "Q":
                            if packets_captured >= number_capture:
                                raise KeyboardInterrupt
                        else:
                            if time.time() - start_time > time_capture:
                                raise KeyboardInterrupt

                    # Just show the captured package if it is not black listed
                    else:
                        show_time() ; print(f" -- Captured package : {ip_src} -> {ip_rec} - {mac_src} -> {mac_rec} (Protocol : {protocol_num} -> {get_protocol(protocol_num)})")
                        packets_captured += 1
                        # If a quantity of packages is asked by the user, stop the capture if the correct number of captured packages has been reached
                        if ask_number_time == "Q":
                            if packets_captured >= number_capture:
                                raise KeyboardInterrupt
                        else:
                            if time.time() - start_time > time_capture:
                                raise KeyboardInterrupt

                # If no black listed Mac addresses are imported, just show the captured package
                else:
                    show_time() ; print(f" -- Captured package : {ip_src} -> {ip_rec} - {mac_src} -> {mac_rec} (Protocol : {protocol_num} -> {get_protocol(protocol_num)})")
                    packets_captured += 1
                    # If a quantity of packages is asked by the user, stop the capture if the correct number of captured packages has been reached
                    if ask_number_time == "Q":
                        if packets_captured >= number_capture:
                            raise KeyboardInterrupt
                    else:
                        if time.time() - start_time > time_capture:
                            raise KeyboardInterrupt

        while True:
            # If there are safe Mac addresses, ask if the user wants to hide them in the result of the capture
            if presence_mac_safe == True:
                ask_hide_safe = input("Do you want to hide the packages with the safe Mac addresses (Y/n) : ")

                if ask_hide_safe == "Y":
                    hide_safe = True
                elif ask_hide_safe == "n":
                    pass
                else:
                    print("[Warning] -- Wrong command")
            else:
                pass

            # Ask the user if he wants to sniff a quantity of packets or for a certain period of time
            ask_number_time = input("Do you want to sniff a quantity of packets or for a certain period of time (Q/P) : ")

            if ask_number_time == "Q":
                try:
                    number_capture = int(input("Enter the number of packages you want to sniff : "))
                    print("")
                    # At the start, set the number of captured packages to 0
                    packets_captured = 0
                    # Capture packages until the wished number of captured packages has been reached and call the function to sniff packages
                    while packets_captured < number_capture:
                        sniff(prn=monitor_packet, count=number_capture, timeout=10)
                    print("")
                    print(f"Capture complete - {packets_captured} package(s) sniffed")
                    print("")
                except ValueError:
                    print("[Warning] -- Invalid number entered")
                break

            elif ask_number_time == "P":
                try:
                    time_capture = int(input("Enter the period in seconds of packages sniffing : "))
                    print("")
                    # At the start, set the number of captured packages to 0
                    packets_captured = 0
                    # Start the timer
                    start_time = time.time()
                    # Capture packages until the wished time of capture has been reached
                    while time.time() - start_time < time_capture:
                        sniff(prn=monitor_packet, count=1, timeout=10)
                        # Add a little pause
                        time.sleep(0.1)
                    if packets_captured == 0:
                        print("No packages were captured, certainly good news, isn't it ?")
                        print("")
                    else:
                        print("")
                        print(f"Capture complete - {packets_captured} package(s) sniffed")
                        print("")
                except ValueError:
                    print("[Error] -- Invalid time entered")
                break

            else:
                print("[Warning] -- Wrong command")
        continue
    # ---------------------------------------------------------------------------------- Commande "Sniff -Src"
    elif command == "Sniff -Src":
        packets_captured = 0
        start_time = None
        sniff_src = str(input("Enter the source you want to sniff : "))

        def monitor_packet(packet):
            global packets_captured, start_time

            if start_time is None:
                start_time = time.time()

            if packet.haslayer("IP"):
                ip_src = packet["IP"].src
                mac_src = packet["Ether"].src
                ip_rec = packet["IP"].dst
                mac_rec = packet["Ether"].dst
                protocol_num = packet["IP"].proto

                if presence_mac_safe == True and hide_safe == True:
                    if mac_src in mac_safe:
                        return
                    elif mac_rec in mac_safe:
                        return

                if presence_mac_black:
                    if mac_src in mac_black:
                        if mac_src == sniff_src:
                            show_time() ; print(f" -- [CRITICAL] -- The device with IP address : {ip_src} and Mac address : {mac_src} send a package on this network")
                            packets_captured += 1
                            notification.notify(title="Security Alert", message=f"Device with IP address : {ip_src} and Mac address : {mac_src} send a package on this network", timeout=7, app_icon="danger_ico.ico")
                            if ask_number_time == "Q":
                                if packets_captured >= number_capture:
                                    raise KeyboardInterrupt
                            else:
                                if time.time() - start_time > time_capture:
                                    raise KeyboardInterrupt

                    elif mac_rec in mac_black:
                        if mac_src == sniff_src:
                            show_time() ; print(f" -- [CRITICAL] -- The device with IP address : {ip_rec} and Mac address : {mac_rec} received a package on this network")
                            packets_captured += 1
                            notification.notify(title="Security Alert", message=f"Device with IP address : {ip_rec} and Mac address : {mac_rec} received a package on this network", timeout=7, app_icon="danger_ico.ico")
                            if ask_number_time == "Q":
                                if packets_captured >= number_capture:
                                    raise KeyboardInterrupt
                            else:
                                if time.time() - start_time > time_capture:
                                    raise KeyboardInterrupt

                    else:
                        if mac_src == sniff_src:
                            show_time() ; print(f" -- Captured package : {ip_src} -> {ip_rec} - {mac_src} -> {mac_rec} (Protocol : {protocol_num} -> {get_protocol(protocol_num)})")
                            packets_captured += 1
                            if ask_number_time == "Q":
                                if packets_captured >= number_capture:
                                    raise KeyboardInterrupt
                            else:
                                if time.time() - start_time > time_capture:
                                    raise KeyboardInterrupt

                else:
                    if mac_src == sniff_src:
                        show_time() ; print(f" -- Captured package : {ip_src} -> {ip_rec} - {mac_src} -> {mac_rec} (Protocol : {protocol_num} -> {get_protocol(protocol_num)})")
                        packets_captured += 1
                        if ask_number_time == "Q":
                            if packets_captured >= number_capture:
                                raise KeyboardInterrupt
                        else:
                            if time.time() - start_time > time_capture:
                                raise KeyboardInterrupt

        while True:
            if presence_mac_safe == True:
                ask_hide_safe = input("Do you want to hide the packages with the safe Mac addresses (Y/n) : ")

                if ask_hide_safe == "Y":
                    hide_safe = True
                elif ask_hide_safe == "n":
                    pass
                else:
                    print("[Warning] -- Wrong command")
            else:
                pass

            ask_number_time = input("Do you want to sniff a quantity of packets or for a certain period of time (Q/P) : ")

            if ask_number_time == "Q":
                try:
                    number_capture = int(input("Enter the number of packages you want to sniff : "))
                    print("")
                    while packets_captured < number_capture:
                        sniff(prn=monitor_packet, count=number_capture, timeout=10)
                    print("")
                    print(f"Capture complete - {packets_captured} package(s) sniffed")
                    print("")
                except ValueError:
                    print("[Warning] -- Invalid number entered")
                break

            elif ask_number_time == "P":
                try:
                    time_capture = int(input("Enter the period in seconds of packages sniffing : "))
                    print("")
                    packets_captured = 0
                    start_time = time.time()
                    while time.time() - start_time < time_capture:
                        sniff(prn=monitor_packet, count=1, timeout=10)
                        time.sleep(0.1)
                    if packets_captured == 0:
                        print("No packages were captured, certainly good news, isn't it ?")
                        print("")
                    else:
                        print("")
                        print(f"Capture complete {packets_captured} package(s) sniffed")
                        print("")
                except ValueError:
                    print("[Error] -- Invalid time entered")
                break

            else:
                print("[Warning] -- Wrong command")
        continue
    # ---------------------------------------------------------------------------------- Commande "Sniff -Rec"
    elif command == "Sniff -Rec":
        packets_captured = 0
        start_time = None
        sniff_rec = str(input("Enter the recipient you want to sniff : "))

        def monitor_packet(packet):
            global packets_captured, start_time

            if start_time is None:
                start_time = time.time()

            if packet.haslayer("IP"):
                ip_src = packet["IP"].src
                mac_src = packet["Ether"].src
                ip_rec = packet["IP"].dst
                mac_rec = packet["Ether"].dst
                protocol_num = packet["IP"].proto

                if presence_mac_safe == True and hide_safe == True:
                    if mac_src in mac_safe:
                        return
                    elif mac_rec in mac_safe:
                        return

                if presence_mac_black:
                    if mac_src in mac_black:
                        if mac_rec == sniff_rec:
                            show_time() ; print(f" -- [CRITICAL] -- The device with IP address : {ip_src} and Mac address : {mac_src} send a package on this network")
                            packets_captured += 1
                            notification.notify(title="Security Alert", message=f"Device with IP address : {ip_src} and Mac address : {mac_src} send a package on this network", timeout=7, app_icon="danger_ico.ico")
                            if ask_number_time == "Q":
                                if packets_captured >= number_capture:
                                    raise KeyboardInterrupt
                            else:
                                if time.time() - start_time > time_capture:
                                    raise KeyboardInterrupt

                    elif mac_rec in mac_black:
                        if mac_rec == sniff_rec:
                            show_time() ; print(f" -- [CRITICAL] -- The device with IP address : {ip_rec} and Mac address : {mac_rec} received a package on this network")
                            packets_captured += 1
                            notification.notify(title="Security Alert", message=f"Device with IP address : {ip_rec} and Mac address : {mac_rec} received a package on this network", timeout=7, app_icon="danger_ico.ico")
                            if ask_number_time == "Q":
                                if packets_captured >= number_capture:
                                    raise KeyboardInterrupt
                            else:
                                if time.time() - start_time > time_capture:
                                    raise KeyboardInterrupt

                    else:
                        if mac_rec == sniff_rec:
                            show_time() ; print(f" -- Captured package : {ip_src} -> {ip_rec} - {mac_src} -> {mac_rec} (Protocol : {protocol_num} -> {get_protocol(protocol_num)})")
                            packets_captured += 1
                            if ask_number_time == "Q":
                                if packets_captured >= number_capture:
                                    raise KeyboardInterrupt
                            else:
                                if time.time() - start_time > time_capture:
                                    raise KeyboardInterrupt

                else:
                    if mac_rec == sniff_rec:
                        show_time() ; print(f" -- Captured package : {ip_src} -> {ip_rec} - {mac_src} -> {mac_rec} (Protocol : {protocol_num} -> {get_protocol(protocol_num)})")
                        packets_captured += 1
                        if ask_number_time == "Q":
                            if packets_captured >= number_capture:
                                raise KeyboardInterrupt
                        else:
                            if time.time() - start_time > time_capture:
                                raise KeyboardInterrupt


        while True:
            if presence_mac_safe == True:
                ask_hide_safe = input("Do you want to hide the packages with the safe Mac addresses (Y/n) : ")

                if ask_hide_safe == "Y":
                    hide_safe = True
                elif ask_hide_safe == "n":
                    pass
                else:
                    print("[Warning] -- Wrong command")
            else:
                pass

            ask_number_time = input("Do you want to sniff a quantity of packets or for a certain period of time (Q/P) : ")

            if ask_number_time == "Q":
                try:
                    number_capture = int(input("Enter the number of packages you want to sniff : "))
                    print("")
                    while packets_captured < number_capture:
                        sniff(prn=monitor_packet, count=number_capture, timeout=10)
                    print("")
                    print("Capture complete")
                    print("")
                except ValueError:
                    print("[Warning] -- Invalid number entered")
                break

            elif ask_number_time == "P":
                try:
                    time_capture = int(input("Enter the period in seconds of packages sniffing : "))
                    print("")
                    packets_captured = 0
                    start_time = time.time()
                    while time.time() - start_time < time_capture:
                        sniff(prn=monitor_packet, count=1, timeout=10)
                        time.sleep(0.1)
                    if packets_captured == 0:
                        print("No packages were captured, certainly good news, isn't it ?")
                        print("")
                    else:
                        print("")
                        print("Capture complete")
                        print("")
                except ValueError:
                    print("[Error] -- Invalid time entered")
                break

            else:
                print("[Warning] -- Wrong command")
        continue
    # ---------------------------------------------------------------------------------- Commande "Sniff -Src -Rec"
    elif command == "Sniff -Src -Rec":
        packets_captured = 0
        start_time = None
        sniff_src = str(input("Enter the source you want to sniff : "))
        sniff_rec = str(input("Enter the recipient you want to sniff : "))

        def monitor_packet(packet):
            global packets_captured, start_time

            if start_time is None:
                start_time = time.time()

            if packet.haslayer("IP"):
                ip_src = packet["IP"].src
                mac_src = packet["Ether"].src
                ip_rec = packet["IP"].dst
                mac_rec = packet["Ether"].dst
                protocol_num = packet["IP"].proto

                if presence_mac_safe == True and hide_safe == True:
                    if mac_src in mac_safe:
                        return
                    elif mac_rec in mac_safe:
                        return

                if presence_mac_black:
                    if mac_src in mac_black:
                        if mac_src == sniff_src and mac_rec == sniff_rec:
                            show_time() ; print(f" -- [CRITICAL] -- The device with IP address : {ip_src} and Mac address : {mac_src} send a package on this network")
                            packets_captured += 1
                            notification.notify(title="Security Alert", message=f"Device with IP address : {ip_src} and Mac address : {mac_src} send a package on this network", timeout=7, app_icon="danger_ico.ico")
                            if ask_number_time == "Q":
                                if packets_captured >= number_capture:
                                    raise KeyboardInterrupt
                            else:
                                if time.time() - start_time > time_capture:
                                    raise KeyboardInterrupt


                    elif mac_rec in mac_black:
                        if mac_src == sniff_src and mac_rec == sniff_rec:
                            show_time() ; print(f" -- [CRITICAL] -- The device with IP address : {ip_rec} and Mac address : {mac_rec} received a package on this network")
                            packets_captured += 1
                            notification.notify(title="Security Alert", message=f"Device with IP address : {ip_rec} and Mac address : {mac_rec} received a package on this network", timeout=7, app_icon="danger_ico.ico")
                            if ask_number_time == "Q":
                                if packets_captured >= number_capture:
                                    raise KeyboardInterrupt
                            else:
                                if time.time() - start_time > time_capture:
                                    raise KeyboardInterrupt

                    else:
                        if mac_src == sniff_src and mac_rec == sniff_rec:
                            show_time() ; print(f" -- Captured package : {ip_src} -> {ip_rec} - {mac_src} -> {mac_rec} (Protocol : {protocol_num} -> {get_protocol(protocol_num)})")
                            packets_captured += 1
                            if ask_number_time == "Q":
                                if packets_captured >= number_capture:
                                    raise KeyboardInterrupt
                            else:
                                if time.time() - start_time > time_capture:
                                    raise KeyboardInterrupt

                else:
                    if mac_src == sniff_src and mac_rec == sniff_rec:
                        show_time() ; print(f" -- Captured package : {ip_src} -> {ip_rec} - {mac_src} -> {mac_rec} (Protocol : {protocol_num} -> {get_protocol(protocol_num)})")
                        packets_captured += 1
                        if ask_number_time == "Q":
                            if packets_captured >= number_capture:
                                raise KeyboardInterrupt
                        else:
                            if time.time() - start_time > time_capture:
                                raise KeyboardInterrupt


        while True:
            if presence_mac_safe == True:
                ask_hide_safe = input("Do you want to hide the packages with the safe Mac addresses (Y/n) : ")

                if ask_hide_safe == "Y":
                    hide_safe = True
                elif ask_hide_safe == "n":
                    pass
                else:
                    print("[Warning] -- Wrong command")
            else:
                pass

            ask_number_time = input(
                "Do you want to sniff a quantity of packets or for a certain period of time (Q/P) : ")

            if ask_number_time == "Q":
                try:
                    number_capture = int(input("Enter the number of packages you want to sniff : "))
                    print("")
                    while packets_captured < number_capture:
                        sniff(prn=monitor_packet, count=number_capture, timeout=10)
                    print("")
                    print(f"Capture complete - {packets_captured} package(s) sniffed")
                    print("")
                except ValueError:
                    print("[Warning] -- Invalid number entered")
                break

            elif ask_number_time == "P":
                try:
                    time_capture = int(input("Enter the period in seconds of packages sniffing : "))
                    print("")
                    packets_captured = 0
                    start_time = time.time()
                    while time.time() - start_time < time_capture:
                        sniff(prn=monitor_packet, count=1, timeout=10)
                        time.sleep(0.1)
                    if packets_captured == 0:
                        print("No packages were captured, certainly good news, isn't it ?")
                        print("")
                    else:
                        print("")
                        print(f"Capture complete - {packets_captured} package(s) sniffed")
                        print("")
                except ValueError:
                    print("[Error] -- Invalid time entered")
                break

            else:
                print("[Warning] -- Wrong command")
        continue
    # ---------------------------------------------------------------------------------- Commande "Devices -Find"
    elif command == "Devices -Find":
        def find_mac_info(mac_address):
            mac_prefix = mac_address[:8].upper().replace(":", "-")
            with open("oui.txt", "r", encoding="utf-8") as file:
                for line in file:
                    if mac_prefix in line:
                        manufacturer = line.split("\t")[-1].strip()
                        return manufacturer

            return "No informations found for this Mac address"

        number_devices = 0
        def scan_network(ip_range):
            global number_devices
            arp_request = ARP(pdst=ip_range)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether / arp_request

            result = srp(packet, timeout=2, verbose=False)[0]

            devices = []
            for sent, received in result:
                devices.append({'ip': received.psrc, 'mac': received.hwsrc})
                number_devices += 1

            return devices

        if __name__ == "__main__":
            ip_range = "192.168.1.0/24"
            devices = scan_network(ip_range)
            if number_devices >= 1:
                print("")
                print("Appareils connectés :")
            else:
                print("")
                print("[Warning] -- No devices found on this network")
                print("It is certainly due to a firewall on this network")
                print("Are you sure to be an administrator ?")
            for device in devices:
                if presence_mac_black == True:
                    if device['ip'] in mac_black:
                        print(f"[CRITICAL] -- the device with the IP address : {device['ip']} and the Mac address : {device['mac']} is connected to the network")
                        notification.notify(title="Security Alert", message=f"Device with IP address : {device['ip']} and Mac address : {device['mac']} is connected on the network",timeout=7, app_icon="danger_ico.ico")
                    else:
                        print(f"IP: {device['ip']}, Mac: {device['mac']}, Manufacturer: {find_mac_info(device['mac'])}")
                        continue
                else:
                    print(f"IP: {device['ip']}, Mac: {device['mac']}, Manufacturer: {find_mac_info(device['mac'])}")
                    continue
            print("")
        continue
    # ---------------------------------------------------------------------------------- Commande Mac -Find
    elif command == "Mac -Find":
        mac_address = str(input("Enter the Mac address with the unknown manufacturer : "))

        def find_mac_info(mac_address):
            mac_prefix = mac_address[:8].upper().replace(":", "-")
            with open("oui.txt", "r", encoding="utf-8") as file:
                for line in file:
                    if mac_prefix in line:
                        manufacturer = line.split("\t")[-1].strip()
                        print("")
                        print(f"Manufacturer found : {manufacturer}")
                        print("")
                        return

            print("")
            print("No informations found for this Mac address")
            print("")

        find_mac_info(mac_address)
    # ---------------------------------------------------------------------------------- Commande "Import -Mac -Safe"
    elif command == "Import -Mac -Safe":
        while True:
            mac_safe = []
            presence_mac_safe = True

            mac_safe_file = str(input("Enter the path to the file with the safe Mac addresses : "))

            with open(mac_safe_file, "r", encoding="utf-8") as file:
                for line in file:
                    mac_safe.append(line.strip())

            problematic_mac_safe = []
            if presence_mac_black == True:
                for mac in mac_safe:
                    if mac in mac_black:
                        problematic_mac_safe.append(mac)

            if problematic_mac_safe:
                print("")
                for mac in problematic_mac_safe:
                    print(f"[ERROR] -- Mac address : {mac} is already in the black Mac addresses list")
                break

            len_mac_safe = len(mac_safe)

            print("")
            print("Here is the list of safe Mac addresses you want to import :")
            for i in range(len_mac_safe):
                print(mac_safe[i])
            print("")

            while True:
                confirmation_mac_safe = str(input("Is it correct? (Y/n) : "))
                if confirmation_mac_safe == "Y":
                    break
                elif confirmation_mac_safe == "n":
                    break
                else:
                    print("[Warning] -- Wrong command")

            if confirmation_mac_safe == "Y":
                break
        print("")
        continue
    # ---------------------------------------------------------------------------------- Commande "Import -Mac -Black"
    elif command == "Import -Mac -Black":
        while True:
            mac_black = []
            presence_mac_black = True

            mac_black_file = str(input("Enter the path to the file with the black Mac addresses : "))

            with open(mac_black_file, "r", encoding="utf-8") as file:
                for line in file:
                    mac_black.append(line.strip())

            problematic_mac_black = []
            if presence_mac_safe == True:
                for mac in mac_black:
                    if mac in mac_safe:
                        problematic_mac_black.append(mac)

            if problematic_mac_black:
                print("")
                for mac in problematic_mac_black:
                    print(f"[ERROR] -- Mac address : {mac} is already in the safe Mac addresses list")
                break

            len_mac_black = len(mac_black)

            print("")
            print("Here is the list of black Mac addresses you want to import :")
            for i in range(len_mac_black):
                print(mac_black[i])
            print("")

            while True:
                confirmation_mac_black = str(input("Is it correct? (Y/n) : "))
                if confirmation_mac_black == "Y":
                    break
                elif confirmation_mac_black == "n":
                    break
                else:
                    print("[Warning] -- Wrong command")

            if confirmation_mac_black == "Y":
                break
        print("")
        continue
    # ---------------------------------------------------------------------------------- Commande "Display -Mac -Safe"
    elif command == "Display -Mac -Safe":
        if presence_mac_safe == True:
            print("")
            print("Here is the list of all the safe Mac addresses :")
            for i in range(len_mac_safe):
                print(mac_safe[i])
            print("")
        else:
            print("")
            print("[WARNING] -- No Mac safe addresses list imported")
            print("")
        continue
    # ---------------------------------------------------------------------------------- Commande "Display -Mac -Black"
    elif command == "Display -Mac -Black":
        if presence_mac_black == True:
            print("")
            print("Here is the list of all the black Mac addresses :")
            for i in range(len_mac_black):
                print(mac_black[i])
            print("")
        else:
            print("")
            print("[WARNING] -- No Mac black addresses list imported")
            print("")
        continue
    # ---------------------------------------------------------------------------------- Commande "Remove -Mac -Safe
    elif command == "Remove -Mac -Safe":
        if presence_mac_safe == True:
            confirmation_remove = str(input(f"Are you sure you want to remove {len_mac_safe} Mac safe addresse(s) ? (Y/n) : "))
            if confirmation_remove == "Y":
                mac_safe.clear()
                print("")
                print("The list of all the safe Mac addresses was successfully cleared")
                print("")
                presence_mac_safe = False
            elif confirmation_remove == "n":
                continue
            else:
                print("")
                print("[WARNING] -- Wrong command")
                print("")
        else:
            print("")
            print("[WARNING] -- No Mac safe addresses list imported")
            print("")
        continue
    # ---------------------------------------------------------------------------------- Commande "Remove -Mac -Black
    elif command == "Remove -Mac -Black":
        if presence_mac_black == True:
            confirmation_remove = str(
                input(f"Are you sure you want to remove {len_mac_black} Mac black addresse(s) ? (Y/n) : "))
            if confirmation_remove == "Y":
                mac_black.clear()
                print("")
                print("The list of all the black Mac addresses was successfully cleared")
                print("")
                presence_mac_black = False
            elif confirmation_remove == "n":
                continue
            else:
                print("")
                print("[WARNING] -- Wrong command")
                print("")
        else:
            print("")
            print("[WARNING] -- No Mac black addresses list imported")
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
        print("\"Import -Mac -Safe\" : Import in the software a list of safe Mac addresses")
        print("\"Import -Mac -Black\" : Import in the software a list of black Mac addresses")
        print("\"Display -Mac -Safe\" : Display the list of all the safe Mac addresses")
        print("\"Display -Mac -Black\" : Display the list of all the black Mac addresses")
        print("\"Remove -Mac -Safe\" : Remove all the Mac addresses in the safe Mac addresses list")
        print("\"Remove -Mac -Black\" : Remove all the Mac addresses in the black Mac addresses list")
        print("\"Exit\" : Exit the software")
        print("")
    # ---------------------------------------------------------------------------------- Commande non valide
    else:
        print("[Warning] -- Wrong command")
        continue