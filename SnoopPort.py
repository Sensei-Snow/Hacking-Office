
# Importing libraries :
# pyfiglet: for logo creation
# socket: to manage network connections
# time : to add timeouts
import pyfiglet, socket, time

# Create a function to display the logo
def show_logo():
    ascii_banner = pyfiglet.figlet_format("SnoopPort")
    print(ascii_banner)

# Logo display
show_logo()
# Creation of a loop to start the software once the “enter” key has been pressed
while True:
    confirmation = str(input("Press the Enter key "))
    if confirmation =="":
        break
    else:
        print("[Warning] -- Wrong command")
        continue
print("")

# Display of rules and instructions for use
print("This tool has been created for learning purposes. The developer is not responsible for any misuse of the software.")
print("Don't hesitate to check the python code :-)")
# Create a loop to continue using the software if the rules are accepted (using the “Y” key)
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

# Display software developers
print("Lead developper : $now_")
print("Additionnal developpers : TechieNeurons")
print("")

# Request the target IP
ip = str(input("Enter the target IP adress : "))

# Create a function to display time as [Hours:Minutes:Seconds]
def show_time():
    actual_time = time.strftime("%H:%M:%S")
    print("[" + actual_time + "]", end="")

# Create a loop to ask the user which command to execute
while True :
    ports_command = str(input("Enter your command for the ports (you can use the command \"Help\") : "))
    # Display the list of all commands which are available
    if ports_command == "Help":
        print("")
        print("Here are all the commands for the ports that you can use :")
        print("\"One\" : You just have to write the number of the port that you want to test")
        print("\"List\" : You just have to write a list of all the ports numbers you want to test separated with a space")
        print("\"Important\" : The most important ports will be test with this command")
        print("\"Important - Explain\" : You will see the list of the most important ports that SnoopPort will test")
        print("")
    # Ask the number of the port to test and create a list with this number
    elif ports_command == "One":
        port = int(input("Enter the number of the port that you want to test : "))
        ports_list = [port]
        break
    # Ask the numbers of all the ports number that the software has to test and create a list with all the numbers
    elif ports_command == "List":
        ports_list = list(map(int, input("Enter all the ports numbers that you want to test, separated by spaces : ").split()))
        break
    # Execute the test with the list of the 30 most important ports
    elif ports_command == "Important":
        ports_list = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1433, 1434, 1521, 3306,
                      3389, 4444, 5900, 8080, 8443, 8888, 10000, 31337, 9200, 27017, 6379]
        break
    # Display the description of all the 30 ports that the software test with the "important" command
    elif ports_command == "Important - Explain":
        print("")
        print("Port : 21 -- Service : ftp -- Description : File Transfer Protocol")
        print("Port : 22 -- Service : ssh -- Description : Secure Shell")
        print("Port : 23 -- Service : telnet -- Description : Service often vulnerable")
        print("Port : 25 -- Service : smtp -- Description : Simple Mail Transfer Protocol")
        print("Port : 53 -- Service : domain -- description : Domain Name System")
        print("Port : 80 -- Service : http -- Description : HyperText Transfer Protocol")
        print("Port : 110 -- Service : pop3 -- Description : Post Office Protocol V3")
        print("Port : 111 -- Service : sunrpc -- Description : Remote Procedure Call (Sun Microsystems)")
        print("Port : 135 -- Service : epmap -- Description : Remote Procedure Call (Microsoft)")
        print("Port : 139 -- Service : netbios-ssn -- Description : Session Service")
        print("Port : 143 -- Service : imap -- Description : Internet Message Access Protocol")
        print("Port : 443 -- Service : https -- Description : HTTP Secure")
        print("Port : 445 -- Service : microsoft-ds -- Description : Server Message Block")
        print("Port : 993 -- Service : imaps -- Description : IMAP Secure")
        print("Port : 995 -- Service : pop3s -- Description : POP3 Secure")
        print("Port : 1433 -- Service : ms-sql-s -- Description : Microsoft SQL Server")
        print("Port : 1434 -- Service : ms-sql-m -- Description : Microsoft SQL Monitor")
        print("Port : 1521 -- Service : oracle database")
        print("Port : 3306 -- Service : mysql")
        print("Port : 3389 -- Service : ms-wbt-server -- Description : Remote Desktop Protocol")
        print("Port : 4444 -- Service : metasploit default port -- Description : Exploits and reverse shells")
        print("Port : 5900 -- Service : vnc -- Description : Virtual Network Computing")
        print("Port : 8080 -- Service : http proxy")
        print("Port : 8443 -- Service : https alternative")
        print("Port : 8888 -- Service : http alternative")
        print("Port : 10000 -- Service : webmin -- Description : Web administration tool")
        print("Port : 31337 -- Service : back orifice -- Description : Remote control tool, often used by malware")
        print("Port : 9200 -- Service : elasticsearch -- Description : Service often vulnerable")
        print("Port : 27017 -- Service : mongodb -- Description : Service often vulnerable")
        print("Port : 6379 -- Service : redis -- Description : Service often vulnerable")
        print("")
    else:
        print("[Warning] -- Wrong command")
        continue

print("")

# Create 2 list to contain the success ports with the services that they use
list_ports = []
list_services = []
# By default, no ports are active
success = False

# Create a loop for the connexion tests for all ports
for port in ports_list:
    # test the connection with one port
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        result = s.connect_ex((ip, port))

        # Get the service that the port uses
        try:
            service_name = socket.getservbyport(port)
        # Create a list of all ports that the software doesn't know with their right names
        except OSError:
            if port == 1521:
                service_name = "oracle database"
            elif port == 3306:
                service_name = "mysql"
            elif port == 4444:
                service_name = "metasploit default port"
            elif port == 5900:
                service_name = "vnc"
            elif port == 8080:
                service_name = "http proxy"
            elif port == 8443:
                service_name = "https alternative"
            elif port == 8888:
                service_name = "http alternative"
            elif port == 10000:
                service_name = "webmin"
            elif port == 31337:
                service_name = "back orifice"
            elif port == 9200:
                service_name = "elasticsearch"
            elif port == 27017:
                service_name = "mongodb"
            elif port == 6379:
                service_name = "redis"
            # If the port is not in this list, display an error message
            else:
                service_name = "Unknown Service"

        # Create a condition if the result is a success (success = 0 and error = 1)
        if result == 0:
            show_time() ; print(f" -- [SUCCESS] -- Port {port} ({service_name}) : ------------------------------------------OPEN")
            # Set the success variable to "True" because one port minimum is active
            success = True
            # Add in the two lists the number of the port which is active and its service
            list_ports.append(port)
            list_services.append(service_name)
        else:
            show_time() ; print(f" -- [Error] -- Port {port} ({service_name}) : CLOSED")
    # Display an error message if the test is too long, it means that there is a good firewall (ahaha, good luck)
    except socket.timeout:
        show_time() ; print(f" -- [Warning] -- Port {port} is FILTERED (no response)")
    # Display an error message if there is a problem with the target or the internet connexion (the target can be offline)
    except Exception as error:
        show_time() ; print(f" -- [CRITICAL] -- Error : {error}")
    # Close the connection when all the tests are finished
    finally:
        s.close()

# Display the summary
print("")
print("Summary :")
# Count the number of successes
len_list = len(list_ports)

# Create a condition if there is minimum one port which is active
if success == True:
    for i in range(len_list):
        print(f"Port : {list_ports[i]} -- Service : {list_services[i]} -- Open")
# Display an other message if there are nor ports which are active
else:
    print("Sorry :-(")
    print("No open ports")