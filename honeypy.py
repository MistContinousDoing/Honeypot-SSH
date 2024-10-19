import argparse
from ssh_honeypot import *

if __name__ == "_main_":
    parser = argparse.ArgumentParser()

    parser.add_argument('-a','--address',type=str,required=True)
    parser.add_argument('-p','--port',type=int,required=True)
    parser.add_argument('-u','--username',type=str)
    parser.add_argument('-pw','--password',type=str)

    parser.add_argument('-s','--ssh',action="store_true")

    args = parser.parse_args()

    try:
        if args.ssh:
            print("[-] Running SSH Honeypot...")
            honeypot(args.address, args.port, args.username, args.password)
            if args.username is None:
                args.username = None
            if args.password is None:
                args.password = None
        else:
            print("[!] Please choose a particular honeypot type (SSH --ssh).")
    except:
        print("\n Exiting HONEYPOT...\n")