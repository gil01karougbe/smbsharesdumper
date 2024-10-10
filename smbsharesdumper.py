from impacket.smbconnection import SMBConnection, SessionError, SMB2_DIALECT_002, SMB2_DIALECT_21, SMB_DIALECT
from impacket.examples.utils import parse_target
from tabulate import tabulate
from datetime import datetime
import os, argparse

class computer:
    def __init__(self):
        self.domain = ''
        self.ip = ''
        self.hostname = ''
        self.smclient = None
        self.shares = [] #list of share objects

    def authentication(self, username, password, args):
        smbClient = SMBConnection(self.ip, self.hostname, sess_port=int(args.port))
        dialect = smbClient.getDialect()
        if dialect == SMB_DIALECT:
            if args.debug:
                print("[+] SMBv1 dialect used")
        elif dialect == SMB2_DIALECT_002:
            if args.debug:
                print("[+] SMBv2.0 dialect used")
        elif dialect == SMB2_DIALECT_21:
            if args.debug:
                print("[+] SMBv2.1 dialect used")
        else:
            if args.debug:
                print("[+] SMBv3.0 dialect used")
        smbClient.login(username, password, self.domain, lmhash='', nthash='')
        if smbClient.isGuestSession() > 0:
            if args.debug:
                print("[+] GUEST Session Granted")
        else:
            if args.debug:
                print("[+] USER Session Granted")
        self.smclient = smbClient
        return smbClient
    
    def display_shares(self):
        headers = ["Name", "Description", "Computer"]
        rows = []
        for s in self.shares:
            row = [
                s.name,           # Share name
                s.description,    # Share description
                s.computer,       # Computer the share belongs to
            ]
            rows.append(row)
        print(tabulate(rows, headers=headers, tablefmt="grid"))


    def list_shares(self):
        all_shares = self.smbclient.listShares() #list of impacket.dcerpc.v5.srvs.SHARE_INFO_1 objects 
        shares = []
        for s in range(len(all_shares)):
            sharename = all_shares[s]["shi1_netname"][:-1]
            description = all_shares[s]["shi1_remark"][:-1]
            obj = share()
            obj.computer = self.hostname
            obj.name = sharename
            obj.description = description
            obj.smbclient = self.smclient
            shares.append(obj)
        self.shares = shares
        return shares
    
    def list_content(self, sharename='', folder=''):
        if sharename is None:
            print(f"[+] Listing content of shares on {self.ip}...")
            for item in self.shares:
                item.share_content()
        else:
            if folder is None:
                print(f"[+] Listing content of share {sharename}...")
                items = [item for item in self.shares if item.name == sharename]
                items[0].share_content()
            else:
                print(f"[+] Listing content of folder {folder} in share {sharename}...")
                items = [item for item in self.shares if item.name == sharename]
                items[0].share_content(level=folder + '/*')


    def dump_shares(self, localpath, sharename='', folder='', filename=''):
        if sharename is None:
            print(f"[+] Dumping shares on {self.ip}...")
            for item in self.shares:
                localshare = os.path.join(localpath, item.name)
                os.makedirs(localshare, exist_ok=True)
                item.dump_share(localshare)
        else:
            if folder is None:
                print(f"[+] Dumping share {sharename}...")
                items = [item for item in self.shares if item.name == sharename]
                items[0].dump_share(localpath)
            else:
                print(f"[+] Dumping folder {folder} in share {sharename}...")
                items = [item for item in self.shares if item.name == sharename]
                items[0].dump_share(localpath, level=folder + '/*')


    def upload(self, localfile, sharename='', folder=''):
        if localfile is None or sharename is None:
            print("[-] Please Provide a valid file and share name...")
        else:
            print(f"[+] Uploading {localfile} To {folder} in share {sharename}...")
            items = [item for item in self.shares if item.name == sharename]
            remotepath = '/' + os.path.basename(localfile) if folder is None else '/' + folder.rstrip('/') + '/' + os.path.basename(localfile)
            items[0].upload_file(localfile, remotepath)           

    def getfile(self, localpath, sharename, filename):
            if filename is None or sharename is None:
                print("[-] Please Provide a valid filename...")
            else:
                print(f"[+] Dumping file on {filename} in share {sharename}...")
                items = [item for item in self.shares if item.name == sharename]
                items[0].dump_file(localpath, filename)


    def mkdir(self, newfolder, sharename='', folder=''):

        return 0
    
    def delete(self, filename, sharename='', folder=''):

        return 0

def file_reader_callback(filehandle):
    data = filehandle.read(1024)
    return data

class share:
    def __init__(self):
        self.computer = ''
        self.smbclient = None
        self.name = ''
        self.access = ''
        self.description = ''
        self.folders = []
        self.files = []
    
    def display_share_content(self, content):
        headers = ["Name", "isDirectory", "isReadOnly", "creationTime"]
        rows = []
        for s in content:
            row = [
                s.get_longname(),
                s.is_directory(),
                s.is_readonly(),
                datetime.fromtimestamp(s.get_ctime_epoch()).strftime('%Y-%m-%d %H:%M:%S')
            ]
            rows.append(row)
        print(tabulate(rows, headers=headers, tablefmt="grid"))
    
    def share_content(self, level='*'):
        try:
            content = self.smbclient.listPath(self.name, level)
            self.display_share_content(content)
        except SessionError as e:
            print(f"[-] Error accessing share {self.name}: {e}")
        except Exception as e:
            print(f"[-] General error: {e}")              

    def dump_share(self, localpath='', level='*'):
        try:
            base = level.strip('*')
            content = self.smbclient.listPath(self.name, level)
            self.folders = [f for f in content if f.is_directory() !=0 and f.get_longname() not in {'.', '..'}]
            self.files = [f for f in content if f.is_directory() == 0]
            
            # Handling files
            for f in self.files:
                local_file = os.path.join(localpath, f.get_longname())
                os.makedirs(os.path.dirname(local_file), exist_ok=True)
                with open(local_file, 'wb') as file_handle:
                    self.smbclient.getFile(self.name, base + f.get_longname(), file_handle.write)
                    print(f"Dumped file {f.get_longname()} to {local_file}")

            # Handling directories
            for f in self.folders:
                nextlevel = os.path.join(level[:-2], f.get_longname(), '*') if level.endswith("/*") else os.path.join(f.get_longname(), '*')
                local_dir = os.path.join(localpath, f.get_longname())
                os.makedirs(local_dir, exist_ok=True)
                self.dump_share(local_dir, nextlevel)
        except SessionError as e:
            print(f"[-] Error dumping share {self.name}: {e}")
        except Exception as e:
            print(f"[-] General error: {e}")
    

    def dump_file(self, localpath, filename):
        try:
            longname = os.path.basename(filename)
            level = os.path.dirname(filename) + '/*'
            content = self.smbclient.listPath(self.name, level)
            thefile = [f for f in content if f.is_directory() == 0 and f.get_longname()==longname]
            local_file = os.path.join(localpath, thefile[0].get_longname())
            os.makedirs(os.path.dirname(local_file), exist_ok=True)
            with open(local_file, 'wb') as file_handle:
                self.smbclient.getFile(self.name, filename, file_handle.write)
                print(f"[+] Dumped file {filename} to {local_file}") 
        except IndexError:
            print(f"[-] Error File {filename} does not exist on the remote server.")      
        except SessionError as e:
            print(f"[-] Error dumping share {filename}: {e}")
        except Exception as e:
            print(f"[-] General error: {e}")
    

    def upload_file(self, localpath, remotepath):
        try:
            with open(localpath, 'rb') as filehandle:
                self.smbclient.putFile(self.name, remotepath, lambda x: file_reader_callback(filehandle))
        except SessionError as e:
            print(f"[-] Error uploading file to {self.name}: {e}")
        except Exception as e:
            print(f"[-] General error: {e}")

def parse_arguments():
    parser = argparse.ArgumentParser(description="smbsharesdumper for Pentesters")
    parser.add_argument('target', nargs='?', default=None, help='[[domain/]username[:password]@]<targetName or address>')
    parser.add_argument("-d", "--domain", help="Domain name")
    parser.add_argument("-u", "--username", help="Username")
    parser.add_argument("-p", "--password", help="Password")
    parser.add_argument("-H", "--hashes", help="LMHASH:NTHASH")
    parser.add_argument("--host", help="Target address or targetName")
    parser.add_argument("-P", "--port", choices=["139", "445"], nargs="?", default="445", metavar="destination port", help="Destination port to connect to SMB Server")

    parser.add_argument("--folder", help="Folder  name")
    parser.add_argument("--file", help="File name")
    parser.add_argument("--list-shares", action="store_true", help="List of shares on the server")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode")
    parser.add_argument("--list-content", action="store_true", help="List of shares content")
    parser.add_argument("--sharename", help="Name of the share")
    parser.add_argument("--dump", action="store_true", help="Dump content of a share locally")
    parser.add_argument("--dumpfile", action="store_true", help="Dump a single file locally")
    parser.add_argument("--mkdir", action="store_true", help="Make a directory")
    parser.add_argument("--delete", action="store_true", help="Delete a directory or a file")
    parser.add_argument("--upload", action="store_true", help="Upload a file")
    parser.add_argument("--destination", help="Destination path")

    parser.add_argument('--targets-file', type=argparse.FileType('r'), help='list of ipaddress of targets')
    args = parser.parse_args()

    return args

def targets(args):
    Targets =[]
    try:   
        T = []
        for j in args.targets_file:
            T.append(j.strip())
        Targets = T
    except:
        a = args.host if (args.host is not None) else parse_target(args.target)[3]
        Targets.append(a)
    return Targets


def main():
    args = parse_arguments()
    try:
        targets_list = targets(args)
    except:
        print("[-] Error Parsing Targets\n")

    for host_ip in targets_list:
        comp = computer()
        comp.ip = host_ip
        comp.hostname = args.host if args.host else host_ip
        if args.domain is not None:
            comp.domain = args.domain
            username = args.username
            password = args.password
   
        else:
            domain, username, password, address = parse_target(args.target)
            comp.domain = domain

        try:
            print(f"[+] Connecting to {host_ip}...")
            smbclient = comp.authentication(username, password, args)
            comp.smbclient = smbclient
            print(f"[+] Connected to {host_ip} successfully.")
        except SessionError as e:
            print(f"[-] Failed to authenticate on {host_ip}: {e}")
            continue
        
        if args.list_shares:
            try:
                shares = comp.list_shares()
                comp.shares = shares
                comp.display_shares()
            except Exception as e:
                print(f"[-] Error listing shares on {host_ip}: {e}")
        
        if args.list_content:
            try:
                shares = comp.list_shares()
                comp.shares = shares
                comp.list_content(args.sharename, args.folder)
            except Exception as e:
                print(f"[-] Error listing share content on {host_ip}: {e}")
        
        if args.dump:
            try:
                local_path = args.destination if args.destination else '.'
                shares = comp.list_shares()
                comp.shares = shares
                comp.dump_shares(local_path, args.sharename, args.folder, args.file)
            except Exception as e:
                print(f"[-] Error dumping share on {host_ip}: {e}")

        if args.dumpfile:
            try:
                local_path = args.destination if args.destination else '.'
                shares = comp.list_shares()
                comp.shares = shares
                comp.getfile(local_path, args.sharename, args.file)
            except Exception as e:
                print(f"[-] Error dumping share on {host_ip}: {e}")

        if args.upload:
            try:
                shares = comp.list_shares()
                comp.shares = shares
                comp.upload(args.file, args.sharename, args.folder)
            except Exception as e:
                print(f"[-] Error listing shares on {host_ip}: {e}")

        if args.mkdir:
            try:
                shares = comp.list_shares()
                comp.shares = shares
                comp.mkdir()
            except Exception as e:
                print(f"[-] Error listing shares on {host_ip}: {e}")

        if args.delete:
            try:
                shares = comp.list_shares()
                comp.shares = shares
                comp.delete()
            except Exception as e:
                print(f"[-] Error listing shares on {host_ip}: {e}")


class user:
    def __init__(self):
        self.username = ''
        self.password = ''
        self.hashes = ''
        self.ccache = ''


if __name__ == "__main__":
    main()