from impacket.smbconnection import SMBConnection, SessionError, SMB2_DIALECT_002, SMB2_DIALECT_21, SMB_DIALECT
from impacket.examples.utils import parse_target
from impacket import nt_errors
from prettytable import PrettyTable
import argparse, os


def parse_arguments():
    parser = argparse.ArgumentParser(description="smbsharesdumper for Pentesters")
    parser.add_argument('target', nargs='?', default=None, help='[[domain/]username[:password]@]<targetName or address>')
    parser.add_argument("-d", "--domain", help="Domain name")
    parser.add_argument("-u", "--username", help="Username")
    parser.add_argument("-p", "--password", help="Password")
    parser.add_argument("-H", "--hashes", help="LMHASH:NTHASH")
    parser.add_argument("-host", "--host", help="Target address or targetName")
    parser.add_argument("-P", "--port", choices=["139", "445"], nargs="?", default="445", metavar="destination port", help="Destination port to connect to SMB Server")

    parser.add_argument("-folder", "--folder", help="Folder  name")
    parser.add_argument("-file", "--file", help="File name")
    parser.add_argument("--list-shares", action="store_true", help="List all shares on the server")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode")
    parser.add_argument("--list-content", action="store_true", help="List content of a share hierarchically")
    parser.add_argument("-share", "--sharename", help="Name of the share")
    parser.add_argument("--dump", action="store_true", help="Dump content of a share locally")
    parser.add_argument("--mkdir", action="store_true", help="Make a directory")
    parser.add_argument("--delete", action="store_true", help="Delete a directory or a file")
    parser.add_argument("--upload", action="store_true", help="Upload a file")
    parser.add_argument("-destination", "--destination", help="Destination path")

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


def authentication(args, domain='', username='', password='', address='', lmhash='', nthash=''):
    if args.target is not None:
        domain, username, password, address = parse_target(args.target) 
    else:
        if args.host is None:
            domain = args.domain
            username = args.username
            try:
                password = args.password
            except:
                lmhash, nthash = args.hashes.split(':')
        else:
            domain = args.domain
            username = args.username
            address = args.host
            try:
                password = args.password
            except:
                lmhash, nthash = args.hashes.split(':')
    
    smbClient = SMBConnection(address, address, sess_port=int(args.port))
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
    smbClient.login(username, password, domain, lmhash, nthash)
    if smbClient.isGuestSession() > 0:
        if args.debug:
            print("[+] GUEST Session Granted")
    else:
        if args.debug:
            print("[+] USER Session Granted")
    return smbClient

def list_shares(smb):
    all_shares = smb.listShares()
    shares = []
    for s in range(len(all_shares)):
        rsrc = {}
        rsrc["sharename"] = all_shares[s]["shi1_netname"][:-1]
        rsrc["Description"] = all_shares[s]["shi1_remark"][:-1]
        shares.append(rsrc)
    return shares

def list_share_content(smb, sharename, path='/*'):
    print("[+] Listing Content In " + sharename + " Share:")
    all_files = []
    content = smb.listPath(sharename, path)
    for item in content:
        file = {}
        #file["shortname"] = item.get_shortname()
        if item.get_longname() not in ('.', '..'):
            file["name"] = item.get_longname()
            file["size"] = item.get_filesize()
            file["type"] = 'FILE' if (item.is_directory() == 0) else 'DIR'
            all_files.append(file)  
    return all_files

def display(data):
    table = PrettyTable()
    table.field_names = data[0].keys()
    for row in data:
        table.add_row(row.values())
    print(table)


def dumpfile(smb, share, filename, destination='./'):
    name = filename.split('/')[-1]
    output =  os.path.join(destination, name)
    try:
        f = open(name, "wb")
        smb.getFile(share, filename, f.write)
        f.close()
    except SessionError as e:
        print("[-]" + nt_errors.ERROR_MESSAGES[e.error][0])


def list_files(smb, share, dir):
    all_files = []
    try:
        content = list_share_content(smb, share, path=dir)
        for item in content:
            if item['type'] == 'FILE':
                all_files.append(item['name'])
            else:
                subdir_path = os.path.join(dir, item['name'])
                sub_files = list_files(smb, share, subdir_path)
                if sub_files is not None:
                    all_files.extend(sub_files)   
    except SessionError as e:
        print("[-]" + nt_errors.ERROR_MESSAGES[e.error][0])
    print(all_files)

def dumshare(smb, share, destination='.'):
    try:
        content = list_share_content(smb,share)
    except SessionError as e:
        print("[-]" + nt_errors.ERROR_MESSAGES[e.error][0])



if __name__ == "__main__":
    args = parse_arguments()
    Targets = targets(args)
    if len(Targets) == 1:
        smb = authentication(args, address=Targets[0])
        if args.list_shares == True:
            shares = list_shares(smb)
            print("[+] Listing shares ...")
            display(shares)
        
        list_files(smb, 'hackme', '/*')

        if args.dump == True and args.sharename != None and args.file != None:
            print("[+]Dumping file ...")
            dumpfile(smb, args.sharename, args.file)
        
        if args.dump == True and args.sharename != None and args.file == None:
            print("[+]Dumping share ...")


        if args.list_content == True and args.sharename==None and args.folder==None:
            shares = list_shares(smb)
            for item in shares:
                name = item['sharename']
                try:
                    content = list_share_content(smb, name)
                    if len(content) != 0:
                        display(content)
                except SessionError as e:
                    print("[-]" + nt_errors.ERROR_MESSAGES[e.error][0])
                    continue
        elif args.list_content == True and args.sharename != None and args.folder == None:
            try:
                content = list_share_content(smb, args.sharename)
                if len(content) != 0:
                    display(content)
            except SessionError as e:
                print("[-]" + nt_errors.ERROR_MESSAGES[e.error][0])
        
        elif args.list_content == True and args.sharename != None and args.folder != None:
            try:
                content = list_share_content(smb, args.sharename, path=args.folder + '/*')
                if len(content) != 0:
                    display(content)
            except SessionError as e:
                print("[-]" + nt_errors.ERROR_MESSAGES[e.error][0])
 
    else:
        for item in Targets:
            print("[+]Processing: "+ item)
            smb = authentication(args, address=item)
            if args.list_shares == True:
                shares = list_shares(smb)
                print("[+] Listing shares ...")
                display(shares)
                
            if args.list_content == True:
                shares = list_shares(smb)
                for item in shares:
                    name = item['sharename']
                    try:
                        content = list_share_content(smb, name)
                        if len(content) != 0:
                            display(content)
                    except SessionError as e:
                        print("[-]" + nt_errors.ERROR_MESSAGES[e.error][0])
                        continue
