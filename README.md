# smbsharesdumper
Smb Shares Dumper For Pentesters


## Usage
```
$ python3 smbsharesdumper.py                                                                    
usage: smbsharesdumper.py [-h] [-d DOMAIN] [-u USERNAME] [-p PASSWORD] [-H HASHES] [--host HOST] [-P [destination port]] [--folder FOLDER]
                          [--file FILE] [--list-shares] [--debug] [--list-content] [--sharename SHARENAME] [--dump] [--dumpfile] [--mkdir]
                          [--delete] [--upload] [--destination DESTINATION] [--targets-file TARGETS_FILE]
                          [target]

smbsharesdumper for Pentesters

positional arguments:
  target                [[domain/]username[:password]@]<targetName or address>

options:
  -h, --help            show this help message and exit
  -d DOMAIN, --domain DOMAIN
                        Domain name
  -u USERNAME, --username USERNAME
                        Username
  -p PASSWORD, --password PASSWORD
                        Password
  -H HASHES, --hashes HASHES
                        LMHASH:NTHASH
  --host HOST           Target address or targetName
  -P [destination port], --port [destination port]
                        Destination port to connect to SMB Server
  --folder FOLDER       Folder name
  --file FILE           File name
  --list-shares         List of shares on the server
  --debug               Enable debug mode
  --list-content        List of shares content
  --sharename SHARENAME
                        Name of the share
  --dump                Dump content of a share locally
  --dumpfile            Dump a single file locally
  --mkdir               Make a directory
  --delete              Delete a directory or a file
  --upload              Upload a file
  --destination DESTINATION
                        Destination path
  --targets-file TARGETS_FILE
                        list of ipaddress of targets
```
### --list-shares
```
[[domain/]username[:password]@]<targetName or address> --list-shares --debug
--host <HOST> --list-shares
--targets-file <PATH> --list-shares
```

### --list-content
```
[[domain/]username[:password]@]<targetName or address> --list-shares --debug
--host <HOST> --list-shares
--targets-file <PATH> --list-shares
```

### --dump
```
[[domain/]username[:password]@]<targetName or address> --dump
--host <HOST> --dump 
--targets-file <PATH> --dump
```

### --dump-file
```
[[domain/]username[:password]@]<targetName or address> --dump-file --share <SHARE_NAME> --file <REMOTE_FILE> --destination <OUTPUT_FOLDER>
--host <HOST> --dump-file --share <SHARE_NAME> --file <REMOTE_FILE> --destination <OUTPUT_FOLDER>
```

### --upload
```
[[domain/]username[:password]@]<targetName or address> --upload --share <SHARE_NAME> --folder <REMOTE_FOLDER> --file <LOCAL_FILE>
--host <HOST> --upload --share <SHARE_NAME> --folder <REMOTE_FOLDER>  --file <LOCAL_FILE>
```
### --mkdir
```
Comming Soon!!!
```
### --delete
```
Comming Soon!!!
```
