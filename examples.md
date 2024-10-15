# Some Use Cases

### 1-list shares
```
python3 smbsharesdumper.py -d DOMAIN -u USER -p PASS --host IP --list-shares

python3 smbsharesdumper.py  DOMAIN/USER:PASS@IP --list-shares

python3 smbsharesdumper.py -d DOMAIN -u USER -p PASS --targets-file /Path/To/targets.txt --list-shares
```

### 2-list content
```
python3 smbsharesdumper.py -d DOMAIN -u USER -p PASS --host IP --list-content --sharename SHARE

python3 smbsharesdumper.py DOMAIN/USER:PASS@IP --list-content --sharename SHARE --folder FOLDER
```

### 3-dump shares
```
python3 smbsharesdumper.py -d DOMAIN -u USER -p PASS --host IP --dump --destination OUTPUT_FOLDER

python3 smbsharesdumper.py  DOMAIN/USER:PASS@IP --dump --destination OUTPUT_FOLDER

python3 smbsharesdumper.py -d DOMAIN -u USER -p PASS --targets-file /Path/To/targets.txt --dump --destination OUTPUT_FOLDER
```

### 4-dump a single file
```
 --share Helpdesk --file hacker.txt
```

### 5-Upload a file
```
python3 smbsharesdumper.py  DOMAIN/USER:PASS@IP --upload --share SHARE --folder REMOTE_FOLDER --file LOCAL_FILE

python3 smbsharesdumper.py -d DOMAIN -u USER -p PASS --host <HOST> --upload --share SHARE --folder REMOTE_FOLDER --file LOCAL_FILE
```
