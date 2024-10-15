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

```

### 4-dump a single file
```
python3 smbsharesdumper.py  DOMAIN/USER:PASS@IP --dump --share Helpdesk --file hacker.txt
```

### 5-Upload a file
```

```
