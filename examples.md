python3 smbsharesdumper.py -d corp.local -u helpdesk -p YourS3cret --host 192.168.52.129 --list-shares --debug


python3 smbsharesdumper.py -d corp.local -u helpdesk -p YourS3cret --targets-file ip.txt --list-shares --debug


python3 smbsharesdumper.py corp.local/helpdesk:YourS3cret@192.168.52.130 --list-shares --debug

python3 smbsharesdumper.py corp.local/helpdesk:YourS3cret@192.168.52.130 --list-shares --share Helpdesk --debug

python3 smbsharesdumper.py corp.local/helpdesk:YourS3cret@192.168.52.130 --list-content --sharename SYSVOL --folder corp.local

python3 smbsharesdumper.py corp.local/helpdesk:YourS3cret@192.168.52.130 --dump --share Helpdesk --file hacker.txt

python3 smbsharesdumper.py -d corp.local -u helpdesk --hashes aad3b435b51404eeaad3b435b51404ee:c39f2beb3d2ec06a62cb887fb391dee0