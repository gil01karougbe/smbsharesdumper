python3 test.py -d MARVEL.local -u fcastle -p Password1 -host 10.128.0.2 --list-shares --debug


python3 test.py -d MARVEL.local -u fcastle -p Password1 --targets-file /opt/ip.txt --list-shares --debug


python3 test.py MARVEL.local/fcastle:Password1@10.128.0.2 --list-shares --debug


python3 test.py -d MARVEL.local -u fcastle --hashes aad3b435b51404eeaad3b435b51404ee:c39f2beb3d2ec06a62cb887fb391dee0