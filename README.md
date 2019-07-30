# ReadCert

This is a python script that allows you to pass a file via command line, read the remote TLS certificate presented by the hosts specified in the file, and return serial number and validity info for the purpose of validating a certificate update.

## How to use 

Pass the script on the comand line with the file name containing remote hostnames, with each target on a new line
python ReadCert.py hosts.txt

hosts.txt should look like this:
--------------------
www.google.com   
www.stackoverflow.com    
www.github.com     
--------------------
