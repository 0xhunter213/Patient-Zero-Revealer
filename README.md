# Patient-Zero-Revealer
Detection of the first infected Windows machine in the network using event logs

## WMIexec 

- SMBv3.0 dialect
- semi-interactive shell 

### Events used to Detect WMIexec utilization

- microsoft-ds protocol intial connection detect event id 3 , network protocol "microsoft-ds" then "epmap"
- the same protocol port will establish a logon event 4624
