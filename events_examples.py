import Evtx.Evtx as evtx
import os,xmltodict,contextlib,json,mmap,traceback
import xml.etree.ElementTree as ET
from datetime import datetime
from Evtx.Evtx import FileHeader
from Evtx.Views import evtx_file_xml_view
import sys

file_path = './EVTX-to-MITRE-Attack/TA0008-Lateral Movement/' 

EVENTS = [1149,]

LOGIN_INFORMATIONS = [{"user":"","sucessful login":0,"failed login":0}]
KERBEROS_AUTH = []
NTLM_AUTHENTIFICATION=[]
ASSIGNED_ADMIN = []

# suspicious events and movements 

POWERSHELL_SUSPICOUS_COMMANDS = ['Invoke-DllInjection', 'Invoke-Shellcode', 'Invoke-WmiCommand', 'Get-GPPPassword', 'Get-Keystrokes', 'Get-TimedScreenshot', 'Get-VaultCredential', 'Invoke-CredentialInjection', 'Invoke-Mimikatz', 'Invoke-NinjaCopy', 'Invoke-TokenManipulation', 'Out-Minidump', 'VolumeShadowCopyTools', 'Invoke-ReflectivePEInjection', 'Invoke-UserHunter', 'Find-GPOLocation', 'Invoke-ACLScanner', 'Invoke-DowngradeAccount', 'Get-ServiceUnquoted', 'Get-ServiceFilePermission', 'Get-ServicePermission', 'Invoke-ServiceAbuse', 'Install-ServiceBinary', 'Get-RegAutoLogon', 'Get-VulnAutoRun', 'Get-VulnSchTask', 'Get-UnattendedInstallFile', 'Get-WebConfig', 'Get-ApplicationHost', 'Get-RegAlwaysInstallElevated', 'Get-Unconstrained', 'Add-RegBackdoor', 'Add-ScrnSaveBackdoor', 'Gupt-Backdoor', 'Invoke-ADSBackdoor', 'Enabled-DuplicateToken', 'Invoke-PsUaCme', 'Remove-Update', 'Check-VM', 'Get-LSASecret', 'Get-PassHashes', 'Invoke-Mimikatz', 'Show-TargetScreen', 'Port-Scan', 'Invoke-PoshRatHttp', 'Invoke-PowerShellTCP', 'Invoke-PowerShellWMI', 'Add-Exfiltration', 'Add-Persistence', 'Do-Exfiltration', 'Start-CaptureServer', 'Invoke-DllInjection', 'Invoke-ReflectivePEInjection', 'Invoke-ShellCode', 'Get-ChromeDump', 'Get-ClipboardContents', 'Get-FoxDump', 'Get-IndexedItem', 'Get-Keystrokes', 'Get-Screenshot', 'Invoke-Inveigh', 'Invoke-NetRipper', 'Invoke-NinjaCopy', 'Out-Minidump', 'Invoke-EgressCheck', 'Invoke-PostExfil', 'Invoke-PSInject', 'Invoke-RunAs', 'MailRaider', 'New-HoneyHash', 'Set-MacAttribute', 'Get-VaultCredential', 'Invoke-DCSync', 'Invoke-Mimikatz', 'Invoke-PowerDump', 'Invoke-TokenManipulation', 'Exploit-Jboss', 'Invoke-ThunderStruck', 'Invoke-VoiceTroll', 'Set-Wallpaper', 'Invoke-InveighRelay', 'Invoke-PsExec', 'Invoke-SSHCommand', 'Get-SecurityPackages', 'Install-SSP', 'Invoke-BackdoorLNK', 'PowerBreach', 'Get-GPPPassword', 'Get-SiteListPassword', 'Get-System', 'Invoke-BypassUAC', 'Invoke-Tater', 'Invoke-WScriptBypassUAC', 'PowerUp', 'PowerView', 'Get-RickAstley', 'Find-Fruit', 'HTTP-Login', 'Find-TrustedDocuments', 'Invoke-Paranoia', 'Invoke-WinEnum', 'Invoke-ARPScan', 'Invoke-PortScan', 'Invoke-ReverseDNSLookup', 'Invoke-SMBScanner', 'Invoke-Mimikittenz']



def parse_evtx_to_dict(filename):
    with open(filename) as f:
        with contextlib.closing(mmap.mmap(f.fileno(),0,access=mmap.ACCESS_READ)) as buf:
            fh = FileHeader(buf,0)
            for xml , record in evtx_file_xml_view(fh):
                try:
                    yield xmltodict.parse(xml)
                except:
                    print("Parsing Exception")
                    print(traceback.print_exc()) 

def event_logon_type(event):
    for data in event["Event"]["EventData"]["Data"]:
        if data["@Name"] == "LogonType":
            return data["#text"]

def target_username(event):
    for data in event["Event"]["EventData"]["Data"]:
        if data["@Name"] == "TargetUserName":
            return data["#text"]
# RDP Suspicious

def RDP_ANALYZING(event):
    event_id =event["Event"]["System"]["EventID"]["#text"]
    logon_type = event_logon_type(event)
    if event_id == "4624" and event_id == "7":
        print("RDP event weeee")
        print(target_username(event))
        sys.exit(0)
# dirs = os.listdir(file_path)
# for dir in dirs:
#     files = os.listdir(file_path+dir)
#     for file in files:
#         print("=========: "+file)
#         print("<Events>")     
#         with evtx.Evtx(file_path+dir+"/"+file) as log:
#             for record in log.records():
#                 try:
#                     node = record.xml()
#                     # Parse XML data into a dictionary
#                     xml_dict = xmltodict.parse(node)

#                     # Convert the dictionary to JSON
#                     json_data = json.dumps(xml_dict, indent=4)

#                     # Print the JSON data
#                     print(json_data)
#                     exit(0)
#                 except:
#                     pass

filename = "/home/hunter/Documents/PFE/zero_patient/EVTX-to-MITRE-Attack/TA0008-Lateral Movement/T1021.001-Remote Desktop Protocol/ID4688-4778 RDP hijack command execution.evtx"
filename = "./Security.evtx"

for event in parse_evtx_to_dict(filename):
    try:
        RDP_ANALYZING(event=event)
    except:
        pass
# with evtx.Evtx(filename) as log:
#     for recorde in log.records():
#         print(recorde.xml())