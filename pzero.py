# here pzero will start searching using a username or IP address and utilize timestamps
#It will then trace events depending on the user or source IP address until 
#it reaches an IP address that is outside the network or an interactive logon

from Impacket_detection import *
from Elk import *
from Network_protocols_detection import *
from datetime import datetime
from argparse import ArgumentParser
from elasticsearch import Elasticsearch
from decouple import config
from Revealer.pzero_detection import *
import pyfiglet



if __name__ == "__main__":
    # Ascii Art text for tool Name `PZERO`
    pzero_text = "PZero"
    ascii_art_pzero = pyfiglet.figlet_format(text=pzero_text,font = "banner3-D")
    print('')
    print(ascii_art_pzero)
   
    # cli configuration arguments and options for tool usage

    parser = ArgumentParser(description="Patient Zero Revealer a tool to detect first infected machine \
    in the netwrok using Windows Event logs \n using one of those informations is required (USER or IP_SOURCE)")

    parser.add_argument("-u","--user",help="Username of a suspicious user in the network",action="store",required=True)
    parser.add_argument("-i","--ip-source",help="Ip address from Network of a machine to follow its events",action="store")
    parser.add_argument("-t","--timestamp",help="Start time for analysing events",action="store")
    parser.add_argument("-o","--output",help="Output of Detection results in given filename",action="store_true")
    parser.add_argument("-r","--rdp",help="Analyzing only RDP connections",action="store_true")
    parser.add_argument("-s","--ssh",help="Analyzing only ssh connections",action="store_true")
    parser.add_argument("-w","--winrm",help="Analyzing only WinRM connections",action="store_true")
    parser.add_argument("-I","--impackt",help="Analyzing Impacket tools use cases from events (psexec,smbexec,wmiexec,...)",action="store_true")
    parser.add_argument("-Ip","--psexec",help="Detect of Impacket psexec tools from event",action="store_true")
    parser.add_argument("-Is","--smbexec",help="Detect of Impacket smbexec tools from event",action="store_true")
    parser.add_argument("-Iw","--wmiexec",help="Detect of Impacket wmiexec tools from event",action="store_true")

    # store a pared args on variables like its names

    args = parser.parse_args()
    user = args.user # username required
    ip_source = args.ip_source # ip source of a machine
    timestamp = args.timestamp
    timestamp = datetime.strptime(timestamp,"%Y-%m-%dT%H:%M:%S.%fZ") if timestamp else None 
    rdp = args.rdp
    ssh = args.ssh
    winrm = args.winrm
    impacket = args.impackt
    psexec = args.psexec
    smbexec = args.smbexec
    wmiexec = args.wmiexec
    output = args.output

    ELASTIC_PASSWORD = config("ELASTIC_PASSWORD")
    CLOUD_ID = config("CLOUD_ID")
    INDEX_PATTERN = 'winlogbeat-*'

    try:
        es = Elasticsearch(cloud_id=CLOUD_ID,basic_auth=("elastic",ELASTIC_PASSWORD))
    except:
        es = Elasticsearch(cloud_id=CLOUD_ID,http_auth=("elastic",ELASTIC_PASSWORD))

    #analyzing events
    try:
        if rdp:
            header("RDP connections")
            events= rdp_detection.RDP_detection(es=es,user=user,ip_source=ip_source,timestamp=timestamp,all=True)
            print(events)
            events = remove_dubplication(events=events)
            data = print_events(events=events)
            print("="*128)
        
        if ssh:
            header("SSH connections")
            events= ssh_detection.SSH_detection(es=es,user=user,ip_source=ip_source,timestamp=timestamp,all=True)
            events = remove_dubplication(events=events)
            print_events(events=events)
            print("="*128)

        if winrm:
            header("WinRM connections")
            events = winrm_detection.WinRM_detection(es=es,user=user,ip_source=ip_source,timestamp=timestamp,all=True)
            events = remove_dubplication(events=events)
            print_events(events=events)
            print("="*128)        
        
        if impacket:
            header("events caused by Impacket")
            events = pssmbexec_detection.PSSMBexec_detection(es=es,user=user,ip_source=ip_source,timestamp=timestamp,all=True)
            events = remove_dubplication(events=events)
            print_events(events=events)
            events= wmiexec_detection.WMI_detection(es=es,user=user,ip_source=ip_source,timestamp=timestamp,all=True)
            events = remove_dubplication(events=events)
            print_events(events=events)
            print("="*128)
        elif psexec or smbexec:
            header("PSexec events") if psexec else header("SMBexec Events")
            events = pssmbexec_detection.PSSMBexec_detection(es=es,user=user,ip_source=ip_source,timestamp=timestamp,all=True)
            events = remove_dubplication(events=events)
            print_events(events=events)
            print("="*128)
        elif wmiexec:
            header("WMIexec events")
            events = impacket.WMI_detection(es=es,user=user,ip_source=ip_source,timestamp=timestamp,all=True)
            events = remove_dubplication(events=events)
            print_events(events=events)
            print("="*128)

        if not any([rdp,ssh,winrm,impacket,psexec,wmiexec,smbexec]):
            # list all events and get where is the patient zero for each timeline
            header("Detection patient zero")
            # list all last events related 
            events = last_logons(es=es,user=user,ip_source=ip_source,timestamp=timestamp,all=True)
            if events == None:
                print("No events founded!")
                print("="*128)
                exit(0)
            # list of series of events that represent the attack path from patien zero for each timerange
            attacker_paths = list()
            # remove duplicated events
            seens_id = set()
            events = [evt for evt in events if (evt["event"]["code"]+evt["agent"]["ephemeral_id"]) not in seens_id and not seens_id.add(evt["event"]["code"]+evt["agent"]["ephemeral_id"]) ]
            events.sort(key=lambda x: datetime.strptime(x["@timestamp"],"%Y-%m-%dT%H:%M:%S.%fZ"),reverse=True)
            # display diffrent path to patient zero in each timerange   
            for i in range(len(events)):
                print_machine_infos(event=events[i])
                attacker_paths = pzero_revealer(es=es,entry_event=events[i])
                for event in attacker_paths:
                    if event in events[i+1:]:
                        events.pop(i)
                print("="*128)
    except ConnectionError:
        print("[x] Elasticsearch Connection Error")
