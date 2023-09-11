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
from Revealer.pzero_detection import pzero_revealer
# lookin for interactive logon

if __name__ == "__main__":
    # cli configuration arguments and options for tool usage
    parser = ArgumentParser(description="Patient Zero Revealer a tool to detect first infected machine\
                            in the netwrok using Windows Event logs")
    parser.add_argument("-u","--user",help="Username of a suspicious user in the network",action="store")
    parser.add_argument("-i","--ip-source",help="Ip address from Network of a machine to follow its events",action="store")
    parser.add_argument("-t","--timestamp",help="start time for analysing events",action="store")
    args = parser.parse_args()
    user= args.user # username required
    ip_source = args.ip_source # ip source of a machine
    timestamp = args.timestamp
    timestamp = datetime.strptime(timestamp,"%Y-%m-%dT%H:%M:%S.%fZ") if timestamp else None 
    ELASTIC_PASSWORD = config("ELASTIC_PASSWORD")
    CLOUD_ID = config("CLOUD_ID")
    INDEX_PATTERN = 'winlogbeat-*'

    es = Elasticsearch(cloud_id=CLOUD_ID,http_auth=("elastic",ELASTIC_PASSWORD))
    pzero_machine_infos = pzero_revealer(es=es,user=user,ip_source=ip_source,timestamp=timestamp)
    print_machine_infos(pzero_machine_infos)