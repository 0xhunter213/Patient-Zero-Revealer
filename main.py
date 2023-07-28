from elasticsearch import Elasticsearch
from decouple import config
from datetime import datetime, timedelta
import re
from argparse import ArgumentParser
# Import Deployment Secrets keys
 
ELASTIC_PASSWORD = config("ELASTIC_PASSWORD")
CLOUD_ID = config("CLOUD_ID")
INDEX_PATTERN = 'winlogbeat-*'
es = Elasticsearch(cloud_id=CLOUD_ID,http_auth=("elastic",ELASTIC_PASSWORD))

# searching for event with query
def event_searching(query):
    r = es.search(index=INDEX_PATTERN,query=query)
    if r["hits"]["total"]["value"] != 0:
        event=r["hits"]["hits"][0]["_source"]
        return event
    else:
        return None

# printing style of specific events
def printing_event(event):
    try:
        print(f'Timestamp        : {event["@timestamp"]}\n\
                Username         : {event["user"]}\n\
                Ip Address Host  : {event["host"]["ip"]}\n\
                Ip Addres Source : {event["source"]}\n')
    except:
        print(event)

def RDP_connections(user=None,ip_source=None,timestamp=None):
    '''
        Remote Desktop connections for a specifc user parameters
    '''
    # RDP searching query

    search_query ={ 
        "bool":{
            "must":[
                {"match":{"event.code":"4624"}},
                {"match":{"winlog.event_data.LogonType":"10" or "7"}},
                #{"match":{"winlog.event_data.LogonType":"7"}},
            ],
            "filter":[
            ],
            }
    }

    if user != None:
        # searching with user name (attacker)
        search_query["bool"]["filter"].append({"term":{"winlog.event_data.TargetUserName":user}})
    
    if ip_source != None:
        # adding Ip address source of previous event
        search_query["bool"]["filter"].append({"term":{"host.ip":ip_source}})
    
    if timestamp != None:
        # searching with timestamp range
        timeline = datetime.strptime(timestamp,"%Y-%m-%dT%H:%M:%S.%fZ") - timedelta(hours=24)
        min_timestamp = timeline.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        search_query["bool"]["filter"].append({"range":{
            "@timestamp":{
                "lte":timestamp,
                "gte":min_timestamp,
            }
        }})

    # searching results
    # exisit item with event ID 4624 type 10 searched
    # also we can use timestamp or machine `ip` `name` ...
    # adding a range timestamp to just analysis the last 24 hours events
    timeline = datetime.now() - timedelta(hours=24)
    min_timestamp = timeline.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    search_query["bool"]["filter"].append({"range":{
            "@timestamp":{
                "gte":min_timestamp,
            }
    }}) 
    event_4624_rdp = event_searching(query=search_query)


    if event_4624_rdp != None: 
        printing_event(event_4624_rdp)
        return event_4624_rdp
    else:
        print(f"No RDP connections with this Parameters\n")
        return None

def WinRM_connections(user=None,ip_source=None,timestamp=None):
    '''
        Windows Remote Management Connection depending to user or ip source of suspicious machine or with timestamp
    '''
    # winrm searching query 
    search_query = {
        "bool":{
            "must":[{"match":{"event.code":"91"}}],
            "filter":[],
        }
    }
    
    if user != None:
        # searching with user name (attacker)
        search_query["bool"]["filter"].append({"term":{"winlog.user.name":user}})
    
    if ip_source != None:
        # adding Ip address source of previous event
        search_query["bool"]["filter"].append({"term":{"host.ip":ip_source}})
    
    if timestamp != None:
        # searching with timestamp range
        timeline = datetime.strptime(timestamp,"%Y-%m-%dT%H:%M:%S.%fZ") - timedelta(hours=24)
        min_timestamp = timeline.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        search_query["bool"]["filter"].append({"range":{
            "@timestamp":{
                "lte":timestamp,
                "gte":min_timestamp,
            }
        }})
    # adding this line for testing need to just get event of last 24 hours

        timeline = datetime.now() - timedelta(hours=24)
        min_timestamp = timeline.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        search_query["bool"]["filter"].append({"range":{
            "@timestamp":{
                "gte":min_timestamp,
            }
        }})

    event_winrm_rquest = event_searching(query=search_query)
    if event_winrm_rquest != None:
        # message of event contains ip address of attacker machine
        source_machine_info = re.search(r'.clientIP:...\)$',event_winrm_rquest["message"])
        print(event_winrm_rquest)
        if source_machine_info:
            # winrm shell was initialized by a machine out of network
            printing_event(event_winrm_rquest)
            return event_winrm_rquest
        else:
            # winrm was started by a machine within network
            # so looking for event id 6 with process name "WSMan API Initialize" wich occured 0..1 min before 91

            timestamp = datetime.strptime(event_winrm_rquest["@timestamp"],"%Y-%m-%dT%H:%M:%S.%fZ") + timedelta(minutes=1)
            timestamp = timestamp.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
            print(timestamp)
            search_query = {
                "bool":{
                    "must":[
                        {"match":{"event.code": "6"}},
                        #{"match":{"event.action":"WSMan API Initialize"}}
                    ],
                    "filter":[
                        {"range":{
                            "@timestamp":{
                                "gte":event_winrm_rquest["@timestamp"],
                                "lte":timestamp,
                            }
                        }}
                    ]
                }
            }

            event_wsman_init = event_searching(query=search_query)

            if event_wsman_init:
                return event_wsman_init
            else:
                print("No WSMan API Initialize event")
                return None

    else:
        print("No WinRM connections with this Paremeters\n")
        return None

if __name__ == "__main__":

    # cli configuration arguments and options for tool usage
    parser = ArgumentParser(description="Patient Zero Revealer a tool to detect first infected machine\
                            in the netwrok using Windows Event logs")
    parser.add_argument("-u","--user",help="Username of a suspicious user in the network",action="store",required=True)
    parser.add_argument("-i","--ip-source",help="Ip address from Network of a machine to follow its events",action="store")
    args = parser.parse_args()
    user= args.user # username required
    ip_source = args.ip_source # ip source of a machine
    
    # testing RDP events first

    event_rdp = RDP_connections(user=user,ip_source=ip_source)    
    event_winrm = WinRM_connections(user=user,ip_source=ip_source)
    print(f"RDP flow:")
    print(event_rdp)
    print(f"WinRM flow:")
    printing_event(event_winrm)
    print("DONE ")