from elasticsearch import Elasticsearch
from decouple import config
from datetime import datetime, timedelta
import re
import argparse
# Import Deployment Secret keys
 
ELASTIC_PASSWORD = config("ELASTIC_PASSWORD")
CLOUD_ID = config("CLOUD_ID")
INDEX_PATTERN = 'winlogbeat-*'

es = Elasticsearch(cloud_id=CLOUD_ID,http_auth=("elastic",ELASTIC_PASSWORD))

# searching for event with query
def event_searching(query,sort={"@timestamp":{"order":"desc"}},all=False):
    r = es.search(index=INDEX_PATTERN,query=query,sort=sort)
    if r["hits"]["total"]["value"] != 0:
        if all:
            # return all the events 
            events = [ evt["_source"] for evt in r["hits"]["hits"]] # return only _source item from each event in the list
            return events
        # return only the last events
        event=r["hits"]["hits"][0]["_source"]
        return event
    else:
        return None

# printing RDP event
def print_event(event):
    try:
        # get the event id to define the structre of the event
        event__code = event["event"]["code"]

        if event__code == "4624":
            print(f'''
                    RDP Connection:
                    Timestamp               : {event["@timestamp"]}\n\
                    Id                      : {event["user"]["id"]}\n\
                    Username                : {event["user"]["name"]}\n\
                    Domaine                 : {event["user"]["domain"]}\n\
                    Host Name               : {event["host"]["hostname"]}\n\
                    Ip Address Host (IPV4)  : {event["host"]["ip"][1]}\n\
                    Ip Address Host (IPV6)  : {event["host"]["ip"][0]}\n\
                    Source Domain           : {event["source"]["domain"]}\n\
                    Ip Addres Source        : {event["source"]["ip"]}\n''')
        
        elif event__code in ["91","6"]:
            print(f'''
                    WinRM Connection:
                    Timestamp               : {event["@timestamp"]}\n\
                    Id                      : {event["winlog"]["user"]["identifier"]}\n\
                    Username                : {event["winlog"]["user"]["name"]}\n\
                    Domaine                 : {event["winlog"]["user"]["domain"]}
                    Host Name               : {event["host"]["hostname"]}\n\
                    Ip Address Host (IPV4)  : {event["host"]["ip"][1]}\n\
                    Ip Address Host (IPV6)  : {event["host"]["ip"][0]}\n\
                    Connection              : {event["winlog"]["event_data"]["connection"]}\n\
            ''')
        elif event__code == "4":
            print(f'''
                    SSH Connection:
                    Timestamp               : {event["@timestamp"]}\n\
                    Id                      : {event["winlog"]["user"]["identifier"]}\n\
                    Username                : {event["winlog"]["user"]["name"]}\n\
                    Domaine                 : {event["winlog"]["user"]["domain"]}
                    Host Name               : {event["host"]["hostname"]}\n\
                    Ip Address Host (IPV4)  : {event["host"]["ip"][1]}\n\
                    Ip Address Host (IPV6)  : {event["host"]["ip"][0]}\n\
                    Information             : {event["message"]}\n\
            ''')
        
        # more events ? ...

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
                {"match":{"winlog.event_data.LogonType":"10"}}
            ],
            "filter":[
            ],
            }
    }

    if user != None:
        # searching with user name (attacker)
        search_query["bool"]["must"].append({"match":{"winlog.event_data.TargetUserName":user}})
    
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
    else:
        # adding a range timestamp to just analysis the last 48 hours events
        timeline = datetime.now() - timedelta(hours=48)
        min_timestamp = timeline.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        search_query["bool"]["filter"].append({"range":{
                "@timestamp":{
                    "gte":min_timestamp,
                }
        }}) 
    # searching results
    # exisit item with event ID 4624 type 10 searched
    # also we can use timestamp or machine `ip` `name` ...

    event_4624_rdp = event_searching(query=search_query)


    if event_4624_rdp: 
        return event_4624_rdp
    else:
        search_query["bool"]["must"][1]= {"match":{"winlog.event_data.LogonType":"7"}}
        event_4624_rdp = event_searching(query=search_query)
        if event_4624_rdp:
            return event_4624_rdp
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
        search_query["bool"]["must"].append({"match":{"winlog.user.name":user}})
    
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
    else:
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
        source_machine_info = re.search(r'clientIP:',event_winrm_rquest["message"])

        if source_machine_info:
            # winrm shell was initialized by a machine out of network
            return event_winrm_rquest
        else:
            # winrm was started by a machine within network
            # so looking for event id 6 with process name "WSMan API Initialize" wich occured 0..1 min before 91

            timestamp = datetime.strptime(event_winrm_rquest["@timestamp"],"%Y-%m-%dT%H:%M:%S.%fZ") + timedelta(minutes=1)
            timestamp = timestamp.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
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
                print("No WSMan session Initialize event")
                return None

    else:
        print("No WinRM connections with this Paremeters\n")
        return None

def SSH_connections(user=None,ip_source=None,timestamp=None):
    '''
        ssh connection events
        event id is 4 also sysmon there is an event with id 4 so we diffrence between them with message item
    '''
    # searching with event.code = "4" and an accepting connection message from openssh
    search_query = {
        "bool":{
            "must":[
                {"match":{"event.code":"4"}},
                {"match_phrase_prefix":{"message":"sshd: Accepted password for .*"}}
            ],
            "filter":[],
        }
    }
    
    if user != None:
        # searching with user name (attacker)
        # ssh query diffrenete user with mentioned in message as he made a succeful connection
        search_query["bool"]["must"][1]["match_phrase_prefix"]["message"] = f"sshd: Accepted password for {user} .*"
    
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
    else:
        timeline = datetime.now() - timedelta(hours=24)
        min_timestamp = timeline.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        search_query["bool"]["filter"].append({"range":{
            "@timestamp":{
                "gte":min_timestamp,
            }
        }})


    event_ssh = event_searching(search_query)
    
    if event_ssh:
        return event_ssh
    else:
        return None

def PSSMBexec_connections(user=None,ip_source=None,timestamp=None):
    '''
    Detection of a potential PsExec connection based on the usage of SMB\
    This function looks for all events with ID 7045 (service installed) and events that came after event 3 with\
    network protocol "microsoft-ds" (SMB)Additionally, it checks for event ID 4624 with type 3, which indicates \
    that PsExec or SMBExec was used to log in to this machine.
    '''
    # looking for sequence of events 3,4624,4672,7045
    # need argument for searching cause it possible there's a lot of 7045
    # so need to specify the search

    #user is required arg    
    assert user
    
    # search for the serveci event id == 7045
    search_query ={
        "bool":{
            "must":[
                {"match":{"event.code":"7045"}}, 
                {"match":{"winlog.user.name":user}},
            ],
            "filter":[]
            }
    }

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
    else:
        timeline = datetime.now() - timedelta(hours=24)
        min_timestamp = timeline.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        search_query["bool"]["filter"].append({"range":{
            "@timestamp":{
                "gte":min_timestamp,
            }
        }})

    events_sercice_installed = event_searching(search_query,all=True)
    returned_event = None
    if events_sercice_installed:
        for event in events_sercice_installed:
            backwarding_timestamp = datetime.strptime(event["@timestamp"],"%Y-%m-%dT%H:%M:%S.%fZ") - timedelta(seconds=5)
            backwarding_timestamp = backwarding_timestamp.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
            machine_ip_dest = event["host"]["ip"][1] # ip address of destination machine target
            search_query_event_4624 = {
                "bool":{
                    "must":[
                    {"match":{"event.code":"4624"}},
                    {"match":{"user.name":user}},
                    {"match":{"host.ip":machine_ip_dest}},
                    {"match":{"winlog.event_data.LogonType":"3"}}
                    ],
                    # time range of 0 to 5 seconds, this ensures that the events are sequenced consecutively.
                    "filter":[
                        {"range":{
                            "@timestamp":{
                                "lte":event["@timestamp"],
                                "gt":backwarding_timestamp
                            }
                        }}
                    ]
            }
            }
            # smb connection on the machie
            search_query_event_3 = {
                "bool":{
                    "must":[
                        {"match":{"event.code":"3"}},
                        {"match":{"network.protocol":"microsoft-ds"}},
                        {"match":{"related.ip":machine_ip_dest}},
                    ],
                    "filter":[
                        {"range":{
                            "@timestamp":{
                                "lte":event["@timestamp"],
                                "gte":backwarding_timestamp
                            }
                        }}
                    ]
                }
            }
            # with the searching query above now searching for 4624 event and 3 
            event_4624 = event_searching(search_query_event_4624)
            event_3 = event_searching(search_query_event_3)

            if event_3 and event_4624:
                return event_4624 # return login event bcz it contain all infos of user
            elif event_4624:
                #Save the login event because sometimes event 3 may fall outside our specified time range. Not sure here
                returned_event = event_4624 
        
        # if we dont find any correct sequence with return a valid 4624 event came before 7045
        return returned_event 
    else:
        return None
def WMI_connections(user=None,ip_source=None,timestamp=None):
    """
        Detection utilization of wmiexec from impacket tool kit in the network\
        using event id 3,4672,4624
    """
    assert user
    
    # first find epmap connection
    search_query = {
        "bool":{
            "must":[
                {"match":{"event.code":"3"}},
                {"match":{"network.protocol":"epmap"}}
            ],
            "filter":[]
        }
    }

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
    else:
        timeline = datetime.now() - timedelta(hours=72)
        min_timestamp = timeline.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        search_query["bool"]["filter"].append({"range":{
            "@timestamp":{
                "gte":min_timestamp,
            }
        }})

    event_epmap = event_searching(search_query)
    # if epmap exist we look for 4624 forward and event id 3 backward by 5 seconds range and comparing source port from two events
    if event_epmap:
        machine_ip_dest = event_epmap["host"]["ip"][1] # ip address of destination machine target
        machine_ip_src = event_epmap["source"]["ip"] # ip address of source attacker machine
        # delta time range used for searching adding 1 second to epmap event bcz logon happening after it
        delta_timestamp = datetime.strptime(event_epmap["@timestamp"],"%Y-%m-%dT%H:%M:%S.%fZ") + timedelta(seconds=1)
        delta_timestamp_4624 = delta_timestamp.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        # search query for 4624 with user parmaters
        search_query_4624={
            "bool":{
                "must":[
                    {"match":{"event.code":"4624"}},
                    {"match":{"winlog.event_data.TargetUserName":user}},
                    {"match":{"source.ip":machine_ip_src}},
                    {"match":{"host.ip":machine_ip_dest}}
                ],
                "filter":[
                    {"range":{
                        "@timestamp":{
                            "lte":delta_timestamp_4624,
                            "gt":event_epmap["@timestamp"] # range time bigger then event epmap timestamp and less then it adding 1 second
                        }
                    }}
                ]
            }
        }
        event_4624 = event_searching(search_query_4624)
        #delta time range substration of 1 second bcz SMB connection heppening before it
        backwarding_timestamp = datetime.strptime(event_epmap["@timestamp"],"%Y-%m-%dT%H:%M:%S.%fZ") - timedelta(seconds=1)
        backwarding_timestamp = backwarding_timestamp.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        # event id 3
        search_query_3 = {
            "bool":{
                    "must":[
                        {"match":{"event.code":"3"}},
                        {"match":{"network.protocol":"microsoft-ds"}},
                        {"match":{"related.ip":machine_ip_dest}},
                        {"match":{"source.ip":machine_ip_src}}
                    ],
                    "filter":[
                        {"range":{
                            "@timestamp":{
                                "lte":event_epmap["@timestamp"],
                                "gte":backwarding_timestamp
                            }
                        }}
                    ]
                }
        }
        
        event_3 = event_searching(search_query_3)
        if event_3:
            return event_4624
        else:
            print("[X] No event 3 but there is 4624 events")
            print_event(event_4624) # if there was a problem print event 4624 
            return None
    else:
        return None



def patient_zero(user=None,ip_source=None,timestamp=None):
    '''
        analysing different windows events log (rdp,winrm)\
        to get to first machine was infected by attacker
    '''
    # checks all availible intial connections of the user
    event = True
    past_event = None
    target_user = user
    source_ip = ip_source
    starting_time = timestamp  

    while event:
        event = RDP_connections(user=target_user,ip_source=source_ip,timestamp=starting_time)
        if event == None:
            # RDP connection event
            event = WinRM_connections(user=target_user,ip_source=source_ip,timestamp=starting_time)
            
            if event == None:
                event = SSH_connections(user=target_user,ip_source=source_ip,timestamp=starting_time)
                if event:
                    message = event["message"]
                    frm_idx = message.index(" from")
                    prt_idx = message.index(" port")

                    target_user = message[28,frm_idx]
                    ip_source = message[frm_idx:prt_idx]
                else:
                    print("No SSH connections with this Parameters")
                    # psexec and smbexec detection
                    event = PSSMBexec_connections(user=target_user,ip_source=source_ip,timestamp=starting_time)
                    if event:
                        source_ip =event["source"]["ip"]
                        target_user = event["winlog"]["event_data"]["TargetUserName"]
                    else:
                        print("No SMB connections with this Parameters")
                        event = WMI_connections(user=target_user,ip_source=source_ip,timestamp=starting_time)
                        if event:
                            source_ip =event["source"]["ip"]
                            target_user = event["winlog"]["event_data"]["TargetUserName"]
                        else:
                            print("No WMI connections with this Parameters")
                            break
            else:
                # condition to recover the source machine 
                if event["event"]["code"] == "91":
                    source_ip = event["message"].split("clientIP: ")[1][:-1]
    
                target_user = event["winlog"]["user"]["name"] # take a username who caused the event from winrm event
        else:
            source_ip = event["source"]["ip"] # source ip address of the source machine
            target_user = event["winlog"]["event_data"]["TargetUserName"] # username of rdp event

        #@timestamp of the event    
        starting_time = event["@timestamp"]
        past_event=event

    return past_event
    
if __name__ == "__main__":

    # cli configuration arguments and options for tool usage
    parser = argparse.ArgumentParser(description="Patient Zero Revealer a tool to detect first infected machine\
                            in the netwrok using Windows Event logs")
    parser.add_argument("-u","--user",help="Username of a suspicious user in the network",action="store")
    parser.add_argument("-i","--ip-source",help="Ip address from Network of a machine to follow its events",action="store")
    parser.add_argument("-t","--timestamp",help="start time for analysing events",action="store")
    args = parser.parse_args()
    user= args.user # username required
    ip_source = args.ip_source # ip source of a machine
    timestamp = args.timestamp
    timestamp = datetime.strptime(timestamp,"%Y-%m-%dT%H:%M:%S.%fZ") if timestamp else None 
    #analyzing events
    event = patient_zero(user=user,ip_source=ip_source,timestamp=timestamp)
    print_event(event)
    print("DONE ")