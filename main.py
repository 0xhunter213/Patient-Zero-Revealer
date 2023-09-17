from elasticsearch import Elasticsearch,ConnectionError
from decouple import config
from datetime import datetime, timedelta
import re
import argparse
import pyfiglet

# Import Deployment Secret keys
 
ELASTIC_PASSWORD = config("ELASTIC_PASSWORD")
CLOUD_ID = config("CLOUD_ID")
INDEX_PATTERN = 'winlogbeat-*'

es = Elasticsearch(cloud_id=CLOUD_ID,http_auth=("elastic",ELASTIC_PASSWORD))

# searching for event with query
def event_searching(es=es,query={},sort={"@timestamp":{"order":"desc"}},all=False):
    if es:
        es = Elasticsearch(cloud_id=CLOUD_ID,http_auth=("elastic",ELASTIC_PASSWORD))
        r = es.search(index=INDEX_PATTERN,query=query,sort=sort)
        if r["hits"]["total"]["value"] != 0:
            if all:
                # return all the events 
                events = [evt["_source"] for evt in r["hits"]["hits"]] # return only _source item from each event in the list
                return events
            # return only the last events
            event=r["hits"]["hits"][0]["_source"]
            return event
        else:
            return None
    else:
        return None

# printing RDP event

def print_machine_infos(event):
    try:
        # get the event id to define the structre of the event
        event__code = event["event"]["code"]
        if event__code == "4624" and event["winlog"]["event_data"]["LogonType"] in ["10","7"]:
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
                    Ip Address Source       : {event["source"]["ip"]}\n\
                    Channel                 : {event["event"]["provider"]}\n\
            ''')
        elif event__code == "4624":
            print(f'''
                    Interactive Logon:
                    Timestamp               : {event["@timestamp"]}\n\
                    Id                      : {event["user"]["id"]}\n\
                    Username                : {event["user"]["name"]}\n\
                    Domaine                 : {event["user"]["domain"]}\n\
                    Host Name               : {event["host"]["hostname"]}\n\
                    Ip Address Host (IPV4)  : {event["host"]["ip"][1]}\n\
                    Ip Address Host (IPV6)  : {event["host"]["ip"][0]}\n\
                    Source Domain           : {event["source"]["domain"]}\n\
                    Ip Address Source       : {event["source"]["ip"]}\n\
                    Channel                 : {event["event"]["provider"]}\n\
            ''')
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
                    Channel                 : {event["event"]["provider"]}\n\
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
                    Channel                 : {event["event"]["provider"]}\n\
            ''')
        
        # more events ? ...
    except Exception:
        print(event)

def print_events(events):
    """
    printing each event from a list in readable format
    """
    for evt in events:
        print_machine_infos(event=evt)

def header(title):
    r = (124 - len(title))
    pad = r//2
    if r%2==0:
        print("="*pad+": "+title+" :"+"="*pad)
    else:
        print("="*pad+": "+title+" :"+"="*pad+1)

def RDP_connections(user=None,ip_source=None,timestamp=None,all=False):
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
        # timeline = datetime.strptime(timestamp,"%Y-%m-%dT%H:%M:%S.%fZ") - timedelta(hours=24)
        # min_timestamp = timeline.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        search_query["bool"]["filter"].append({"range":{
            "@timestamp":{
                "lte":timestamp,
                #"gte":min_timestamp,
            }
        }})


    event_4624_rdp = event_searching(query=search_query,all=all)


    if event_4624_rdp: 
        return event_4624_rdp
    else:
        search_query["bool"]["must"][1]= {"match":{"winlog.event_data.LogonType":"7"}}
        event_4624_rdp = event_searching(query=search_query,all=all)
        if event_4624_rdp:
            return event_4624_rdp
        return None

def WinRM_connections(user=None,ip_source=None,timestamp=None,all=False):
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
        #time changing here for new metology
        # timeline = datetime.strptime(timestamp,"%Y-%m-%dT%H:%M:%S.%fZ") - timedelta(hours=24)
        # min_timestamp = timeline.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        search_query["bool"]["filter"].append({"range":{
            "@timestamp":{
                "lte":timestamp,
                #"gte":min_timestamp,
            }
        }})

    event_winrm_rquest = event_searching(query=search_query,all=all)
    winrm_events = []
    if event_winrm_rquest != None:
        # message of event contains ip address of attacker machine
        if all:
            for event in event_winrm_rquest:
                source_machine_info = re.search(r'clientIP:',event["message"])

                if source_machine_info:
                    # winrm shell was initialized by a machine out of network
                    return event_winrm_rquest
                else:
                    # winrm was started by a machine within network
                    # so looking for event id 6 with process name "WSMan API Initialize" wich occured 0..1 min before 91

                    # timestamp = datetime.strptime(event_winrm_rquest["@timestamp"],"%Y-%m-%dT%H:%M:%S.%fZ") + timedelta(minutes=1)
                    # timestamp = timestamp.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
                    search_query = {
                        "bool":{
                            "must":[
                                {"match":{"event.code": "6"}},
                                #{"match":{"event.action":"WSMan API Initialize"}}
                            ],
                            # "filter":[
                            #     {"range":{
                            #         "@timestamp":{
                            #             "gte":timestamp_delta(event_winrm_rquest["@timestamp"],minutes=1),
                            #             "lte":event_winrm_rquest["@timestamp"],
                            #         }
                            #     }}
                            # ]
                        }
                    }

                    event_wsman_init = event_searching(es,query=search_query)
                    if event_wsman_init:
                        winrm_events.append(event_wsman_init)
            
            return winrm_events
        else:
            source_machine_info = re.search(r'clientIP:',event_winrm_rquest["message"])

        if source_machine_info:
            # winrm shell was initialized by a machine out of network
            return event_winrm_rquest
        else:
            # winrm was started by a machine within network
            # so looking for event id 6 with process name "WSMan API Initialize" wich occured 0..1 min before 91

            # timestamp = datetime.strptime(event_winrm_rquest["@timestamp"],"%Y-%m-%dT%H:%M:%S.%fZ") + timedelta(minutes=1)
            # timestamp = timestamp.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
            search_query = {
                "bool":{
                    "must":[
                        {"match":{"event.code": "6"}},
                        #{"match":{"event.action":"WSMan API Initialize"}}
                    ],
                    # "filter":[
                    #     {"range":{
                    #         "@timestamp":{
                    #             "gte":timestamp_delta(event_winrm_rquest["@timestamp"],minutes=1),
                    #             "lte":event_winrm_rquest["@timestamp"],
                    #         }
                    #     }}
                    # ]
                }
            }

            event_wsman_init = event_searching(es,query=search_query)

            if event_wsman_init:
                return event_wsman_init
            else:
                return None

    else:
        return None

def SSH_connections(user=None,ip_source=None,timestamp=None,all=False):
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
        # timeline = datetime.strptime(timestamp,"%Y-%m-%dT%H:%M:%S.%fZ") - timedelta(hours=24)
        # min_timestamp = timeline.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        search_query["bool"]["filter"].append({"range":{
            "@timestamp":{
                "lte":timestamp,
                #"gte":min_timestamp,
            }
        }})



    event_ssh = event_searching(query=search_query,all=all)
    
    if event_ssh:
        return event_ssh
    else:
        return None

def PSSMBexec_connections(user=None,ip_source=None,timestamp=None,all=False):
    '''
    Detection of a potential PsExec connection based on the usage of SMB\
    This function looks for all events with ID 7045 (service installed) and events that came after event 3 with\
    network protocol "microsoft-ds" (SMB)Additionally, it checks for event ID 4624 with type 3, which indicates \
    that PsExec or SMBExec was used to log in to this machine.
    '''
    # looking for sequence of events 3,4624,4672,7045
    # need argument for searching cause it possible there's a lot of 7045
    # so need to specify the search
    
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
        # timeline = datetime.strptime(timestamp,"%Y-%m-%dT%H:%M:%S.%fZ") - timedelta(hours=24)
        # min_timestamp = timeline.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        search_query["bool"]["filter"].append({"range":{
            "@timestamp":{
                "lte":timestamp,
                #"gte":min_timestamp,
            }
        }})
    events_sercice_installed = event_searching(query=search_query,all=True)
    returned_event = None
    returned_events = []
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
            event_4624 = event_searching(query=search_query_event_4624)
            event_3 = event_searching(query=search_query_event_3)

            if event_3 and event_4624:
                if all:
                    returned_events.append(event_4624)
                else:
                    return event_4624 # return login event bcz it contain all infos of user
            elif event_4624:
                #Save the login event because sometimes event 3 may fall outside our specified time range. Not sure here
                if all:
                    returned_events.append(event_4624)
                else:
                    returned_event = event_4624
        
        # if we dont find any correct sequence with return a valid 4624 event came before 7045
        return returned_event if not all else returned_events
    else:
        return None
    
def WMI_events_checks(event_epmap):
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
    event_4624 = event_searching(query=search_query_4624)
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
        
    event_3 = event_searching(query=search_query_3)
    if event_3:
        return event_4624
    else:
        print("[X] No event 3 but there is 4624 events")
        return None

def WMI_connections(user=None,ip_source=None,timestamp=None,all=False):
    """
        Detection utilization of wmiexec from impacket tool kit in the network\
        using event id 3,4672,4624
    """    
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
        # timeline = datetime.strptime(timestamp,"%Y-%m-%dT%H:%M:%S.%fZ") - timedelta(hours=24)
        # min_timestamp = timeline.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        search_query["bool"]["filter"].append({"range":{
            "@timestamp":{
                "lte":timestamp,
                #"gte":min_timestamp,
            }
        }})


    event_epmap = event_searching(query=search_query,all=all)
    results_events = []
    # if epmap exist we look for 4624 forward and event id 3 backward by 5 seconds range and comparing source port from two events
    if all and event_epmap:
        for event in event_epmap:
            rst = WMI_events_checks(event)
            if rst:
                results_events.append(rst)
        return results_events
    elif event_epmap:
        return WMI_events_checks(event_epmap)
    else:
        return None

def Interactive_login(user=None,ip_source=None,timestamp=None):
    """
        detection of logon event id 4624 type 2 for interactive login
    """
    try:
        assert user
    except AssertionError:
        print("[X] username required !")
        return None
    
    search_query = {
        "bool":{
            "must":[
                {"match":{"event.code":"4624"}},
                {"match":{"winlog.event_data.LogonType":"2"}},
                {"match":{"user.name":user}},
                {"match":{"event.outcome":"success"}},
                {"match":{"source.ip":"127.0.0.1"}}
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


    event = event_searching(query=search_query)
    if event:
        return event
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
                            event = Interactive_login(user=target_user,ip_source=source_ip,timestamp=starting_time)
                            if event:
                                source_ip =event["source"]["ip"]
                                target_user = event["winlog"]["event_data"]["TargetUserName"]
                            else:
                                print("No Interactive login with this Parameters")
                                break
            else:
                # condition to recover the source machine 
                if event["event"]["code"] == "91":
                    source_ip = event["message"].split("clientIP: ")[1][:-1]
    
                target_user = event["winlog"]["user"]["name"] # take a username who caused the event from winrm event
        else:
            source_ip = event["source"]["ip"] # source ip address of the source machine
            #target_user = event["winlog"]["event_data"]["TargetUserName"] # username of rdp event
            target_user = None
        #@timestamp of the event 
        starting_time = event["@timestamp"]
        past_event=event

    return past_event
    
def entries(user=None,ip_source=None,timestamp=None,all=False):

    assert user or ip_source

    event = RDP_connections(user=user,ip_source=ip_source,timestamp=timestamp,all=all)
    if event:
        logon_events = event
    event = WinRM_connections(user=user,ip_source=ip_source,timestamp=timestamp,all=all)
    if logon_events and event:
        logon_events.extend(event)
    elif event:
        logon_events=event
    event = SSH_connections(user=user,ip_source=ip_source,timestamp=timestamp,all=all)
    if logon_events and event:
        logon_events.extend(event)
    elif event:
        logon_events=event

    return logon_events

def extract_infos(event):
    event__code = event["event"]["code"]
    username = None
    ip_source = None
    timestamp = None
    if event__code == "4624":
        username = event["user"]["name"]
        ip_source = event["source"]["ip"]
        timestamp = event["@timestamp"]
    elif event__code == "4":
        message = event["message"]
        frm_idx = message.index(" from")
        prt_idx = message.index(" port")
        username = message[28,frm_idx]
        ip_source = message[frm_idx:prt_idx]
        timestamp = event = event["@timestamp"]
    elif event__code in ["91","6"] :
        username = event["winlog"]["user"]["name"]
        ip_source = event["message"].split("clientIP: ")[1][:-1] if re.search(r'clientIP:',event["message"]) else event["host"]["ip"][1]
        timestamp = event["@timestamp"]

    return username,ip_source,timestamp

def pzero_revealer(entry_event):
    event = entry_event
    target_user,source_ip,starting_time = extract_infos(event)
    past_event = None
    events=list()
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
                    source_ip = message[frm_idx:prt_idx]
                else:
                    # psexec and smbexec detection
                    event = PSSMBexec_connections(user=target_user,ip_source=source_ip,timestamp=starting_time)
                    if event:
                        source_ip =event["source"]["ip"]
                        target_user = event["winlog"]["event_data"]["TargetUserName"]
                    else:
                        event = WMI_connections(user=target_user,ip_source=source_ip,timestamp=starting_time)
                        if event:
                            source_ip =event["source"]["ip"]
                            target_user = event["winlog"]["event_data"]["TargetUserName"]
                        else:
                            event = Interactive_login(user=target_user,ip_source=source_ip,timestamp=starting_time)
                            if event:
                                source_ip =event["source"]["ip"]
                                target_user = event["winlog"]["event_data"]["TargetUserName"]
                            else:
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
        if event:
            print_machine_infos(event=event)
            events.append(event) 
    return events




if __name__ == "__main__":
    text = "PZero"
  # You can specify a
    ascii_art = pyfiglet.figlet_format(text=text,font = "banner3-D")
    print('')
    print(ascii_art)
    # cli configuration arguments and options for tool usage
    parser = argparse.ArgumentParser(description="Patient Zero Revealer a tool to detect first infected machine \
    in the netwrok using Windows Event logs \n using one of those informations is required (USER or IP_SOURCE)")

    parser.add_argument("-u","--user",help="Username of a suspicious user in the network",action="store",required=True)
    parser.add_argument("-i","--ip-source",help="Ip address from Network of a machine to follow its events",action="store")
    parser.add_argument("-t","--timestamp",help="Start time for analysing events",action="store")
    parser.add_argument("-r","--rdp",help="Analyzing only RDP connections",action="store_true")
    parser.add_argument("-s","--ssh",help="Analyzing only ssh connections",action="store_true")
    parser.add_argument("-w","--winrm",help="Analyzing only WinRM connections",action="store_true")
    parser.add_argument("-I","--impackt",help="Analyzing Impacket tools use cases from events (psexec,smbexec,wmiexec,...)",action="store_true")
    parser.add_argument("-Ip","--psexec",help="detect of Impacket psexec tools from event",action="store_true")
    parser.add_argument("-Is","--smbexec",help="detect of Impacket smbexec tools from event",action="store_true")
    parser.add_argument("-Iw","--wmiexec",help="detect of Impacket wmiexec tools from event",action="store_true")
    

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
    #analyzing events
    try:
        if rdp:
            header("RDP connections")
            print_events(RDP_connections(user=user,ip_source=ip_source,timestamp=timestamp,all=True))
            print("="*128)
        
        if ssh:
            header("SSH connections")
            print_events(SSH_connections(user=user,ip_source=ip_source,timestamp=timestamp,all=True))
            print("="*128)
        if winrm:
            header("WinRM connections")
            print_events(WinRM_connections(user=user,ip_source=ip_source,timestamp=timestamp,all=True))
            print("="*128)        
        
        if impacket:
            header("events caused by Impacket")
            print_events(PSSMBexec_connections(user=user,ip_source=ip_source,timestamp=timestamp,all=True))
            print_events(WMI_connections(user=user,ip_source=ip_source,timestamp=timestamp,all=True))
            print("="*128) 
        elif psexec:
            header("PSexec events")
            print_events(PSSMBexec_connections(user=user,ip_source=ip_source,timestamp=timestamp,all=True))
            print("="*128) 
        elif wmiexec:
            header("WMIexec events")
            print_events(WMI_connections(user=user,ip_source=ip_source,timestamp=timestamp,all=True))
            print("="*128)

        if not any([rdp,ssh,winrm,impacket,psexec,wmiexec]):
            # list all events and get where is the patient zero for each timeline
            header("Detection patient zero")
            events = entries(user=user,ip_source=ip_source,timestamp=timestamp,all=True)
            
            # list of series of events that represent the attack path from patien zero for each timerange
            attacker_paths = list() 
            
            # remove duplicated events
            seens_id = set()
            events = [evt for evt in events if (evt["event"]["code"],evt["agent"]["ephemeral_id"]) not in seens_id and not seens_id.add((evt["event"]["code"],evt["agent"]["ephemeral_id"])) ]
            events.sort(key=lambda x: datetime.strptime(x["@timestamp"],"%Y-%m-%dT%H:%M:%S.%fZ"),reverse=True)
            
            for i in range(len(events)):
                print_machine_infos(event=events[i])
                attacker_paths = pzero_revealer(entry_event=events[i])
                for event in attacker_paths:
                    if event in events[i+1:]:
                        events.pop(i)
                print("="*128)
    except ConnectionError:
        print("[x] Elasticsearch Connection Error")
        print("="*128)