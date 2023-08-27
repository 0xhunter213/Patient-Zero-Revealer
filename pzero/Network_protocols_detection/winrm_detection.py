# detection winrm connection powershell sesssion assigned 
# using event id 91 in the victim machine if the connection was from inside network
# we looking for event id 6 which refer for wsman session initialization

from Elk import timestamp_delta,timestamp_add,event_searching
import re

def WinRM_detection(es,user=None,ip_source=None,timestamp=None):
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
        # timeline = datetime.strptime(timestamp,"%Y-%m-%dT%H:%M:%S.%fZ") - timedelta(hours=24)
        # min_timestamp = timeline.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        search_query["bool"]["filter"].append({"range":{
            "@timestamp":{
                "lte":timestamp,
                "gte":timestamp_delta(timestamp,hours=24),
            }
        }})
    # adding this line for testing need to just get event of last 24 hours
    else:
        # timeline = datetime.now() - timedelta(hours=24)
        # min_timestamp = timeline.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        search_query["bool"]["filter"].append({"range":{
            "@timestamp":{
                "gte":timestamp_delta(hours=24),
            }
        }})

    event_winrm_rquest = event_searching(es,query=search_query)
    if event_winrm_rquest != None:
        # message of event contains ip address of attacker machine
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
                    "filter":[
                        {"range":{
                            "@timestamp":{
                                "gte":timestamp_delta(event_winrm_rquest["@timestamp"],minutes=1),
                                "lte":event_winrm_rquest["@timestamp"],
                            }
                        }}
                    ]
                }
            }

            event_wsman_init = event_searching(es,query=search_query)
            if event_wsman_init:
                return event_wsman_init
            else:
                print("No WSMan session Initialize event")
                return None

    else:
        print("No WinRM connections with this Paremeters\n")
        return None