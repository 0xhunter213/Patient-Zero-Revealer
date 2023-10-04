# detection winrm connection powershell sesssion assigned 
# using event id 91 in the victim machine if the connection was from inside network
# we looking for event id 6 which refer for wsman session initialization

from Elk import timestamp_delta,timestamp_add,event_searching


def WinRM_detection(es,user=None,ip_source=None,timestamp=None,all=False):
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
        search_query["bool"]["filter"].append({"range":{
            "@timestamp":{
                "lte":timestamp,
                #"gte":min_timestamp,
            }
        }})

    event_winrm_rquest = event_searching(es=es,query=search_query,all=all)
    winrm_events = []
    if event_winrm_rquest != None:
        # message of event contains ip address of attacker machine
        if all:
            for event in event_winrm_rquest:
                # source_machine_info = re.search(r'clientIP:',event["message"])
                # winrm was started by a machine within network
                # so looking for event id 6 with process name "WSMan Session initialize" wich occured 0..1 min before 91
                search_query = {
                        "bool":{
                            "must":[
                                {"match":{"event.code": "6"}},
                                {"match":{"event.action":"WSMan Session initialize"}}
                            ],
                            "must_not":{
                                "term":{"winlog.user.name":user}
                            },
                            "filter":[
                                {"range":{
                                    "@timestamp":{
                                        "gte":timestamp_delta(event["@timestamp"],minutes=59),
                                        "lte":event["@timestamp"],
                                    }
                                }}
                            ]
                        }
                    }

                event_wsman_session_init = event_searching(es=es,query=search_query)
                if event_wsman_session_init:
                    winrm_events.append(event_wsman_session_init)
            
            return winrm_events
        else:
            # winrm was started by a machine within network
            # so looking for event id 6 with process name "WSMan API Initialize" wich occured 0..1 min before 91
            search_query = {
                "bool":{
                    "must":[
                        {"match":{"event.code": "6"}},
                        {"match":{"event.action":"WSMan Session initialize"}}
                    ],
                    "must_not":{
                        "term":{"winlog.user.name":user}
                    },
                    "filter":[
                        {"range":{
                            "@timestamp":{
                                "gte":timestamp_delta(event["@timestamp"],minutes=59),# capturing event time and event created time cause prblm
                                "lte":event_winrm_rquest["@timestamp"],
                                }
                        }}
                    ]
                }
            }
            event_wsman_session_init = event_searching(es=es,query=search_query)
            if event_wsman_session_init:
                return event_wsman_session_init
            else:
                return None
    else:
        return None