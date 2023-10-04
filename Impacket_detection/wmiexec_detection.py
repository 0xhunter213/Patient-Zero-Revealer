
from Elk import timestamp_delta,event_searching,timestamp_add

def WMI_events_checks(es,event_epmap):
    machine_ip_dest = event_epmap["host"]["ip"][1] # ip address of destination machine target
    machine_ip_src = event_epmap["source"]["ip"] # ip address of source attacker machine
    
    # delta time range used for searching adding 1 second to epmap event bcz logon happening after it
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
                            "lte":timestamp_add(event_epmap["@timestamp"],seconds=1),
                            "gt":event_epmap["@timestamp"] # range time bigger then event epmap timestamp and less then it adding 1 second
                        }
                    }}
                ]
            }
    }
    event_4624 = event_searching(es=es,query=search_query_4624)
    #delta time range substration of 1 second bcz SMB connection heppening before it
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
                                "gte":timestamp_delta(event_epmap["@timestamp"],seconds=1)
                            }
                        }}
                    ]
                }
    }
        
    event_3 = event_searching(es=es,query=search_query_3)
    if event_3:
        return event_4624
    else:
        print("[X] No event 3 but there is 4624 events")
        return None

def WMIexec_detection(es,user=None,ip_source=None,timestamp=None,all=False):
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


    event_epmap = event_searching(es=es,query=search_query,all=all)
    results_events = []
    # if epmap exist we look for 4624 forward and event id 3 backward by 5 seconds range and comparing source port from two events
    if all and event_epmap:
        for event in event_epmap:
            rst = WMI_events_checks(es=es,event_epmap=event)
            if rst:
                results_events.append(rst)
        return results_events
    elif event_epmap:
        return WMI_events_checks(es=es,event_epmap=event_epmap)
    else:
        return None