
from Elk import timestamp_delta,event_searching,timestamp_add

def WMIexec_detection(user=None,ip_source=None,timestamp=None):
    """
        Detection utilization of wmiexec from impacket tool kit in the network\
        using event id 3,4672,4624
    """
    try:
        assert user
    except AssertionError:
        print("[X] username required !")
        return None
    
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

    event_epmap = event_searching(search_query)
    # if epmap exist we look for 4624 forward and event id 3 backward by 5 seconds range and comparing source port from two events
    if event_epmap:
        machine_ip_dest = event_epmap["host"]["ip"][1] # ip address of destination machine target
        machine_ip_src = event_epmap["source"]["ip"] # ip address of source attacker machine
        # delta time range used for searching adding 1 second to epmap event bcz logon happening after it
        # delta_timestamp = datetime.strptime(event_epmap["@timestamp"],"%Y-%m-%dT%H:%M:%S.%fZ") + timedelta(seconds=1)
        # delta_timestamp_4624 = delta_timestamp.strftime("%Y-%m-%dT%H:%M:%S.%fZ")

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
        event_4624 = event_searching(search_query_4624)
        #delta time range substration of 1 second bcz SMB connection heppening before it
        # backwarding_timestamp = datetime.strptime(event_epmap["@timestamp"],"%Y-%m-%dT%H:%M:%S.%fZ") - timedelta(seconds=1)
        # backwarding_timestamp = backwarding_timestamp.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
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
        
        event_3 = event_searching(search_query_3)
        if event_3:
            return event_4624
        else:
            return None
    else:
        return None
