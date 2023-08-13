# detection of utilization of smbexec.py and psexec.py from impacket
# the detection based on following windows events log the two tools use smb protocols 
# then insall a service which run cmd so the function look for event id 7045 service installed
# then check if there was a smb connection before it and after that event id logon 4624 type 3
# the exists of this sequence of events mean there was an utilization of those funcitons on the network

from Elk import timestamp_delta,event_searching

def PSSMBexec_detection(es,user=None,ip_source=None,timestamp=None):
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
    try:
        assert user
    except AssertionError:
        print("[X] username required !")
        return None
    
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

    events_sercice_installed = event_searching(es,query=search_query,all=True)
    returned_event = None
    if events_sercice_installed:
        for event in events_sercice_installed:
            # backwarding_timestamp = datetime.strptime(event["@timestamp"],"%Y-%m-%dT%H:%M:%S.%fZ") - timedelta(seconds=5)
            # backwarding_timestamp = backwarding_timestamp.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
            backwarding_timestamp = timestamp_delta(event["@timestamp"],seconds=5)
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
            event_4624 = event_searching(es,query=search_query_event_4624)
            event_3 = event_searching(es,query=search_query_event_3)

            if event_3 and event_4624:
                return event_4624 # return login event bcz it contain all infos of user
            elif event_4624:
                #Save the login event because sometimes event 3 may fall outside our specified time range. Not sure here
                returned_event = event_4624 
        
        # if we dont find any correct sequence with return a valid 4624 event came before 7045
        return returned_event 
    else:
        return None