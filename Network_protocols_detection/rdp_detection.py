# detection RDP connection with event id 4624 type 10

from Elk import timestamp_delta,event_searching
def RDP_detection(user=None,ip_source=None,timestamp=None):
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
                "gte":timestamp_delta(timestamp,hours=24),
            }
        }})
    else:
        # adding a range timestamp to just analysis the last 48 hours events
        # timeline = datetime.now() - timedelta(hours=48)
        # min_timestamp = timeline.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        search_query["bool"]["filter"].append({"range":{
                "@timestamp":{
                    "gte":timestamp_delta(hours=24),
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
