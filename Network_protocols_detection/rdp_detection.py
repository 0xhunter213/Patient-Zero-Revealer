# detection RDP connection with event id 4624 type 10

from Elk import timestamp_delta,event_searching
def RDP_detection(es,user=None,ip_source=None,timestamp=None,all=False):
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
        search_query["bool"]["filter"].append({"range":{
            "@timestamp":{
                "lte":timestamp,
                #"gte":min_timestamp, # stop this conndition for some problems on connection between lab and ELK 
            }
        }})


    event_4624_type_10_rdp = event_searching(es=es,query=search_query,all=all)


    if event_4624_type_10_rdp: 
        # if all was true will retuen all event id 4624 with type 10
        return event_4624_type_10_rdp
    else:
        search_query["bool"]["must"][1]= {"match":{"winlog.event_data.LogonType":"7"}}
        event_4624_type_7_rdp = event_searching(es=es,query=search_query,all=all)

        if event_4624_type_7_rdp:
            # if there was not a event ID 4624 type 10 will return of type 7 related also to rdp connections
            return event_4624_type_7_rdp
        return None