# detection a ssh connection on machine from network
# using username ofc attacker use to get in to network
# and event id 4 from OpenSSH/Operational channel and with 
# message `sshd: Accepted password for`

from Elk import event_searching,timestamp_delta


def SSH_detection(es,user=None,ip_source=None,timestamp=None,all=False):
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
        search_query["bool"]["filter"].append({"range":{
            "@timestamp":{
                "lte":timestamp,
                #"gte":min_timestamp,
            }
        }})



    event_ssh = event_searching(es=es,query=search_query,all=all)
    
    if event_ssh:
        # return event or events if all is true related to ssh conntection depends on the listed parameters
        return event_ssh
    else:
        return None
