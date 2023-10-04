from Impacket_detection import *
from Elk import *
from Network_protocols_detection import *

# lookin for interactive logon
def Interactive_login(es,user=None,ip_source=None,timestamp=None,all=False):
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

    event = event_searching(es=es,query=search_query,all=all)
    if event:
        return event
    else:
        return None


# detecting last logons of the attacker
def last_logons(es,user=None,ip_source=None,timestamp=None,all=False):
    """
    List all login events with different protocols based on specified parameters and return the last connection.
    """
    assert user or ip_source
    logon_events = None
    event = rdp_detection.RDP_detection(es=es,user=user,ip_source=ip_source,timestamp=timestamp,all=all)
    if event:
        logon_events = event

    event = winrm_detection.WinRM_detection(es=es,user=user,ip_source=ip_source,timestamp=timestamp,all=all)
    if logon_events and event:
        logon_events.extend(event)
    elif event:
        logon_events=event
    event = ssh_detection.SSH_detection(es=es,user=user,ip_source=ip_source,timestamp=timestamp,all=all)
    if logon_events and event:
        logon_events.extend(event)
    elif event:
        logon_events=event
    event = pssmbexec_detection.PSSMBexec_detection(es=es,user=user,ip_source=ip_source,timestamp=timestamp,all=all)
    if logon_events and event:
        logon_events.extend(event)
    elif event:
        logon_events=event
    event = wmiexec_detection.WMIexec_detection(es=es,user=user,ip_source=ip_source,timestamp=timestamp,all=all)
    if logon_events and event:
        logon_events.extend(event)
    elif event:
        logon_events=event

    return logon_events

def pzero_revealer(es,entry_event):
    event = entry_event
    target_user,source_ip,starting_time = extract_infos(event)
    past_event = None
    events=list()
    while event:
        event = rdp_detection.RDP_detection(es=es,user=target_user,ip_source=source_ip,timestamp=starting_time)
        if event == None:
            # RDP connection event
            event = winrm_detection.WinRM_detection(es=es,user=target_user,ip_source=source_ip,timestamp=starting_time)
            
            if event == None:
                event = ssh_detection.SSH_detection(es=es,user=target_user,ip_source=source_ip,timestamp=starting_time)
                if event:
                    message = event["message"]
                    frm_idx = message.index(" from")
                    prt_idx = message.index(" port")

                    target_user = message[28,frm_idx]
                    source_ip = message[frm_idx:prt_idx]
                else:
                    # psexec and smbexec detection
                    event = pssmbexec_detection.PSSMBexec_detection(es=es,user=target_user,ip_source=source_ip,timestamp=starting_time)
                    if event:
                        source_ip =event["source"]["ip"]
                        target_user = event["winlog"]["event_data"]["TargetUserName"]
                    else:
                        event = wmiexec_detection.WMIexec_detection(es=es,user=target_user,ip_source=source_ip,timestamp=starting_time)
                        if event:
                            source_ip =event["source"]["ip"]
                            target_user = event["winlog"]["event_data"]["TargetUserName"]
                        else:
                            event = Interactive_login(es=es,user=target_user,ip_source=source_ip,timestamp=starting_time)
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
