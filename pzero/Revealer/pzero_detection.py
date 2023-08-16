from Impacket_detection import *
from Elk import *
from Network_protocols_detection import *

# lookin for interactive logon
def Interactive_login(es,user=None,ip_source=None,timestamp=None):
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

    event = event_searching(es,query=search_query)
    if event:
        return event
    else:
        return None


def pzero_revealer(es,user=None,ip_source=None,timestamp=None):
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
        event = rdp_detection.RDP_detection(es,user=target_user,ip_source=source_ip,timestamp=starting_time)
        if event == None:
            # RDP connection event
            event = winrm_detection.WinRM_detection(es,user=target_user,ip_source=source_ip,timestamp=starting_time)
            
            if event == None:
                event = ssh_detection.SSH_detection(es,user=target_user,ip_source=source_ip,timestamp=starting_time)
                if event:
                    message = event["message"]
                    frm_idx = message.index(" from")
                    prt_idx = message.index(" port")

                    target_user = message[28,frm_idx]
                    ip_source = message[frm_idx:prt_idx]
                else:
                    print("No SSH connections with this Parameters")
                    # psexec and smbexec detection
                    event = pssmbexec_detection.PSSMBexec_detection(es,user=target_user,ip_source=source_ip,timestamp=starting_time)
                    if event:
                        source_ip =event["source"]["ip"]
                        target_user = event["winlog"]["event_data"]["TargetUserName"]
                    else:
                        print("No SMB connections with this Parameters")
                        event = wmiexec_detection.WMIexec_detection(es,user=target_user,ip_source=source_ip,timestamp=starting_time)
                        if event:
                            source_ip =event["source"]["ip"]
                            target_user = event["winlog"]["event_data"]["TargetUserName"]
                        else:
                            print("No WMI connections with this Parameters")
                            event = Interactive_login(es,user=target_user,ip_source=source_ip,timestamp=starting_time)
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
            target_user = event["winlog"]["event_data"]["TargetUserName"] # username of rdp event

        #@timestamp of the event    
        starting_time = event["@timestamp"]
        past_event=event

    return past_event