#Connection module for different types of connections to the ELK stack.
#Includes Elastic Search Cloud connection and Elastic Search self-hosted server connection.
# searching for event with query

from datetime import datetime
import re
def event_searching(es=None,index='winlogbeat-*',query={},sort={"@timestamp":{"order":"desc"}},all=False):
    if es:
        r = es.search(index=index,query=query,sort=sort)
        if r["hits"]["total"]["value"] != 0:
            if all:
                # return all the events 
                events = [ evt["_source"] for evt in r["hits"]["hits"]] # return only _source item from each event in the list
                return events
            # return only the last events
            event=r["hits"]["hits"][0]["_source"]
            return event
        else:
            return None

def print_machine_infos(event):
    try:
        # get the event id to define the structre of the event
        event__code = event["event"]["code"]

        if event__code == "4624" and event["winlog"]["event_data"]["LogonType"] in ["10","7"]:
            print(f'''
                    RDP Connection:
                    Timestamp               : {event["@timestamp"]}\n\
                    Id                      : {event["user"]["id"]}\n\
                    Username                : {event["user"]["name"]}\n\
                    Domaine                 : {event["user"]["domain"]}\n\
                    Host Name               : {event["host"]["hostname"]}\n\
                    Ip Address Host (IPV4)  : {event["host"]["ip"][1]}\n\
                    Ip Address Host (IPV6)  : {event["host"]["ip"][0]}\n\
                    Source Domain           : {event["source"]["domain"]}\n\
                    Ip Addres Source        : {event["source"]["ip"]}\n''')
        elif event__code == "4624":
            print(f'''
                    Logon:
                    Timestamp               : {event["@timestamp"]}\n\
                    Id                      : {event["user"]["id"]}\n\
                    Username                : {event["user"]["name"]}\n\
                    Domaine                 : {event["user"]["domain"]}\n\
                    Host Name               : {event["host"]["hostname"]}\n\
                    Ip Address Host (IPV4)  : {event["host"]["ip"][1]}\n\
                    Ip Address Host (IPV6)  : {event["host"]["ip"][0]}\n\
                    Source Domain           : {event["source"]["domain"]}\n\
                    Ip Addres Source        : {event["source"]["ip"]}\n''')
        elif event__code in ["91","6"]:
            print(f'''
                    WinRM Connection:
                    Timestamp               : {event["@timestamp"]}\n\
                    Id                      : {event["winlog"]["user"]["identifier"]}\n\
                    Username                : {event["winlog"]["user"]["name"]}\n\
                    Domaine                 : {event["winlog"]["user"]["domain"]}
                    Host Name               : {event["host"]["hostname"]}\n\
                    Ip Address Host (IPV4)  : {event["host"]["ip"][1]}\n\
                    Ip Address Host (IPV6)  : {event["host"]["ip"][0]}\n\
                    Connection              : {event["winlog"]["event_data"]["connection"]}\n\
            ''')
        elif event__code == "4":
            print(f'''
                    SSH Connection:
                    Timestamp               : {event["@timestamp"]}\n\
                    Id                      : {event["winlog"]["user"]["identifier"]}\n\
                    Username                : {event["winlog"]["user"]["name"]}\n\
                    Domaine                 : {event["winlog"]["user"]["domain"]}
                    Host Name               : {event["host"]["hostname"]}\n\
                    Ip Address Host (IPV4)  : {event["host"]["ip"][1]}\n\
                    Ip Address Host (IPV6)  : {event["host"]["ip"][0]}\n\
                    Information             : {event["message"]}\n\
            ''')
        
        # more events ? ...

    except:
        print(event)

def print_events(events):
    """
    printing each event from a list in readable format
    """
    datas = None
    if events:
        for evt in events:
            data = print_machine_infos(event=evt)
            if datas:
                datas+='\n'+data
            else:
                datas = data
        
        return datas
    else:
        print("No events founded!")

def header(title):
    r = (124 - len(title))
    pad = r//2
    if r%2==0:
        print("="*pad+": "+title+" :"+"="*pad)
    else:
        print("="*pad+": "+title+" :"+"="*(pad+1))

def remove_dubplication(events=None):
    if events:
        seens_id = set()
        events = [evt for evt in events if (evt["agent"]["ephemeral_id"]) not in seens_id and not seens_id.add(evt["agent"]["ephemeral_id"]) ]
        events.sort(key=lambda x: datetime.strptime(x["@timestamp"],"%Y-%m-%dT%H:%M:%S.%fZ"),reverse=True)
        return events
    else:
        return None      
    
def extract_infos(event):
    event__code = event["event"]["code"]
    username = None
    ip_source = None
    timestamp = None
    if event__code == "4624":
        username = event["user"]["name"]
        ip_source = event["source"]["ip"]
        timestamp = event["@timestamp"]
    elif event__code == "4":
        message = event["message"]
        frm_idx = message.index(" from")
        prt_idx = message.index(" port")
        username = message[28,frm_idx]
        ip_source = message[frm_idx:prt_idx]
        timestamp = event = event["@timestamp"]
    elif event__code in ["91","6"] :
        username = event["winlog"]["user"]["name"]
        ip_source = event["message"].split("clientIP: ")[1][:-1] if re.search(r'clientIP:',event["message"]) else event["host"]["ip"][1]
        timestamp = event["@timestamp"]

    return username,ip_source,timestamp

