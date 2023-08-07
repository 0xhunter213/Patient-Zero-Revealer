#Connection module for different types of connections to the ELK stack.
#Includes Elastic Search Cloud connection and Elastic Search self-hosted server connection.

from elasticsearch import Elasticsearch
from decouple import config

ELASTIC_PASSWORD = config("ELASTIC_PASSWORD")
CLOUD_ID = config("CLOUD_ID")
INDEX_PATTERN = 'winlogbeat-*'

es = Elasticsearch(cloud_id=CLOUD_ID,http_auth=("elastic",ELASTIC_PASSWORD))

# searching for event with query
def event_searching(query,sort={"@timestamp":{"order":"desc"}},all=False):
    r = es.search(index=INDEX_PATTERN,query=query,sort=sort)
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

        if event__code == "4624":
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
