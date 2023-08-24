from elasticsearch import Elasticsearch
from Elk import event_searching
from decouple import config
import asyncio
import re
CLOUD_ID = config("CLOUD_ID")
PASSWORD = config("ELASTIC_PASSWORD")

def data_format(event):
    assert event
    data_notes = {
        "id":event["winlog"]["computer_name"],
        "label":event["winlog"]["computer_name"],
        "title":event["host"]["hostname"],
        "color": "blue",
        "shape": "image",
        "image":"https://raw.githubusercontent.com/MEhrn00/Havoc/main/client/Data/resources/win10-8-icon.png",
        #https://raw.githubusercontent.com/MEhrn00/Havoc/blob/main/client/Data/resources/win10-8-icon-high.png
        "size": 40,
        "ip":event["source"]["ip"],
        "build":event["host"]["os"]["build"],
        "os":event["host"]["os"]["name"],
        "domain":event["source"]["domain"],
        "infected_first":False,
    }

    return data_notes

async def retrieve_netwrok_tpoplogy(es):
    """
        fetching machines exist and different connections on the network from elastic
    """
    ip_addresses=[]
    data = {"nodes":[],"egdges":[]}
    search_query = {
            "bool":{
                "must":[{"match":{"event.code":"3"}}]
            }
    }
    
    events = event_searching(es,query=search_query,all=True)


    nodes = {}
    for evt in events:
        ip_addresses = [item["ip"] for item in data["nodes"]]
        if (evt["source"]["ip"] not in ip_addresses) and (not re.search(r":",evt["source"]["ip"])):
            data["nodes"].append(data_format(evt))
            nodes[str(evt["source"]["ip"])] = data_format(evt)

    for ip_src in ip_addresses:
        rst_ips = ip_addresses.copy()
        rst_ips.pop(ip_addresses.index(ip_src))
        for ip_dest in rst_ips:
                # add edges machine to elastic if you wish to add it
            search_query = {
                "bool":{
                    "must":{"match":{"source.ip":ip_src}},
                    "must":{"match":{"destination.ip":ip_dest}}
                }   
            }
            event = event_searching(es,query=search_query)
            
            if event:      
                data["egdges"].append({"from":nodes[ip_src]["id"],"to":nodes[ip_dest]["id"],"color":"red"})

    return data
    




if __name__ == "__main__":
    es = Elasticsearch(cloud_id=CLOUD_ID,http_auth=("elastic",PASSWORD))
    print(asyncio.run(retrieve_netwrok_tpoplogy(es)))