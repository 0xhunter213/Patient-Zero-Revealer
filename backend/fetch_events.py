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
    data = {"nodes":[],"edges":[]}
    search_query = {
            "bool":{
                "must":[
                    {"match":{"event.code":"3"}},
                    {"match":{"network.protocol": "https"}},# use network protocol = https to avoid source.ip in IPV6 format
                ],
            }
   }
    
    nodes = {}
    event = event_searching(es,query=search_query)
    
    hosts = []
    while event != None:
        # list all available ip address till now
        ip_addresses = [item["ip"] for item in data["nodes"]]

        if (event["source"]["ip"] not in ip_addresses) and (not re.search(r":",event["source"]["ip"])):
            data["nodes"].append(data_format(event))
            nodes[str(event["source"]["ip"])] = data_format(event)
            hosts.append(event["winlog"]["computer_name"])
        elif event["winlog"]["computer_name"] in hosts:
            # if get a host already captured with break the loop
            break

        search_query = {
            "bool":{
                "must":[{"match":{"event.code":"3"}},
                {"match":{"network.protocol": "https"}}],
                "must_not":[{"match":{"source.ip":event["source"]["ip"]}}]
            }
        }
        event = event_searching(es,query=search_query)

    # Structure the aggregated data in a format that the frontend is familiar with
    for ip_src in ip_addresses:
        rst_ips = ip_addresses.copy()
        rst_ips.pop(ip_addresses.index(ip_src))
        for ip_dest in rst_ips:
                # add edges machine to elastic if you wish to add it
                # i have done it using frontend (react)
            search_query = {
                "bool":{
                    "must":{"match":{"source.ip":ip_src}},
                    "must":{"match":{"destination.ip":ip_dest}}
                }   
            }
            event = event_searching(es,query=search_query)
            
            if event:      
                data["edges"].append({"from":nodes[ip_src]["id"],"to":nodes[ip_dest]["id"],"color":"red"})

    return data
    




if __name__ == "__main__":
    es = Elasticsearch(cloud_id=CLOUD_ID,http_auth=("elastic",PASSWORD))
    # this is test for get network topology machines alread have a logs on elastic server
    print(asyncio.run(retrieve_netwrok_tpoplogy(es)))