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
        "id":event["user"]["domain"],
        "label":event["winlog"]["computer_name"],
        "title":event["host"]["hostname"],
        "color": "blue",
        "shape": "image",
        "image":"https://cdn.icon-icons.com/icons2/595/PNG/512/Computer_icon-icons.com_55509.png",
        "size": 40,
        "ip":event["source"]["ip"],
        "build":event["host"]["os"]["build"],
        "os":event["host"]["os"]["name"],
        "domain":event["source"]["domain"]
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
    
    for evt in events:
        ip_addresses = [item["ip"] for item in data["nodes"]]
        if evt["source"]["ip"] not in ip_addresses and not re.search(r":",evt["source"]["ip"]):
            data["nodes"].append(data_format(evt))
    for evt in events:
        if evt["source"]["ip"] in ip_addresses:
            rst_ips = ip_addresses.copy()
            rst_ips.pop(ip_addresses.index(evt["source"]["ip"]))
            for ip_dest in rst_ips:
                # add edges machine to elastic if you wish to add it
                if ip_dest in evt["related"]["ip"] or ip_dest == evt["destination"]["ip"]:
                    for item in data["nodes"]:
                        if item["ip"] == ip_dest:
                            data["egdges"].append({"from":evt["id"],"to":item["id"],"color":"red"})
                            break

    

    return data
    




if __name__ == "__main__":
    es = Elasticsearch(cloud_id=CLOUD_ID,http_auth=("elastic",PASSWORD))
    print(asyncio.run(retrieve_netwrok_tpoplogy(es)))