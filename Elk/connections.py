# connection module for diffrent type of connnection to elk stack 
# elastic search cloud connection and elastic search self host server connection 

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
