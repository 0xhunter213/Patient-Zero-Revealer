from elasticsearch import Elasticsearch
from decouple import config
from datetime import datetime, timedelta
from elasticsearch_dsl import Search,Q
# Import Deployment Secrets keys
 
ELASTIC_PASSWORD = config("ELASTIC_PASSWORD")
CLOUD_ID = config("CLOUD_ID")
INDEX_PATTERN = 'winlogbeat-*'
es = Elasticsearch(cloud_id=CLOUD_ID,http_auth=("elastic",ELASTIC_PASSWORD))

def event_searching(query):
    r = es.search(index=INDEX_PATTERN,query=query)
    if r["hits"]["total"]["value"] != 0:
        event=r["hits"]["hits"][0]["_source"]
        return event
    else:
        return None


def printing_event(event):
    try:
        print(f'Timestamp        : {event["@timestamp"]}\n\
                Username         : {event["user"]}\n\
                Ip Address Host  : {event["host"]["ip"]}\n\
                Ip Addres Source : {event["source"]}\n')
    except:
        print(event)

def RDP_connections(user=None,ip_source=None,timestamp=None):
    '''
        RDP connection for a specifc user parameter
    '''
    search_query ={ 
    "bool":{
        "must":[
            {"match":{"event.code":"4624"}},
        ],
        "filter":[
        ],
        "should":[
            {"match":{"winlog.event_data.LogonType":"10"}},
            {"match":{"winlog.event_data.LogonType":"7"}},
        ]
        }
    }

    if user != None:
        # searching with user name (attacker)
        search_query["bool"]["filter"].append({"term":{"winlog.event_data.TargetUserName":user}})
    
    if ip_source != None:
        # adding Ip address source of previous event
        search_query["bool"]["filter"].append({"term":{"host.ip":ip_source}})
    
    if timestamp != None:
        # searching with timestamp range
        timeline = datetime.strptime(timestamp,"%Y-%m-%dT%H:%M:%S.%fZ") - timedelta(hours=24)
        min_timestamp = timeline.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        search_query["bool"]["filter"].append({"range":{
            "@timestamp":{
                "lte":timestamp,
                "gte":min_timestamp,
            }
        }})

    # searching results
    # exisit item with event ID 4624 type 10 searched
    # also we can use timestamp or machine `ip` `name` ...

    event_4624_rdp = event_searching(query=search_query)


    if event_4624_rdp != None: 
        printing_event(event_4624_rdp)
        return event_4624_rdp
    else:
        print(f"No RDP connections with this Parameters")
        return None


print("WinRM Connections\n")
    # Looking for winrm connections
search_query = {
    "bool":{
        "must":[
            {"match":{"event.code":"91"}},
            {"match":{"winlog.user.name":"user-pc0"}}
        ]    
    }
}
    
event = event_searching(search_query)
printing_event(event)

RDP_connections(user="user-pc1")

print("DONE ")