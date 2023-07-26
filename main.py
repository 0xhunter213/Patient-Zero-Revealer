from elasticsearch import Elasticsearch
from decouple import config

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


"""
******* RDP connection ********
"""

# search query

search_query ={ 
    "bool":{
        "must":[
            {"match":{"event.code":"4624"}},
        ],
        "filter":{
             "term":{"winlog.event_data.TargetUserName":"user-pc1"} # attacker user name
        },
        "should":[
            {"match":{"winlog.event_data.LogonType":"10"}},
            {"match":{"winlog.event_data.LogonType":"7"}},
        ]
    }
}
# searching results
# exisit item with event ID 4624 type 10 searched
# also we can use timestamp or machine `ip` `name` ...

event_4624_rdp = event_searching(query=search_query)

if event_4624_rdp != None: 

    print(f'last login RDP:\n\
            Timestamp        : {event_4624_rdp["@timestamp"]}\n\
            Username         : {event_4624_rdp["user"]}\n\
            Ip Address Host  : {event_4624_rdp["host"]["ip"]}\n\
            Ip Addres Source : {event_4624_rdp["source"]}\n')
    event = event_4624_rdp
    while event["host"]["ip"][1] != event["source"]["ip"]:
        print(event["source"]["ip"])
            # find another logon rdp type 10 or 7 in order to follow traces of attacker
        search_query = {
                "bool":{
                    "must":[
                        {"match":{"event.code":"4624"}},
                        
                    ],
                    "filter":[
                        {"term":{"host.ip":event["source"]["ip"]}},
                    ],
                    "should":[
                        {"match":{"winlog.event_data.LogonType":"10"}},
                        {"match":{"winlog.event_data.LogonType":"7"}},
                    ]
                }
            }
        event_4624_rdp = event
        event = event_searching(search_query)
        print(event)
        if event == None or event["source"]["domain"] == "-":
            event=event_4624_rdp
            break
        

    print(f'First Machine Infected :\n\
            Timestamp        : {event["@timestamp"]}\n\
            Username         : {event["user"]}\n\
            Ip Address Host  : {event["host"]["ip"]}\n\
            Ip Addres Source : {event["source"]}\n')
        
else:
    print("\033[1;31;40m RDP logon for this User does not exist !")
       
    