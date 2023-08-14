from fastapi import FastAPI
from decouple import config
from elasticsearch import Elasticsearch
from ..pzero.Elk import event_searching
app = FastAPI()

CLOUD_ID = config("CLOUD_ID")
PASSWORD = config("ELASTIC_PASSWORD")

@app.get("/")
async def index():
    global es
    if CLOUD_ID and PASSWORD:
        data ={"nodes":[],"edges":[]} # machines network data
        es = Elasticsearch(cloud_id=CLOUD_ID,http_auth=("elastic",PASSWORD))
        query = {
            "bool":{
                "must":[{"match":{"event.code":"3"}}],
                "filter":[]
            }
        }
        print(event_searching(es,query=query))
    else:
        return {"network_data":None}
