from fastapi import FastAPI
from decouple import config
from elasticsearch import Elasticsearch
from Elk import event_searching
from fetch_events import retrieve_netwrok_tpoplogy
app = FastAPI()

CLOUD_ID = config("CLOUD_ID")
PASSWORD = config("ELASTIC_PASSWORD")


@app.get("/")
async def index():
    global es
    if CLOUD_ID and PASSWORD:
        data ={"nodes":[],"edges":[]} # machines network data
        es = Elasticsearch(cloud_id=CLOUD_ID,http_auth=("elastic",PASSWORD))
        return await retrieve_netwrok_tpoplogy(es)
    else:
        return {"network_data":None}
