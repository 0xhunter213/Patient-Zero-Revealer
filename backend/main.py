from fastapi import FastAPI,Depends,status,Response
from fastapi.middleware.cors import CORSMiddleware
from decouple import Config
from elasticsearch import Elasticsearch
from fetch_events import retrieve_netwrok_tpoplogy
from database import SessionLocal,engine
from sqlalchemy.orm import Session
from schemas import ElasticCreds
from models import Base
from crud import update_creds,get_creds,create_creds
from Elk import event_searching
from Revealer import pzero_revealer

Base.metadata.create_all(bind=engine)

app = FastAPI()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

origins = ["http://localhost:3000/","http://localhost"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
)

CLOUD_ID = Config("CLOUD_ID")
PASSWORD = Config("ELASTIC_PASSWORD")


@app.get("/")
async def index(db: Session = Depends(get_db)):
    global es
    data ={"nodes":[],"edges":[]} # machines network data
    try:
        # check for creds in db 
        creds = get_creds(id=1,db=db)
        if creds:
            es = Elasticsearch(cloud_id=creds.apikey,http_auth=(creds.username,creds.password))
        elif CLOUD_ID and PASSWORD:
            creds_obj = ElasticCreds(id=1,apikey=CLOUD_ID,username="elastic",password=PASSWORD)
            creds = create_creds(db=db,credsItem=creds_obj)
            es= Elasticsearch(cloud_id=CLOUD_ID,http_auth=("elastic",PASSWORD))
        
        return await retrieve_netwrok_tpoplogy(es)
    except:
         return data   


@app.post("/elastic",response_model=ElasticCreds)
async def elastic(creds : ElasticCreds, db: Session = Depends(get_db)):
    """
        temp solution to store elastic creds (for cloud)
    """
    obj = get_creds(db,creds.id)
    if obj:
        updated_obj = update_creds(db,creds)
        global es
        es = Elasticsearch(cloud_id=creds.apikey,http_auth=(creds.username,creds.password))
        return creds
    else:
        obj=create_creds(db,creds)
    return obj

@app.get("/search")
async def search_event(event_code: int ,username: str | None = None,ip_address: str | None = None, event_date_start : str | None = None, event_date_end : str | None = None):
    search_query = {
        "bool":{
            "must":[
                {"match":{"event.code":str(event_code)}}
            ],
            "filter":[]
        }
    }
    if username:
        search_query["bool"]["must"].append({"match":{"winlog.user.name":username}})
    if ip_address:
        search_query["bool"]["must"].append({"match":{"host.ip":ip_address}})
    
    if event_date_start or event_date_end:

        search_query["bool"]["filter"].append({"range":{
            "@timestamp":{
                "gte":event_date_start,
                "lte":event_date_end
            }
        }})

    return event_searching(es,search_query)


@app.post("/pzero")
async def pzero_detection(username:str,ip_address:str| None = None,timestamp:str | None = None):
    return pzero_revealer(es,username,ip_address,timestamp)