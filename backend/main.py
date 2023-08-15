from fastapi import FastAPI,Depends,status,Response
from fastapi.middleware.cors import CORSMiddleware
from decouple import Config
from elasticsearch import Elasticsearch
from fetch_events import retrieve_netwrok_tpoplogy
from database import SessionLocal,engine
from sqlalchemy.orm import Session
from schemas import ElasticCreds
from models import ElasticCredsModel,Base
from crud import update_creds,get_creds,create_creds

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
async def index():
    global es
    data ={"nodes":[],"edges":[]} # machines network data
    if CLOUD_ID and PASSWORD:
        try:
            es = Elasticsearch(cloud_id=CLOUD_ID,http_auth=("elastic",PASSWORD))
            return await retrieve_netwrok_tpoplogy(es)
        except:
            return data
    else:
        return {"message":"No Parameters Exist"}
    


@app.post("/elastic",response_model=ElasticCreds)
async def elastic(creds : ElasticCreds, db: Session = Depends(get_db)):
    """
        temp solution to store elastic creds (for cloud)
    """
    
    obj = get_creds(db,creds.id)
    if obj:
        updated_obj = update_creds(db,creds)
        print(updated_obj)
        return creds
    else:
        obj=create_creds(db,creds)
    return obj
    