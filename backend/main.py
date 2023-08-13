from fastapi import FastAPI
from decouple import Config

app = FastAPI()

CLOUD_ID = Config("CLOUD_ID")
PASSWORD = Config("ELASTIC_PASSWORD")
INDEX_PATTERN = 'winlogbeat-*'



@app.get("/")
async def index():
    global es
    if CLOUD_ID and PASSWORD:
        es = 
    
    return {"message":None}
