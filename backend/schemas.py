from pydantic import BaseModel

class ElasticCreds(BaseModel):
    id : int
    apikey : str 
    username : str | None = None
    password : str

    class Config:
        orm_mode = True

