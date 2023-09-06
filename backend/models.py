from database import Base
from sqlalchemy import Column,Integer, String

class ElasticCredsModel(Base):
    __tablename__ = "elastic_creds"

    id = Column(Integer,primary_key=True,index=True,autoincrement=True)
    apikey = Column(String,index=True)
    username=Column(String,unique=True,index=True)
    password=Column(String,index=True)

class Infected(Base):
    __tablename__= "infected"
    id = Column(Integer,primary_key=True,index=True,autoincrement=True)
    name = Column(String)
    timestamp = Column(String)