from sqlalchemy.orm import Session
import models, schemas


def get_creds(db: Session, id: int):
    return db.query(models.ElasticCredsModel).filter(models.ElasticCredsModel.id == id).first()

def create_creds(db:Session,credsItem: schemas.ElasticCreds):
    db_creds = models.ElasticCredsModel(apikey=credsItem.apikey,username=credsItem.username,password=credsItem.password)
    db.add(db_creds)
    db.commit()
    db.refresh(db_creds)

    return db_creds

def update_creds(db: Session,creds:schemas.ElasticCreds):
    db_creds = db.query(models.ElasticCredsModel).filter(models.ElasticCredsModel.id == creds.id).update(values={"apikey":creds.apikey,"username":creds.username,"password":creds.password})
    db.commit()
    return db_creds

def delete_creds(db:Session,id:int):
    db.query(models.ElasticCredsModel).filter(models.ElasticCredsModel.id == id).delete()
    db.commit()

def get_infected(db:Session,id: int):
    return db.query(models.Infected).filter(models.Infected.id == id).first()

def insert_infected(db:Session,machine:schemas.Infected):
    db_machine = models.Infected(name=machine.name,timestamp=machine.timestamp)
    db.add(db_machine)
    db.commit()
    db.refresh(db_machine)

def update_infected(db:Session,machine:schemas.Infected):
    db_machine = db.query(models.Infected).filter(models.Infected.id == id).update(values={"name":machine.name,"timestamp":machine.timestamp})  
    db.commit()
    return db_machine

def delete(db:Session,id:int):
    db.query(models.Infected).filter(models.Infected.id == id).delete()
    db.commit()
    