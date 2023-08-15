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

