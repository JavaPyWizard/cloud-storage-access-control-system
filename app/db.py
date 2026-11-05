import os
from pathlib import Path
from dotenv import load_dotenv
from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker
load_dotenv()
DATABASE_URL=os.getenv('DATABASE_URL','sqlite:///./cloudguard_sim.db')
if DATABASE_URL.startswith('postgresql://'):
    DATABASE_URL=DATABASE_URL.replace('postgresql://','postgresql+psycopg://',1)
engine=create_engine(DATABASE_URL,connect_args={'check_same_thread':False} if DATABASE_URL.startswith('sqlite') else {},pool_pre_ping=True)
SessionLocal=sessionmaker(bind=engine,expire_on_commit=False)
class Base(DeclarativeBase): pass
def get_db():
    with SessionLocal() as db: yield db
