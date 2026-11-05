from datetime import datetime,timezone
from sqlalchemy import String,Integer,ForeignKey,DateTime,Boolean
from sqlalchemy.orm import Mapped,mapped_column
from app.db import Base
def now(): return datetime.now(timezone.utc)
class User(Base):
 __tablename__='users'
 id:Mapped[int]=mapped_column(primary_key=True)
 username:Mapped[str]=mapped_column(String(60),unique=True,index=True)
 password_hash:Mapped[str]=mapped_column(String(255))
 role:Mapped[str]=mapped_column(String(20),default='VIEWER')
class Object(Base):
 __tablename__='objects'
 id:Mapped[int]=mapped_column(primary_key=True)
 name:Mapped[str]=mapped_column(String(255))
 stored_name:Mapped[str]=mapped_column(String(255))
 content_type:Mapped[str]=mapped_column(String(120),default='application/octet-stream')
 owner_id:Mapped[int]=mapped_column(ForeignKey('users.id'))
 policy:Mapped[str]=mapped_column(String(30))
 allowed_role:Mapped[str|None]=mapped_column(String(20),nullable=True)
 size:Mapped[int]=mapped_column(Integer,default=0)
 created_at:Mapped[datetime]=mapped_column(DateTime(timezone=True),default=now)
class Audit(Base):
 __tablename__='audits'
 id:Mapped[int]=mapped_column(primary_key=True)
 actor_id:Mapped[int|None]=mapped_column(Integer,nullable=True)
 object_id:Mapped[int|None]=mapped_column(Integer,nullable=True)
 action:Mapped[str]=mapped_column(String(30))
 allowed:Mapped[bool]=mapped_column(Boolean)
 reason:Mapped[str]=mapped_column(String(200))
 simulated:Mapped[bool]=mapped_column(Boolean,default=False)
 created_at:Mapped[datetime]=mapped_column(DateTime(timezone=True),default=now)
