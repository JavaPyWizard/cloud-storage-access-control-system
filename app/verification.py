from app.policy import ACTIONS
# Independent, table-oriented oracle. Does not invoke the production policy engine.
def expected(actor_id,actor_role,owner_id,policy,allowed_role,action):
 if action not in ('READ','WRITE','DELETE'): return False
 if actor_id is not None and actor_id==owner_id: return True
 if action!='READ': return False
 if policy=='PUBLIC_READ': return True
 if policy=='ROLE_RESTRICTED' and actor_id is not None:
  return actor_role==allowed_role
 return False

def matrix(users,objects,decider):
 rows=[]
 for obj in objects:
  for user in [None,*users]:
   for action in ACTIONS:
    actual,reason=decider(user,obj,action)
    want=expected(user.id if user else None,user.role if user else None,obj.owner_id,obj.policy,obj.allowed_role,action)
    rows.append({'object':obj.name,'object_id':obj.id,'actor':user.username if user else 'ANONYMOUS','action':action,'policy':obj.policy,'expected':want,'actual':actual,'match':want==actual,'reason':reason})
 return rows
