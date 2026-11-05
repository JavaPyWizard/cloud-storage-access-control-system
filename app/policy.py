POLICIES=('PRIVATE','PUBLIC_READ','ROLE_RESTRICTED')
ROLES=('ADMIN','EDITOR','VIEWER')
ACTIONS=('READ','WRITE','DELETE')
def decide(user,obj,action):
 """Production policy evaluator: owner may manage, public permits read, role permits read."""
 if action not in ACTIONS: return False,'Unknown action'
 if user is None:
  if obj.policy=='PUBLIC_READ' and action=='READ': return True,'Public read permitted'
  return False,'Authentication required'
 if user.id==obj.owner_id: return True,'Object owner'
 if obj.policy=='PUBLIC_READ' and action=='READ': return True,'Public read permitted'
 if obj.policy=='ROLE_RESTRICTED' and action=='READ' and user.role==obj.allowed_role:
  return True,'Matching role'
 return False,'Policy denies access'
