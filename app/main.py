import os
import re
import secrets
import uuid
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from pwdlib import PasswordHash
from sqlalchemy import func, select
from sqlalchemy.orm import Session
from starlette.middleware.sessions import SessionMiddleware

from app.db import Base, engine, get_db
from app.models import Audit, Object, User
from app.policy import ACTIONS, POLICIES, ROLES, decide
from app.security_rate_limit import login_limiter
from app.services.security_analytics import get_security_analytics
from app.upload_security import validate_upload
from app.verification import matrix

ROOT = Path(__file__).resolve().parent.parent
STORAGE = ROOT / "storage"
STORAGE.mkdir(exist_ok=True)
ph = PasswordHash.recommended()


@asynccontextmanager
async def lifespan(app):
    Base.metadata.create_all(bind=engine)
    yield


app = FastAPI(title="AegisVault | Access Control Lab", version="1.0", lifespan=lifespan)
secret = os.getenv("SESSION_SECRET", "")
if len(secret) < 32:
    secret = secrets.token_urlsafe(48)
app.add_middleware(
    SessionMiddleware,
    secret_key=secret,
    session_cookie="aegisvault_session",
    max_age=1800,
    same_site="lax",
    https_only=os.getenv("COOKIE_SECURE", "false").lower() == "true",
)
app.mount("/static", StaticFiles(directory=ROOT / "app" / "static"), name="static")


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)

    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"

    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data: blob:; "
        "connect-src 'self'; "
        "object-src 'none'; "
        "base-uri 'self'; "
        "frame-ancestors 'none'; "
        "form-action 'self'"
    )

    if request.url.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store"
    else:
        response.headers["Cache-Control"] = "no-cache"

    return response


def actor(req, db):
    uid = req.session.get("uid")
    return db.get(User, uid) if uid else None


def required(req: Request, db: Session = Depends(get_db)):
    u = actor(req, db)
    if not u:
        raise HTTPException(401, "Please sign in")
    return u


def csrf(req):
    token = req.headers.get("x-csrf-token", "")
    if not token or not secrets.compare_digest(token, req.session.get("csrf", "")):
        raise HTTPException(403, "Invalid CSRF token")


def log(db, u, obj, action, allowed, reason, simulated=False):
    db.add(
        Audit(
            actor_id=u.id if u else None,
            object_id=obj.id if obj else None,
            action=action,
            allowed=allowed,
            reason=reason,
            simulated=simulated,
        )
    )
    db.commit()


def objdict(o, owner=None):
    return {
        "id": o.id,
        "name": o.name,
        "size": o.size,
        "policy": o.policy,
        "allowed_role": o.allowed_role,
        "owner_id": o.owner_id,
        "owner": owner,
        "created_at": o.created_at.isoformat(),
    }


@app.get("/", response_class=HTMLResponse)
def home():
    return (ROOT / "app" / "static" / "index.html").read_text()


@app.get("/health")
def health():
    return {"status": "healthy", "app": "AegisVault"}


@app.get("/api/session")
def session(req: Request, db: Session = Depends(get_db)):
    if "csrf" not in req.session:
        req.session["csrf"] = secrets.token_urlsafe(32)
    u = actor(req, db)
    return {
        "user": {
            "id": u.id,
            "username": u.username,
            "role": u.role,
            "can_admin": u.id == db.scalar(select(func.min(User.id))),
        }
        if u
        else None,
        "csrf": req.session["csrf"],
    }


@app.post("/api/register")
def register(req: Request, body: dict, db: Session = Depends(get_db)):
    csrf(req)
    name = str(body.get("username", "")).strip().lower()
    pw = str(body.get("password", ""))
    if not re.fullmatch(r"[a-z][a-z0-9_]{2,29}", name):
        raise HTTPException(
            400,
            "Username must be 3-30 lowercase letters, digits or underscores, starting with a letter",
        )
    if len(pw) < 10 or len(pw) > 128:
        raise HTTPException(400, "Password must be 10-128 characters")
    if db.scalar(select(User).where(User.username == name)):
        raise HTTPException(409, "Username already exists")
    u = User(
        username=name,
        password_hash=ph.hash(pw),
        role="ADMIN" if db.scalar(select(func.count(User.id))) == 0 else "VIEWER",
    )
    db.add(u)
    db.commit()
    db.refresh(u)
    req.session["uid"] = u.id
    return {"username": u.username, "role": u.role}


@app.post("/api/login")
def login(
    req: Request,
    body: dict,
    db: Session = Depends(get_db),
):
    csrf(req)

    name = str(body.get("username", "")).strip().lower()
    pw = str(body.get("password", ""))

    client_ip = req.client.host if req.client else "unknown"
    rate_key = f"{client_ip}:{name}"

    if login_limiter.is_blocked(rate_key):
        raise HTTPException(
            status_code=429,
            detail="Too many failed login attempts. Try again later.",
            headers={"Retry-After": "300"},
        )

    u = db.scalar(select(User).where(User.username == name))

    if not u or not ph.verify(pw, u.password_hash):
        login_limiter.record_failure(rate_key)

        raise HTTPException(
            status_code=401,
            detail="Invalid credentials",
        )

    login_limiter.reset(rate_key)

    req.session.clear()
    req.session["uid"] = u.id
    req.session["csrf"] = secrets.token_urlsafe(32)

    return {
        "username": u.username,
        "role": u.role,
        "csrf": req.session["csrf"],
    }


@app.post("/api/logout")
def logout(req: Request):
    csrf(req)
    req.session.clear()
    return {"ok": True}


@app.get("/api/users")
def users(u: User = Depends(required), db: Session = Depends(get_db)):
    return [
        {"id": x.id, "username": x.username, "role": x.role}
        for x in db.scalars(select(User).order_by(User.id))
    ]


@app.patch("/api/users/{uid}/role")
def role(
    uid: int,
    body: dict,
    req: Request,
    u: User = Depends(required),
    db: Session = Depends(get_db),
):
    csrf(req)
    # Demo role administration: only first registered user (bootstrap administrator) can manage roles.
    first = db.scalar(select(func.min(User.id)))
    if u.id != first:
        raise HTTPException(403, "Only the bootstrap administrator can assign roles")
    target = db.get(User, uid)
    value = body.get("role")
    if not target or value not in ROLES:
        raise HTTPException(400, "Invalid user or role")
    if target.id == first and value != "ADMIN":
        raise HTTPException(400, "Cannot demote bootstrap administrator")
    target.role = value
    db.commit()
    return {"ok": True}


@app.get("/api/objects")
def objects(u: User = Depends(required), db: Session = Depends(get_db)):
    users = {x.id: x.username for x in db.scalars(select(User))}
    result = []
    for o in db.scalars(select(Object).order_by(Object.id.desc())):
        item = objdict(o, users.get(o.owner_id))
        item["permissions"] = {action: decide(u, o, action)[0] for action in ACTIONS}
        result.append(item)
    return result


@app.post("/api/objects")
async def upload(
    req: Request,
    file: UploadFile = File(...),
    policy: str = Form("PRIVATE"),
    allowed_role: str = Form(""),
    u: User = Depends(required),
    db: Session = Depends(get_db),
):
    csrf(req)

    if policy not in POLICIES or (
        policy == "ROLE_RESTRICTED" and allowed_role not in ROLES
    ):
        raise HTTPException(400, "Invalid policy or role")

    filename = file.filename or ""

    limit = int(os.getenv("MAX_UPLOAD_MB", "5")) * 1024 * 1024

    data = await file.read(limit + 1)

    if len(data) > limit:
        raise HTTPException(413, "File too large")

    content_type = validate_upload(filename, data)

    stored = uuid.uuid4().hex
    storage_path = STORAGE / stored

    storage_path.write_bytes(data)

    try:
        obj = Object(
            name=filename,
            stored_name=stored,
            content_type=content_type,
            owner_id=u.id,
            policy=policy,
            allowed_role=(allowed_role if policy == "ROLE_RESTRICTED" else None),
            size=len(data),
        )

        db.add(obj)
        db.commit()
        db.refresh(obj)

    except Exception:
        db.rollback()
        storage_path.unlink(missing_ok=True)
        raise

    log(db, u, obj, "UPLOAD", True, "Owner uploaded file")

    return objdict(obj, u.username)


@app.get("/api/objects/{oid}/download")
def download(oid: int, req: Request, db: Session = Depends(get_db)):
    o = db.get(Object, oid)
    if not o:
        raise HTTPException(404, "Object not found")
    u = actor(req, db)
    ok, reason = decide(u, o, "READ")
    log(db, u, o, "READ", ok, reason)
    if not ok:
        raise HTTPException(403, reason)
    path = STORAGE / o.stored_name
    if not path.is_file():
        raise HTTPException(404, "Stored file missing")
    return FileResponse(path, media_type="application/octet-stream", filename=o.name)


@app.delete("/api/objects/{oid}")
def delete(
    oid: int, req: Request, u: User = Depends(required), db: Session = Depends(get_db)
):
    csrf(req)
    o = db.get(Object, oid)
    if not o:
        raise HTTPException(404, "Object not found")
    ok, reason = decide(u, o, "DELETE")
    log(db, u, o, "DELETE", ok, reason)
    if not ok:
        raise HTTPException(403, reason)
    (STORAGE / o.stored_name).unlink(missing_ok=True)
    db.delete(o)
    db.commit()
    return {"ok": True}


@app.patch("/api/objects/{oid}/policy")
def change_policy(
    oid: int,
    body: dict,
    req: Request,
    u: User = Depends(required),
    db: Session = Depends(get_db),
):
    csrf(req)
    o = db.get(Object, oid)
    if not o:
        raise HTTPException(404, "Object not found")
    ok, reason = decide(u, o, "WRITE")
    log(db, u, o, "WRITE", ok, reason)
    if not ok:
        raise HTTPException(403, reason)
    policy = body.get("policy")
    r = body.get("allowed_role")
    if policy not in POLICIES or (policy == "ROLE_RESTRICTED" and r not in ROLES):
        raise HTTPException(400, "Invalid policy")
    o.policy = policy
    o.allowed_role = r if policy == "ROLE_RESTRICTED" else None
    db.commit()
    return {"ok": True}


@app.post("/api/simulate")
def simulate(
    body: dict, req: Request, u: User = Depends(required), db: Session = Depends(get_db)
):
    csrf(req)
    o = db.get(Object, body.get("object_id"))
    if not o:
        raise HTTPException(404, "Object not found")
    action = body.get("action")
    if action not in ACTIONS:
        raise HTTPException(400, "Invalid action")
    aid = body.get("actor_id")
    target = db.get(User, aid) if isinstance(aid, int) else None
    if aid is not None and target is None:
        raise HTTPException(400, "Unknown actor")
    ok, reason = decide(target, o, action)
    log(db, target, o, action, ok, reason, True)
    return {
        "allowed": ok,
        "reason": reason,
        "actor": target.username if target else "ANONYMOUS",
        "action": action,
        "object": o.name,
        "simulated": True,
    }


@app.get("/api/verify")
def verify(u: User = Depends(required), db: Session = Depends(get_db)):
    if u.id != db.scalar(select(func.min(User.id))):
        raise HTTPException(403, "Administrator access required")
    rows = matrix(
        list(db.scalars(select(User))), list(db.scalars(select(Object))), decide
    )
    return {
        "total": len(rows),
        "passed": sum(x["match"] for x in rows),
        "failed": sum(not x["match"] for x in rows),
        "rows": rows,
    }


@app.get("/api/audits")
def audits(
    decision: str = "ALL",
    action: str = "ALL",
    simulated: str = "ALL",
    u: User = Depends(required),
    db: Session = Depends(get_db),
):
    if u.id != db.scalar(select(func.min(User.id))):
        raise HTTPException(403, "Administrator access required")
    if (
        decision not in ("ALL", "ALLOW", "DENY")
        or action not in ("ALL", "READ", "WRITE", "DELETE", "UPLOAD")
        or simulated not in ("ALL", "YES", "NO")
    ):
        raise HTTPException(400, "Invalid audit filter")
    query = select(Audit)
    if decision != "ALL":
        query = query.where(Audit.allowed == (decision == "ALLOW"))
    if action != "ALL":
        query = query.where(Audit.action == action)
    if simulated != "ALL":
        query = query.where(Audit.simulated == (simulated == "YES"))
    rows = db.scalars(query.order_by(Audit.id.desc()).limit(200))
    return [
        {
            "id": a.id,
            "actor_id": a.actor_id,
            "object_id": a.object_id,
            "action": a.action,
            "allowed": a.allowed,
            "reason": a.reason,
            "simulated": a.simulated,
            "time": a.created_at.isoformat(),
        }
        for a in rows
    ]


@app.get("/api/security/analytics")
def security_analytics(
    u: User = Depends(required),
    db: Session = Depends(get_db),
):
    first_admin_id = db.scalar(select(func.min(User.id)))

    if u.id != first_admin_id:
        raise HTTPException(
            status_code=403,
            detail="Administrator access required",
        )

    return get_security_analytics(db)
