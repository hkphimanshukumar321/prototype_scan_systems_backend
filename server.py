from fastapi import FastAPI, APIRouter, HTTPException, Depends, UploadFile, File, Header
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
import socketio

import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field, ConfigDict
from typing import List, Optional
import uuid
from datetime import datetime, timezone, timedelta
import jwt
import bcrypt
import hashlib
import base64
from PIL import Image
import io
import json

from db import supabase


ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / ".env")

# JWT Configuration
JWT_SECRET = os.environ.get("JWT_SECRET", "change-me")
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_HOURS = int(os.environ.get("JWT_EXPIRATION_HOURS", "24"))

# Socket.IO setup
sio = socketio.AsyncServer(async_mode="asgi", cors_allowed_origins="*")

# Create the main app
app = FastAPI()
api_router = APIRouter(prefix="/api")
security = HTTPBearer()


def verify_admin_secret(x_admin_secret: Optional[str]) -> None:
    """Simple bootstrap guard for provisioning Security/Admin accounts.

    Minimal-work approach: set ADMIN_SECRET in Railway env and call the provisioning endpoint once.
    """
    expected = os.environ.get("ADMIN_SECRET")
    if not expected:
        raise HTTPException(status_code=403, detail="ADMIN_SECRET not configured")
    if (x_admin_secret or "") != expected:
        raise HTTPException(status_code=403, detail="Invalid admin secret")


class ProvisionUserRequest(BaseModel):
    name: str
    role: str  # Security or Admin
    institute_id: Optional[str] = None
    phone: Optional[str] = None
    password: str
    department: Optional[str] = None


# -------------------------
# Pydantic Models
# -------------------------
class UserRole(str):
    STUDENT = "Student"
    PROFESSOR = "Professor"
    EMPLOYEE = "Employee"
    WORKER = "Worker"
    VISITOR = "Visitor"
    SECURITY = "Security"
    ADMIN = "Admin"


class VehicleType(str):
    TWO_WHEELER = "2-wheeler"
    FOUR_WHEELER = "4-wheeler"


class LogStatus(str):
    IN = "IN"
    OUT = "OUT"


class LoginRequest(BaseModel):
    institute_id: Optional[str] = None
    phone: Optional[str] = None
    password: str


class RegisterRequest(BaseModel):
    """Self-signup payload.

    Role-specific requirements are enforced in the /auth/register handler.
    """

    name: str
    role: str
    password: str
    institute_id: Optional[str] = None  # roll no / employee id etc. can be stored separately; institute_id is a login identifier
    phone: Optional[str] = None
    aadhaar_number: str
    department: Optional[str] = None
    roll_no: Optional[str] = None
    employee_id: Optional[str] = None
    designation: Optional[str] = None
    program: Optional[str] = None
    year: Optional[str] = None
    address: Optional[str] = None
    emergency_contact: Optional[str] = None
    # Vehicle (captured during registration; no vehicle scanning required)
    vehicle_number: Optional[str] = None
    vehicle_type: Optional[str] = None
    vehicle_model: Optional[str] = None
    # Visitor-specific fields
    visitor_purpose: Optional[str] = None
    host_name: Optional[str] = None
    host_department: Optional[str] = None
    host_contact: Optional[str] = None


class UpdateMeRequest(BaseModel):
    name: Optional[str] = None
    phone: Optional[str] = None
    department: Optional[str] = None
    roll_no: Optional[str] = None
    employee_id: Optional[str] = None
    designation: Optional[str] = None
    program: Optional[str] = None
    year: Optional[str] = None
    address: Optional[str] = None
    emergency_contact: Optional[str] = None
    photo_url: Optional[str] = None
    license_number: Optional[str] = None
    # Vehicle
    vehicle_number: Optional[str] = None
    vehicle_type: Optional[str] = None
    vehicle_model: Optional[str] = None
    # Visitor fields
    visitor_purpose: Optional[str] = None
    host_name: Optional[str] = None
    host_department: Optional[str] = None
    host_contact: Optional[str] = None
    # Password change (optional)
    current_password: Optional[str] = None
    new_password: Optional[str] = None


class LoginResponse(BaseModel):
    token: str
    user: dict


class UserBase(BaseModel):
    model_config = ConfigDict(extra="ignore")
    name: str
    role: str
    department: Optional[str] = None
    institute_id: Optional[str] = None
    phone: Optional[str] = None
    aadhaar_hash: Optional[str] = None
    aadhaar_last4: Optional[str] = None
    roll_no: Optional[str] = None
    employee_id: Optional[str] = None
    designation: Optional[str] = None
    program: Optional[str] = None
    year: Optional[str] = None
    address: Optional[str] = None
    emergency_contact: Optional[str] = None
    photo_url: Optional[str] = None
    license_number: Optional[str] = None
    # Vehicle
    vehicle_number: Optional[str] = None
    vehicle_type: Optional[str] = None
    vehicle_model: Optional[str] = None
    # Visitor fields
    visitor_purpose: Optional[str] = None
    host_name: Optional[str] = None
    host_department: Optional[str] = None
    host_contact: Optional[str] = None
    is_blocked: bool = False


class User(UserBase):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class UserCreate(UserBase):
    password: Optional[str] = None


class Vehicle(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    user_id: str
    vehicle_number: str
    model: Optional[str] = None
    vehicle_type: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class VehicleCreate(BaseModel):
    vehicle_number: str
    model: Optional[str] = None
    vehicle_type: str


class Gate(BaseModel):
    model_config = ConfigDict(extra="ignore")
    gate_id: str
    name: str
    location: str
    gate_type: str
    description: Optional[str] = None
    is_active: bool = True
    qr_code_data: Optional[str] = None
    total_entries: int = 0
    total_exits: int = 0
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_scan_at: Optional[datetime] = None


class GateCreate(BaseModel):
    gate_id: str
    name: str
    location: str
    gate_type: str
    description: Optional[str] = None
    is_active: bool = True


class GateUpdate(BaseModel):
    name: Optional[str] = None
    location: Optional[str] = None
    gate_type: Optional[str] = None
    description: Optional[str] = None
    is_active: Optional[bool] = None


class Log(BaseModel):
    model_config = ConfigDict(extra="ignore")
    log_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    user_id: str
    gate_id: str
    location: str
    status: str
    purpose: Optional[str] = None
    vehicle_number: Optional[str] = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ScanRequest(BaseModel):
    gate_id: str
    location: Optional[str] = None
    user_id: Optional[str] = None
    purpose: Optional[str] = None
    vehicle_number: Optional[str] = None


class Analytics(BaseModel):
    total_entries_today: int
    total_exits_today: int
    current_inside: int
    total_visitors_today: int
    peak_hour: str
    hourly_data: List[dict]


# -------------------------
# Helpers
# -------------------------
def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode("utf-8"), hashed.encode("utf-8"))


def hash_aadhaar(aadhaar_number: str) -> tuple[str, str]:
    """Returns (aadhaar_hash, last4). Stores only hashed Aadhaar for privacy."""
    normalized = "".join(ch for ch in aadhaar_number.strip() if ch.isdigit())
    if len(normalized) != 12:
        raise HTTPException(status_code=400, detail="Aadhaar must be exactly 12 digits")
    digest = hashlib.sha256(normalized.encode("utf-8")).hexdigest()
    return digest, normalized[-4:]


def create_token(user_id: str) -> str:
    expiration = datetime.now(timezone.utc) + timedelta(hours=JWT_EXPIRATION_HOURS)
    payload = {"user_id": user_id, "exp": expiration}
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def _parse_dt(value):
    if value is None:
        return None
    if isinstance(value, datetime):
        return value
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


async def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        token = credentials.credentials
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        user_id = payload.get("user_id")
        if not user_id:
            raise HTTPException(status_code=401, detail="Invalid token")
        return user_id
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")


def _one(res):
    return res.data[0] if getattr(res, "data", None) else None


def _get_role(user_id: str) -> Optional[str]:
    """Best-effort role lookup. Returns None if missing."""
    try:
        row = _one(
            supabase.table("users").select("role").eq("id", user_id).limit(1).execute()
        )
        return row.get("role") if row else None
    except Exception:
        return None


def require_security_or_admin(user_id: str) -> None:
    role = _get_role(user_id)
    if role not in {UserRole.SECURITY, UserRole.ADMIN}:
        raise HTTPException(status_code=403, detail="Security/Admin access required")


# -------------------------
# API Routes
# -------------------------
@api_router.post("/auth/login", response_model=LoginResponse)
async def login(request: LoginRequest):
    if not request.institute_id and not request.phone:
        raise HTTPException(status_code=400, detail="Provide institute_id or phone")

    q = supabase.table("users").select("*")
    if request.institute_id:
        q = q.eq("institute_id", request.institute_id)
    else:
        q = q.eq("phone", request.phone)

    user_doc = _one(q.limit(1).execute())
    if not user_doc:
        raise HTTPException(status_code=404, detail="User not found")

    password_hash = user_doc.get("password_hash")
    if not password_hash:
        raise HTTPException(status_code=401, detail="Account has no password set")
    if not verify_password(request.password, password_hash):
        raise HTTPException(status_code=401, detail="Invalid password")

    user_doc.pop("password_hash", None)
    token = create_token(user_doc["id"])
    return LoginResponse(token=token, user=user_doc)


@api_router.post("/auth/register", response_model=LoginResponse)
async def register(req: RegisterRequest):
    # Require a stable login identifier
    # - Visitors must provide phone
    # - Others may use institute_id (preferred) or phone
    if not req.institute_id and not req.phone:
        raise HTTPException(status_code=400, detail="Provide institute_id (preferred) or phone")

    role = (req.role or "").strip()
    allowed_roles = {UserRole.STUDENT, UserRole.PROFESSOR, UserRole.EMPLOYEE, UserRole.WORKER, UserRole.VISITOR}
    if role not in allowed_roles:
        raise HTTPException(status_code=400, detail=f"Role must be one of: {', '.join(sorted(allowed_roles))}")

    # Role-specific requirements
    if role == UserRole.STUDENT:
        if not req.roll_no:
            raise HTTPException(status_code=400, detail="roll_no is required for Student")
    if role == UserRole.VISITOR:
        if not req.phone:
            raise HTTPException(status_code=400, detail="phone is required for Visitor")
        if not req.visitor_purpose:
            raise HTTPException(status_code=400, detail="visitor_purpose is required for Visitor")
        if not req.host_name:
            raise HTTPException(status_code=400, detail="host_name is required for Visitor")
        if not req.host_department:
            raise HTTPException(status_code=400, detail="host_department is required for Visitor")
    if role in {UserRole.PROFESSOR, UserRole.EMPLOYEE, UserRole.WORKER}:
        if not req.employee_id:
            raise HTTPException(status_code=400, detail="employee_id is required for Professor/Employee/Worker")
        if role == UserRole.PROFESSOR and not req.designation:
            raise HTTPException(status_code=400, detail="designation is required for Professor")
    if role == UserRole.VISITOR:
        # Visitors generally won't have an institute_id. Require phone for login.
        if not req.phone:
            raise HTTPException(status_code=400, detail="phone is required for Visitor")
        if not req.visitor_purpose:
            raise HTTPException(status_code=400, detail="visitor_purpose is required for Visitor")
        if not req.host_name or not req.host_department:
            raise HTTPException(status_code=400, detail="host_name and host_department are required for Visitor")

    aadhaar_hash, aadhaar_last4 = hash_aadhaar(req.aadhaar_number)

    # Uniqueness checks (friendlier than raw DB errors)
    if req.institute_id:
        existing = _one(
            supabase.table("users").select("id").eq("institute_id", req.institute_id).limit(1).execute()
        )
        if existing:
            raise HTTPException(status_code=409, detail="institute_id already registered")
    if req.phone:
        existing = _one(
            supabase.table("users").select("id").eq("phone", req.phone).limit(1).execute()
        )
        if existing:
            raise HTTPException(status_code=409, detail="phone already registered")

    user_obj = User(
        name=req.name.strip(),
        role=role,
        department=req.department,
        institute_id=req.institute_id,
        phone=req.phone,
        aadhaar_hash=aadhaar_hash,
        aadhaar_last4=aadhaar_last4,
        roll_no=req.roll_no,
        employee_id=req.employee_id,
        designation=req.designation,
        program=req.program,
        year=req.year,
        address=req.address,
        emergency_contact=req.emergency_contact,
        vehicle_number=req.vehicle_number,
        vehicle_type=req.vehicle_type,
        vehicle_model=req.vehicle_model,
        visitor_purpose=req.visitor_purpose,
        host_name=req.host_name,
        host_department=req.host_department,
        host_contact=req.host_contact,
    )

    doc = user_obj.model_dump()
    doc["password_hash"] = hash_password(req.password)
    doc["created_at"] = doc["created_at"].isoformat()

    try:
        supabase.table("users").insert(doc).execute()
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to register user")

    token = create_token(user_obj.id)
    safe_user = doc.copy()
    safe_user.pop("password_hash", None)
    return LoginResponse(token=token, user=safe_user)


@api_router.post("/admin/provision")
async def provision_security_user(
    payload: ProvisionUserRequest,
    x_admin_secret: Optional[str] = Header(None, alias="X-Admin-Secret"),
):
    """Provision Security/Admin accounts (no public signup for these roles).

    Call once using ADMIN_SECRET, then use normal /auth/login.
    """
    verify_admin_secret(x_admin_secret)
    role = (payload.role or "").strip()
    if role not in {UserRole.SECURITY, UserRole.ADMIN}:
        raise HTTPException(status_code=400, detail="role must be Security or Admin")
    if not payload.institute_id and not payload.phone:
        raise HTTPException(status_code=400, detail="Provide institute_id or phone")

    # Uniqueness checks
    if payload.institute_id:
        existing = _one(
            supabase.table("users").select("id").eq("institute_id", payload.institute_id).limit(1).execute()
        )
        if existing:
            raise HTTPException(status_code=409, detail="institute_id already registered")
    if payload.phone:
        existing = _one(
            supabase.table("users").select("id").eq("phone", payload.phone).limit(1).execute()
        )
        if existing:
            raise HTTPException(status_code=409, detail="phone already registered")

    user_obj = User(
        name=payload.name.strip(),
        role=role,
        department=payload.department,
        institute_id=payload.institute_id,
        phone=payload.phone,
    )
    doc = user_obj.model_dump()
    doc["password_hash"] = hash_password(payload.password)
    doc["created_at"] = doc["created_at"].isoformat()
    supabase.table("users").insert(doc).execute()
    safe_user = doc.copy()
    safe_user.pop("password_hash", None)
    return {"message": f"{role} account created", "user": safe_user}


@api_router.get("/users/me", response_model=User)
async def get_me(user_id: str = Depends(verify_token)):
    user_doc = _one(supabase.table("users").select("*").eq("id", user_id).limit(1).execute())
    if not user_doc:
        raise HTTPException(status_code=404, detail="User not found")
    user_doc.pop("password_hash", None)
    user_doc["created_at"] = _parse_dt(user_doc.get("created_at"))
    return user_doc


@api_router.put("/users/me", response_model=User)
async def update_me(payload: UpdateMeRequest, user_id: str = Depends(verify_token)):
    current = _one(supabase.table("users").select("*").eq("id", user_id).limit(1).execute())
    if not current:
        raise HTTPException(status_code=404, detail="User not found")

    update_data = {k: v for k, v in payload.model_dump().items() if v is not None}

    # Password change
    if "new_password" in update_data:
        new_password = update_data.pop("new_password")
        current_password = update_data.pop("current_password", None)
        if not current.get("password_hash"):
            # Allow first-time set
            supabase.table("users").update({"password_hash": hash_password(new_password)}).eq("id", user_id).execute()
        else:
            if not current_password or not verify_password(current_password, current.get("password_hash")):
                raise HTTPException(status_code=401, detail="Current password is incorrect")
            supabase.table("users").update({"password_hash": hash_password(new_password)}).eq("id", user_id).execute()

    # Uniqueness for phone if updating
    if "phone" in update_data and update_data.get("phone"):
        existing = _one(
            supabase.table("users").select("id").eq("phone", update_data["phone"]).limit(1).execute()
        )
        if existing and existing.get("id") != user_id:
            raise HTTPException(status_code=409, detail="phone already registered")

    # Apply rest fields
    if update_data:
        supabase.table("users").update(update_data).eq("id", user_id).execute()

    updated = _one(supabase.table("users").select("*").eq("id", user_id).limit(1).execute())
    updated.pop("password_hash", None)
    updated["created_at"] = _parse_dt(updated.get("created_at"))
    return updated


@api_router.get("/users", response_model=List[User])
async def get_users(role: Optional[str] = None, user_id: str = Depends(verify_token)):
    require_security_or_admin(user_id)
    q = supabase.table("users").select(
        "id,name,role,department,institute_id,phone,aadhaar_hash,aadhaar_last4,roll_no,employee_id,designation,program,year,address,emergency_contact,photo_url,license_number,vehicle_number,vehicle_type,vehicle_model,visitor_purpose,host_name,host_department,host_contact,is_blocked,created_at"
    )
    if role:
        q = q.eq("role", role)
    res = q.execute()
    users = res.data or []
    for u in users:
        u["created_at"] = _parse_dt(u.get("created_at"))
    return users


@api_router.get("/users/{user_id_param}", response_model=User)
async def get_user(user_id_param: str, user_id: str = Depends(verify_token)):
    require_security_or_admin(user_id)
    user_doc = _one(
        supabase.table("users")
        .select(
            "id,name,role,department,institute_id,phone,aadhaar_hash,aadhaar_last4,roll_no,employee_id,designation,program,year,address,emergency_contact,photo_url,license_number,vehicle_number,vehicle_type,vehicle_model,visitor_purpose,host_name,host_department,host_contact,is_blocked,created_at"
        )
        .eq("id", user_id_param)
        .limit(1)
        .execute()
    )
    if not user_doc:
        raise HTTPException(status_code=404, detail="User not found")
    user_doc["created_at"] = _parse_dt(user_doc.get("created_at"))
    return user_doc


@api_router.post("/vehicles", response_model=Vehicle)
async def create_vehicle(vehicle_data: VehicleCreate, user_id: str = Depends(verify_token)):
    require_security_or_admin(user_id)
    vehicle_obj = Vehicle(user_id=user_id, **vehicle_data.model_dump())
    doc = vehicle_obj.model_dump()
    doc["created_at"] = doc["created_at"].isoformat()

    supabase.table("vehicles").insert(doc).execute()
    return vehicle_obj


@api_router.get("/vehicles", response_model=List[Vehicle])
async def get_vehicles(
    user_id_query: Optional[str] = None, current_user: str = Depends(verify_token)
):
    require_security_or_admin(current_user)
    q = supabase.table("vehicles").select("*")
    if user_id_query:
        q = q.eq("user_id", user_id_query)
    res = q.execute()
    vehicles = res.data or []
    for v in vehicles:
        v["created_at"] = _parse_dt(v.get("created_at"))
    return vehicles


# -------------------------
# Gate Management
# -------------------------
@api_router.post("/gates", response_model=Gate)
async def create_gate(gate_data: GateCreate, user_id: str = Depends(verify_token)):
    require_security_or_admin(user_id)
    existing = _one(
        supabase.table("gates").select("gate_id").eq("gate_id", gate_data.gate_id).limit(1).execute()
    )
    if existing:
        raise HTTPException(
            status_code=400, detail=f"Gate with ID '{gate_data.gate_id}' already exists"
        )

    gate_obj = Gate(**gate_data.model_dump())
    gate_obj.qr_code_data = json.dumps({"gate_id": gate_obj.gate_id, "location": gate_obj.location})

    doc = gate_obj.model_dump()
    doc["created_at"] = doc["created_at"].isoformat()
    doc["last_scan_at"] = doc["last_scan_at"].isoformat() if doc.get("last_scan_at") else None

    supabase.table("gates").insert(doc).execute()
    return gate_obj


@api_router.get("/gates", response_model=List[Gate])
async def get_gates(
    is_active: Optional[bool] = None,
    gate_type: Optional[str] = None,
    user_id: str = Depends(verify_token),
):
    q = supabase.table("gates").select("*")
    if is_active is not None:
        q = q.eq("is_active", is_active)
    if gate_type:
        q = q.eq("gate_type", gate_type)
    res = q.execute()
    gates = res.data or []
    for g in gates:
        g["created_at"] = _parse_dt(g.get("created_at"))
        g["last_scan_at"] = _parse_dt(g.get("last_scan_at"))
    return gates


@api_router.get("/gates/{gate_id}", response_model=Gate)
async def get_gate(gate_id: str, user_id: str = Depends(verify_token)):
    gate_doc = _one(supabase.table("gates").select("*").eq("gate_id", gate_id).limit(1).execute())
    if not gate_doc:
        raise HTTPException(status_code=404, detail="Gate not found")
    gate_doc["created_at"] = _parse_dt(gate_doc.get("created_at"))
    gate_doc["last_scan_at"] = _parse_dt(gate_doc.get("last_scan_at"))
    return gate_doc


@api_router.put("/gates/{gate_id}", response_model=Gate)
async def update_gate(gate_id: str, gate_update: GateUpdate, user_id: str = Depends(verify_token)):
    require_security_or_admin(user_id)
    gate_doc = _one(supabase.table("gates").select("*").eq("gate_id", gate_id).limit(1).execute())
    if not gate_doc:
        raise HTTPException(status_code=404, detail="Gate not found")

    update_data = {k: v for k, v in gate_update.model_dump().items() if v is not None}
    if "location" in update_data:
        update_data["qr_code_data"] = json.dumps({"gate_id": gate_id, "location": update_data["location"]})

    if update_data:
        supabase.table("gates").update(update_data).eq("gate_id", gate_id).execute()

    updated = _one(supabase.table("gates").select("*").eq("gate_id", gate_id).limit(1).execute())
    updated["created_at"] = _parse_dt(updated.get("created_at"))
    updated["last_scan_at"] = _parse_dt(updated.get("last_scan_at"))
    return updated


@api_router.delete("/gates/{gate_id}")
async def delete_gate(gate_id: str, user_id: str = Depends(verify_token)):
    require_security_or_admin(user_id)
    supabase.table("gates").delete().eq("gate_id", gate_id).execute()
    return {"message": f"Gate {gate_id} deleted successfully"}


@api_router.get("/gates/{gate_id}/qr-data")
async def get_gate_qr_data(gate_id: str, user_id: str = Depends(verify_token)):
    require_security_or_admin(user_id)
    gate_doc = _one(
        supabase.table("gates")
        .select("gate_id,location,qr_code_data,name")
        .eq("gate_id", gate_id)
        .limit(1)
        .execute()
    )
    if not gate_doc:
        raise HTTPException(status_code=404, detail="Gate not found")
    return gate_doc


@api_router.get("/gates/{gate_id}/stats")
async def get_gate_stats(gate_id: str, user_id: str = Depends(verify_token)):
    require_security_or_admin(user_id)
    gate_doc = _one(supabase.table("gates").select("*").eq("gate_id", gate_id).limit(1).execute())
    if not gate_doc:
        raise HTTPException(status_code=404, detail="Gate not found")

    today_start = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)

    today_logs = (
        supabase.table("logs")
        .select("status")
        .eq("gate_id", gate_id)
        .gte("timestamp", today_start.isoformat())
        .execute()
        .data
        or []
    )
    entries_today = sum(1 for l in today_logs if l.get("status") == LogStatus.IN)
    exits_today = sum(1 for l in today_logs if l.get("status") == LogStatus.OUT)

    all_logs = (
        supabase.table("logs").select("status").eq("gate_id", gate_id).execute().data or []
    )
    total_entries = sum(1 for l in all_logs if l.get("status") == LogStatus.IN)
    total_exits = sum(1 for l in all_logs if l.get("status") == LogStatus.OUT)

    last_log = _one(
        supabase.table("logs")
        .select("timestamp,user_id")
        .eq("gate_id", gate_id)
        .order("timestamp", desc=True)
        .limit(1)
        .execute()
    )

    return {
        "gate_id": gate_id,
        "name": gate_doc.get("name"),
        "entries_today": entries_today,
        "exits_today": exits_today,
        "total_entries": total_entries,
        "total_exits": total_exits,
        "last_scan_at": last_log.get("timestamp") if last_log else None,
        "last_scan_user": last_log.get("user_id") if last_log else None,
        "is_active": gate_doc.get("is_active", True),
    }


# -------------------------
# Scan
# -------------------------
@api_router.post("/scan", response_model=Log)
async def scan_qr(scan_data: ScanRequest, requester_id: str = Depends(verify_token)):
    # New primary flow (per project plan):
    # - Gates/Labs have a fixed QR containing gate_id (+ optional location)
    # - The authenticated end-user scans the gate QR with their smartphone
    # - Backend logs IN/OUT by toggling based on the user's latest log
    # Legacy support:
    # - If user_id is supplied and differs from requester_id, only Security/Admin can scan for others.

    target_user_id = scan_data.user_id or requester_id
    if scan_data.user_id and scan_data.user_id != requester_id:
        role = _get_role(requester_id)
        if role not in {UserRole.SECURITY, UserRole.ADMIN}:
            raise HTTPException(status_code=403, detail="Not authorized to scan for other users")

    gate_doc = _one(
        supabase.table("gates").select("*").eq("gate_id", scan_data.gate_id).limit(1).execute()
    )
    if not gate_doc:
        raise HTTPException(
            status_code=404,
            detail=f"Gate '{scan_data.gate_id}' not registered in system",
        )
    if not gate_doc.get("is_active", True):
        raise HTTPException(status_code=403, detail=f"Gate '{scan_data.gate_id}' is currently inactive")

    # Resolve location: prefer payload (from gate QR), else take from registered gate.
    location = (scan_data.location or gate_doc.get("location") or f"Gate {scan_data.gate_id}").strip()

    user_doc = _one(
        supabase.table("users")
        .select(
            "id,name,role,department,institute_id,phone,aadhaar_hash,aadhaar_last4,photo_url,license_number,is_blocked,created_at,vehicle_number,visitor_purpose,host_name,host_department,host_contact"
        )
        .eq("id", target_user_id)
        .limit(1)
        .execute()
    )
    if not user_doc:
        raise HTTPException(status_code=404, detail="User not found")

    if user_doc.get("is_blocked", False):
        log_obj = Log(
            user_id=target_user_id,
            gate_id=scan_data.gate_id,
            location=location,
            status="BLOCKED",
            purpose=scan_data.purpose,
            vehicle_number=scan_data.vehicle_number or user_doc.get("vehicle_number"),
        )
        doc = log_obj.model_dump()
        doc["timestamp"] = doc["timestamp"].isoformat()
        supabase.table("logs").insert(doc).execute()

        await sio.emit(
            "scan_alert",
            {
                **doc,
                "user": user_doc,
                "timestamp": doc["timestamp"],
            },
        )
        raise HTTPException(status_code=403, detail="User is blocked")

    last_log = _one(
        supabase.table("logs")
        .select("status")
        .eq("user_id", target_user_id)
        .order("timestamp", desc=True)
        .limit(1)
        .execute()
    )

    new_status = LogStatus.IN
    if last_log and last_log.get("status") == LogStatus.IN:
        new_status = LogStatus.OUT

    vehicle_number = (scan_data.vehicle_number or user_doc.get("vehicle_number") or None)

    log_obj = Log(
        user_id=target_user_id,
        gate_id=scan_data.gate_id,
        location=location,
        status=new_status,
        purpose=scan_data.purpose,
        vehicle_number=vehicle_number,
    )
    doc = log_obj.model_dump()
    doc["timestamp"] = doc["timestamp"].isoformat()
    supabase.table("logs").insert(doc).execute()

    # Update gate counters atomically via RPC function created in Supabase migration.
    try:
        supabase.rpc(
            "bump_gate_counter",
            {"p_gate_id": scan_data.gate_id, "p_is_entry": new_status == LogStatus.IN},
        ).execute()
    except Exception:
        # Fallback (non-atomic): best-effort update if RPC isn't installed.
        field = "total_entries" if new_status == LogStatus.IN else "total_exits"
        current = _one(
            supabase.table("gates")
            .select(f"{field}")
            .eq("gate_id", scan_data.gate_id)
            .limit(1)
            .execute()
        )
        new_val = int((current or {}).get(field, 0)) + 1
        supabase.table("gates").update(
            {field: new_val, "last_scan_at": doc["timestamp"]}
        ).eq("gate_id", scan_data.gate_id).execute()

    await sio.emit(
        "scan_alert",
        {
            **doc,
            "user": user_doc,
            "gate": gate_doc,
            "timestamp": doc["timestamp"],
        },
    )

    return log_obj


@api_router.get("/logs", response_model=List[Log])
async def get_logs(
    gate_id: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = 100,
    user_id: str = Depends(verify_token),
):
    role = _get_role(user_id)
    q = supabase.table("logs").select("*").order("timestamp", desc=True).limit(limit)
    # Default data-scope: non-security users can only see their own activity.
    if role not in {UserRole.SECURITY, UserRole.ADMIN}:
        q = q.eq("user_id", user_id)
    if gate_id:
        q = q.eq("gate_id", gate_id)
    if status:
        q = q.eq("status", status)

    logs = q.execute().data or []
    for l in logs:
        l["timestamp"] = _parse_dt(l.get("timestamp"))
    return logs


@api_router.get("/status/me")
async def get_my_status(user_id: str = Depends(verify_token)):
    """Return app-friendly, computed 'inside/outside' status for the logged-in user."""
    last = _one(
        supabase.table("logs")
        .select("gate_id,location,status,timestamp")
        .eq("user_id", user_id)
        .order("timestamp", desc=True)
        .limit(1)
        .execute()
    )
    if not last:
        return {
            "inside": False,
            "last_status": None,
            "gate_id": None,
            "location": None,
            "timestamp": None,
        }
    ts = _parse_dt(last.get("timestamp"))
    last_status = last.get("status")
    return {
        "inside": last_status == LogStatus.IN,
        "last_status": last_status,
        "gate_id": last.get("gate_id"),
        "location": last.get("location"),
        "timestamp": ts.isoformat() if ts else last.get("timestamp"),
    }


@api_router.get("/analytics", response_model=Analytics)
async def get_analytics(user_id: str = Depends(verify_token)):
    require_security_or_admin(user_id)
    today_start = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)

    today_logs = (
        supabase.table("logs")
        .select("user_id,status,timestamp")
        .gte("timestamp", today_start.isoformat())
        .execute()
        .data
        or []
    )

    entries_today = sum(1 for l in today_logs if l.get("status") == LogStatus.IN)
    exits_today = sum(1 for l in today_logs if l.get("status") == LogStatus.OUT)
    current_inside = entries_today - exits_today

    unique_user_ids = sorted({l.get("user_id") for l in today_logs if l.get("user_id")})
    user_map = {}
    if unique_user_ids:
        users = (
            supabase.table("users")
            .select("id,role")
            .in_("id", unique_user_ids)
            .execute()
            .data
            or []
        )
        user_map = {u["id"]: u for u in users}

    visitor_ids = set()
    for l in today_logs:
        u = user_map.get(l.get("user_id"))
        if u and u.get("role") == UserRole.VISITOR:
            visitor_ids.add(l.get("user_id"))

    hourly_data = []
    # Convert timestamps once
    parsed_logs = [
        {**l, "_ts": _parse_dt(l.get("timestamp"))}
        for l in today_logs
        if l.get("timestamp")
    ]

    for hour in range(24):
        hour_start = today_start + timedelta(hours=hour)
        hour_end = hour_start + timedelta(hours=1)
        hour_logs = [l for l in parsed_logs if hour_start <= l["_ts"] < hour_end]
        hourly_data.append(
            {
                "hour": f"{hour:02d}:00",
                "entries": sum(1 for l in hour_logs if l.get("status") == LogStatus.IN),
                "exits": sum(1 for l in hour_logs if l.get("status") == LogStatus.OUT),
            }
        )

    peak_hour_data = max(hourly_data, key=lambda x: x["entries"]) if hourly_data else {"hour": "00:00"}
    peak_hour = peak_hour_data["hour"]

    return Analytics(
        total_entries_today=entries_today,
        total_exits_today=exits_today,
        current_inside=current_inside,
        total_visitors_today=len(visitor_ids),
        peak_hour=peak_hour,
        hourly_data=hourly_data,
    )


@api_router.post("/upload-photo")
async def upload_photo(file: UploadFile = File(...)):
    contents = await file.read()
    try:
        image = Image.open(io.BytesIO(contents))
        image.verify()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid image file")

    base64_image = base64.b64encode(contents).decode("utf-8")
    data_url = f"data:{file.content_type};base64,{base64_image}"
    return {"photo_url": data_url}


# Include router
app.include_router(api_router)

# Socket.IO ASGI app
socket_app = socketio.ASGIApp(sio, app)

# CORS
origins = [o.strip() for o in os.environ.get("CORS_ORIGINS", "*").split(",") if o.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=origins if origins else ["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


@sio.event
async def connect(sid, environ):
    logger.info(f"Client connected: {sid}")


@sio.event
async def disconnect(sid):
    logger.info(f"Client disconnected: {sid}")
