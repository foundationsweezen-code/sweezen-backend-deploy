from fastapi import FastAPI, APIRouter, HTTPException, Depends, Request
from fastapi.responses import StreamingResponse
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
import os, uuid, logging, bcrypt, jwt, razorpay, io, csv, time, re
from pathlib import Path
from datetime import datetime, timezone, timedelta
from pdf_utils import generate_80g_receipt_pdf, generate_csr1_report_pdf, generate_donation_report_pdf, generate_volunteer_id_card_pdf

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

# JWT
JWT_SECRET = os.environ.get('JWT_SECRET', '').strip()
JWT_ALGORITHM = 'HS256'
JWT_EXPIRY_HOURS = 24
ALLOW_INSECURE_DEV_AUTH = os.environ.get('ALLOW_INSECURE_DEV_AUTH', 'false').strip().lower() == 'true'

if not JWT_SECRET and not ALLOW_INSECURE_DEV_AUTH:
    raise RuntimeError('JWT_SECRET is required. Set ALLOW_INSECURE_DEV_AUTH=true only for temporary local development.')
if not JWT_SECRET and ALLOW_INSECURE_DEV_AUTH:
    logger = logging.getLogger(__name__)
    logger.warning('JWT_SECRET is empty. Falling back to temporary insecure development secret.')
    JWT_SECRET = 'dev-insecure-secret-change-me'

# Razorpay
RAZORPAY_KEY = os.environ.get('RAZORPAY_KEY_ID', '')
RAZORPAY_SECRET = os.environ.get('RAZORPAY_KEY_SECRET', '')
RAZORPAY_ENABLED = bool(RAZORPAY_KEY and RAZORPAY_SECRET)
razorpay_client = None
if RAZORPAY_ENABLED:
    razorpay_client = razorpay.Client(auth=(RAZORPAY_KEY, RAZORPAY_SECRET))

app = FastAPI(title="Sweezen Foundation API")
api_router = APIRouter(prefix="/api")
security = HTTPBearer(auto_error=False)

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)
APP_START_TIME = time.time()

DEFAULT_SYSTEM_SETTINGS = {
    "maintenanceMode": False,
    "registrationOpen": True,
    "donationsActive": True,
    "fcraEnabled": True,
    "blockchainEnabled": False,
    "razorpayLiveMode": bool(RAZORPAY_ENABLED),
    "allowedAdminIPs": [],
    "featureFlags": {
        "superAdminMFARequired": True,
        "allowPaymentOverride": True,
    },
    "updated_at": "",
    "updated_by": "system",
}

VOLUNTEER_LEVELS = [
    ("Seedling", 0),
    ("Sapling", 200),
    ("Branch", 500),
    ("Wing", 1000),
    ("Eagle", 2500),
]

VOLUNTEER_BADGE_CATALOG = [
    {"badgeId": "first_responder", "name": "First Responder", "rule": "Complete first approved task"},
    {"badgeId": "century_club", "name": "Century Club (100hrs)", "rule": "Log 100 volunteer hours"},
    {"badgeId": "eagle_scout", "name": "Eagle Scout (5 tasks)", "rule": "Complete 5 approved tasks"},
    {"badgeId": "environment_guardian", "name": "Environment Guardian", "rule": "Complete 3 environment tasks"},
    {"badgeId": "education_champion", "name": "Education Champion", "rule": "Complete 3 education tasks"},
    {"badgeId": "humanity_hero", "name": "Humanity Hero (100 scans)", "rule": "Complete 100 Humanity Card scans"},
]

DONOR_TIERS = [
    ("Supporter", 0),
    ("Friend", 10000),
    ("Champion", 50000),
    ("Eagle Patron", 100000),
]

CSR_TIERS = ["Bronze", "Silver", "Gold", "Platinum"]
CSR_COMPANY_SIZES = ["1-50", "51-500", "500-5000", "5000+"]
CSR_KYC_STATUSES = ["pending", "verified", "failed"]
CSR_PROPOSAL_STATUSES = ["draft", "submitted", "under_review", "approved", "rejected"]
CSR_ALLOWED_SDG = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17}
CSR_EARLY_RELEASE_STATUSES = ["pending", "approved", "rejected"]

SELF_REGISTER_ROLES = {"donor", "volunteer", "researcher"}
APPROVAL_REQUIRED_ROLES = {"volunteer", "researcher"}
DUMMY_BCRYPT_HASH = "$2b$12$C6UzMDM.H6dfI/f/IKcEe.OA91cBhA.J2f8M6ya2G6bA4jE7E7VwK"
LOGIN_MAX_ATTEMPTS = int(os.environ.get("LOGIN_MAX_ATTEMPTS", "5"))
LOGIN_LOCK_MINUTES = int(os.environ.get("LOGIN_LOCK_MINUTES", "15"))
MAX_SEARCH_LEN = 60
TRUST_PROXY_HEADERS = os.environ.get("TRUST_PROXY_HEADERS", "false").strip().lower() == "true"
SEED_DEMO_DATA = os.environ.get("SEED_DEMO_DATA", "false").strip().lower() == "true"

# ─── Helpers ───
def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode(), hashed.encode())


def normalize_email(value: str) -> str:
    return (value or "").strip().lower()


def is_valid_email(value: str) -> bool:
    if not value or len(value) > 254:
        return False
    return re.fullmatch(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$", value) is not None


def get_seed_password(env_name: str, fallback_label: str) -> str:
    provided = os.environ.get(env_name, "").strip()
    if provided:
        return provided
    generated = uuid.uuid4().hex + "!Aa1"
    logger.warning("%s not set. Generated one-time seed password for %s account.", env_name, fallback_label)
    return generated

def create_token(user_id: str, role: str) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        'sub': user_id,
        'role': role,
        'iat': int(now.timestamp()),
        'exp': now + timedelta(hours=JWT_EXPIRY_HOURS)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

def decode_token(token: str):
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
        return None

def get_client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for", "")
    if TRUST_PROXY_HEADERS and forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"

def ensure_iso_date(value: str) -> str:
    if not value:
        return ""
    try:
        return datetime.fromisoformat(value).isoformat()
    except ValueError:
        return value


def sanitize_plain_text(value: str, max_len: int = 500) -> str:
    cleaned = re.sub(r"[\x00-\x1F\x7F]", "", (value or ""))
    return cleaned.strip()[:max_len]


def escape_regex_input(value: str, max_len: int = MAX_SEARCH_LEN) -> str:
    safe = sanitize_plain_text(value, max_len)
    return re.escape(safe)


def normalize_csr_tranches(tranches: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    normalized: List[Dict[str, Any]] = []
    if not isinstance(tranches, list):
        return normalized
    for item in tranches[:12]:
        if not isinstance(item, dict):
            continue
        amount = _safe_float(item.get("amount", 0))
        if amount <= 0 or amount > 1_000_000_000:
            continue
        normalized.append({
            "amount": round(amount, 2),
            "releaseDate": ensure_iso_date(str(item.get("releaseDate", ""))),
            "status": sanitize_plain_text(str(item.get("status", "pending")), 30).lower() or "pending",
        })
    return normalized

def compute_level(points: int) -> str:
    current = "Seedling"
    for level, threshold in VOLUNTEER_LEVELS:
        if points >= threshold:
            current = level
    return current

def next_level_info(points: int) -> Dict[str, Any]:
    current = compute_level(points)
    for idx, (level, threshold) in enumerate(VOLUNTEER_LEVELS):
        if level == current:
            if idx == len(VOLUNTEER_LEVELS) - 1:
                return {
                    "current": current,
                    "next": current,
                    "currentThreshold": threshold,
                    "nextThreshold": threshold,
                    "remaining": 0,
                    "progress": 100,
                }
            next_level, next_threshold = VOLUNTEER_LEVELS[idx + 1]
            progress = 0
            span = max(1, next_threshold - threshold)
            progress = min(100, int(((points - threshold) / span) * 100))
            return {
                "current": current,
                "next": next_level,
                "currentThreshold": threshold,
                "nextThreshold": next_threshold,
                "remaining": max(0, next_threshold - points),
                "progress": progress,
            }
    return {
        "current": "Seedling",
        "next": "Sapling",
        "currentThreshold": 0,
        "nextThreshold": 200,
        "remaining": max(0, 200 - points),
        "progress": min(100, int((points / 200) * 100)),
    }

def default_volunteer_profile(data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    now = datetime.now(timezone.utc).isoformat()
    base = {
        "dateOfBirth": "",
        "gender": "",
        "address": "",
        "city": "",
        "district": "",
        "state": "",
        "pincode": "",
        "idDocumentType": "",
        "idDocumentUrl": "",
        "skills": [],
        "languages": [],
        "availability": {
            "daysPerWeek": 0,
            "preferredDays": [],
            "preferredTime": "flexible",
        },
        "preferredCategories": [],
        "totalHoursLogged": 0,
        "impactPoints": 0,
        "currentLevel": "Seedling",
        "badgesEarned": [],
        "certificatesIssued": [],
        "assignedTasks": [],
        "completedTasks": [],
        "savedTasks": [],
        "humanityCardScans": 0,
        "joinedAt": now,
        "lastActiveAt": now,
        "rating": 0,
        "privacyOptOutLeaderboard": False,
    }
    if data:
        for k, v in data.items():
            if k == "availability" and isinstance(v, dict):
                base["availability"] = {
                    **base["availability"],
                    **v,
                }
            elif k in base:
                base[k] = v
    base["impactPoints"] = int(base.get("impactPoints", 0))
    base["totalHoursLogged"] = float(base.get("totalHoursLogged", 0))
    base["currentLevel"] = compute_level(base["impactPoints"])
    return base


def mask_pan(pan_number: str) -> str:
    raw = (pan_number or "").strip().upper()
    if len(raw) < 4:
        return ""
    return raw[-4:]


def compute_donor_tier(total_donated: float) -> str:
    current = "Supporter"
    for tier, threshold in DONOR_TIERS:
        if total_donated >= threshold:
            current = tier
    return current


def next_donor_tier_info(total_donated: float) -> Dict[str, Any]:
    current = compute_donor_tier(total_donated)
    for idx, (tier, threshold) in enumerate(DONOR_TIERS):
        if tier == current:
            if idx == len(DONOR_TIERS) - 1:
                return {
                    "current": current,
                    "next": current,
                    "currentThreshold": threshold,
                    "nextThreshold": threshold,
                    "remaining": 0,
                    "progress": 100,
                }
            next_tier, next_threshold = DONOR_TIERS[idx + 1]
            span = max(1, next_threshold - threshold)
            progress = min(100, int(((total_donated - threshold) / span) * 100))
            return {
                "current": current,
                "next": next_tier,
                "currentThreshold": threshold,
                "nextThreshold": next_threshold,
                "remaining": max(0, next_threshold - total_donated),
                "progress": progress,
            }
    return {
        "current": "Supporter",
        "next": "Friend",
        "currentThreshold": 0,
        "nextThreshold": 10000,
        "remaining": max(0, 10000 - total_donated),
        "progress": min(100, int((total_donated / 10000) * 100)),
    }


def default_donor_profile(data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    base = {
        "panNumber": "",
        "panVerified": False,
        "gstNumber": "",
        "address": "",
        "city": "",
        "state": "",
        "pincode": "",
        "isCorporate": False,
        "companyName": "",
        "cin": "",
        "preferredCategories": [],
        "isAnonymous": False,
        "recurringDonations": [],
        "totalDonated": 0,
        "donationCount": 0,
        "firstDonationAt": "",
        "lastDonationAt": "",
        "donorTier": "Supporter",
    }
    if data:
        for k, v in data.items():
            if k in base:
                base[k] = v
    base["totalDonated"] = float(base.get("totalDonated", 0) or 0)
    base["donationCount"] = int(base.get("donationCount", 0) or 0)
    if not isinstance(base.get("recurringDonations"), list):
        base["recurringDonations"] = []
    base["donorTier"] = compute_donor_tier(base["totalDonated"])
    return base


def default_csr_profile(data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    now = datetime.now(timezone.utc).isoformat()
    base = {
        "companyName": "",
        "cin": "",
        "gstin": "",
        "panNumber": "",
        "industry": "",
        "companySize": "",
        "registeredAddress": "",
        "csrBudgetFY": 0,
        "csrPolicyUrl": "",
        "csrCommitteeNames": [],
        "tier": "Silver",
        "tierAssignedAt": now,
        "partnerSince": now,
        "relationshipManagerId": "",
        "kycStatus": "pending",
        "kycDocuments": [],
        "totalFunded": 0,
        "activeProjects": [],
        "apiKeyEnabled": False,
        "apiKey": "",
    }
    if data:
        for k, v in data.items():
            if k in base:
                base[k] = v
    base["tier"] = base["tier"] if base["tier"] in CSR_TIERS else "Silver"
    base["companySize"] = base["companySize"] if base["companySize"] in CSR_COMPANY_SIZES else ""
    base["kycStatus"] = base["kycStatus"] if base["kycStatus"] in CSR_KYC_STATUSES else "pending"
    base["csrBudgetFY"] = float(base.get("csrBudgetFY", 0) or 0)
    base["totalFunded"] = float(base.get("totalFunded", 0) or 0)
    if not isinstance(base.get("csrCommitteeNames"), list):
        base["csrCommitteeNames"] = []
    if not isinstance(base.get("kycDocuments"), list):
        base["kycDocuments"] = []
    if not isinstance(base.get("activeProjects"), list):
        base["activeProjects"] = []
    return base

def normalize_application(task: Dict[str, Any], user_id: str) -> Optional[Dict[str, Any]]:
    for app in task.get("applied", []):
        if isinstance(app, str) and app == user_id:
            return {
                "volunteer_id": user_id,
                "status": "pending",
                "matched_skills": [],
                "availability": {},
                "message": "",
                "applied_at": task.get("created_at", datetime.now(timezone.utc).isoformat()),
            }
        if isinstance(app, dict):
            aid = app.get("volunteer_id") or app.get("user_id")
            if aid == user_id:
                return {
                    "volunteer_id": aid,
                    "status": app.get("status", "pending"),
                    "matched_skills": app.get("matched_skills", []),
                    "availability": app.get("availability", {}),
                    "message": app.get("message", ""),
                    "applied_at": app.get("applied_at", datetime.now(timezone.utc).isoformat()),
                    "reviewed_at": app.get("reviewed_at", ""),
                    "reviewed_by": app.get("reviewed_by", ""),
                    "admin_rating": app.get("admin_rating", 0),
                }
    return None

def user_assigned_to_task(task: Dict[str, Any], user_id: str) -> bool:
    assigned = task.get("assigned_volunteers", [])
    return user_id in assigned

def user_completed_task(task: Dict[str, Any], user_id: str) -> bool:
    completed = task.get("completed_by", [])
    return user_id in completed

def sanitize_humanity_card_lookup(card_code: str) -> Dict[str, Any]:
    # Privacy-safe placeholder lookup used for development and demos.
    masked = card_code[-4:] if card_code else "0000"
    age_groups = ["Adult (25-45)", "Youth (18-24)", "Senior (60+)"]
    villages = ["Khed, Pune District", "Baramati, Pune District", "Talera, Bundi District"]
    idx = len(card_code or "") % len(age_groups)
    return {
        "ageGroup": age_groups[idx],
        "village": villages[idx],
        "serviceHistory": ["Health screening (x3)", "Education kit (x1)"],
        "humanityCardMasked": masked,
    }


def _parse_date(date_value: str) -> Optional[datetime]:
    if not date_value:
        return None
    try:
        return datetime.fromisoformat(date_value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _compute_age_from_dob(dob_value: str) -> int:
    dob = _parse_date(dob_value)
    if not dob:
        return -1
    today = datetime.now(timezone.utc).date()
    born = dob.date()
    return today.year - born.year - ((today.month, today.day) < (born.month, born.day))


def _valid_id_card_photo(data_url: str) -> bool:
    if not data_url or not isinstance(data_url, str):
        return False
    if not data_url.startswith("data:image/"):
        return False
    return len(data_url) <= 2_500_000


def _normalize_id_card_status(value: str) -> str:
    requested = (value or "").strip().lower()
    if requested in ["approve", "approved"]:
        return "approved"
    if requested in ["reject", "rejected"]:
        return "rejected"
    if requested in ["under_review", "review"]:
        return "under_review"
    return requested


async def generate_volunteer_card_id() -> str:
    year = datetime.now(timezone.utc).year
    count = await db.volunteer_id_cards.count_documents({
        "card_status": {"$in": ["approved", "expired", "revoked"]},
        "generated_card.year": year,
    })
    sequence = str(count + 1).zfill(6)
    return f"SWZ-VOL-{year}-{sequence}"

async def get_system_settings() -> Dict[str, Any]:
    settings = await db.system_settings.find_one({"id": "global"}, {"_id": 0})
    if settings:
        return settings
    initial = {
        "id": "global",
        **DEFAULT_SYSTEM_SETTINGS,
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "updated_by": "system",
    }
    await db.system_settings.insert_one(initial)
    return initial

async def write_audit_log(actor: Dict[str, Any], action: str, target_id: str = "", target_type: str = "", details: Optional[Dict[str, Any]] = None, ip: str = "unknown"):
    await db.admin_audit_logs.insert_one({
        "id": str(uuid.uuid4()),
        "actor_id": actor.get("id", "system"),
        "actor_email": actor.get("email", "system"),
        "actor_role": actor.get("role", "system"),
        "action": action,
        "target_id": target_id,
        "target_type": target_type,
        "details": details or {},
        "ip": ip,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    if not credentials:
        raise HTTPException(status_code=401, detail="Not authenticated")
    payload = decode_token(credentials.credentials)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    user = await db.users.find_one({"id": payload['sub']}, {"_id": 0, "password_hash": 0})
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    if user.get("status") != "active":
        raise HTTPException(status_code=401, detail="Session invalid for inactive account")
    token_invalid_before = user.get("token_invalid_before")
    if token_invalid_before:
        try:
            invalid_after = int(datetime.fromisoformat(token_invalid_before).timestamp())
            if payload.get("iat", 0) <= invalid_after:
                raise HTTPException(status_code=401, detail="Session revoked. Please login again.")
        except ValueError:
            pass
    return user

async def require_admin(user=Depends(get_current_user)):
    if user.get('role') not in ['admin', 'super_admin']:
        raise HTTPException(status_code=403, detail="Admin access required")
    return user

async def require_super_admin(request: Request, user=Depends(get_current_user)):
    if user.get("role") != "super_admin":
        raise HTTPException(status_code=403, detail="Super admin access required")
    settings = await get_system_settings()
    allowed = settings.get("allowedAdminIPs", [])
    if allowed:
        ip = get_client_ip(request)
        if ip not in allowed and ip != "127.0.0.1" and ip != "::1":
            raise HTTPException(status_code=403, detail="IP is not whitelisted for super admin access")
    return user

async def require_csr(user=Depends(get_current_user)):
    if user.get('role') not in ['admin', 'super_admin', 'csr_partner']:
        raise HTTPException(status_code=403, detail="CSR access required")
    return user


async def require_csr_partner(user=Depends(get_current_user)):
    if user.get("role") != "csr_partner":
        raise HTTPException(status_code=403, detail="CSR partner access required")
    return user


async def require_donor(user=Depends(get_current_user)):
    if user.get("role") not in ["donor", "admin", "super_admin"]:
        raise HTTPException(status_code=403, detail="Donor access required")
    return user


async def require_volunteer_or_admin(user=Depends(get_current_user)):
    if user.get("role") not in ["volunteer", "admin", "super_admin"]:
        raise HTTPException(status_code=403, detail="Volunteer access required")
    return user


async def require_volunteer_or_admin(user=Depends(get_current_user)):
    if user.get("role") not in ["volunteer", "admin", "super_admin"]:
        raise HTTPException(status_code=403, detail="Volunteer access required")
    return user

# ─── Models ───
class RegisterInput(BaseModel):
    name: str
    email: str
    password: str
    phone: Optional[str] = ""
    role: Optional[str] = "donor"

class LoginInput(BaseModel):
    email: str
    password: str

class ProjectCreate(BaseModel):
    title: str
    description: str
    category: str  # healthcare, education, environment
    location: str = ""
    budget: float = 0
    raised: float = 0
    beneficiary_count: int = 0
    status: str = "active"
    image_url: str = ""
    milestones: list = []

class ProjectUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    category: Optional[str] = None
    location: Optional[str] = None
    budget: Optional[float] = None
    raised: Optional[float] = None
    beneficiary_count: Optional[int] = None
    status: Optional[str] = None
    image_url: Optional[str] = None
    milestones: Optional[list] = None

class DonationCreate(BaseModel):
    donor_name: str
    donor_email: str
    donor_phone: str = ""
    donor_pan: str = ""
    amount: float
    project_id: Optional[str] = None
    is_recurring: bool = False

class DonationVerify(BaseModel):
    order_id: str
    payment_id: str = ""
    signature: str = ""


class DonorProfileUpdateInput(BaseModel):
    panNumber: str = ""
    gstNumber: str = ""
    address: str = ""
    city: str = ""
    state: str = ""
    pincode: str = ""
    isCorporate: bool = False
    companyName: str = ""
    cin: str = ""
    preferredCategories: List[str] = []
    isAnonymous: bool = False


class RecurringDonationCreateInput(BaseModel):
    projectId: str = ""
    amount: float
    frequency: str = "monthly"


class RecurringDonationUpdateInput(BaseModel):
    amount: Optional[float] = None
    frequency: Optional[str] = None
    status: Optional[str] = None

class PublicationCreate(BaseModel):
    title: str
    content: str
    type: str = "blog"  # blog, news, report
    image_url: str = ""
    published: bool = True

class ContactCreate(BaseModel):
    name: str
    email: str
    phone: str = ""
    subject: str
    message: str

class NewsletterSubscribe(BaseModel):
    email: str

class CSRPartnerCreate(BaseModel):
    company_name: str
    contact_person: str
    email: str
    phone: str = ""
    tier: str = "silver"
    funds_committed: float = 0
    project_ids: list = []


class CsrProfileUpdateInput(BaseModel):
    companyName: str
    cin: str = ""
    gstin: str = ""
    panNumber: str = ""
    industry: str = ""
    companySize: str = ""
    registeredAddress: str = ""
    csrBudgetFY: float = 0
    csrPolicyUrl: str = ""
    csrCommitteeNames: List[str] = []
    tier: str = "Silver"
    relationshipManagerId: str = ""
    kycStatus: str = "pending"
    kycDocuments: List[Dict[str, Any]] = []


class CsrProposalCreateInput(BaseModel):
    projectId: str
    proposedAmount: float
    tranches: List[Dict[str, Any]] = []
    sdgAlignment: List[int] = []
    businessObjectives: str = ""
    expectedCompletionDate: str = ""
    geographicalFocusArea: str = ""


class CsrProposalStatusUpdateInput(BaseModel):
    status: str


class CsrEarlyReleaseRequestInput(BaseModel):
    tranche_name: str
    requested_amount: Optional[float] = None
    reason: str


class CsrEarlyReleaseReviewInput(BaseModel):
    status: str
    admin_notes: str = ""

class RoleUpdate(BaseModel):
    role: str

class VolunteerTaskCreate(BaseModel):
    title: str
    description: str
    category: str = "general"
    location: str = ""
    date: str = ""
    hours_required: int = 4
    skills_needed: list = []
    max_volunteers: int = 10

class HoursLog(BaseModel):
    task_id: str
    hours: float
    notes: str = ""

class VolunteerTaskApplicationInput(BaseModel):
    matched_skills: List[str] = []
    availability_start: str = ""
    availability_end: str = ""
    message: str = ""

class VolunteerTaskLogInput(BaseModel):
    date_worked: str
    hours: float
    activity_type: str
    description: str
    evidence_photos: List[str] = []
    location_name: str = ""
    geo_lat: Optional[float] = None
    geo_lng: Optional[float] = None

class VolunteerTaskSubmitInput(BaseModel):
    final_note: str = ""

class HumanityCardScanInput(BaseModel):
    card_code: str
    service_type: str
    service_subtype: str
    notes: str = ""
    quantity: int = 1
    photo_url: str = ""
    geo_lat: Optional[float] = None
    geo_lng: Optional[float] = None


class VolunteerIdCardApplyInput(BaseModel):
    photo_data_url: str
    full_name: str
    date_of_birth: str
    phone: str
    address: str
    education: str = ""
    gender: str = ""
    emergency_contact_name: str = ""
    emergency_contact_phone: str = ""


class VolunteerIdCardReviewInput(BaseModel):
    status: str
    rejection_reason: str = ""
    admin_notes: str = ""

class VolunteerApplicationReviewInput(BaseModel):
    status: str
    feedback: str = ""
    admin_rating: Optional[float] = None


class MilestoneCreateInput(BaseModel):
    name: str
    target_date: str = ""


class MilestoneUpdateInput(BaseModel):
    name: Optional[str] = None
    target_date: Optional[str] = None
    status: Optional[str] = None
    evidence_url: Optional[str] = None
    admin_note: Optional[str] = None

class UserApproval(BaseModel):
    status: str  # approved, rejected
    reason: str = ""


class BulkUserActionInput(BaseModel):
    action: str
    user_ids: List[str]
    reason: str = ""

class SystemSettingsUpdate(BaseModel):
    maintenanceMode: Optional[bool] = None
    registrationOpen: Optional[bool] = None
    donationsActive: Optional[bool] = None
    fcraEnabled: Optional[bool] = None
    blockchainEnabled: Optional[bool] = None
    razorpayLiveMode: Optional[bool] = None
    allowedAdminIPs: Optional[List[str]] = None

class CreateAdminInput(BaseModel):
    name: str
    email: str
    password: str = Field(min_length=6)
    phone: str = ""

class DonationStatusOverride(BaseModel):
    status: str
    reason: str

class EnhancedRegister(BaseModel):
    name: str
    email: str
    password: str
    phone: str = ""
    role: str = "donor"
    # Role-specific
    skills: list = []
    availability: str = ""
    pan_number: str = ""
    affiliation: str = ""
    purpose: str = ""

# ─── AUTH ROUTES ───
@api_router.post("/auth/register")
async def register(data: EnhancedRegister):
    settings = await get_system_settings()
    if not settings.get("registrationOpen", True):
        raise HTTPException(status_code=503, detail="Registrations are temporarily disabled")
    email = normalize_email(data.email)
    if not is_valid_email(email):
        raise HTTPException(status_code=400, detail="Invalid email address")
    safe_name = sanitize_plain_text(data.name, 120)
    if len(safe_name) < 2:
        raise HTTPException(status_code=400, detail="Name must be at least 2 characters")
    if len((data.password or "")) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters")
    existing = await db.users.find_one({"email": email}, {"_id": 0})
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    user_id = str(uuid.uuid4())
    requested_role = (data.role or "donor").strip().lower()
    role = requested_role if requested_role in SELF_REGISTER_ROLES else "donor"
    needs_approval = role in APPROVAL_REQUIRED_ROLES

    if role == "volunteer" and not data.skills:
        raise HTTPException(status_code=400, detail="Please add at least one skill for volunteer registration")

    if role == "researcher":
        if not (data.affiliation or "").strip():
            raise HTTPException(status_code=400, detail="Institutional affiliation is required for researcher registration")
        if not (data.purpose or "").strip():
            raise HTTPException(status_code=400, detail="Research purpose is required for researcher registration")
    user = {
        "id": user_id, "name": safe_name, "email": email,
        "password_hash": hash_password(data.password),
        "phone": sanitize_plain_text(data.phone, 30), "role": role,
        "status": "pending" if needs_approval else "active",
        "skills": data.skills, "availability": data.availability,
        "pan_number": data.pan_number, "affiliation": data.affiliation,
        "purpose": data.purpose, "impact_points": 0, "hours_logged": 0,
        "badges": [], "created_at": datetime.now(timezone.utc).isoformat()
    }
    if role == "volunteer":
        user["volunteerProfile"] = default_volunteer_profile({
            "skills": data.skills or [],
            "availability": {
                "preferredTime": data.availability if data.availability else "flexible",
            },
            "joinedAt": datetime.now(timezone.utc).isoformat(),
            "lastActiveAt": datetime.now(timezone.utc).isoformat(),
        })
    if role == "donor":
        user["donorProfile"] = default_donor_profile({
            "panNumber": data.pan_number.upper().strip() if data.pan_number else "",
            "panVerified": bool(data.pan_number),
        })
    await db.users.insert_one(user)
    if needs_approval:
        await db.notifications.insert_one({
            "id": str(uuid.uuid4()), "user_id": "admin", "type": "user_approval",
            "title": f"New {role} registration: {data.name}",
            "message": f"{data.name} ({email}) has registered as {role} and needs approval.",
            "ref_id": user_id, "read": False,
            "created_at": datetime.now(timezone.utc).isoformat()
        })
        return {
            "message": "Registration submitted. Your account is pending admin approval.",
            "status": "pending",
            "approval_required": True,
            "user": {"id": user_id, "name": data.name, "email": email, "role": role, "status": "pending"},
        }
    token = create_token(user_id, user["role"])
    return {
        "token": token,
        "approval_required": False,
        "user": {"id": user_id, "name": data.name, "email": email, "role": user["role"], "status": "active"},
    }

@api_router.post("/auth/login")
async def login(data: LoginInput):
    email = normalize_email(data.email)
    if not is_valid_email(email):
        raise HTTPException(status_code=400, detail="Invalid credentials")
    user = await db.users.find_one({"email": email}, {"_id": 0})

    now = datetime.now(timezone.utc)
    if user and user.get("lock_until"):
        try:
            lock_until = datetime.fromisoformat(user["lock_until"])
            if now < lock_until:
                raise HTTPException(status_code=429, detail="Too many failed attempts. Try again later.")
        except ValueError:
            pass

    hash_to_check = user.get("password_hash") if user and user.get("password_hash") else DUMMY_BCRYPT_HASH
    password_ok = verify_password(data.password, hash_to_check)
    if not user or not password_ok:
        if user:
            attempts = int(user.get("login_attempts", 0)) + 1
            patch = {"login_attempts": attempts}
            if attempts >= LOGIN_MAX_ATTEMPTS:
                patch["lock_until"] = (now + timedelta(minutes=LOGIN_LOCK_MINUTES)).isoformat()
            await db.users.update_one({"id": user["id"]}, {"$set": patch})
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if user.get("status") == "pending":
        raise HTTPException(status_code=403, detail="Account pending approval. You will be notified once approved.")
    if user.get("status") == "rejected":
        raise HTTPException(status_code=403, detail="Account has been rejected. Please contact support.")
    if user.get("status") == "suspended":
        raise HTTPException(status_code=403, detail="Account is suspended. Please contact support.")

    await db.users.update_one(
        {"id": user["id"]},
        {"$set": {"login_attempts": 0, "lock_until": "", "last_login_at": now.isoformat()}},
    )
    token = create_token(user["id"], user["role"])
    return {"token": token, "user": {"id": user["id"], "name": user["name"], "email": user["email"], "role": user["role"], "status": user.get("status", "active")}}

@api_router.get("/auth/me")
async def get_me(user=Depends(get_current_user)):
    return {"user": user}

# ─── PROJECT ROUTES ───
@api_router.get("/projects")
async def list_projects(category: Optional[str] = None, status: Optional[str] = None):
    query = {}
    if category:
        query["category"] = category
    if status:
        query["status"] = status
    projects = await db.projects.find(query, {"_id": 0}).sort("created_at", -1).to_list(100)
    return {"projects": projects}

@api_router.get("/projects/{project_id}")
async def get_project(project_id: str):
    project = await db.projects.find_one({"id": project_id}, {"_id": 0})
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    return {"project": project}

@api_router.post("/projects")
async def create_project(data: ProjectCreate, user=Depends(require_admin)):
    project = {
        "id": str(uuid.uuid4()), **data.model_dump(),
        "created_by": user["id"],
        "created_at": datetime.now(timezone.utc).isoformat(),
        "updated_at": datetime.now(timezone.utc).isoformat()
    }
    await db.projects.insert_one(project)
    created = await db.projects.find_one({"id": project["id"]}, {"_id": 0})
    return {"project": created}

@api_router.put("/projects/{project_id}")
async def update_project(project_id: str, data: ProjectUpdate, user=Depends(require_admin)):
    update_data = {k: v for k, v in data.model_dump().items() if v is not None}
    update_data["updated_at"] = datetime.now(timezone.utc).isoformat()
    result = await db.projects.update_one({"id": project_id}, {"$set": update_data})
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Project not found")
    updated = await db.projects.find_one({"id": project_id}, {"_id": 0})
    return {"project": updated}

@api_router.delete("/projects/{project_id}")
async def delete_project(project_id: str, user=Depends(require_admin)):
    result = await db.projects.delete_one({"id": project_id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Project not found")
    return {"message": "Project deleted"}

# ─── DONATION ROUTES ───
@api_router.post("/donations/create-order")
async def create_donation_order(data: DonationCreate, credentials: HTTPAuthorizationCredentials = Depends(security)):
    settings = await get_system_settings()
    if not settings.get("donationsActive", True):
        raise HTTPException(status_code=503, detail="Donations are temporarily disabled")
    if data.amount <= 0:
        raise HTTPException(status_code=400, detail="Donation amount must be greater than zero")
    donor_user = None
    if credentials:
        payload = decode_token(credentials.credentials)
        if payload and payload.get("sub"):
            donor_user = await db.users.find_one({"id": payload["sub"]}, {"_id": 0, "password_hash": 0})

    if donor_user and donor_user.get("role") == "donor":
        if donor_user.get("email") != data.donor_email:
            raise HTTPException(status_code=403, detail="Authenticated donor can only donate using their own email")

    # Use stored donor PAN when available so donor users do not need to re-enter it every time.
    effective_pan = (data.donor_pan or "").strip().upper()
    if donor_user and donor_user.get("role") == "donor":
        donor_profile = default_donor_profile(donor_user.get("donorProfile", {}))
        if not effective_pan:
            effective_pan = (donor_profile.get("panNumber", "") or "").strip().upper()

    if data.amount >= 10000 and not effective_pan:
        raise HTTPException(status_code=400, detail="PAN is required for donations of Rs 10,000 or above")

    donation_id = str(uuid.uuid4())
    order_id = f"order_mock_{donation_id[:12]}"
    razorpay_order = None

    if RAZORPAY_ENABLED:
        try:
            razorpay_order = razorpay_client.order.create({
                "amount": int(data.amount * 100),
                "currency": "INR",
                "payment_capture": 1,
                "receipt": f"don_{donation_id[:8]}"
            })
            order_id = razorpay_order['id']
        except Exception as e:
            logger.error(f"Razorpay order creation failed: {e}")

    donation = {
        "id": donation_id, "order_id": order_id,
        "donor_id": donor_user.get("id", "") if donor_user else "",
        "donor_name": data.donor_name, "donor_email": data.donor_email,
        "donor_phone": data.donor_phone, "donor_pan": effective_pan,
        "amount": data.amount, "project_id": data.project_id,
        "is_recurring": data.is_recurring, "status": "created",
        "currency": "INR",
        "is80G": True,
        "isFcra": bool(settings.get("fcraEnabled", True)),
        "payment_id": "", "receipt_number": f"SF-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{donation_id[:6].upper()}",
        "receipt_url": "",
        "receipt_sent_at": "",
        "pan_last4": mask_pan(effective_pan),
        "razorpay_mode": RAZORPAY_ENABLED,
        "created_at": datetime.now(timezone.utc).isoformat()
    }
    await db.donations.insert_one(donation)
    return {
        "donation_id": donation_id, "order_id": order_id,
        "amount": data.amount, "razorpay_enabled": RAZORPAY_ENABLED,
        "razorpay_key": RAZORPAY_KEY if RAZORPAY_ENABLED else None
    }

@api_router.post("/donations/verify")
async def verify_donation(data: DonationVerify):
    donation = await db.donations.find_one({"order_id": data.order_id}, {"_id": 0})
    if not donation:
        raise HTTPException(status_code=404, detail="Donation not found")

    if RAZORPAY_ENABLED and data.payment_id and data.signature:
        try:
            razorpay_client.utility.verify_payment_signature({
                'razorpay_order_id': data.order_id,
                'razorpay_payment_id': data.payment_id,
                'razorpay_signature': data.signature
            })
        except Exception:
            await db.donations.update_one({"order_id": data.order_id}, {"$set": {"status": "failed"}})
            raise HTTPException(status_code=400, detail="Payment verification failed")

    completed_at = datetime.now(timezone.utc).isoformat()
    await db.donations.update_one(
        {"order_id": data.order_id},
        {"$set": {
            "status": "completed",
            "payment_id": data.payment_id or f"pay_mock_{uuid.uuid4().hex[:12]}",
            "razorpay_payment_id": data.payment_id or "",
            "verified_at": completed_at,
            "receipt_url": f"/api/donor/receipts/{donation.get('id', '')}/download",
        }}
    )

    # Update project raised amount
    if donation.get("project_id"):
        await db.projects.update_one(
            {"id": donation["project_id"]},
            {"$inc": {"raised": donation["amount"]}}
        )

    updated = await db.donations.find_one({"order_id": data.order_id}, {"_id": 0})

    donor_user = None
    if updated.get("donor_id"):
        donor_user = await db.users.find_one({"id": updated.get("donor_id")}, {"_id": 0})
    if not donor_user:
        donor_user = await db.users.find_one({"email": updated.get("donor_email", ""), "role": "donor"}, {"_id": 0})

    if donor_user:
        donor_profile = default_donor_profile(donor_user.get("donorProfile", {}))
        donor_profile["totalDonated"] = float(donor_profile.get("totalDonated", 0)) + float(updated.get("amount", 0))
        donor_profile["donationCount"] = int(donor_profile.get("donationCount", 0)) + 1
        if not donor_profile.get("firstDonationAt"):
            donor_profile["firstDonationAt"] = completed_at
        donor_profile["lastDonationAt"] = completed_at
        if updated.get("donor_pan") and not donor_profile.get("panNumber"):
            donor_profile["panNumber"] = updated.get("donor_pan", "").upper().strip()
            donor_profile["panVerified"] = True
        if updated.get("is_recurring"):
            recurring = donor_profile.get("recurringDonations", [])
            recurring.append({
                "razorpaySubId": f"sub_mock_{updated.get('id', '')[:10]}",
                "projectId": updated.get("project_id", ""),
                "amount": float(updated.get("amount", 0)),
                "frequency": "monthly",
                "status": "active",
                "nextChargeDate": (datetime.now(timezone.utc) + timedelta(days=30)).isoformat(),
            })
            donor_profile["recurringDonations"] = recurring
        donor_profile["donorTier"] = compute_donor_tier(float(donor_profile.get("totalDonated", 0)))
        await db.users.update_one(
            {"id": donor_user["id"]},
            {
                "$set": {
                    "donorProfile": donor_profile,
                }
            },
        )

    return {"donation": updated, "message": "Payment verified successfully"}

@api_router.get("/donations")
async def list_donations(user=Depends(require_admin)):
    donations = await db.donations.find({}, {"_id": 0}).sort("created_at", -1).to_list(500)
    return {"donations": donations}

@api_router.get("/donations/my")
async def my_donations(user=Depends(get_current_user)):
    donations = await db.donations.find({"donor_email": user["email"]}, {"_id": 0}).sort("created_at", -1).to_list(100)
    return {"donations": donations}

# ─── PUBLICATION ROUTES ───
@api_router.get("/publications")
async def list_publications(type: Optional[str] = None):
    query = {"published": True}
    if type:
        query["type"] = type
    pubs = await db.publications.find(query, {"_id": 0}).sort("created_at", -1).to_list(100)
    return {"publications": pubs}

@api_router.get("/publications/{pub_id}")
async def get_publication(pub_id: str):
    pub = await db.publications.find_one({"id": pub_id}, {"_id": 0})
    if not pub:
        raise HTTPException(status_code=404, detail="Publication not found")
    return {"publication": pub}

@api_router.post("/publications")
async def create_publication(data: PublicationCreate, user=Depends(require_admin)):
    pub = {
        "id": str(uuid.uuid4()), **data.model_dump(),
        "author_id": user["id"], "author_name": user["name"],
        "created_at": datetime.now(timezone.utc).isoformat(),
        "updated_at": datetime.now(timezone.utc).isoformat()
    }
    await db.publications.insert_one(pub)
    created = await db.publications.find_one({"id": pub["id"]}, {"_id": 0})
    return {"publication": created}

@api_router.put("/publications/{pub_id}")
async def update_publication(pub_id: str, data: PublicationCreate, user=Depends(require_admin)):
    update_data = data.model_dump()
    update_data["updated_at"] = datetime.now(timezone.utc).isoformat()
    result = await db.publications.update_one({"id": pub_id}, {"$set": update_data})
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Publication not found")
    updated = await db.publications.find_one({"id": pub_id}, {"_id": 0})
    return {"publication": updated}

@api_router.delete("/publications/{pub_id}")
async def delete_publication(pub_id: str, user=Depends(require_admin)):
    result = await db.publications.delete_one({"id": pub_id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Publication not found")
    return {"message": "Publication deleted"}

# ─── CONTACT ROUTES ───
@api_router.post("/contact")
async def submit_contact(data: ContactCreate):
    contact = {
        "id": str(uuid.uuid4()), **data.model_dump(),
        "status": "new",
        "created_at": datetime.now(timezone.utc).isoformat()
    }
    await db.contacts.insert_one(contact)
    return {"message": "Message sent successfully", "id": contact["id"]}

@api_router.get("/contact")
async def list_contacts(user=Depends(require_admin)):
    contacts = await db.contacts.find({}, {"_id": 0}).sort("created_at", -1).to_list(200)
    return {"contacts": contacts}

# ─── NEWSLETTER ───
@api_router.post("/newsletter/subscribe")
async def subscribe_newsletter(data: NewsletterSubscribe):
    existing = await db.newsletter_subscribers.find_one({"email": data.email})
    if existing:
        return {"message": "Already subscribed"}
    sub = {"id": str(uuid.uuid4()), "email": data.email, "subscribed_at": datetime.now(timezone.utc).isoformat()}
    await db.newsletter_subscribers.insert_one(sub)
    return {"message": "Subscribed successfully"}

# ─── STATS / TRANSPARENCY ───
@api_router.get("/stats")
async def get_stats():
    project_count = await db.projects.count_documents({"status": "active"})
    total_donations = await db.donations.count_documents({"status": "completed"})
    donation_pipeline = [{"$match": {"status": "completed"}}, {"$group": {"_id": None, "total": {"$sum": "$amount"}}}]
    donation_sum = await db.donations.aggregate(donation_pipeline).to_list(1)
    total_raised = donation_sum[0]["total"] if donation_sum else 0
    volunteer_count = await db.users.count_documents({"role": "volunteer"})
    beneficiary_pipeline = [{"$group": {"_id": None, "total": {"$sum": "$beneficiary_count"}}}]
    beneficiary_sum = await db.projects.aggregate(beneficiary_pipeline).to_list(1)
    total_beneficiaries = beneficiary_sum[0]["total"] if beneficiary_sum else 0
    return {
        "active_projects": project_count, "total_donations": total_donations,
        "total_raised": total_raised, "volunteers": volunteer_count,
        "beneficiaries_reached": total_beneficiaries, "districts_covered": 12
    }

@api_router.get("/transparency/impact")
async def get_impact_data():
    projects = await db.projects.find({}, {"_id": 0}).to_list(100)
    category_stats = {}
    for p in projects:
        cat = p.get("category", "other")
        if cat not in category_stats:
            category_stats[cat] = {"count": 0, "budget": 0, "raised": 0, "beneficiaries": 0}
        category_stats[cat]["count"] += 1
        category_stats[cat]["budget"] += p.get("budget", 0)
        category_stats[cat]["raised"] += p.get("raised", 0)
        category_stats[cat]["beneficiaries"] += p.get("beneficiary_count", 0)

    monthly_donations = await db.donations.aggregate([
        {"$match": {"status": "completed"}},
        {"$addFields": {"month": {"$substr": ["$created_at", 0, 7]}}},
        {"$group": {"_id": "$month", "total": {"$sum": "$amount"}, "count": {"$sum": 1}}},
        {"$sort": {"_id": 1}}, {"$limit": 12}
    ]).to_list(12)

    return {
        "category_stats": category_stats,
        "monthly_donations": [{"month": d["_id"], "total": d["total"], "count": d["count"]} for d in monthly_donations],
        "fund_utilization": {
            "healthcare": {"allocated": 2500000, "utilized": 1850000},
            "education": {"allocated": 2000000, "utilized": 1420000},
            "environment": {"allocated": 1500000, "utilized": 980000}
        }
    }

# ─── ADMIN ROUTES ───
@api_router.get("/admin/users")
async def list_users(user=Depends(require_admin)):
    users = await db.users.find({}, {"_id": 0, "password_hash": 0}).sort("created_at", -1).to_list(500)
    return {"users": users}

@api_router.put("/admin/users/{user_id}/role")
async def update_user_role(user_id: str, data: RoleUpdate, request: Request, admin=Depends(require_admin)):
    if data.role not in ["donor", "volunteer", "editor", "csr_partner", "admin", "super_admin"]:
        raise HTTPException(status_code=400, detail="Invalid role")
    if data.role in ["admin", "super_admin"] and admin.get("role") != "super_admin":
        raise HTTPException(status_code=403, detail="Only super admin can assign admin roles")
    if data.role == "super_admin":
        current_count = await db.users.count_documents({"role": "super_admin"})
        target_user = await db.users.find_one({"id": user_id}, {"_id": 0, "role": 1})
        target_role = target_user.get("role") if target_user else ""
        if target_role != "super_admin" and current_count >= 3:
            raise HTTPException(status_code=400, detail="Maximum 3 super admin accounts allowed")
    result = await db.users.update_one({"id": user_id}, {"$set": {"role": data.role}})
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="User not found")
    await write_audit_log(
        admin,
        "changed_user_role",
        target_id=user_id,
        target_type="user",
        details={"new_role": data.role},
        ip=get_client_ip(request),
    )
    return {"message": "Role updated"}

@api_router.delete("/admin/users/{user_id}")
async def delete_user(user_id: str, request: Request, admin=Depends(require_admin)):
    if user_id == admin["id"]:
        raise HTTPException(status_code=400, detail="Cannot delete yourself")
    target = await db.users.find_one({"id": user_id}, {"_id": 0, "email": 1, "role": 1})
    if target and target.get("role") == "super_admin" and admin.get("role") != "super_admin":
        raise HTTPException(status_code=403, detail="Only super admin can delete super admin accounts")
    result = await db.users.delete_one({"id": user_id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="User not found")
    await write_audit_log(
        admin,
        "deleted_user",
        target_id=user_id,
        target_type="user",
        details={"target_email": target.get("email", "") if target else ""},
        ip=get_client_ip(request),
    )
    return {"message": "User deleted"}

@api_router.get("/admin/analytics")
async def admin_analytics(user=Depends(require_admin)):
    total_users = await db.users.count_documents({})
    total_donors = await db.users.count_documents({"role": "donor"})
    total_volunteers = await db.users.count_documents({"role": "volunteer"})
    total_projects = await db.projects.count_documents({})
    active_projects = await db.projects.count_documents({"status": "active"})
    total_donations_count = await db.donations.count_documents({"status": "completed"})
    donation_sum = await db.donations.aggregate([
        {"$match": {"status": "completed"}},
        {"$group": {"_id": None, "total": {"$sum": "$amount"}}}
    ]).to_list(1)
    total_raised = donation_sum[0]["total"] if donation_sum else 0
    total_contacts = await db.contacts.count_documents({})
    total_subscribers = await db.newsletter_subscribers.count_documents({})
    recent_donations = await db.donations.find({"status": "completed"}, {"_id": 0}).sort("created_at", -1).to_list(10)
    recent_contacts = await db.contacts.find({}, {"_id": 0}).sort("created_at", -1).to_list(5)
    return {
        "total_users": total_users, "total_donors": total_donors, "total_volunteers": total_volunteers,
        "total_projects": total_projects, "active_projects": active_projects,
        "total_donations": total_donations_count, "total_raised": total_raised,
        "total_contacts": total_contacts, "total_subscribers": total_subscribers,
        "recent_donations": recent_donations, "recent_contacts": recent_contacts
    }

# ─── ENHANCED ADMIN DASHBOARD ───
@api_router.get("/admin/dashboard")
async def admin_dashboard(user=Depends(require_admin)):
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    pending_users = await db.users.count_documents({"status": "pending"})
    # volunteer task applications: tasks where anyone applied but status pending
    all_tasks = await db.tasks.find({"applied": {"$exists": True, "$ne": []}}, {"_id": 0, "applied": 1}).to_list(500)
    pending_vol_apps = sum(len([a for a in t.get("applied", []) if isinstance(a, dict) and a.get("status") == "pending"]) for t in all_tasks)
    pending_csr = await db.csr_partners.count_documents({"status": "pending"})
    pending_csr_early_release = await db.csr_early_release_requests.count_documents({"status": "pending"})
    unread_contacts = await db.contacts.count_documents({"status": "new"})

    today_donation_pipeline = [
        {"$match": {"status": "completed", "created_at": {"$gte": today}}},
        {"$group": {"_id": None, "total": {"$sum": "$amount"}, "count": {"$sum": 1}}}
    ]
    td = await db.donations.aggregate(today_donation_pipeline).to_list(1)
    today_donations = td[0] if td else {"total": 0, "count": 0}
    today_registrations = await db.users.count_documents({"created_at": {"$gte": today}})
    active_volunteers = await db.users.count_documents({"role": "volunteer", "status": "active"})
    on_track_projects = await db.projects.count_documents({"status": "active"})

    recent_donations = await db.donations.find({"status": "completed"}, {"_id": 0}).sort("created_at", -1).to_list(10)
    activity_logs = await db.admin_audit_logs.find({}, {"_id": 0}).sort("timestamp", -1).to_list(20)

    projects = await db.projects.find({}, {"_id": 0}).to_list(100)
    kanban = {"planning": [], "active": [], "near_deadline": [], "completed": []}
    for p in projects:
        ms = p.get("milestones", [])
        all_done = all(m.get("status") == "completed" for m in ms) if ms else False
        if p.get("status") == "completed" or all_done:
            kanban["completed"].append(p)
        elif p.get("status") == "active":
            raised_pct = (p.get("raised", 0) / p["budget"] * 100) if p.get("budget", 0) > 0 else 0
            if raised_pct >= 80:
                kanban["near_deadline"].append(p)
            else:
                kanban["active"].append(p)
        else:
            kanban["planning"].append(p)

    return {
        "urgent": {
            "pending_users": pending_users,
            "pending_volunteer_apps": pending_vol_apps,
            "pending_csr": pending_csr,
            "pending_csr_early_release": pending_csr_early_release,
            "unread_contacts": unread_contacts,
        },
        "today": {
            "donations_amount": today_donations.get("total", 0),
            "donations_count": today_donations.get("count", 0),
            "new_registrations": today_registrations,
            "active_volunteers": active_volunteers,
            "projects_on_track": on_track_projects,
        },
        "recent_donations": recent_donations,
        "activity_feed": activity_logs,
        "kanban": kanban,
    }

# ─── ENHANCED ADMIN USER MANAGEMENT ───
@api_router.get("/admin/users/search")
async def search_users(
    role: Optional[str] = None,
    status: Optional[str] = None,
    q: Optional[str] = None,
    page: int = 1,
    limit: int = 50,
    user=Depends(require_admin)
):
    query: Dict[str, Any] = {}
    safe_page = max(1, int(page or 1))
    safe_limit = min(100, max(1, int(limit or 50)))
    if role and role != "all":
        query["role"] = role
    if status and status != "all":
        query["status"] = status
    if q:
        q_escaped = escape_regex_input(q, MAX_SEARCH_LEN)
        query["$or"] = [
            {"name": {"$regex": q_escaped, "$options": "i"}},
            {"email": {"$regex": q_escaped, "$options": "i"}},
        ]
    skip = (safe_page - 1) * safe_limit
    total = await db.users.count_documents(query)
    users = await db.users.find(query, {"_id": 0, "password_hash": 0}).sort("created_at", -1).skip(skip).limit(safe_limit).to_list(safe_limit)
    return {"users": users, "total": total, "page": safe_page, "pages": (total + safe_limit - 1) // safe_limit}

@api_router.get("/admin/users/{user_id}/profile")
async def get_user_profile(user_id: str, admin=Depends(require_admin)):
    target = await db.users.find_one({"id": user_id}, {"_id": 0, "password_hash": 0})
    if not target:
        raise HTTPException(status_code=404, detail="User not found")
    donations = []
    tasks_applied = []
    audit_trail = []
    if target.get("role") == "donor":
        donations = await db.donations.find({"donor_email": target.get("email", "")}, {"_id": 0}).sort("created_at", -1).to_list(50)
    if target.get("role") == "volunteer":
        all_tasks = await db.tasks.find({}, {"_id": 0}).to_list(200)
        for t in all_tasks:
            for a in t.get("applied", []):
                if isinstance(a, dict) and a.get("user_id") == user_id:
                    tasks_applied.append({**t, "application": a})
                    break
    audit_trail = await db.admin_audit_logs.find({"target_id": user_id}, {"_id": 0}).sort("timestamp", -1).to_list(30)
    return {"user": target, "donations": donations, "tasks": tasks_applied, "audit_trail": audit_trail}

@api_router.put("/admin/users/{user_id}/suspend")
async def suspend_user(user_id: str, request: Request, admin=Depends(require_admin)):
    target = await db.users.find_one({"id": user_id}, {"_id": 0, "status": 1, "role": 1})
    if not target:
        raise HTTPException(status_code=404, detail="User not found")
    if target.get("role") in ["admin", "super_admin"] and admin.get("role") != "super_admin":
        raise HTTPException(status_code=403, detail="Cannot suspend admin accounts")
    new_status = "active" if target.get("status") == "suspended" else "suspended"
    await db.users.update_one({"id": user_id}, {"$set": {"status": new_status}})
    await write_audit_log(admin, f"{'unsuspended' if new_status == 'active' else 'suspended'}_user", target_id=user_id, target_type="user", ip=get_client_ip(request))
    return {"message": f"User {new_status}", "status": new_status}

@api_router.post("/admin/users/bulk")
async def bulk_user_action(
    data: BulkUserActionInput,
    request: Request = None,
    admin=Depends(require_admin)
):
    action = (data.action or "").strip().lower()
    user_ids = data.user_ids or []
    reason = data.reason or ""

    if not user_ids:
        raise HTTPException(status_code=400, detail="No users selected")
    if action not in ["approve", "reject", "suspend", "delete"]:
        raise HTTPException(status_code=400, detail="Invalid action")
    results = {"success": 0, "failed": 0}
    for uid in user_ids:
        try:
            if uid == admin.get("id"):
                results["failed"] += 1
                continue
            target = await db.users.find_one({"id": uid}, {"_id": 0, "role": 1})
            if not target:
                results["failed"] += 1
                continue
            target_role = target.get("role", "")
            if target_role in ["admin", "super_admin"] and admin.get("role") != "super_admin":
                results["failed"] += 1
                continue
            if action == "approve":
                await db.users.update_one({"id": uid}, {"$set": {"status": "active"}})
            elif action == "reject":
                await db.users.update_one({"id": uid}, {"$set": {"status": "rejected"}})
            elif action == "suspend":
                await db.users.update_one({"id": uid}, {"$set": {"status": "suspended"}})
            elif action == "delete":
                await db.users.delete_one({"id": uid})
            await write_audit_log(admin, f"bulk_{action}_user", target_id=uid, target_type="user", details={"reason": reason}, ip=get_client_ip(request) if request else "unknown")
            results["success"] += 1
        except Exception:
            results["failed"] += 1
    return {"message": f"Bulk {action} completed", "results": results}

# ─── ADMIN VOLUNTEER MANAGEMENT ───
@api_router.get("/admin/volunteers")
async def list_volunteers(status: Optional[str] = None, user=Depends(require_admin)):
    query: Dict[str, Any] = {"role": "volunteer"}
    if status:
        query["status"] = status
    volunteers = await db.users.find(query, {"_id": 0, "password_hash": 0}).sort("created_at", -1).to_list(200)
    return {"volunteers": volunteers}

@api_router.get("/admin/volunteers/applications")
async def list_volunteer_applications(user=Depends(require_admin)):
    tasks = await db.tasks.find({}, {"_id": 0}).to_list(200)
    applications = []
    for task in tasks:
        for application in task.get("applied", []):
            if isinstance(application, str):
                app = {
                    "volunteer_id": application,
                    "status": "pending",
                    "applied_at": task.get("created_at", datetime.now(timezone.utc).isoformat()),
                    "message": "",
                }
            elif isinstance(application, dict):
                app = {
                    "volunteer_id": application.get("volunteer_id") or application.get("user_id", ""),
                    "status": application.get("status", "pending"),
                    "applied_at": application.get("applied_at", task.get("created_at", datetime.now(timezone.utc).isoformat())),
                    "message": application.get("message", ""),
                    "matched_skills": application.get("matched_skills", []),
                }
            else:
                continue

            if app.get("status") not in ["pending", None]:
                continue

            vol = await db.users.find_one({"id": app.get("volunteer_id", "")}, {"_id": 0, "password_hash": 0})
            applications.append({
                "task_id": task["id"],
                "task_title": task.get("title", ""),
                "project_title": task.get("project_name", ""),
                "task_date": task.get("date", ""),
                "task_location": task.get("location", ""),
                "volunteer_id": app.get("volunteer_id", ""),
                "volunteer_name": (vol or {}).get("name", "Unknown Volunteer"),
                "volunteer_email": (vol or {}).get("email", ""),
                "status": app.get("status", "pending"),
                "cover_note": app.get("message", ""),
                "matched_skills": app.get("matched_skills", []),
                "applied_at": app.get("applied_at", ""),
            })
    return {"applications": applications, "total": len(applications)}


@api_router.get("/admin/volunteer-id-cards")
async def list_volunteer_id_cards(status: str = "", search: str = "", user=Depends(require_admin)):
    query: Dict[str, Any] = {}
    if status:
        query["card_status"] = status
    cards = await db.volunteer_id_cards.find(query, {"_id": 0}).sort("applied_at", -1).to_list(500)

    results = []
    for card in cards:
        profile = card.get("personal_details", {})
        text_blob = " ".join([
            card.get("card_id", ""),
            profile.get("full_name", ""),
            profile.get("phone", ""),
            card.get("volunteer_email", ""),
        ]).lower()
        if search and search.lower() not in text_blob:
            continue
        results.append(card)
    return {"applications": results, "total": len(results)}


@api_router.put("/admin/volunteer-id-cards/{application_id}/review")
async def review_volunteer_id_card(
    application_id: str,
    payload: VolunteerIdCardReviewInput,
    request: Request,
    admin=Depends(require_admin),
):
    record = await db.volunteer_id_cards.find_one({"id": application_id}, {"_id": 0})
    if not record:
        raise HTTPException(status_code=404, detail="Application not found")

    status = _normalize_id_card_status(payload.status)
    if status not in ["approved", "rejected", "under_review"]:
        raise HTTPException(status_code=400, detail="Status must be approved, rejected, or under_review")

    update_doc: Dict[str, Any] = {
        "card_status": status,
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "review": {
            "reviewed_by": admin.get("id"),
            "reviewed_by_name": admin.get("name", "Admin"),
            "reviewed_at": datetime.now(timezone.utc).isoformat(),
            "admin_notes": payload.admin_notes[:500],
            "rejection_reason": payload.rejection_reason[:500],
        },
    }

    if status == "approved":
        card_id = record.get("card_id") or await generate_volunteer_card_id()
        now = datetime.now(timezone.utc)
        valid_until = now + timedelta(days=365)
        update_doc.update({
            "card_id": card_id,
            "generated_card": {
                "generated_at": now.isoformat(),
                "valid_from": now.isoformat(),
                "valid_until": valid_until.isoformat(),
                "verify_url": f"https://sweezen.org/verify/volunteer/{card_id}",
                "barcode_data": card_id,
                "qr_data": f"https://sweezen.org/verify/volunteer/{card_id}",
                "year": now.year,
                "version": int(record.get("generated_card", {}).get("version", 0)) + 1,
            },
        })

    await db.volunteer_id_cards.update_one({"id": application_id}, {"$set": update_doc})

    await db.notifications.insert_one({
        "id": str(uuid.uuid4()),
        "user_id": record.get("volunteer_id"),
        "type": "volunteer_id_card_review",
        "title": "Volunteer ID Card application updated",
        "message": (
            f"Your ID card application was approved. Card ID: {update_doc.get('card_id', record.get('card_id', 'pending'))}"
            if status == "approved"
            else f"Your ID card application was {status}. {payload.rejection_reason[:120]}"
        ),
        "ref_id": application_id,
        "read": False,
        "created_at": datetime.now(timezone.utc).isoformat(),
    })

    await write_audit_log(
        admin,
        "reviewed_volunteer_id_card",
        target_id=application_id,
        target_type="volunteer_id_card",
        details={"status": status},
        ip=get_client_ip(request),
    )
    return {"message": f"Application marked as {status}", "status": status}


@api_router.get("/admin/volunteer-id-cards/{application_id}/pdf")
async def download_volunteer_id_card_pdf_admin(application_id: str, user=Depends(require_admin)):
    record = await db.volunteer_id_cards.find_one({"id": application_id}, {"_id": 0})
    if not record:
        raise HTTPException(status_code=404, detail="Application not found")
    if record.get("card_status") != "approved":
        raise HTTPException(status_code=400, detail="Only approved cards can be downloaded")

    volunteer = await db.users.find_one({"id": record.get("volunteer_id")}, {"_id": 0, "password_hash": 0}) or {}
    logo_path = ROOT_DIR.parent / "frontend" / "public" / "New Logo Sweezen Foundation 11-03-26.png"
    pdf_buffer = generate_volunteer_id_card_pdf(record, volunteer, logo_path=logo_path)
    filename = f"volunteer-id-card-{record.get('card_id', record.get('id', 'card'))}.pdf"
    return StreamingResponse(
        pdf_buffer,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )

@api_router.put("/admin/volunteers/tasks/{task_id}/applications/{applicant_id}")
async def review_volunteer_application(
    task_id: str,
    applicant_id: str,
    payload: VolunteerApplicationReviewInput,
    request: Request,
    admin=Depends(require_admin)
):
    task = await db.tasks.find_one({"id": task_id}, {"_id": 0})
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    requested_status = payload.status.lower().strip()
    if requested_status in ["approve", "approved"]:
        new_status = "approved"
    elif requested_status in ["reject", "rejected"]:
        new_status = "rejected"
    else:
        raise HTTPException(status_code=400, detail="Status must be approved or rejected")

    updated_applied = []
    for a in task.get("applied", []):
        if isinstance(a, str) and a == applicant_id:
            updated_applied.append({
                "volunteer_id": applicant_id,
                "status": new_status,
                "reviewed_at": datetime.now(timezone.utc).isoformat(),
                "reviewed_by": admin.get("id", ""),
                "message": payload.feedback,
            })
        elif isinstance(a, dict) and (a.get("user_id") == applicant_id or a.get("volunteer_id") == applicant_id):
            updated_applied.append({
                **a,
                "volunteer_id": applicant_id,
                "status": new_status,
                "reviewed_at": datetime.now(timezone.utc).isoformat(),
                "reviewed_by": admin.get("id", ""),
                "admin_rating": payload.admin_rating or a.get("admin_rating", 0),
            })
        else:
            updated_applied.append(a)

    update_doc: Dict[str, Any] = {"applied": updated_applied}
    if new_status == "approved":
        current_assigned = task.get("assigned_volunteers", [])
        if applicant_id not in current_assigned:
            current_assigned.append(applicant_id)
        update_doc["assigned_volunteers"] = current_assigned

    await db.tasks.update_one({"id": task_id}, {"$set": update_doc})

    if payload.admin_rating and payload.admin_rating > 0:
        volunteer = await db.users.find_one({"id": applicant_id}, {"_id": 0})
        if volunteer and volunteer.get("role") == "volunteer":
            profile = default_volunteer_profile(volunteer.get("volunteerProfile", {}))
            current_rating = float(profile.get("rating", 0))
            profile["rating"] = round((current_rating + float(payload.admin_rating)) / (2 if current_rating > 0 else 1), 2)
            if float(payload.admin_rating) >= 5:
                profile["impactPoints"] += 100
            profile["currentLevel"] = compute_level(int(profile["impactPoints"]))
            profile["lastActiveAt"] = datetime.now(timezone.utc).isoformat()
            await db.users.update_one(
                {"id": applicant_id},
                {
                    "$set": {
                        "volunteerProfile": profile,
                        "impact_points": profile["impactPoints"],
                        "hours_logged": profile["totalHoursLogged"],
                    }
                },
            )

    await write_audit_log(admin, f"{new_status}_volunteer_application", target_id=applicant_id, target_type="volunteer", details={"task_id": task_id}, ip=get_client_ip(request))
    return {"message": f"Application {new_status}"}

# ─── ADMIN FINANCES ───
@api_router.get("/admin/finances/donations")
async def admin_donations_filtered(
    status: Optional[str] = None,
    project_id: Optional[str] = None,
    date_from: Optional[str] = None,
    date_to: Optional[str] = None,
    q: Optional[str] = None,
    page: int = 1,
    limit: int = 50,
    user=Depends(require_admin)
):
    query: Dict[str, Any] = {}
    safe_page = max(1, int(page or 1))
    safe_limit = min(100, max(1, int(limit or 50)))
    if status and status != "all":
        query["status"] = status
    if project_id:
        query["project_id"] = project_id
    if date_from:
        query.setdefault("created_at", {})["$gte"] = date_from
    if date_to:
        query.setdefault("created_at", {})["$lte"] = date_to + "T23:59:59"
    if q:
        q_escaped = escape_regex_input(q, MAX_SEARCH_LEN)
        query["$or"] = [
            {"donor_name": {"$regex": q_escaped, "$options": "i"}},
            {"donor_email": {"$regex": q_escaped, "$options": "i"}},
            {"receipt_number": {"$regex": q_escaped, "$options": "i"}},
        ]
    skip = (safe_page - 1) * safe_limit
    total = await db.donations.count_documents(query)
    donations = await db.donations.find(query, {"_id": 0}).sort("created_at", -1).skip(skip).limit(safe_limit).to_list(safe_limit)
    agg = await db.donations.aggregate([
        {"$match": query},
        {"$match": {"status": "completed"}},
        {"$group": {"_id": None, "total": {"$sum": "$amount"}, "count": {"$sum": 1}}}
    ]).to_list(1)
    summary = agg[0] if agg else {"total": 0, "count": 0}
    return {"donations": donations, "total": total, "page": safe_page, "pages": (total + safe_limit - 1) // safe_limit, "summary": summary}

@api_router.get("/admin/finances/stats")
async def admin_financial_stats(user=Depends(require_admin)):
    completed_agg = await db.donations.aggregate([
        {"$match": {"status": "completed"}},
        {"$group": {"_id": None, "total": {"$sum": "$amount"}, "count": {"$sum": 1}, "avg": {"$avg": "$amount"}}}
    ]).to_list(1)
    monthly = await db.donations.aggregate([
        {"$match": {"status": "completed"}},
        {"$addFields": {"month": {"$substr": ["$created_at", 0, 7]}}},
        {"$group": {"_id": "$month", "total": {"$sum": "$amount"}, "count": {"$sum": 1}}},
        {"$sort": {"_id": -1}}, {"$limit": 12}
    ]).to_list(12)
    by_project = await db.donations.aggregate([
        {"$match": {"status": "completed"}},
        {"$group": {"_id": "$project_id", "total": {"$sum": "$amount"}, "count": {"$sum": 1}}},
        {"$sort": {"total": -1}}, {"$limit": 10}
    ]).to_list(10)
    cs = completed_agg[0] if completed_agg else {"total": 0, "count": 0, "avg": 0}
    return {"total_raised": cs.get("total", 0), "total_count": cs.get("count", 0), "avg_donation": round(cs.get("avg", 0), 2), "monthly": monthly, "by_project": by_project}

# ─── ADMIN MILESTONE MANAGEMENT ───
@api_router.post("/admin/projects/{project_id}/milestones")
async def add_milestone(project_id: str, milestone: MilestoneCreateInput, admin=Depends(require_admin)):
    project = await db.projects.find_one({"id": project_id}, {"_id": 0})
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    if len((milestone.name or "").strip()) < 2:
        raise HTTPException(status_code=400, detail="Milestone name is required")
    new_milestone = {
        "id": str(uuid.uuid4()),
        "name": sanitize_plain_text(milestone.name, 120),
        "target_date": ensure_iso_date(milestone.target_date or ""),
        "status": "pending",
        "evidence_url": "",
        "admin_note": "",
        "created_at": datetime.now(timezone.utc).isoformat()
    }
    await db.projects.update_one({"id": project_id}, {"$push": {"milestones": new_milestone}})
    return {"milestone": new_milestone}

@api_router.put("/admin/projects/{project_id}/milestones/{milestone_id}")
async def update_milestone(project_id: str, milestone_id: str, data: MilestoneUpdateInput, request: Request, admin=Depends(require_admin)):
    project = await db.projects.find_one({"id": project_id}, {"_id": 0})
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    update_map: Dict[str, Any] = {}
    if data.name is not None:
        update_map["name"] = sanitize_plain_text(data.name, 120)
    if data.target_date is not None:
        update_map["target_date"] = ensure_iso_date(data.target_date)
    if data.status is not None:
        requested_status = sanitize_plain_text(data.status, 30).lower()
        if requested_status not in ["pending", "in_progress", "completed"]:
            raise HTTPException(status_code=400, detail="Invalid milestone status")
        update_map["status"] = requested_status
    if data.evidence_url is not None:
        update_map["evidence_url"] = sanitize_plain_text(data.evidence_url, 500)
    if data.admin_note is not None:
        update_map["admin_note"] = sanitize_plain_text(data.admin_note, 500)

    updated_milestones = []
    for m in project.get("milestones", []):
        if isinstance(m, dict) and m.get("id") == milestone_id:
            updated_milestones.append({**m, **update_map})
        else:
            updated_milestones.append(m)
    await db.projects.update_one({"id": project_id}, {"$set": {"milestones": updated_milestones, "updated_at": datetime.now(timezone.utc).isoformat()}})
    if update_map.get("status") == "completed":
        await write_audit_log(admin, "completed_milestone", target_id=project_id, target_type="project", details={"milestone_id": milestone_id}, ip=get_client_ip(request))
    return {"message": "Milestone updated"}

# ─── ADMIN CONTENT (all publications including drafts) ───
@api_router.get("/admin/content")
async def admin_list_content(user=Depends(require_admin)):
    pubs = await db.publications.find({}, {"_id": 0}).sort("created_at", -1).to_list(200)
    return {"publications": pubs}

# ─── ADMIN CONTACTS MANAGEMENT ───
@api_router.put("/admin/contacts/{contact_id}/status")
async def update_contact_status(contact_id: str, status: str, admin=Depends(require_admin)):
    result = await db.contacts.update_one({"id": contact_id}, {"$set": {"status": status}})
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Contact not found")
    return {"message": "Contact status updated"}

# ─── SUPER ADMIN ROUTES ───
@api_router.get("/super-admin/overview")
async def super_admin_overview(request: Request, user=Depends(require_super_admin)):
    settings = await get_system_settings()
    total_users = await db.users.count_documents({})
    active_admins = await db.users.count_documents({"role": {"$in": ["admin", "super_admin"]}, "status": "active"})
    total_projects = await db.projects.count_documents({"status": "active"})
    pending_approvals = await db.users.count_documents({"status": "pending"})
    donations_sum = await db.donations.aggregate([
        {"$match": {"status": "completed"}},
        {"$group": {"_id": None, "total": {"$sum": "$amount"}}}
    ]).to_list(1)
    total_raised = donations_sum[0]["total"] if donations_sum else 0
    uptime_seconds = int(time.time() - APP_START_TIME)
    recent_logs = await db.admin_audit_logs.find({}, {"_id": 0}).sort("timestamp", -1).limit(20).to_list(20)
    escalations = await db.notifications.find({"type": {"$in": ["user_approval", "account_status"]}}, {"_id": 0}).sort("created_at", -1).limit(10).to_list(10)
    return {
        "kpis": {
            "total_users": total_users,
            "active_admins": active_admins,
            "total_raised": total_raised,
            "active_projects": total_projects,
            "pending_approvals": pending_approvals,
            "system_uptime_percent": 99.9,
            "uptime_seconds": uptime_seconds,
        },
        "activity_feed": recent_logs,
        "pending_escalations": escalations,
        "settings": settings,
        "client_ip": get_client_ip(request),
    }

@api_router.get("/super-admin/settings")
async def get_super_admin_settings(user=Depends(require_super_admin)):
    settings = await get_system_settings()
    return {"settings": settings}

@api_router.put("/super-admin/settings")
async def update_super_admin_settings(data: SystemSettingsUpdate, request: Request, user=Depends(require_super_admin)):
    patch = {k: v for k, v in data.model_dump().items() if v is not None}
    if not patch:
        raise HTTPException(status_code=400, detail="No settings provided")
    patch["updated_at"] = datetime.now(timezone.utc).isoformat()
    patch["updated_by"] = user["id"]
    await db.system_settings.update_one({"id": "global"}, {"$set": patch}, upsert=True)
    await write_audit_log(
        user,
        "changed_system_settings",
        target_id="global",
        target_type="system_settings",
        details=patch,
        ip=get_client_ip(request),
    )
    updated = await get_system_settings()
    return {"message": "Settings updated", "settings": updated}

@api_router.get("/super-admin/admins")
async def list_admin_accounts(user=Depends(require_super_admin)):
    admins = await db.users.find({"role": {"$in": ["admin", "super_admin"]}}, {"_id": 0, "password_hash": 0}).sort("created_at", -1).to_list(100)
    return {"admins": admins}

@api_router.post("/super-admin/admins")
async def create_admin_account(data: CreateAdminInput, request: Request, user=Depends(require_super_admin)):
    exists = await db.users.find_one({"email": data.email}, {"_id": 0})
    if exists:
        raise HTTPException(status_code=400, detail="Email already registered")
    admin_user = {
        "id": str(uuid.uuid4()),
        "name": data.name,
        "email": data.email,
        "password_hash": hash_password(data.password),
        "phone": data.phone,
        "role": "admin",
        "status": "active",
        "impact_points": 0,
        "hours_logged": 0,
        "badges": [],
        "created_at": datetime.now(timezone.utc).isoformat(),
        "created_by": user["id"],
    }
    await db.users.insert_one(admin_user)
    await write_audit_log(
        user,
        "created_admin",
        target_id=admin_user["id"],
        target_type="user",
        details={"email": admin_user["email"]},
        ip=get_client_ip(request),
    )
    return {"message": "Admin account created", "admin": {"id": admin_user["id"], "name": admin_user["name"], "email": admin_user["email"], "role": admin_user["role"]}}

@api_router.post("/super-admin/force-logout")
async def force_logout_all_users(request: Request, user=Depends(require_super_admin)):
    now_iso = datetime.now(timezone.utc).isoformat()
    await db.users.update_many({}, {"$set": {"token_invalid_before": now_iso}})
    await write_audit_log(
        user,
        "forced_logout_all_users",
        target_id="all",
        target_type="session",
        details={"revoked_at": now_iso},
        ip=get_client_ip(request),
    )
    return {"message": "All user sessions invalidated"}

@api_router.post("/super-admin/rotate-api-keys")
async def rotate_api_keys(request: Request, user=Depends(require_super_admin)):
    await write_audit_log(
        user,
        "rotated_api_keys",
        target_id="integrations",
        target_type="system",
        details={"note": "Rotation requested. In this environment keys are managed via .env and external secret manager."},
        ip=get_client_ip(request),
    )
    return {"message": "API key rotation request logged. Apply updated keys in environment secret store."}

@api_router.put("/super-admin/donations/{donation_id}/status")
async def override_donation_status(donation_id: str, data: DonationStatusOverride, request: Request, user=Depends(require_super_admin)):
    if data.status not in ["completed", "failed", "refunded", "created"]:
        raise HTTPException(status_code=400, detail="Invalid donation status")
    donation = await db.donations.find_one({"id": donation_id}, {"_id": 0})
    if not donation:
        raise HTTPException(status_code=404, detail="Donation not found")
    await db.donations.update_one({"id": donation_id}, {"$set": {"status": data.status, "override_reason": data.reason, "override_by": user["id"], "override_at": datetime.now(timezone.utc).isoformat()}})
    await write_audit_log(
        user,
        "override_payment_status",
        target_id=donation_id,
        target_type="donation",
        details={"new_status": data.status, "reason": data.reason},
        ip=get_client_ip(request),
    )
    return {"message": "Donation status updated"}

@api_router.delete("/super-admin/users/{user_id}/permanent")
async def anonymize_user(user_id: str, request: Request, user=Depends(require_super_admin)):
    if user_id == user["id"]:
        raise HTTPException(status_code=400, detail="Cannot anonymize your own account")
    target = await db.users.find_one({"id": user_id}, {"_id": 0})
    if not target:
        raise HTTPException(status_code=404, detail="User not found")
    masked_email = f"anonymized_{user_id[:8]}@deleted.local"
    await db.users.update_one(
        {"id": user_id},
        {"$set": {
            "name": "Anonymized User",
            "email": masked_email,
            "phone": "",
            "pan_number": "",
            "affiliation": "",
            "purpose": "",
            "status": "anonymized",
            "anonymized_at": datetime.now(timezone.utc).isoformat(),
            "anonymized_by": user["id"],
        }}
    )
    await write_audit_log(
        user,
        "anonymized_user",
        target_id=user_id,
        target_type="user",
        details={"old_email": target.get("email", ""), "new_email": masked_email},
        ip=get_client_ip(request),
    )
    return {"message": "User anonymized"}

@api_router.get("/super-admin/audit-logs")
async def get_audit_logs(limit: int = 100, action: str = "", actor_email: str = "", user=Depends(require_super_admin)):
    query: Dict[str, Any] = {}
    if action:
        query["action"] = action
    if actor_email:
        query["actor_email"] = actor_email
    logs = await db.admin_audit_logs.find(query, {"_id": 0}).sort("timestamp", -1).limit(min(max(limit, 1), 1000)).to_list(min(max(limit, 1), 1000))
    return {"logs": logs}

@api_router.get("/super-admin/audit-logs/export")
async def export_audit_logs_csv(user=Depends(require_super_admin)):
    logs = await db.admin_audit_logs.find({}, {"_id": 0}).sort("timestamp", -1).to_list(5000)
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=["timestamp", "actor_email", "actor_role", "action", "target_type", "target_id", "ip", "details"])
    writer.writeheader()
    for row in logs:
        writer.writerow({
            "timestamp": row.get("timestamp", ""),
            "actor_email": row.get("actor_email", ""),
            "actor_role": row.get("actor_role", ""),
            "action": row.get("action", ""),
            "target_type": row.get("target_type", ""),
            "target_id": row.get("target_id", ""),
            "ip": row.get("ip", ""),
            "details": str(row.get("details", {})),
        })
    output.seek(0)
    return StreamingResponse(io.BytesIO(output.getvalue().encode()), media_type="text/csv", headers={"Content-Disposition": "attachment; filename=super_admin_audit_logs.csv"})

# ─── CSR ROUTES ───
async def _get_or_create_csr_partner_context(user: Dict[str, Any]) -> Dict[str, Any]:
    partner = await db.csr_partners.find_one(
        {
            "$or": [
                {"user_id": user.get("id", "")},
                {"email": user.get("email", "")},
            ]
        },
        {"_id": 0},
    )
    if partner:
        return partner

    profile = default_csr_profile(user.get("csrProfile", {}))
    partner = {
        "id": str(uuid.uuid4()),
        "user_id": user.get("id", ""),
        "email": user.get("email", ""),
        "company_name": profile.get("companyName", "") or user.get("name", "CSR Partner"),
        "contact_person": user.get("name", "CSR Contact"),
        "phone": user.get("phone", ""),
        "tier": (profile.get("tier", "Silver") or "Silver").lower(),
        "funds_committed": float(profile.get("csrBudgetFY", 0) or 0),
        "funds_utilized": float(profile.get("totalFunded", 0) or 0),
        "project_ids": profile.get("activeProjects", []),
        "status": "active",
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    await db.csr_partners.insert_one(partner)
    return partner


async def _get_csr_partner_projects(partner: Dict[str, Any]) -> List[Dict[str, Any]]:
    raw_project_ids = partner.get("project_ids", []) or []
    if isinstance(raw_project_ids, str):
        project_ids = [raw_project_ids]
    elif isinstance(raw_project_ids, list):
        project_ids = [str(pid) for pid in raw_project_ids if pid]
    else:
        project_ids = []
    if not project_ids:
        return []
    return await db.projects.find({"id": {"$in": project_ids}}, {"_id": 0}).to_list(500)


def _compute_compliance_score(utilization_pct: float, completed_projects: int, total_projects: int) -> Dict[str, Any]:
    report_component = 100 if utilization_pct >= 75 else 60 if utilization_pct >= 40 else 30
    completion_rate = (completed_projects / total_projects) * 100 if total_projects else 0
    completion_component = 100 if completion_rate >= 70 else 65 if completion_rate >= 40 else 30
    score = int((utilization_pct * 0.4) + (report_component * 0.3) + (completion_component * 0.3))
    score = max(0, min(100, score))
    color = "green" if score > 80 else "gold" if score >= 60 else "red"
    return {
        "score": score,
        "color": color,
        "breakdown": {
            "utilizationPercent": round(utilization_pct, 1),
            "reporting": report_component,
            "completion": completion_component,
        },
    }


@api_router.get("/csr/me/profile")
async def get_csr_profile(user=Depends(require_csr_partner)):
    full_user = await db.users.find_one({"id": user["id"]}, {"_id": 0, "password_hash": 0}) or user
    profile = default_csr_profile(full_user.get("csrProfile", {}))
    return {"csrProfile": profile}


@api_router.put("/csr/me/profile")
async def update_csr_profile(payload: CsrProfileUpdateInput, user=Depends(require_csr_partner)):
    if not (payload.companyName or "").strip():
        raise HTTPException(status_code=400, detail="Company name is required")
    if payload.companySize and payload.companySize not in CSR_COMPANY_SIZES:
        raise HTTPException(status_code=400, detail="Invalid company size")
    if payload.tier and payload.tier not in CSR_TIERS:
        raise HTTPException(status_code=400, detail="Invalid partner tier")
    if payload.kycStatus and payload.kycStatus not in CSR_KYC_STATUSES:
        raise HTTPException(status_code=400, detail="Invalid KYC status")

    updated_profile = default_csr_profile(payload.model_dump())
    await db.users.update_one({"id": user["id"]}, {"$set": {"csrProfile": updated_profile}})

    partner = await _get_or_create_csr_partner_context(user)
    await db.csr_partners.update_one(
        {"id": partner["id"]},
        {
            "$set": {
                "company_name": updated_profile.get("companyName", ""),
                "email": user.get("email", ""),
                "contact_person": user.get("name", ""),
                "phone": user.get("phone", ""),
                "tier": updated_profile.get("tier", "Silver").lower(),
                "funds_committed": updated_profile.get("csrBudgetFY", 0),
                "project_ids": updated_profile.get("activeProjects", []),
            }
        },
    )
    return {"message": "CSR profile updated", "csrProfile": updated_profile}


@api_router.get("/csr/dashboard")
async def csr_dashboard(user=Depends(require_csr)):
    if user.get("role") in ["admin", "super_admin"]:
        partners = await db.csr_partners.find({}, {"_id": 0}).to_list(500)
        total_committed = sum(_safe_float(p.get("funds_committed", 0)) for p in partners)
        total_utilized = sum(_safe_float(p.get("funds_utilized", 0)) for p in partners)
        return {
            "mode": "admin",
            "total_partners": len(partners),
            "total_committed": total_committed,
            "total_utilized": total_utilized,
            "utilization_rate": round((total_utilized / total_committed * 100) if total_committed else 0, 1),
            "partners": partners,
            "projects": await db.projects.find({}, {"_id": 0}).to_list(300),
        }

    partner = await _get_or_create_csr_partner_context(user)
    full_user = await db.users.find_one({"id": user["id"]}, {"_id": 0, "password_hash": 0}) or user
    profile = default_csr_profile(full_user.get("csrProfile", {}))
    projects = await _get_csr_partner_projects(partner)
    project_ids = [p.get("id", "") for p in projects]

    donation_query: Dict[str, Any] = {"status": "completed", "project_id": {"$in": project_ids}} if project_ids else {"status": "completed", "project_id": "__none__"}
    donations = await db.donations.find(donation_query, {"_id": 0, "amount": 1, "project_id": 1, "created_at": 1}).to_list(5000)

    committed = _safe_float(partner.get("funds_committed", 0) or profile.get("csrBudgetFY", 0) or 0)
    utilized = round(sum(_safe_float(d.get("amount", 0)) for d in donations), 2)
    beneficiaries = int(sum(_safe_float(p.get("beneficiary_count", 0)) for p in projects))
    utilization_rate = round((utilized / committed * 100), 1) if committed > 0 else 0
    completed_projects = len([p for p in projects if p.get("status") == "completed"])
    compliance = _compute_compliance_score(utilization_rate, completed_projects, len(projects))

    markers = []
    for p in projects:
        budget = float(p.get("budget", 0) or 0)
        raised = float(p.get("raised", 0) or 0)
        milestones = p.get("milestones", []) if isinstance(p.get("milestones", []), list) else []
        done = len([m for m in milestones if isinstance(m, dict) and m.get("status") == "completed"])
        milestone_pct = int((done / len(milestones)) * 100) if milestones else 0
        markers.append({
            "id": p.get("id", ""),
            "title": p.get("title", "Project"),
            "category": p.get("category", "other"),
            "state": p.get("location", ""),
            "lat": p.get("lat", None),
            "lng": p.get("lng", None),
            "amount": min(utilized, raised if raised > 0 else budget),
            "status": p.get("status", "active"),
            "milestonesPct": milestone_pct,
        })

    category_breakdown: Dict[str, float] = {}
    for p in projects:
        cat = p.get("category", "other")
        category_breakdown.setdefault(cat, 0.0)
        category_breakdown[cat] += _safe_float(p.get("raised", 0))

    return {
        "mode": "csr_partner",
        "header": {
            "companyName": profile.get("companyName", "") or partner.get("company_name", "CSR Partner"),
            "tier": profile.get("tier", "Silver"),
            "relationshipManagerName": "Sweezen Relationship Team",
            "mfaStatus": "enabled",
        },
        "complianceHealth": compliance,
        "kpis": {
            "budgetUtilized": {"used": utilized, "total": committed, "percent": utilization_rate},
            "activeProjects": len([p for p in projects if p.get("status") == "active"]),
            "beneficiariesReached": beneficiaries,
            "upcomingDeadlineDays": 14,
        },
        "portfolioMap": {"markers": markers},
        "fundFlow": category_breakdown,
        "calendar": [
            {"title": "CSR-1 filing", "date": (datetime.now(timezone.utc) + timedelta(days=14)).date().isoformat(), "status": "upcoming"},
            {"title": "Tranche release review", "date": (datetime.now(timezone.utc) + timedelta(days=7)).date().isoformat(), "status": "this_week"},
        ],
        # Backward compatibility for existing UI/tests
        "total_partners": 1,
        "total_committed": committed,
        "total_utilized": utilized,
        "utilization_rate": utilization_rate,
        "partners": [partner],
        "projects": projects,
    }

@api_router.post("/csr/partners")
async def create_csr_partner(data: CSRPartnerCreate, user=Depends(require_admin)):
    partner = {
        "id": str(uuid.uuid4()), **data.model_dump(),
        "funds_utilized": 0, "status": "active",
        "created_at": datetime.now(timezone.utc).isoformat()
    }
    await db.csr_partners.insert_one(partner)
    created = await db.csr_partners.find_one({"id": partner["id"]}, {"_id": 0})
    return {"partner": created}


@api_router.get("/csr/funds")
async def csr_funds(user=Depends(require_csr_partner)):
    partner = await _get_or_create_csr_partner_context(user)
    projects = await _get_csr_partner_projects(partner)
    project_ids = [p.get("id", "") for p in projects]
    donations = await db.donations.find(
        {"status": "completed", "project_id": {"$in": project_ids}} if project_ids else {"project_id": "__none__"},
        {"_id": 0, "project_id": 1, "amount": 1, "created_at": 1, "receipt_number": 1},
    ).to_list(5000)

    rows = []
    total_beneficiaries = 0
    for p in projects:
        project_donations = [d for d in donations if d.get("project_id") == p.get("id")]
        allocated = float(p.get("budget", 0) or 0)
        utilized = round(sum(float(d.get("amount", 0) or 0) for d in project_donations), 2)
        beneficiaries = int(p.get("beneficiary_count", 0) or 0)
        total_beneficiaries += beneficiaries
        milestones = p.get("milestones", []) if isinstance(p.get("milestones", []), list) else []
        completed = len([m for m in milestones if isinstance(m, dict) and m.get("status") == "completed"])
        milestone_pct = int((completed / len(milestones)) * 100) if milestones else 0
        rows.append({
            "projectId": p.get("id", ""),
            "project": p.get("title", "Project"),
            "allocated": allocated,
            "utilized": utilized,
            "utilizationPercent": round((utilized / allocated * 100), 1) if allocated > 0 else 0,
            "beneficiaries": beneficiaries,
            "milestonesPercent": milestone_pct,
            "lastUpdate": p.get("updated_at", p.get("created_at", "")),
            "status": p.get("status", "active"),
        })

    audit = []
    for d in donations[-200:]:
        tx_seed = f"{d.get('receipt_number', '')}{d.get('created_at', '')}"
        audit.append({
            "entryType": "fund_movement",
            "amount": float(d.get("amount", 0) or 0),
            "projectId": d.get("project_id", ""),
            "timestamp": d.get("created_at", ""),
            "txHash": f"0x{abs(hash(tx_seed)):x}",
        })

    return {
        "fundUtilization": rows,
        "roi": {
            "totalSpent": round(sum(r["utilized"] for r in rows), 2),
            "totalBeneficiaries": total_beneficiaries,
            "costPerBeneficiary": round((sum(r["utilized"] for r in rows) / total_beneficiaries), 2) if total_beneficiaries > 0 else 0,
        },
        "tranches": [
            {"name": "Tranche 1", "amount": round((partner.get("funds_committed", 0) or 0) * 0.4, 2), "status": "released", "milestoneProof": "", "date": ""},
            {"name": "Tranche 2", "amount": round((partner.get("funds_committed", 0) or 0) * 0.6, 2), "status": "pending", "milestoneProof": "", "date": ""},
        ],
        "auditTrail": sorted(audit, key=lambda x: x.get("timestamp", ""), reverse=True),
    }

@api_router.get("/csr/reports")
async def csr_reports(user=Depends(require_csr)):
    if user.get("role") in ["admin", "super_admin"]:
        projects = await db.projects.find({}, {"_id": 0}).to_list(500)
        donations = await db.donations.find({"status": "completed"}, {"_id": 0}).to_list(5000)
    else:
        partner = await _get_or_create_csr_partner_context(user)
        projects = await _get_csr_partner_projects(partner)
        project_ids = [p.get("id", "") for p in projects]
        donations = await db.donations.find(
            {"status": "completed", "project_id": {"$in": project_ids}} if project_ids else {"project_id": "__none__"},
            {"_id": 0},
        ).to_list(5000)

    total_raised = round(sum(float(d.get("amount", 0) or 0) for d in donations), 2)
    category_breakdown = {}
    for p in projects:
        cat = p.get("category", "other")
        if cat not in category_breakdown:
            category_breakdown[cat] = {"projects": 0, "budget": 0, "raised": 0, "beneficiaries": 0}
        category_breakdown[cat]["projects"] += 1
        category_breakdown[cat]["budget"] += float(p.get("budget", 0) or 0)
        category_breakdown[cat]["raised"] += float(p.get("raised", 0) or 0)
        category_breakdown[cat]["beneficiaries"] += int(p.get("beneficiary_count", 0) or 0)

    mode = "admin" if user.get("role") in ["admin", "super_admin"] else "csr_partner"
    return {
        "mode": mode,
        "total_projects": len(projects), "total_donations": len(donations),
        "total_raised": total_raised, "category_breakdown": category_breakdown,
        "sdg_alignment": {"SDG 3": "Healthcare", "SDG 4": "Education", "SDG 13": "Environment", "SDG 17": "Partnerships"},
        "esg": {
            "environmental": {"trees_planted": int(total_raised // 500), "co2_offset_tonnes": round(total_raised / 1000000, 2), "waste_managed_tonnes": int(total_raised // 250000)},
            "social": {"beneficiaries": sum(v["beneficiaries"] for v in category_breakdown.values()), "programs_covered": len(projects)},
            "governance": {"audit_cleanliness": "high", "reporting_standard": "GRI/BRSR"},
        },
        "generated_at": datetime.now(timezone.utc).isoformat()
    }


@api_router.get("/csr/compliance-calendar")
async def csr_compliance_calendar(user=Depends(require_csr_partner)):
    now = datetime.now(timezone.utc)
    return {
        "items": [
            {"title": "CSR-1 filing", "date": (now + timedelta(days=14)).date().isoformat(), "status": "upcoming"},
            {"title": "Board meeting report", "date": (now + timedelta(days=4)).date().isoformat(), "status": "this_week"},
            {"title": "Annual audit package", "date": (now - timedelta(days=2)).date().isoformat(), "status": "overdue"},
        ]
    }


@api_router.post("/csr/proposals")
async def create_csr_proposal(payload: CsrProposalCreateInput, user=Depends(require_csr_partner)):
    if payload.proposedAmount <= 0 or payload.proposedAmount > 1_000_000_000:
        raise HTTPException(status_code=400, detail="Proposed amount must be between 1 and 1,000,000,000")
    project = await db.projects.find_one({"id": payload.projectId}, {"_id": 0, "id": 1, "title": 1})
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    sdg = sorted({int(s) for s in payload.sdgAlignment if int(s) in CSR_ALLOWED_SDG})
    if not sdg:
        raise HTTPException(status_code=400, detail="At least one valid SDG alignment is required")

    normalized_tranches = normalize_csr_tranches(payload.tranches)
    if not normalized_tranches:
        normalized_tranches = [{
            "amount": round(float(payload.proposedAmount), 2),
            "releaseDate": ensure_iso_date(payload.expectedCompletionDate),
            "status": "pending",
        }]
    tranche_total = round(sum(_safe_float(t.get("amount", 0)) for t in normalized_tranches), 2)
    if abs(tranche_total - round(float(payload.proposedAmount), 2)) > 1:
        raise HTTPException(status_code=400, detail="Total tranche amount must match proposed amount")

    business_objectives = sanitize_plain_text(payload.businessObjectives, 1000)
    if business_objectives and len(business_objectives) < 10:
        raise HTTPException(status_code=400, detail="Business objectives must be at least 10 characters")

    geo_focus = sanitize_plain_text(payload.geographicalFocusArea, 200)
    expected_completion = ensure_iso_date(payload.expectedCompletionDate)

    partner = await _get_or_create_csr_partner_context(user)
    proposal = {
        "id": str(uuid.uuid4()),
        "partnerId": partner.get("id", ""),
        "partnerUserId": user.get("id", ""),
        "projectId": payload.projectId,
        "projectTitle": project.get("title", "Project"),
        "proposedAmount": float(payload.proposedAmount),
        "tranches": normalized_tranches,
        "sdgAlignment": sdg,
        "businessObjectives": business_objectives,
        "expectedCompletionDate": expected_completion,
        "geographicalFocusArea": geo_focus,
        "status": "draft",
        "adminNotes": "",
        "docuSignEnvelopeId": "",
        "agreementUrl": "",
        "createdAt": datetime.now(timezone.utc).isoformat(),
        "updatedAt": datetime.now(timezone.utc).isoformat(),
    }
    # PyMongo may mutate the inserted dict with _id (ObjectId), which breaks JSON serialization.
    proposal_doc = dict(proposal)
    await db.csr_proposals.insert_one(proposal_doc)
    return {"message": "Proposal saved as draft", "proposal": proposal}


@api_router.get("/csr/proposals")
async def list_csr_proposals(user=Depends(require_csr_partner)):
    partner = await _get_or_create_csr_partner_context(user)
    proposals = await db.csr_proposals.find({"partnerId": partner.get("id", "")}, {"_id": 0}).sort("createdAt", -1).to_list(500)
    return {"proposals": proposals}


@api_router.put("/csr/proposals/{proposal_id}/status")
async def update_csr_proposal_status(proposal_id: str, payload: CsrProposalStatusUpdateInput, user=Depends(require_csr_partner)):
    requested = (payload.status or "").strip().lower()
    if requested not in CSR_PROPOSAL_STATUSES:
        raise HTTPException(status_code=400, detail="Invalid proposal status")
    if requested in ["under_review", "approved", "rejected"]:
        raise HTTPException(status_code=403, detail="Only admin can move proposal to review/approval states")

    partner = await _get_or_create_csr_partner_context(user)
    result = await db.csr_proposals.update_one(
        {"id": proposal_id, "partnerId": partner.get("id", "")},
        {"$set": {"status": requested, "updatedAt": datetime.now(timezone.utc).isoformat()}},
    )
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Proposal not found")
    updated = await db.csr_proposals.find_one({"id": proposal_id}, {"_id": 0})
    if requested == "submitted":
        admins = await db.users.find({"role": {"$in": ["admin", "super_admin"]}}, {"_id": 0, "id": 1}).to_list(100)
        for admin in admins:
            await db.notifications.insert_one({
                "id": str(uuid.uuid4()),
                "user_id": admin.get("id"),
                "type": "csr_proposal_submitted",
                "title": "New CSR Proposal Submitted",
                "message": f"{user.get('name', 'CSR Partner')} submitted proposal {updated.get('id', '')}.",
                "ref_id": updated.get("id", ""),
                "read": False,
                "created_at": datetime.now(timezone.utc).isoformat(),
            })
    return {"message": "Proposal status updated", "proposal": updated}


@api_router.post("/csr/funds/early-release-requests")
async def create_early_release_request(payload: CsrEarlyReleaseRequestInput, user=Depends(require_csr_partner)):
    tranche_name = sanitize_plain_text(payload.tranche_name, 80)
    if len(tranche_name) < 3:
        raise HTTPException(status_code=400, detail="Tranche name is required")
    reason = sanitize_plain_text(payload.reason, 800)
    if len(reason) < 20:
        raise HTTPException(status_code=400, detail="Reason must be at least 20 characters")
    requested_amount = _safe_float(payload.requested_amount or 0)
    if requested_amount < 0 or requested_amount > 1_000_000_000:
        raise HTTPException(status_code=400, detail="Invalid requested amount")

    partner = await _get_or_create_csr_partner_context(user)
    open_count = await db.csr_early_release_requests.count_documents({
        "partnerId": partner.get("id", ""),
        "status": "pending",
    })
    if open_count >= 20:
        raise HTTPException(status_code=429, detail="Too many pending requests. Please wait for review")

    req_id = str(uuid.uuid4())
    now_iso = datetime.now(timezone.utc).isoformat()
    request_doc = {
        "id": req_id,
        "partnerId": partner.get("id", ""),
        "partnerUserId": user.get("id", ""),
        "partnerName": partner.get("company_name", user.get("name", "CSR Partner")),
        "trancheName": tranche_name,
        "requestedAmount": round(requested_amount, 2),
        "reason": reason,
        "status": "pending",
        "adminNotes": "",
        "createdAt": now_iso,
        "updatedAt": now_iso,
    }
    request_doc_for_insert = dict(request_doc)
    await db.csr_early_release_requests.insert_one(request_doc_for_insert)

    admins = await db.users.find({"role": {"$in": ["admin", "super_admin"]}}, {"_id": 0, "id": 1}).to_list(100)
    for admin in admins:
        await db.notifications.insert_one({
            "id": str(uuid.uuid4()),
            "user_id": admin.get("id"),
            "type": "csr_early_release_request",
            "title": "CSR Early Release Request",
            "message": f"{request_doc['partnerName']} requested early release for {tranche_name}.",
            "ref_id": req_id,
            "read": False,
            "created_at": now_iso,
        })
    return {"message": "Early release request submitted", "request": request_doc}


@api_router.get("/csr/funds/early-release-requests")
async def list_early_release_requests(user=Depends(require_csr_partner)):
    partner = await _get_or_create_csr_partner_context(user)
    requests = await db.csr_early_release_requests.find(
        {"partnerId": partner.get("id", "")},
        {"_id": 0},
    ).sort("createdAt", -1).to_list(200)
    return {"requests": requests}


@api_router.get("/admin/csr/early-release-requests")
async def admin_list_early_release_requests(status: str = "pending", admin=Depends(require_admin)):
    query: Dict[str, Any] = {}
    requested_status = (status or "").strip().lower()
    if requested_status and requested_status != "all":
        if requested_status not in CSR_EARLY_RELEASE_STATUSES:
            raise HTTPException(status_code=400, detail="Invalid status")
        query["status"] = requested_status
    requests = await db.csr_early_release_requests.find(query, {"_id": 0}).sort("createdAt", -1).to_list(500)
    return {"requests": requests}


@api_router.put("/admin/csr/early-release-requests/{request_id}/review")
async def admin_review_early_release_request(request_id: str, payload: CsrEarlyReleaseReviewInput, admin=Depends(require_admin)):
    status = (payload.status or "").strip().lower()
    if status not in ["approved", "rejected"]:
        raise HTTPException(status_code=400, detail="Status must be approved or rejected")
    notes = sanitize_plain_text(payload.admin_notes, 500)
    result = await db.csr_early_release_requests.update_one(
        {"id": request_id},
        {"$set": {
            "status": status,
            "adminNotes": notes,
            "reviewedBy": admin.get("id", ""),
            "reviewedAt": datetime.now(timezone.utc).isoformat(),
            "updatedAt": datetime.now(timezone.utc).isoformat(),
        }},
    )
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Request not found")

    updated = await db.csr_early_release_requests.find_one({"id": request_id}, {"_id": 0})
    await db.notifications.insert_one({
        "id": str(uuid.uuid4()),
        "user_id": updated.get("partnerUserId", ""),
        "type": "csr_early_release_reviewed",
        "title": "Early Release Request Reviewed",
        "message": f"Your early release request was {status}.{(' Notes: ' + notes) if notes else ''}",
        "ref_id": request_id,
        "read": False,
        "created_at": datetime.now(timezone.utc).isoformat(),
    })
    return {"message": f"Request {status}", "request": updated}

# ─── SEED DATA ───
@app.on_event("startup")
async def seed_data():
    if not SEED_DEMO_DATA:
        logger.info("Skipping demo seed data (SEED_DEMO_DATA is false)")
        await get_system_settings()
        return
    admin_exists = await db.users.find_one({"email": "admin@sweezen.org"})
    super_admin_exists = await db.users.find_one({"email": "superadmin@sweezen.org"})
    tasks_exist = await db.tasks.count_documents({})
    datasets_exist = await db.datasets.count_documents({})
    await get_system_settings()
    
    if admin_exists and super_admin_exists and tasks_exist > 0 and datasets_exist > 0:
        return
    logger.info("Seeding initial data...")
    if not super_admin_exists:
        super_admin_password = get_seed_password("SEED_SUPERADMIN_PASSWORD", "super admin")
        super_admin_user = {
            "id": str(uuid.uuid4()), "name": "Sweezen Super Admin", "email": "superadmin@sweezen.org",
            "password_hash": hash_password(super_admin_password), "phone": "+91-9876543200",
            "role": "super_admin", "status": "active", "impact_points": 0, "hours_logged": 0, "badges": [],
            "created_at": datetime.now(timezone.utc).isoformat()
        }
        await db.users.insert_one(super_admin_user)
    if not admin_exists:
        admin_password = get_seed_password("SEED_ADMIN_PASSWORD", "admin")
        csr_password = get_seed_password("SEED_CSR_PASSWORD", "csr")
        # Admin user
        admin_user = {
            "id": str(uuid.uuid4()), "name": "Sweezen Admin", "email": "admin@sweezen.org",
            "password_hash": hash_password(admin_password), "phone": "+91-9876543210",
            "role": "admin", "status": "active", "impact_points": 0, "hours_logged": 0, "badges": [],
            "created_at": datetime.now(timezone.utc).isoformat()
        }
        await db.users.insert_one(admin_user)
        # Sample CSR user
        csr_user = {
            "id": str(uuid.uuid4()), "name": "CSR Partner", "email": "csr@company.com",
            "password_hash": hash_password(csr_password), "phone": "+91-9876543211",
            "role": "csr_partner", "status": "active", "impact_points": 0, "hours_logged": 0, "badges": [],
            "created_at": datetime.now(timezone.utc).isoformat(),
            "csrProfile": default_csr_profile({
                "companyName": "Sweezen CSR Corporate Partner",
                "industry": "Technology",
                "companySize": "500-5000",
                "csrBudgetFY": 2000000,
                "tier": "Gold",
                "kycStatus": "verified",
                "activeProjects": [],
            }),
        }
        await db.users.insert_one(csr_user)
        # Sample projects
        projects = [
        {"id": str(uuid.uuid4()), "title": "Rural Health Camps Initiative", "description": "Providing free medical check-ups and essential healthcare services to underserved rural communities across 5 districts. Our mobile health units travel to remote villages, offering preventive care, diagnostics, and health education.", "category": "healthcare", "location": "Uttar Pradesh, Bihar", "budget": 1500000, "raised": 980000, "beneficiary_count": 12500, "status": "active", "image_url": "https://images.unsplash.com/photo-1606309028742-4039c7b625b8?w=600", "milestones": [{"name": "Phase 1 - Setup", "status": "completed"}, {"name": "Phase 2 - Outreach", "status": "in_progress"}, {"name": "Phase 3 - Expansion", "status": "pending"}], "created_at": "2024-06-15T10:00:00+00:00", "updated_at": "2025-01-20T10:00:00+00:00", "created_by": admin_user["id"]},
        {"id": str(uuid.uuid4()), "title": "Highway Driver Wellness Program", "description": "Dedicated health lounges and wellness check-ups for long-haul truck drivers at key highway rest stops. Addressing cardiovascular health, mental wellness, and nutrition for one of India's most overlooked workforce segments.", "category": "healthcare", "location": "National Highways - NH44, NH48", "budget": 800000, "raised": 520000, "beneficiary_count": 5200, "status": "active", "image_url": "https://images.unsplash.com/photo-1606309028742-4039c7b625b8?w=600", "milestones": [{"name": "Lounge Setup", "status": "completed"}, {"name": "Medical Staff Recruitment", "status": "completed"}, {"name": "Operations Launch", "status": "in_progress"}], "created_at": "2024-08-20T10:00:00+00:00", "updated_at": "2025-02-10T10:00:00+00:00", "created_by": admin_user["id"]},
        {"id": str(uuid.uuid4()), "title": "Digital Literacy for Rural Youth", "description": "Empowering rural youth with essential digital skills through community learning centers. Covering basic computer literacy, internet safety, coding fundamentals, and career guidance in collaboration with local schools.", "category": "education", "location": "Madhya Pradesh, Rajasthan", "budget": 1200000, "raised": 870000, "beneficiary_count": 8500, "status": "active", "image_url": "https://images.unsplash.com/flagged/photo-1574097656146-0b43b7660cb6?w=600", "milestones": [{"name": "Center Setup", "status": "completed"}, {"name": "Curriculum Design", "status": "completed"}, {"name": "Enrollment Drive", "status": "in_progress"}, {"name": "Assessment Phase", "status": "pending"}], "created_at": "2024-04-10T10:00:00+00:00", "updated_at": "2025-01-15T10:00:00+00:00", "created_by": admin_user["id"]},
        {"id": str(uuid.uuid4()), "title": "Women Skill Development Centers", "description": "Establishing skill development centers for women in underserved communities, providing training in tailoring, handicrafts, food processing, and entrepreneurship. Creating pathways to financial independence.", "category": "education", "location": "Odisha, Bihar", "budget": 900000, "raised": 650000, "beneficiary_count": 3200, "status": "active", "image_url": "https://images.unsplash.com/photo-1763733593326-758b2271d725?w=600", "milestones": [{"name": "Facility Setup", "status": "completed"}, {"name": "Training Programs", "status": "in_progress"}, {"name": "Market Linkage", "status": "pending"}], "created_at": "2024-09-05T10:00:00+00:00", "updated_at": "2025-02-01T10:00:00+00:00", "created_by": admin_user["id"]},
        {"id": str(uuid.uuid4()), "title": "Community Reforestation Drive", "description": "Large-scale tree plantation drives across degraded forest lands and community spaces. Engaging volunteers and local communities in planting, nurturing, and monitoring native tree species for long-term ecological restoration.", "category": "environment", "location": "Uttarakhand, Himachal Pradesh", "budget": 600000, "raised": 420000, "beneficiary_count": 15000, "status": "active", "image_url": "https://images.unsplash.com/photo-1758390286700-06f93fddec45?w=600", "milestones": [{"name": "Land Identification", "status": "completed"}, {"name": "Sapling Procurement", "status": "completed"}, {"name": "Plantation Phase 1", "status": "in_progress"}, {"name": "Monitoring & Maintenance", "status": "pending"}], "created_at": "2024-03-22T10:00:00+00:00", "updated_at": "2025-01-28T10:00:00+00:00", "created_by": admin_user["id"]},
        {"id": str(uuid.uuid4()), "title": "Clean Water & Sanitation Access", "description": "Installing water purification systems and sanitation facilities in rural villages lacking clean water access. Complemented by hygiene education programs to ensure sustainable community health outcomes.", "category": "environment", "location": "Jharkhand, Chhattisgarh", "budget": 1000000, "raised": 780000, "beneficiary_count": 9800, "status": "active", "image_url": "https://images.unsplash.com/photo-1758390286700-06f93fddec45?w=600", "milestones": [{"name": "Survey & Assessment", "status": "completed"}, {"name": "Installation Phase", "status": "in_progress"}, {"name": "Community Training", "status": "pending"}], "created_at": "2024-07-01T10:00:00+00:00", "updated_at": "2025-02-15T10:00:00+00:00", "created_by": admin_user["id"]},
    ]
    if not admin_exists:
        await db.projects.insert_many(projects)
        # Sample publications
        publications = [
            {"id": str(uuid.uuid4()), "title": "Annual Impact Report 2024-25", "content": "Sweezen Foundation's annual impact report showcasing our work across healthcare, education, and environmental sustainability. This year, we reached over 54,000 beneficiaries across 12 districts, deployed 6 active projects, and partnered with 8 CSR partners to create lasting change in underserved communities.", "type": "report", "image_url": "https://images.unsplash.com/photo-1758691736975-9f7f643d178e?w=600", "published": True, "author_id": admin_user["id"], "author_name": "Sweezen Admin", "created_at": "2025-01-15T10:00:00+00:00", "updated_at": "2025-01-15T10:00:00+00:00"},
            {"id": str(uuid.uuid4()), "title": "Building Bridges: How CSR Partnerships Transform Rural India", "content": "Corporate Social Responsibility is more than compliance. In this article, we explore how Sweezen Foundation's transparent CSR portal and real-time impact dashboards are helping companies move from obligation to genuine impact. With automated CSR-1 reporting and ESG-aligned metrics, our partners are seeing measurable social returns.", "type": "blog", "image_url": "https://images.unsplash.com/photo-1758691736975-9f7f643d178e?w=600", "published": True, "author_id": admin_user["id"], "author_name": "Sweezen Admin", "created_at": "2025-02-01T10:00:00+00:00", "updated_at": "2025-02-01T10:00:00+00:00"},
            {"id": str(uuid.uuid4()), "title": "Humanity Card: Dignity-First Beneficiary Identity", "content": "The Humanity Card is Sweezen Foundation's flagship innovation - a smart QR-based identity system that enables dignified, fraud-proof service delivery without requiring Aadhaar or sensitive documents. Learn how this technology is transforming beneficiary management across our projects.", "type": "news", "image_url": "https://images.unsplash.com/photo-1606309028742-4039c7b625b8?w=600", "published": True, "author_id": admin_user["id"], "author_name": "Sweezen Admin", "created_at": "2025-02-10T10:00:00+00:00", "updated_at": "2025-02-10T10:00:00+00:00"},
        ]
        await db.publications.insert_many(publications)
        # Sample CSR partners
        csr_partners = [
            {"id": str(uuid.uuid4()), "user_id": csr_user["id"], "company_name": "TechCorp India", "contact_person": "Rahul Sharma", "email": "csr@company.com", "phone": "+91-9876543212", "tier": "gold", "funds_committed": 2000000, "funds_utilized": 1450000, "project_ids": [], "status": "active", "created_at": "2024-04-01T10:00:00+00:00"},
            {"id": str(uuid.uuid4()), "company_name": "GreenLeaf Industries", "contact_person": "Priya Patel", "email": "csr@greenleaf.co.in", "phone": "+91-9876543213", "tier": "silver", "funds_committed": 1000000, "funds_utilized": 680000, "project_ids": [], "status": "active", "created_at": "2024-06-15T10:00:00+00:00"},
            {"id": str(uuid.uuid4()), "company_name": "Bharat Finance Ltd", "contact_person": "Arun Kumar", "email": "csr@bharatfinance.com", "phone": "+91-9876543214", "tier": "platinum", "funds_committed": 5000000, "funds_utilized": 3200000, "project_ids": [], "status": "active", "created_at": "2024-02-10T10:00:00+00:00"},
        ]
        await db.csr_partners.insert_many(csr_partners)
        # Sample donations
        donations = [
            {"id": str(uuid.uuid4()), "order_id": f"order_mock_{uuid.uuid4().hex[:12]}", "donor_name": "Amit Verma", "donor_email": "amit@gmail.com", "donor_phone": "+91-9988776655", "donor_pan": "ABCPV1234D", "amount": 5000, "project_id": projects[0]["id"], "is_recurring": False, "status": "completed", "payment_id": f"pay_mock_{uuid.uuid4().hex[:12]}", "receipt_number": f"SF-20250115-{uuid.uuid4().hex[:6].upper()}", "razorpay_mode": False, "created_at": "2025-01-15T14:30:00+00:00"},
            {"id": str(uuid.uuid4()), "order_id": f"order_mock_{uuid.uuid4().hex[:12]}", "donor_name": "Sneha Iyer", "donor_email": "sneha@outlook.com", "donor_phone": "+91-8877665544", "donor_pan": "CDEPI5678F", "amount": 10000, "project_id": projects[2]["id"], "is_recurring": True, "status": "completed", "payment_id": f"pay_mock_{uuid.uuid4().hex[:12]}", "receipt_number": f"SF-20250201-{uuid.uuid4().hex[:6].upper()}", "razorpay_mode": False, "created_at": "2025-02-01T09:15:00+00:00"},
            {"id": str(uuid.uuid4()), "order_id": f"order_mock_{uuid.uuid4().hex[:12]}", "donor_name": "Rajesh Gupta", "donor_email": "rajesh@company.com", "donor_phone": "+91-7766554433", "donor_pan": "FGHPG9012H", "amount": 25000, "project_id": projects[4]["id"], "is_recurring": False, "status": "completed", "payment_id": f"pay_mock_{uuid.uuid4().hex[:12]}", "receipt_number": f"SF-20250210-{uuid.uuid4().hex[:6].upper()}", "razorpay_mode": False, "created_at": "2025-02-10T16:45:00+00:00"},
        ]
        await db.donations.insert_many(donations)

    # Seed volunteer tasks
    if tasks_exist == 0:
        tasks = [
            {"id": str(uuid.uuid4()), "title": "Health Camp Volunteer - Lucknow", "description": "Assist medical team at rural health camp.", "category": "healthcare", "location": "Lucknow, UP", "lat": 26.85, "lng": 80.95, "date": "2025-03-15", "hours_required": 8, "skills_needed": ["communication", "first_aid"], "max_volunteers": 15, "applied": [], "status": "open", "created_at": "2025-02-20T10:00:00+00:00"},
            {"id": str(uuid.uuid4()), "title": "Digital Literacy Instructor", "description": "Teach basic computer skills to rural youth.", "category": "education", "location": "Bhopal, MP", "lat": 23.26, "lng": 77.41, "date": "2025-03-20", "hours_required": 6, "skills_needed": ["teaching", "computers"], "max_volunteers": 8, "applied": [], "status": "open", "created_at": "2025-02-22T10:00:00+00:00"},
            {"id": str(uuid.uuid4()), "title": "Tree Plantation Drive", "description": "Join our community reforestation drive.", "category": "environment", "location": "Dehradun, UK", "lat": 30.32, "lng": 78.03, "date": "2025-04-05", "hours_required": 5, "skills_needed": ["physical_fitness"], "max_volunteers": 30, "applied": [], "status": "open", "created_at": "2025-02-25T10:00:00+00:00"},
            {"id": str(uuid.uuid4()), "title": "Women Empowerment Workshop Facilitator", "description": "Facilitate skill development workshops for women.", "category": "education", "location": "Patna, Bihar", "lat": 25.61, "lng": 85.14, "date": "2025-03-25", "hours_required": 4, "skills_needed": ["teaching", "empathy"], "max_volunteers": 5, "applied": [], "status": "open", "created_at": "2025-03-01T10:00:00+00:00"},
        ]
        await db.tasks.insert_many(tasks)

    # Seed researcher datasets
    if datasets_exist == 0:
        datasets = [
            {"id": str(uuid.uuid4()), "title": "Healthcare Impact Data 2024-25", "description": "Anonymized data on healthcare program outcomes across 5 districts.", "type": "healthcare", "records": 12500, "format": "CSV", "size": "2.4 MB", "created_at": "2025-01-15T10:00:00+00:00"},
            {"id": str(uuid.uuid4()), "title": "Education Program Enrollment Data", "description": "Anonymized enrollment and completion rates for digital literacy programs.", "type": "education", "records": 8500, "format": "CSV", "size": "1.8 MB", "created_at": "2025-02-01T10:00:00+00:00"},
            {"id": str(uuid.uuid4()), "title": "Environmental Impact Metrics", "description": "Tree survival rates, carbon offset estimates, and water quality measurements.", "type": "environment", "records": 5200, "format": "CSV", "size": "1.1 MB", "created_at": "2025-02-10T10:00:00+00:00"},
        ]
        await db.datasets.insert_many(datasets)
    logger.info("Seed data created successfully")

# ─── 80G RECEIPT PDF ───
@api_router.get("/donations/{donation_id}/receipt-pdf")
async def download_80g_receipt(donation_id: str, user=Depends(get_current_user)):
    if not donation_id or len(donation_id) > 128:
        raise HTTPException(status_code=400, detail="Invalid donation identifier")
    donation = await db.donations.find_one({"id": donation_id}, {"_id": 0})
    if not donation:
        donation = await db.donations.find_one({"order_id": donation_id}, {"_id": 0})
    if not donation:
        raise HTTPException(status_code=404, detail="Donation not found")
    is_admin = user.get("role") in ["admin", "super_admin"]
    is_owner = donation.get("donor_id") == user.get("id") or donation.get("donor_email") == user.get("email")
    if not (is_admin or is_owner):
        raise HTTPException(status_code=403, detail="Not authorized to access this receipt")
    if donation.get("project_id"):
        project = await db.projects.find_one({"id": donation["project_id"]}, {"_id": 0})
        donation["project_name"] = project["title"] if project else "General Fund"
    else:
        donation["project_name"] = "General Fund"
    pdf_buffer = generate_80g_receipt_pdf(donation)
    return StreamingResponse(pdf_buffer, media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=80G_Receipt_{donation.get('receipt_number', 'SF')}.pdf"})

# ─── CSR-1 REPORT PDF ───
@api_router.get("/csr/reports/pdf")
async def download_csr1_report(user=Depends(require_csr)):
    if user.get("role") in ["admin", "super_admin"]:
        projects = await db.projects.find({}, {"_id": 0}).to_list(1000)
        donations = await db.donations.find({"status": "completed"}, {"_id": 0}).to_list(10000)
        partners = await db.csr_partners.find({}, {"_id": 0}).to_list(1000)
    else:
        partner = await _get_or_create_csr_partner_context(user)
        projects = await _get_csr_partner_projects(partner)
        project_ids = [p.get("id", "") for p in projects]
        donations = await db.donations.find(
            {"status": "completed", "project_id": {"$in": project_ids}} if project_ids else {"project_id": "__none__"},
            {"_id": 0},
        ).to_list(10000)
        partners = [partner]

    total_raised = sum(float(d.get("amount", 0) or 0) for d in donations)
    total_committed = sum(float(p.get("funds_committed", 0) or 0) for p in partners)
    total_utilized = sum(float(p.get("funds_utilized", 0) or 0) for p in partners)
    category_breakdown = {}
    for p in projects:
        cat = p.get("category", "other")
        if cat not in category_breakdown:
            category_breakdown[cat] = {"projects": 0, "budget": 0, "raised": 0, "beneficiaries": 0}
        category_breakdown[cat]["projects"] += 1
        category_breakdown[cat]["budget"] += float(p.get("budget", 0) or 0)
        category_breakdown[cat]["raised"] += float(p.get("raised", 0) or 0)
        category_breakdown[cat]["beneficiaries"] += int(p.get("beneficiary_count", 0) or 0)
    report_data = {
        "financial_year": "2024-25", "total_projects": len(projects), "total_donations": len(donations),
        "total_raised": total_raised, "total_partners": len(partners),
        "total_committed": total_committed, "total_utilized": total_utilized,
        "utilization_rate": round((total_utilized / total_committed * 100) if total_committed else 0, 1),
        "category_breakdown": category_breakdown, "partners": partners,
        "sdg_alignment": {"SDG 3": "Good Health & Well-Being", "SDG 4": "Quality Education", "SDG 13": "Climate Action", "SDG 17": "Partnerships for Goals"},
    }
    pdf_buffer = generate_csr1_report_pdf(report_data)
    return StreamingResponse(pdf_buffer, media_type="application/pdf",
        headers={"Content-Disposition": "attachment; filename=CSR1_Report_Sweezen_Foundation.pdf"})

# ─── ADMIN REPORT EXPORTS ───
@api_router.get("/admin/reports/donations/pdf")
async def export_donations_pdf(user=Depends(require_admin)):
    donations = await db.donations.find({"status": "completed"}, {"_id": 0}).sort("created_at", -1).to_list(500)
    total = sum(d.get("amount", 0) for d in donations)
    avg = total / len(donations) if donations else 0
    stats = {"count": len(donations), "total": total, "avg": avg}
    pdf_buffer = generate_donation_report_pdf(donations, stats)
    return StreamingResponse(pdf_buffer, media_type="application/pdf",
        headers={"Content-Disposition": "attachment; filename=Donation_Report_Sweezen.pdf"})

@api_router.get("/admin/reports/donations/csv")
async def export_donations_csv(user=Depends(require_admin)):
    donations = await db.donations.find({"status": "completed"}, {"_id": 0}).sort("created_at", -1).to_list(500)
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=["donor_name", "donor_email", "donor_phone", "amount", "status", "receipt_number", "is_recurring", "created_at"])
    writer.writeheader()
    for d in donations:
        writer.writerow({k: d.get(k, '') for k in writer.fieldnames})
    output.seek(0)
    return StreamingResponse(io.BytesIO(output.getvalue().encode()), media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=donations_export.csv"})

@api_router.get("/admin/reports/volunteers/csv")
async def export_volunteers_csv(user=Depends(require_admin)):
    volunteers = await db.users.find({"role": "volunteer"}, {"_id": 0, "password_hash": 0}).to_list(500)
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=["name", "email", "phone", "skills", "availability", "hours_logged", "impact_points", "status", "created_at"])
    writer.writeheader()
    for v in volunteers:
        row = {k: v.get(k, '') for k in writer.fieldnames}
        row["skills"] = ", ".join(v.get("skills", []))
        writer.writerow(row)
    output.seek(0)
    return StreamingResponse(io.BytesIO(output.getvalue().encode()), media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=volunteers_export.csv"})

# ─── ADMIN APPROVAL WORKFLOW ───
@api_router.get("/admin/pending-users")
async def get_pending_users(user=Depends(require_admin)):
    pending = await db.users.find({"status": "pending"}, {"_id": 0, "password_hash": 0}).sort("created_at", -1).to_list(100)
    return {"users": pending}

@api_router.put("/admin/users/{user_id}/approve")
async def approve_user(user_id: str, data: UserApproval, request: Request, admin=Depends(require_admin)):
    target = await db.users.find_one({"id": user_id}, {"_id": 0})
    if not target:
        raise HTTPException(status_code=404, detail="User not found")
    requested_status = (data.status or "").strip().lower()
    if requested_status not in ["approved", "rejected"]:
        raise HTTPException(status_code=400, detail="Status must be approved or rejected")

    if target.get("role") not in APPROVAL_REQUIRED_ROLES and target.get("status") == "active":
        raise HTTPException(status_code=400, detail="Approval workflow is not applicable for this user role")

    new_status = "active" if requested_status == "approved" else "rejected"
    update_set: Dict[str, Any] = {"status": new_status}
    if new_status == "active" and target.get("role") == "volunteer" and not target.get("volunteerProfile"):
        update_set["volunteerProfile"] = default_volunteer_profile({
            "skills": target.get("skills", []),
            "joinedAt": target.get("created_at", datetime.now(timezone.utc).isoformat()),
            "lastActiveAt": datetime.now(timezone.utc).isoformat(),
        })
    await db.users.update_one({"id": user_id}, {"$set": update_set})
    await db.notifications.insert_one({
        "id": str(uuid.uuid4()), "user_id": user_id, "type": "account_status",
        "title": f"Account {new_status.capitalize()}",
        "message": f"Your account has been {new_status}. {data.reason}" if data.reason else f"Your account has been {new_status}.",
        "read": False, "created_at": datetime.now(timezone.utc).isoformat()
    })
    await write_audit_log(
        admin,
        "approved_user" if new_status == "active" else "rejected_user",
        target_id=user_id,
        target_type="user",
        details={"reason": data.reason},
        ip=get_client_ip(request),
    )
    return {"message": f"User {new_status}"}

# ─── NOTIFICATIONS ───
@api_router.get("/notifications")
async def get_notifications(user=Depends(get_current_user)):
    query = {"$or": [{"user_id": user["id"]}, {"user_id": "admin" if user.get("role") in ["admin", "super_admin"] else "none"}]}
    notifs = await db.notifications.find(query, {"_id": 0}).sort("created_at", -1).to_list(50)
    return {"notifications": notifs}

@api_router.put("/notifications/{notif_id}/read")
async def mark_notification_read(notif_id: str, user=Depends(get_current_user)):
    allowed_user_ids = [user["id"]]
    if user.get("role") in ["admin", "super_admin"]:
        allowed_user_ids.append("admin")
    result = await db.notifications.update_one(
        {"id": notif_id, "user_id": {"$in": allowed_user_ids}},
        {"$set": {"read": True}},
    )
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Notification not found")
    return {"message": "Marked as read"}

# ─── VOLUNTEER ROUTES ───
@api_router.get("/volunteer/dashboard")
async def volunteer_dashboard(user=Depends(get_current_user)):
    if user.get("role") not in ["volunteer", "admin", "super_admin"]:
        raise HTTPException(status_code=403, detail="Volunteer access required")
    full_user = await db.users.find_one({"id": user["id"]}, {"_id": 0, "password_hash": 0}) or user
    profile = default_volunteer_profile(full_user.get("volunteerProfile", {}))
    hours_logs = await db.hours_logs.find({"user_id": user["id"]}, {"_id": 0}).sort("created_at", -1).to_list(200)
    task_logs = await db.task_work_logs.find({"volunteer_id": user["id"]}, {"_id": 0}).sort("created_at", -1).to_list(200)
    scans = await db.humanity_card_logs.find({"volunteer_id": user["id"]}, {"_id": 0}).sort("created_at", -1).to_list(200)
    all_tasks = await db.tasks.find({}, {"_id": 0}).sort("created_at", -1).to_list(300)

    total_hours = sum(float(h.get("hours", 0)) for h in hours_logs) + sum(float(h.get("hours", 0)) for h in task_logs)
    profile["totalHoursLogged"] = round(total_hours, 2)
    profile["impactPoints"] = max(int(profile.get("impactPoints", 0)), int(full_user.get("impact_points", 0)))
    profile["humanityCardScans"] = max(int(profile.get("humanityCardScans", 0)), len(scans))
    profile["currentLevel"] = compute_level(profile["impactPoints"])
    profile["lastActiveAt"] = datetime.now(timezone.utc).isoformat()

    active_tasks = []
    tasks_completed = 0
    for task in all_tasks:
        app = normalize_application(task, user["id"])
        assigned = user_assigned_to_task(task, user["id"])
        completed = user_completed_task(task, user["id"])
        status = "Not Started"
        if app:
            map_status = {
                "pending": "Submitted",
                "approved": "In Progress",
                "rejected": "Rejected",
                "under_review": "Submitted",
            }
            status = map_status.get(app.get("status", "pending"), "Submitted")
        if assigned:
            status = "In Progress"
        if task.get("status") == "under_review":
            status = "Submitted"
        if completed:
            status = "Approved"
            tasks_completed += 1

        if app or assigned or completed:
            active_tasks.append({
                "id": task.get("id"),
                "title": task.get("title", ""),
                "projectName": task.get("project_name", "Foundation Project"),
                "category": task.get("category", "general"),
                "district": task.get("district", ""),
                "state": task.get("state", ""),
                "dueDate": task.get("due_date") or task.get("date", ""),
                "estimatedHours": task.get("estimated_hours", task.get("hours_required", 0)),
                "status": status,
            })

    timeline = []
    for log in task_logs[:40]:
        timeline.append({
            "type": "hours",
            "title": f"Logged {log.get('hours', 0)} hours on {log.get('task_title', 'Task')}",
            "date": log.get("created_at", ""),
        })
    for scan in scans[:40]:
        timeline.append({
            "type": "scan",
            "title": f"Scanned Humanity Card ending {scan.get('humanityCardMasked', '0000')}",
            "date": scan.get("created_at", ""),
        })
    for b in profile.get("badgesEarned", [])[:20]:
        timeline.append({
            "type": "badge",
            "title": f"Earned badge: {b.get('badgeId', 'badge').replace('_', ' ').title()}",
            "date": b.get("earnedAt", ""),
        })
    timeline = sorted(timeline, key=lambda x: x.get("date", ""), reverse=True)[:40]

    profile["completedTasks"] = list(set(profile.get("completedTasks", []) + [t.get("id") for t in active_tasks if t.get("status") == "Approved"]))
    profile["assignedTasks"] = list(set(profile.get("assignedTasks", []) + [t.get("id") for t in active_tasks if t.get("status") in ["In Progress", "Submitted"]]))

    await db.users.update_one(
        {"id": user["id"]},
        {
            "$set": {
                "volunteerProfile": profile,
                "impact_points": profile["impactPoints"],
                "hours_logged": profile["totalHoursLogged"],
            }
        },
    )

    next_level = next_level_info(int(profile["impactPoints"]))
    return {
        "user": {
            "id": full_user.get("id"),
            "name": full_user.get("name", "Volunteer"),
            "email": full_user.get("email", ""),
            "role": full_user.get("role", "volunteer"),
            "volunteerProfile": profile,
        },
        "stats": {
            "totalHoursLogged": profile["totalHoursLogged"],
            "impactPoints": profile["impactPoints"],
            "tasksCompleted": tasks_completed,
            "humanityCardScans": profile["humanityCardScans"],
        },
        "level": next_level,
        "activeTasks": active_tasks,
        # Backward compatibility for older tests/clients.
        "available_tasks": active_tasks,
        "hours_logged": profile["totalHoursLogged"],
        "timeline": timeline,
        "notificationsCount": await db.notifications.count_documents({"user_id": user["id"], "read": False}),
    }

@api_router.get("/volunteer/tasks")
async def get_volunteer_tasks(
    search: str = "",
    category: str = "",
    district: str = "",
    sort: str = "relevant",
    user=Depends(require_volunteer_or_admin)
):
    tasks = await db.tasks.find({"status": {"$in": ["open", "active"]}}, {"_id": 0}).to_list(500)
    full_user = await db.users.find_one({"id": user["id"]}, {"_id": 0, "password_hash": 0}) or user
    profile = default_volunteer_profile(full_user.get("volunteerProfile", {}))
    skills = set((profile.get("skills", []) or full_user.get("skills", [])))

    filtered = []
    for task in tasks:
        text_blob = " ".join([
            task.get("title", ""),
            task.get("description", ""),
            task.get("location", ""),
            task.get("district", ""),
            task.get("state", ""),
            " ".join(task.get("skills_needed", [])),
        ]).lower()
        if search and search.lower() not in text_blob:
            continue
        if category and task.get("category", "").lower() != category.lower():
            continue
        if district and district.lower() not in (task.get("district") or task.get("location", "")).lower():
            continue

        required = set(task.get("skills_needed", []))
        match_pct = 100
        if required:
            match_pct = int((len(required.intersection(skills)) / len(required)) * 100)

        app = normalize_application(task, user["id"])
        filtered.append({
            "id": task.get("id"),
            "title": task.get("title", ""),
            "description": task.get("description", ""),
            "category": task.get("category", "general"),
            "projectName": task.get("project_name", "Foundation Project"),
            "location": task.get("location", ""),
            "district": task.get("district", ""),
            "state": task.get("state", ""),
            "requiredSkills": task.get("skills_needed", []),
            "duration": task.get("date", ""),
            "estimatedHours": task.get("estimated_hours", task.get("hours_required", 0)),
            "volunteersNeeded": max(0, int(task.get("max_volunteers", 0) - len(task.get("assigned_volunteers", [])))),
            "skillsMatch": match_pct,
            "applicationStatus": app.get("status") if app else None,
            "createdAt": task.get("created_at", ""),
        })

    if sort == "newest":
        filtered.sort(key=lambda x: x.get("createdAt", ""), reverse=True)
    elif sort == "highest_impact":
        filtered.sort(key=lambda x: x.get("estimatedHours", 0), reverse=True)
    elif sort == "closest":
        filtered.sort(key=lambda x: x.get("district", ""))
    else:
        filtered.sort(key=lambda x: (x.get("skillsMatch", 0), x.get("createdAt", "")), reverse=True)

    my_apps = []
    for t in filtered:
        if t.get("applicationStatus"):
            my_apps.append({
                "taskId": t.get("id"),
                "title": t.get("title"),
                "status": t.get("applicationStatus"),
                "projectName": t.get("projectName"),
                "location": t.get("location"),
            })

    return {"tasks": filtered, "myApplications": my_apps}

@api_router.get("/volunteer/tasks/my-applications")
async def my_task_applications(user=Depends(require_volunteer_or_admin)):
    tasks = await db.tasks.find({}, {"_id": 0}).to_list(500)
    apps = []
    for task in tasks:
        app = normalize_application(task, user["id"])
        if app:
            apps.append({
                "task_id": task.get("id"),
                "task_title": task.get("title", ""),
                "project_name": task.get("project_name", ""),
                "status": app.get("status", "pending"),
                "applied_at": app.get("applied_at", ""),
            })
    apps.sort(key=lambda x: x.get("applied_at", ""), reverse=True)
    return {"applications": apps}

@api_router.get("/volunteer/tasks/{task_id}")
async def volunteer_task_detail(task_id: str, user=Depends(require_volunteer_or_admin)):
    task = await db.tasks.find_one({"id": task_id}, {"_id": 0})
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    app = normalize_application(task, user["id"])
    logs = await db.task_work_logs.find({"task_id": task_id, "volunteer_id": user["id"]}, {"_id": 0}).sort("created_at", -1).to_list(200)
    return {"task": task, "application": app, "logs": logs}

@api_router.post("/volunteer/tasks/{task_id}/save")
async def save_task_for_later(task_id: str, user=Depends(require_volunteer_or_admin)):
    task = await db.tasks.find_one({"id": task_id}, {"_id": 0})
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    full_user = await db.users.find_one({"id": user["id"]}, {"_id": 0}) or user
    profile = default_volunteer_profile(full_user.get("volunteerProfile", {}))
    saved = set(profile.get("savedTasks", []))
    if task_id in saved:
        saved.remove(task_id)
    else:
        saved.add(task_id)
    profile["savedTasks"] = list(saved)
    await db.users.update_one({"id": user["id"]}, {"$set": {"volunteerProfile": profile}})
    return {"savedTasks": profile["savedTasks"]}

@api_router.post("/volunteer/tasks/{task_id}/apply")
async def apply_for_task(task_id: str, payload: VolunteerTaskApplicationInput = VolunteerTaskApplicationInput(), user=Depends(require_volunteer_or_admin)):
    task = await db.tasks.find_one({"id": task_id}, {"_id": 0})
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    existing = normalize_application(task, user["id"])
    if existing:
        raise HTTPException(status_code=400, detail="Already applied")

    application = {
        "volunteer_id": user["id"],
        "status": "pending",
        "matched_skills": payload.matched_skills,
        "availability": {
            "start": payload.availability_start,
            "end": payload.availability_end,
        },
        "message": payload.message[:200],
        "applied_at": datetime.now(timezone.utc).isoformat(),
    }
    await db.tasks.update_one({"id": task_id}, {"$push": {"applied": application}})

    admins = await db.users.find({"role": {"$in": ["admin", "super_admin"]}}, {"_id": 0, "id": 1}).to_list(50)
    for admin in admins:
        await db.notifications.insert_one({
            "id": str(uuid.uuid4()),
            "user_id": admin.get("id", "admin"),
            "type": "task_application",
            "title": "New volunteer task application",
            "message": f"{user.get('name', 'Volunteer')} applied for {task.get('title', 'a task')}",
            "ref_id": task_id,
            "read": False,
            "created_at": datetime.now(timezone.utc).isoformat(),
        })

    return {"message": "Application submitted"}

@api_router.post("/volunteer/hours")
async def log_volunteer_hours(data: HoursLog, user=Depends(require_volunteer_or_admin)):
    log = {
        "id": str(uuid.uuid4()), "user_id": user["id"], "task_id": data.task_id,
        "hours": data.hours, "notes": data.notes,
        "created_at": datetime.now(timezone.utc).isoformat()
    }
    await db.hours_logs.insert_one(log)
    await db.users.update_one({"id": user["id"]}, {
        "$inc": {"hours_logged": data.hours, "impact_points": int(data.hours * 10)}
    })
    # Check badge milestones
    updated_user = await db.users.find_one({"id": user["id"]}, {"_id": 0})
    total_hours = updated_user.get("hours_logged", 0)
    badges = updated_user.get("badges", [])
    new_badges = []
    if total_hours >= 10 and "Rising Star" not in badges:
        new_badges.append("Rising Star")
    if total_hours >= 50 and "Dedicated Volunteer" not in badges:
        new_badges.append("Dedicated Volunteer")
    if total_hours >= 100 and "Impact Champion" not in badges:
        new_badges.append("Impact Champion")
    if new_badges:
        await db.users.update_one({"id": user["id"]}, {"$push": {"badges": {"$each": new_badges}}})
    return {"message": "Hours logged", "hours": data.hours, "new_badges": new_badges}

@api_router.post("/volunteer/tasks/{task_id}/log")
async def log_task_hours(task_id: str, payload: VolunteerTaskLogInput, user=Depends(require_volunteer_or_admin)):
    task = await db.tasks.find_one({"id": task_id}, {"_id": 0})
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    if payload.hours <= 0 or payload.hours > 12:
        raise HTTPException(status_code=400, detail="Hours must be between 0.5 and 12")
    if len(payload.description.strip()) < 20:
        raise HTTPException(status_code=400, detail="Description must be at least 20 characters")

    item = {
        "id": str(uuid.uuid4()),
        "task_id": task_id,
        "task_title": task.get("title", "Task"),
        "project_name": task.get("project_name", "Foundation Project"),
        "volunteer_id": user["id"],
        "date_worked": payload.date_worked,
        "hours": payload.hours,
        "activity_type": payload.activity_type,
        "description": payload.description[:500],
        "evidence_photos": payload.evidence_photos[:5],
        "location_name": payload.location_name,
        "geo_lat": payload.geo_lat,
        "geo_lng": payload.geo_lng,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    await db.task_work_logs.insert_one(item)

    full_user = await db.users.find_one({"id": user["id"]}, {"_id": 0}) or user
    profile = default_volunteer_profile(full_user.get("volunteerProfile", {}))
    profile["totalHoursLogged"] = round(float(profile.get("totalHoursLogged", 0)) + float(payload.hours), 2)
    profile["impactPoints"] = int(profile.get("impactPoints", 0)) + int(payload.hours * 10)
    profile["currentLevel"] = compute_level(profile["impactPoints"])
    profile["lastActiveAt"] = datetime.now(timezone.utc).isoformat()
    await db.users.update_one(
        {"id": user["id"]},
        {"$set": {"volunteerProfile": profile, "impact_points": profile["impactPoints"], "hours_logged": profile["totalHoursLogged"]}},
    )
    return {"message": "Hours logged", "log": item, "level": next_level_info(profile["impactPoints"]) }

@api_router.get("/volunteer/tasks/{task_id}/logs")
async def list_task_logs(task_id: str, user=Depends(require_volunteer_or_admin)):
    logs = await db.task_work_logs.find({"task_id": task_id, "volunteer_id": user["id"]}, {"_id": 0}).sort("created_at", -1).to_list(300)
    return {"logs": logs}

@api_router.post("/volunteer/tasks/{task_id}/submit")
async def submit_task_work(task_id: str, payload: VolunteerTaskSubmitInput, user=Depends(require_volunteer_or_admin)):
    task = await db.tasks.find_one({"id": task_id}, {"_id": 0})
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")

    app_found = False
    updated_applied = []
    for app in task.get("applied", []):
        if isinstance(app, str) and app == user["id"]:
            app_found = True
            updated_applied.append({
                "volunteer_id": user["id"],
                "status": "under_review",
                "message": payload.final_note,
                "applied_at": datetime.now(timezone.utc).isoformat(),
                "submitted_at": datetime.now(timezone.utc).isoformat(),
            })
        elif isinstance(app, dict) and (app.get("volunteer_id") == user["id"] or app.get("user_id") == user["id"]):
            app_found = True
            updated_applied.append({**app, "status": "under_review", "submitted_at": datetime.now(timezone.utc).isoformat(), "final_note": payload.final_note})
        else:
            updated_applied.append(app)
    if not app_found:
        raise HTTPException(status_code=400, detail="You must apply for this task before submitting")

    await db.tasks.update_one({"id": task_id}, {"$set": {"applied": updated_applied, "status": "under_review"}})

    admins = await db.users.find({"role": {"$in": ["admin", "super_admin"]}}, {"_id": 0, "id": 1}).to_list(50)
    for admin in admins:
        await db.notifications.insert_one({
            "id": str(uuid.uuid4()),
            "user_id": admin.get("id", "admin"),
            "type": "task_submission",
            "title": "Volunteer task submitted",
            "message": f"{user.get('name', 'Volunteer')} submitted work for {task.get('title', 'task')}",
            "ref_id": task_id,
            "read": False,
            "created_at": datetime.now(timezone.utc).isoformat(),
        })
    return {"message": "Submitted for admin review", "status": "under_review"}

@api_router.post("/volunteer/humanity-card/scan")
async def scan_humanity_card(payload: HumanityCardScanInput, user=Depends(get_current_user)):
    if user.get("role") not in ["volunteer", "admin", "super_admin"]:
        raise HTTPException(status_code=403, detail="Volunteer access required")

    safe_lookup = sanitize_humanity_card_lookup(payload.card_code)
    scan = {
        "id": str(uuid.uuid4()),
        "volunteer_id": user["id"],
        "humanityCardMasked": safe_lookup["humanityCardMasked"],
        "ageGroup": safe_lookup["ageGroup"],
        "village": safe_lookup["village"],
        "serviceHistory": safe_lookup["serviceHistory"],
        "service_type": payload.service_type,
        "service_subtype": payload.service_subtype,
        "notes": payload.notes[:200],
        "quantity": max(1, payload.quantity),
        "photo_url": payload.photo_url,
        "geo_lat": payload.geo_lat,
        "geo_lng": payload.geo_lng,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    await db.humanity_card_logs.insert_one(scan)

    full_user = await db.users.find_one({"id": user["id"]}, {"_id": 0}) or user
    profile = default_volunteer_profile(full_user.get("volunteerProfile", {}))
    profile["humanityCardScans"] = int(profile.get("humanityCardScans", 0)) + 1
    profile["impactPoints"] = int(profile.get("impactPoints", 0)) + 25
    profile["currentLevel"] = compute_level(profile["impactPoints"])
    profile["lastActiveAt"] = datetime.now(timezone.utc).isoformat()
    await db.users.update_one(
        {"id": user["id"]},
        {"$set": {"volunteerProfile": profile, "impact_points": profile["impactPoints"]}},
    )

    return {
        "message": "Scan logged successfully",
        "beneficiary": {
            "ageGroup": scan["ageGroup"],
            "village": scan["village"],
            "serviceHistory": scan["serviceHistory"],
            "humanityCardIdLast4": scan["humanityCardMasked"],
        },
        "scan": scan,
    }

@api_router.get("/volunteer/humanity-card/history")
async def humanity_card_history(user=Depends(get_current_user)):
    scans = await db.humanity_card_logs.find({"volunteer_id": user["id"]}, {"_id": 0}).sort("created_at", -1).to_list(200)
    return {"scans": scans}


@api_router.get("/volunteer/id-card")
async def get_my_volunteer_id_card(user=Depends(get_current_user)):
    if user.get("role") not in ["volunteer", "admin", "super_admin"]:
        raise HTTPException(status_code=403, detail="Volunteer access required")
    record = await db.volunteer_id_cards.find_one({"volunteer_id": user.get("id")}, {"_id": 0})
    if not record:
        return {"application": {"card_status": "not_applied"}}
    return {"application": record}


@api_router.post("/volunteer/id-card/apply")
async def apply_for_volunteer_id_card(payload: VolunteerIdCardApplyInput, user=Depends(get_current_user)):
    if user.get("role") not in ["volunteer", "admin", "super_admin"]:
        raise HTTPException(status_code=403, detail="Volunteer access required")
    if user.get("status") not in ["active", None]:
        raise HTTPException(status_code=403, detail="Only active volunteers can apply")

    if len((payload.full_name or "").strip()) < 2:
        raise HTTPException(status_code=400, detail="Full name is required")
    if len((payload.address or "").strip()) < 8:
        raise HTTPException(status_code=400, detail="Address must be at least 8 characters")
    if not re.fullmatch(r"^[6-9]\d{9}$", (payload.phone or "").strip()):
        raise HTTPException(status_code=400, detail="Phone number must be a valid 10-digit Indian mobile number")
    if payload.emergency_contact_phone and not re.fullmatch(r"^[6-9]\d{9}$", payload.emergency_contact_phone.strip()):
        raise HTTPException(status_code=400, detail="Emergency contact phone must be a valid 10-digit Indian mobile number")
    if not _valid_id_card_photo(payload.photo_data_url):
        raise HTTPException(status_code=400, detail="Photo must be a valid image data URL and under 2.5MB")

    age = _compute_age_from_dob(payload.date_of_birth)
    if age < 18 or age > 75:
        raise HTTPException(status_code=400, detail="Date of birth must represent age between 18 and 75")

    existing = await db.volunteer_id_cards.find_one({"volunteer_id": user.get("id")}, {"_id": 0})
    now_iso = datetime.now(timezone.utc).isoformat()
    personal_details = {
        "full_name": payload.full_name.strip(),
        "date_of_birth": payload.date_of_birth,
        "age": age,
        "phone": payload.phone.strip(),
        "address": payload.address.strip(),
        "education": payload.education.strip(),
        "gender": payload.gender.strip(),
        "emergency_contact_name": payload.emergency_contact_name.strip(),
        "emergency_contact_phone": payload.emergency_contact_phone.strip(),
        "photo_data_url": payload.photo_data_url,
    }

    if existing and existing.get("card_status") in ["pending", "under_review", "approved"]:
        raise HTTPException(status_code=400, detail=f"Application already exists with status '{existing.get('card_status')}'")

    base_record = {
        "volunteer_id": user.get("id"),
        "volunteer_email": user.get("email", ""),
        "personal_details": personal_details,
        "card_status": "pending",
        "updated_at": now_iso,
    }

    if existing:
        await db.volunteer_id_cards.update_one(
            {"id": existing.get("id")},
            {
                "$set": {
                    **base_record,
                    "review": {},
                },
                "$inc": {"reapply_count": 1},
            },
        )
        application_id = existing.get("id")
    else:
        application_id = str(uuid.uuid4())
        await db.volunteer_id_cards.insert_one({
            "id": application_id,
            **base_record,
            "applied_at": now_iso,
            "reapply_count": 0,
            "generated_card": {},
            "review": {},
        })

    admins = await db.users.find({"role": {"$in": ["admin", "super_admin"]}}, {"_id": 0, "id": 1}).to_list(100)
    for admin in admins:
        await db.notifications.insert_one({
            "id": str(uuid.uuid4()),
            "user_id": admin.get("id"),
            "type": "volunteer_id_card_application",
            "title": "New Volunteer ID Card Application",
            "message": f"{user.get('name', 'Volunteer')} submitted an ID card application.",
            "ref_id": application_id,
            "read": False,
            "created_at": now_iso,
        })

    return {"message": "Application submitted successfully", "application_id": application_id, "status": "pending"}


@api_router.get("/volunteer/id-card/pdf")
async def download_my_volunteer_id_card_pdf(user=Depends(get_current_user)):
    if user.get("role") not in ["volunteer", "admin", "super_admin"]:
        raise HTTPException(status_code=403, detail="Volunteer access required")
    record = await db.volunteer_id_cards.find_one({"volunteer_id": user.get("id")}, {"_id": 0})
    if not record:
        raise HTTPException(status_code=404, detail="No ID card application found")
    if record.get("card_status") != "approved":
        raise HTTPException(status_code=400, detail="Only approved cards can be downloaded")

    logo_path = ROOT_DIR.parent / "frontend" / "public" / "New Logo Sweezen Foundation 11-03-26.png"
    pdf_buffer = generate_volunteer_id_card_pdf(record, user, logo_path=logo_path)
    filename = f"volunteer-id-card-{record.get('card_id', record.get('id', 'card'))}.pdf"
    return StreamingResponse(
        pdf_buffer,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@api_router.get("/verify/volunteer/{card_id}")
async def public_verify_volunteer_card(card_id: str):
    record = await db.volunteer_id_cards.find_one({"card_id": card_id}, {"_id": 0})
    if not record:
        raise HTTPException(status_code=404, detail="Card not found")
    if record.get("card_status") not in ["approved", "expired", "revoked"]:
        raise HTTPException(status_code=400, detail="Card is not yet approved")

    details = record.get("personal_details", {})
    generated = record.get("generated_card", {})
    return {
        "cardId": record.get("card_id", ""),
        "status": record.get("card_status", "pending"),
        "name": details.get("full_name", "Volunteer"),
        "photoDataUrl": details.get("photo_data_url", ""),
        "validFrom": generated.get("valid_from", ""),
        "validUntil": generated.get("valid_until", ""),
    }

@api_router.get("/volunteer/achievements")
async def volunteer_achievements(user=Depends(get_current_user)):
    full_user = await db.users.find_one({"id": user["id"]}, {"_id": 0, "password_hash": 0}) or user
    profile = default_volunteer_profile(full_user.get("volunteerProfile", {}))

    tasks = await db.tasks.find({}, {"_id": 0}).to_list(300)
    completed = 0
    env_completed = 0
    edu_completed = 0
    for task in tasks:
        if user_completed_task(task, user["id"]):
            completed += 1
            if task.get("category") == "environment":
                env_completed += 1
            if task.get("category") == "education":
                edu_completed += 1

    scans_count = int(profile.get("humanityCardScans", 0))
    hours = float(profile.get("totalHoursLogged", 0))

    earned_ids = set(b.get("badgeId") for b in profile.get("badgesEarned", []))
    if completed >= 1:
        earned_ids.add("first_responder")
    if hours >= 100:
        earned_ids.add("century_club")
    if completed >= 5:
        earned_ids.add("eagle_scout")
    if env_completed >= 3:
        earned_ids.add("environment_guardian")
    if edu_completed >= 3:
        earned_ids.add("education_champion")
    if scans_count >= 100:
        earned_ids.add("humanity_hero")

    now_iso = datetime.now(timezone.utc).isoformat()
    existing = {b.get("badgeId"): b for b in profile.get("badgesEarned", [])}
    profile["badgesEarned"] = [existing.get(bid, {"badgeId": bid, "earnedAt": now_iso}) for bid in earned_ids]
    profile["currentLevel"] = compute_level(int(profile.get("impactPoints", 0)))
    await db.users.update_one({"id": user["id"]}, {"$set": {"volunteerProfile": profile}})

    all_profiles = await db.users.find({"role": "volunteer"}, {"_id": 0, "name": 1, "volunteerProfile": 1}).to_list(1000)
    district = profile.get("district", "")
    state = profile.get("state", "")

    def leaderboard_rows(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        ordered = sorted(rows, key=lambda x: int(default_volunteer_profile(x.get("volunteerProfile", {})).get("impactPoints", 0)), reverse=True)
        output = []
        for idx, v in enumerate(ordered, start=1):
            p = default_volunteer_profile(v.get("volunteerProfile", {}))
            anon = p.get("privacyOptOutLeaderboard", False)
            output.append({
                "rank": idx,
                "name": f"Eagle #{idx}" if anon else v.get("name", "Volunteer"),
                "impactPoints": int(p.get("impactPoints", 0)),
                "hours": float(p.get("totalHoursLogged", 0)),
                "level": p.get("currentLevel", "Seedling"),
                "isCurrentUser": v.get("name") == full_user.get("name") and int(p.get("impactPoints", 0)) == int(profile.get("impactPoints", 0)),
            })
        return output[:50]

    district_rows = [v for v in all_profiles if default_volunteer_profile(v.get("volunteerProfile", {})).get("district", "") == district] if district else all_profiles
    state_rows = [v for v in all_profiles if default_volunteer_profile(v.get("volunteerProfile", {})).get("state", "") == state] if state else all_profiles

    certificates = profile.get("certificatesIssued", [])
    return {
        "level": next_level_info(int(profile.get("impactPoints", 0))),
        "points": {
            "total": int(profile.get("impactPoints", 0)),
            "hours": hours,
            "tasksCompleted": completed,
            "humanityCardScans": scans_count,
        },
        "badges": [
            {
                **b,
                "earned": b["badgeId"] in earned_ids,
                "earnedAt": existing.get(b["badgeId"], {}).get("earnedAt", ""),
            }
            for b in VOLUNTEER_BADGE_CATALOG
        ],
        "leaderboard": {
            "district": leaderboard_rows(district_rows),
            "state": leaderboard_rows(state_rows),
            "india": leaderboard_rows(all_profiles),
        },
        "certificates": certificates,
    }

@api_router.get("/volunteer/certificates")
async def volunteer_certificates(user=Depends(get_current_user)):
    full_user = await db.users.find_one({"id": user["id"]}, {"_id": 0}) or user
    profile = default_volunteer_profile(full_user.get("volunteerProfile", {}))
    certificates = profile.get("certificatesIssued", [])
    return {"certificates": certificates}

@api_router.get("/verify/cert/{cert_id}")
async def verify_certificate(cert_id: str):
    volunteer = await db.users.find_one({"role": "volunteer", "volunteerProfile.certificatesIssued": {"$elemMatch": {"certId": cert_id}}}, {"_id": 0, "name": 1, "volunteerProfile": 1})
    if not volunteer:
        raise HTTPException(status_code=404, detail="Certificate not found")
    certs = default_volunteer_profile(volunteer.get("volunteerProfile", {})).get("certificatesIssued", [])
    cert = next((c for c in certs if c.get("certId") == cert_id), None)
    if not cert:
        raise HTTPException(status_code=404, detail="Certificate not found")
    return {
        "valid": True,
        "certificate": {
            "certId": cert.get("certId"),
            "issuedAt": cert.get("issuedAt"),
            "taskTitle": cert.get("taskTitle", "Volunteer Service"),
            "volunteerName": volunteer.get("name", "Volunteer"),
        },
    }

@api_router.put("/admin/volunteer/tasks/{task_id}/review/{volunteer_id}")
async def admin_review_submitted_task(task_id: str, volunteer_id: str, payload: VolunteerApplicationReviewInput, request: Request, admin=Depends(require_admin)):
    task = await db.tasks.find_one({"id": task_id}, {"_id": 0})
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")

    status = payload.status.lower().strip()
    if status not in ["approved", "rejected"]:
        raise HTTPException(status_code=400, detail="Status must be approved or rejected")

    updated_applied = []
    for app in task.get("applied", []):
        if isinstance(app, str) and app == volunteer_id:
            updated_applied.append({
                "volunteer_id": volunteer_id,
                "status": status,
                "reviewed_by": admin.get("id", ""),
                "reviewed_at": datetime.now(timezone.utc).isoformat(),
                "feedback": payload.feedback,
                "admin_rating": payload.admin_rating or 0,
            })
        elif isinstance(app, dict) and (app.get("volunteer_id") == volunteer_id or app.get("user_id") == volunteer_id):
            updated_applied.append({
                **app,
                "volunteer_id": volunteer_id,
                "status": status,
                "reviewed_by": admin.get("id", ""),
                "reviewed_at": datetime.now(timezone.utc).isoformat(),
                "feedback": payload.feedback,
                "admin_rating": payload.admin_rating or app.get("admin_rating", 0),
            })
        else:
            updated_applied.append(app)

    update_task: Dict[str, Any] = {"applied": updated_applied}
    if status == "approved":
        completed_by = task.get("completed_by", [])
        if volunteer_id not in completed_by:
            completed_by.append(volunteer_id)
        update_task["completed_by"] = completed_by
        update_task["status"] = "completed"
    else:
        update_task["status"] = "open"

    await db.tasks.update_one({"id": task_id}, {"$set": update_task})

    volunteer = await db.users.find_one({"id": volunteer_id}, {"_id": 0})
    if volunteer and volunteer.get("role") == "volunteer":
        profile = default_volunteer_profile(volunteer.get("volunteerProfile", {}))
        if status == "approved":
            profile["impactPoints"] = int(profile.get("impactPoints", 0)) + 50
            completed_tasks = set(profile.get("completedTasks", []))
            completed_tasks.add(task_id)
            profile["completedTasks"] = list(completed_tasks)
            cert_id = str(uuid.uuid4())
            profile["certificatesIssued"] = profile.get("certificatesIssued", []) + [{
                "certId": cert_id,
                "issuedAt": datetime.now(timezone.utc).isoformat(),
                "downloadUrl": f"/verify/cert/{cert_id}",
                "taskTitle": task.get("title", "Volunteer Service"),
            }]
        if payload.admin_rating and payload.admin_rating > 0:
            current_rating = float(profile.get("rating", 0))
            profile["rating"] = round((current_rating + float(payload.admin_rating)) / (2 if current_rating > 0 else 1), 2)
            if float(payload.admin_rating) >= 5:
                profile["impactPoints"] += 100
        profile["currentLevel"] = compute_level(int(profile.get("impactPoints", 0)))
        profile["lastActiveAt"] = datetime.now(timezone.utc).isoformat()

        await db.users.update_one(
            {"id": volunteer_id},
            {
                "$set": {
                    "volunteerProfile": profile,
                    "impact_points": profile["impactPoints"],
                    "hours_logged": profile["totalHoursLogged"],
                }
            },
        )

    await db.notifications.insert_one({
        "id": str(uuid.uuid4()),
        "user_id": volunteer_id,
        "type": "task_review",
        "title": f"Task submission {status}",
        "message": payload.feedback or f"Your submission for {task.get('title', 'task')} was {status}.",
        "ref_id": task_id,
        "read": False,
        "created_at": datetime.now(timezone.utc).isoformat(),
    })

    await write_audit_log(admin, f"{status}_task_submission", target_id=volunteer_id, target_type="volunteer_task", details={"task_id": task_id}, ip=get_client_ip(request))
    return {"message": f"Submission {status}"}

# ─── ADMIN VOLUNTEER TASKS MGMT ───
@api_router.post("/admin/tasks")
async def create_volunteer_task(data: VolunteerTaskCreate, user=Depends(require_admin)):
    model = data.model_dump()
    location = model.get("location", "")
    district = ""
    state = ""
    if "," in location:
        parts = [p.strip() for p in location.split(",")]
        if len(parts) >= 2:
            district = parts[0]
            state = parts[-1]
    task = {
        "id": str(uuid.uuid4()),
        **model,
        "project_name": model.get("title", "Foundation Project"),
        "district": district,
        "state": state,
        "due_date": model.get("date", ""),
        "estimated_hours": model.get("hours_required", 0),
        "lat": 0,
        "lng": 0,
        "applied": [],
        "assigned_volunteers": [],
        "completed_by": [],
        "status": "open",
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    await db.tasks.insert_one(task)
    created = await db.tasks.find_one({"id": task["id"]}, {"_id": 0})
    return {"task": created}

@api_router.get("/admin/tasks")
async def admin_list_tasks(user=Depends(require_admin)):
    tasks = await db.tasks.find({}, {"_id": 0}).sort("created_at", -1).to_list(100)
    return {"tasks": tasks}

# ─── DONOR ROUTES ───
def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _fy_window(fy_label: str) -> Dict[str, str]:
    # Format: YYYY-YY, India FY (Apr-Mar)
    if not fy_label or "-" not in fy_label:
        now = datetime.now(timezone.utc)
        start_year = now.year if now.month >= 4 else now.year - 1
        fy_label = f"{start_year}-{str(start_year + 1)[-2:]}"
    start_year = int(fy_label.split("-")[0])
    start = datetime(start_year, 4, 1, tzinfo=timezone.utc)
    end = datetime(start_year + 1, 3, 31, 23, 59, 59, tzinfo=timezone.utc)
    return {"fy": fy_label, "start": start.isoformat(), "end": end.isoformat()}


async def _donor_donations(user: Dict[str, Any], query: Optional[Dict[str, Any]] = None, limit: int = 1000) -> List[Dict[str, Any]]:
    base_query: Dict[str, Any] = {
        "$or": [
            {"donor_id": user.get("id", "")},
            {"donor_email": user.get("email", "")},
        ]
    }
    if query:
        base_query.update(query)
    return await db.donations.find(base_query, {"_id": 0}).sort("created_at", -1).to_list(limit)


@api_router.put("/donor/profile")
async def update_donor_profile(payload: DonorProfileUpdateInput, user=Depends(require_donor)):
    full_user = await db.users.find_one({"id": user["id"]}, {"_id": 0, "password_hash": 0}) or user
    profile = default_donor_profile(full_user.get("donorProfile", {}))
    pan_number = (payload.panNumber or "").strip().upper()
    if pan_number and not re.match(r"^[A-Z]{5}[0-9]{4}[A-Z]$", pan_number):
        raise HTTPException(status_code=400, detail="Invalid PAN format")
    profile.update({
        "panNumber": pan_number,
        "panVerified": bool(pan_number),
        "gstNumber": payload.gstNumber[:20],
        "address": payload.address[:250],
        "city": payload.city[:80],
        "state": payload.state[:80],
        "pincode": payload.pincode[:10],
        "isCorporate": payload.isCorporate,
        "companyName": payload.companyName[:120],
        "cin": payload.cin[:30],
        "preferredCategories": payload.preferredCategories[:10],
        "isAnonymous": payload.isAnonymous,
    })
    await db.users.update_one({"id": user["id"]}, {"$set": {"donorProfile": profile}})
    return {"message": "Donor profile updated", "donorProfile": profile}


@api_router.post("/donor/recurring")
async def create_recurring_plan(payload: RecurringDonationCreateInput, user=Depends(require_donor)):
    if payload.amount <= 0:
        raise HTTPException(status_code=400, detail="Recurring amount must be positive")
    if payload.frequency not in ["monthly", "annual"]:
        raise HTTPException(status_code=400, detail="Frequency must be monthly or annual")
    if payload.projectId:
        project = await db.projects.find_one({"id": payload.projectId}, {"_id": 0, "id": 1})
        if not project:
            raise HTTPException(status_code=404, detail="Project not found")

    full_user = await db.users.find_one({"id": user["id"]}, {"_id": 0, "password_hash": 0}) or user
    profile = default_donor_profile(full_user.get("donorProfile", {}))
    recurring = profile.get("recurringDonations", [])
    sub_id = f"sub_mock_{uuid.uuid4().hex[:12]}"
    recurring.append({
        "razorpaySubId": sub_id,
        "projectId": payload.projectId,
        "amount": payload.amount,
        "frequency": payload.frequency,
        "status": "active",
        "nextChargeDate": (datetime.now(timezone.utc) + timedelta(days=30 if payload.frequency == "monthly" else 365)).isoformat(),
    })
    profile["recurringDonations"] = recurring
    await db.users.update_one({"id": user["id"]}, {"$set": {"donorProfile": profile}})
    return {"message": "Recurring donation plan created", "plan": recurring[-1]}


@api_router.put("/donor/recurring/{sub_id}")
async def update_recurring_plan(sub_id: str, payload: RecurringDonationUpdateInput, user=Depends(require_donor)):
    full_user = await db.users.find_one({"id": user["id"]}, {"_id": 0, "password_hash": 0}) or user
    profile = default_donor_profile(full_user.get("donorProfile", {}))
    recurring = profile.get("recurringDonations", [])
    found = False
    for plan in recurring:
        if plan.get("razorpaySubId") != sub_id:
            continue
        found = True
        if payload.amount is not None:
            if payload.amount <= 0:
                raise HTTPException(status_code=400, detail="Amount must be greater than zero")
            plan["amount"] = payload.amount
        if payload.frequency:
            if payload.frequency not in ["monthly", "annual"]:
                raise HTTPException(status_code=400, detail="Invalid frequency")
            plan["frequency"] = payload.frequency
        if payload.status:
            if payload.status not in ["active", "paused", "cancelled"]:
                raise HTTPException(status_code=400, detail="Invalid status")
            plan["status"] = payload.status
        if plan.get("status") == "active":
            plan["nextChargeDate"] = (datetime.now(timezone.utc) + timedelta(days=30 if plan.get("frequency") == "monthly" else 365)).isoformat()
        break
    if not found:
        raise HTTPException(status_code=404, detail="Recurring plan not found")
    profile["recurringDonations"] = recurring
    await db.users.update_one({"id": user["id"]}, {"$set": {"donorProfile": profile}})
    return {"message": "Recurring plan updated", "plans": recurring}


@api_router.get("/donor/dashboard")
async def donor_dashboard(user=Depends(require_donor)):
    full_user = await db.users.find_one({"id": user["id"]}, {"_id": 0, "password_hash": 0}) or user
    profile = default_donor_profile(full_user.get("donorProfile", {}))
    donations = await _donor_donations(full_user, {"status": "completed"}, limit=1000)
    total_donated = round(sum(_safe_float(d.get("amount", 0)) for d in donations), 2)
    donation_count = len(donations)
    tax_saved = int(total_donated * 0.5)
    profile["totalDonated"] = total_donated
    profile["donationCount"] = donation_count
    if donations and not profile.get("firstDonationAt"):
        profile["firstDonationAt"] = donations[-1].get("created_at", "")
    if donations:
        profile["lastDonationAt"] = donations[0].get("created_at", "")
    profile["donorTier"] = compute_donor_tier(total_donated)

    funded_projects_map: Dict[str, Dict[str, Any]] = {}
    for d in donations:
        pid = d.get("project_id")
        if not pid:
            continue
        funded_projects_map.setdefault(pid, {"amount": 0, "donations": 0})
        funded_projects_map[pid]["amount"] += _safe_float(d.get("amount", 0))
        funded_projects_map[pid]["donations"] += 1

    project_cards: List[Dict[str, Any]] = []
    for pid, stats in funded_projects_map.items():
        project = await db.projects.find_one({"id": pid}, {"_id": 0})
        if not project:
            continue
        budget = _safe_float(project.get("budget", 0))
        raised = _safe_float(project.get("raised", 0))
        progress = int(min(100, (raised / budget) * 100)) if budget > 0 else 0
        project_cards.append({
            "id": project.get("id"),
            "title": project.get("title", "Project"),
            "category": project.get("category", "general"),
            "image_url": project.get("image_url", ""),
            "progress": progress,
            "yourContribution": round(stats["amount"], 2),
            "beneficiaries": int(project.get("beneficiary_count", 0)),
            "publicProjectPath": f"/programs",
        })

    recurring = profile.get("recurringDonations", [])
    recurring_active = [r for r in recurring if r.get("status") == "active"]
    by_year = _calculate_yearly_summary(donations)
    yearly = []
    for year, row in by_year.items():
        yearly.append({
            "year": year,
            "donations": row["count"],
            "total": row["total"],
            "tax_saved": int(row["total"] * 0.5),
        })
    yearly.sort(key=lambda x: x["year"], reverse=True)

    await db.users.update_one({"id": user["id"]}, {"$set": {"donorProfile": profile}})

    return {
        "user": {
            "id": full_user.get("id", ""),
            "name": full_user.get("name", "Donor"),
            "email": full_user.get("email", ""),
            "created_at": full_user.get("created_at", ""),
        },
        "donorProfile": profile,
        "tier": next_donor_tier_info(total_donated),
        "impactSummary": {
            "totalGiven": total_donated,
            "projectsBacked": len(project_cards),
            "taxSaved": tax_saved,
        },
        "recentDonations": donations[:10],
        "supportedProjects": project_cards,
        "recurring": recurring,
        "recurringActiveCount": len(recurring_active),
        "yearlyTaxSummary": yearly,
        # Backward compatibility for older tests/clients.
        "donations": donations,
        "total_donated": total_donated,
    }


def _calculate_yearly_summary(donations: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    summary: Dict[str, Dict[str, Any]] = {}
    for d in donations:
        year = (d.get("created_at", "") or "")[:4]
        if not year:
            continue
        if year not in summary:
            summary[year] = {"count": 0, "total": 0}
        summary[year]["count"] += 1
        summary[year]["total"] += _safe_float(d.get("amount", 0))
    return summary


@api_router.get("/donor/tax-summary")
async def donor_tax_summary(user=Depends(require_donor)):
    donations = await _donor_donations(user, {"status": "completed"}, limit=5000)
    yearly = _calculate_yearly_summary(donations)
    result = []
    for year, data in yearly.items():
        result.append({"year": year, "donations": data["count"], "total": data["total"], "tax_saved": int(data["total"] * 0.5)})
    return {"tax_summary": sorted(result, key=lambda x: x["year"], reverse=True)}


@api_router.get("/donor/donations")
async def donor_donations(
    date_from: str = "",
    date_to: str = "",
    project_id: str = "",
    dtype: str = "",
    min_amount: float = 0,
    max_amount: float = 0,
    status: str = "",
    user=Depends(require_donor),
):
    query: Dict[str, Any] = {}
    if date_from:
        query.setdefault("created_at", {})["$gte"] = date_from
    if date_to:
        query.setdefault("created_at", {})["$lte"] = f"{date_to}T23:59:59"
    if project_id:
        query["project_id"] = project_id
    if dtype == "one-time":
        query["is_recurring"] = False
    elif dtype == "recurring":
        query["is_recurring"] = True
    if min_amount > 0 or max_amount > 0:
        amount_query: Dict[str, Any] = {}
        if min_amount > 0:
            amount_query["$gte"] = min_amount
        if max_amount > 0:
            amount_query["$lte"] = max_amount
        query["amount"] = amount_query
    if status:
        query["status"] = status

    donations = await _donor_donations(user, query, limit=5000)
    projects = await db.projects.find({}, {"_id": 0, "id": 1, "title": 1}).to_list(500)
    project_map = {p.get("id", ""): p.get("title", "General Fund") for p in projects}
    enriched = []
    for d in donations:
        enriched.append({
            **d,
            "project_title": project_map.get(d.get("project_id", ""), "General Fund"),
            "type": "recurring" if d.get("is_recurring") else "one-time",
            "tax_benefit": int(_safe_float(d.get("amount", 0)) * 0.5) if d.get("status") == "completed" else 0,
        })
    return {"donations": enriched, "count": len(enriched)}


@api_router.get("/donor/annual-80g-summary")
async def donor_annual_80g_summary(fy: str = "", user=Depends(require_donor)):
    window = _fy_window(fy)
    donations = await _donor_donations(
        user,
        {
            "status": "completed",
            "is80G": True,
            "created_at": {"$gte": window["start"], "$lte": window["end"]},
        },
        limit=5000,
    )
    total = round(sum(_safe_float(d.get("amount", 0)) for d in donations), 2)
    return {
        "fy": window["fy"],
        "qualifyingDonations": len(donations),
        "totalQualifyingAmount": total,
        "estimatedTaxBenefit": int(total * 0.5),
        "certificateReady": len(donations) > 0,
    }


@api_router.get("/donor/receipts/{donation_id}/download")
async def donor_download_receipt(donation_id: str, user=Depends(require_donor)):
    donation = await db.donations.find_one(
        {
            "id": donation_id,
            "$or": [
                {"donor_id": user.get("id", "")},
                {"donor_email": user.get("email", "")},
            ],
        },
        {"_id": 0},
    )
    if not donation:
        raise HTTPException(status_code=404, detail="Donation not found")

    if donation.get("project_id"):
        project = await db.projects.find_one({"id": donation["project_id"]}, {"_id": 0})
        donation["project_name"] = project["title"] if project else "General Fund"
    else:
        donation["project_name"] = "General Fund"
    pdf_buffer = generate_80g_receipt_pdf(donation)
    return StreamingResponse(
        pdf_buffer,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=80G_Receipt_{donation.get('receipt_number', 'SWZ')}.pdf"},
    )


@api_router.get("/donor/donations/export/csv")
async def donor_export_donations_csv(user=Depends(require_donor)):
    donations = await _donor_donations(user, limit=5000)
    output = io.StringIO()
    fields = ["created_at", "receipt_number", "project_id", "amount", "status", "is_recurring", "is80G"]
    writer = csv.DictWriter(output, fieldnames=fields)
    writer.writeheader()
    for d in donations:
        writer.writerow({k: d.get(k, "") for k in fields})
    output.seek(0)
    return StreamingResponse(io.BytesIO(output.getvalue().encode()), media_type="text/csv", headers={"Content-Disposition": "attachment; filename=donor_donations.csv"})


@api_router.get("/donor/donations/export/pdf")
async def donor_export_donations_pdf(user=Depends(require_donor)):
    donations = await _donor_donations(user, limit=1000)
    stats = {
        "count": len(donations),
        "total": round(sum(_safe_float(d.get("amount", 0)) for d in donations if d.get("status") == "completed"), 2),
        "avg": round((sum(_safe_float(d.get("amount", 0)) for d in donations if d.get("status") == "completed") / max(1, len([d for d in donations if d.get("status") == "completed"]))), 2),
    }
    pdf_buffer = generate_donation_report_pdf(donations, stats)
    return StreamingResponse(pdf_buffer, media_type="application/pdf", headers={"Content-Disposition": "attachment; filename=donor_donations.pdf"})

# ─── RESEARCHER ROUTES ───
@api_router.get("/researcher/datasets")
async def list_datasets(user=Depends(get_current_user)):
    if user.get("role") not in ["researcher", "admin", "super_admin"]:
        raise HTTPException(status_code=403, detail="Researcher access required")
    datasets = await db.datasets.find({}, {"_id": 0}).to_list(100)
    return {"datasets": datasets}

@api_router.get("/researcher/datasets/{dataset_id}/download")
async def download_dataset(dataset_id: str, user=Depends(get_current_user)):
    if user.get("role") not in ["researcher", "admin", "super_admin"]:
        raise HTTPException(status_code=403, detail="Researcher access required")
    dataset = await db.datasets.find_one({"id": dataset_id}, {"_id": 0})
    if not dataset:
        raise HTTPException(status_code=404, detail="Dataset not found")
    # Generate sample anonymized CSV data
    output = io.StringIO()
    if dataset.get("type") == "healthcare":
        writer = csv.writer(output)
        writer.writerow(["patient_id", "age_group", "gender", "district", "treatment_type", "outcome", "cost_inr"])
        for i in range(min(dataset.get("records", 100), 200)):
            writer.writerow([f"P{i+1:05d}", ["18-25","26-35","36-45","46-60","60+"][i%5], ["M","F"][i%2], ["Lucknow","Patna","Bhopal","Ranchi","Raipur"][i%5], ["General","Dental","Eye","Cardio","Pediatric"][i%5], ["Improved","Stable","Referred"][i%3], [500,1200,2500,800,1500][i%5]])
    elif dataset.get("type") == "education":
        writer = csv.writer(output)
        writer.writerow(["student_id", "age", "gender", "program", "enrollment_date", "completion_status", "skill_score"])
        for i in range(min(dataset.get("records", 100), 200)):
            writer.writerow([f"S{i+1:05d}", 14+i%12, ["M","F"][i%2], ["Digital Literacy","Tailoring","Handicrafts","Coding","English"][i%5], f"2024-{(i%12)+1:02d}-01", ["Completed","In Progress","Dropped"][i%3], 40+i%60])
    else:
        writer = csv.writer(output)
        writer.writerow(["site_id", "district", "trees_planted", "survival_rate", "carbon_offset_kg", "water_quality_index"])
        for i in range(min(dataset.get("records", 100), 200)):
            writer.writerow([f"E{i+1:05d}", ["Dehradun","Shimla","Ranchi","Raipur","Nainital"][i%5], 50+i*3, f"{70+i%25}%", 100+i*5, f"{60+i%35}%"])
    output.seek(0)
    return StreamingResponse(io.BytesIO(output.getvalue().encode()), media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={dataset.get('type', 'data')}_anonymized.csv"})

# ─── DONOR RECOGNITION WALL ───
@api_router.get("/donor-wall")
async def donor_wall():
    donations = await db.donations.find({"status": "completed"}, {"_id": 0}).sort("amount", -1).to_list(100)
    donors = {}
    for d in donations:
        email = d.get("donor_email", "")
        if email not in donors:
            donors[email] = {"name": d.get("donor_name", "Anonymous"), "total": 0, "count": 0}
        donors[email]["total"] += d.get("amount", 0)
        donors[email]["count"] += 1
    wall = sorted(donors.values(), key=lambda x: x["total"], reverse=True)
    return {"donors": wall[:50]}

# ─── GEO DATA FOR MAP ───
@api_router.get("/geo/projects")
async def get_projects_geo():
    projects = await db.projects.find({}, {"_id": 0}).to_list(100)
    geo_data = []
    location_coords = {
        "Uttar Pradesh": [26.85, 80.95], "Bihar": [25.61, 85.14],
        "National Highways": [22.57, 78.96], "Madhya Pradesh": [23.26, 77.41],
        "Rajasthan": [26.92, 75.79], "Odisha": [20.94, 84.80],
        "Uttarakhand": [30.07, 79.49], "Himachal Pradesh": [31.10, 77.17],
        "Jharkhand": [23.61, 85.28], "Chhattisgarh": [21.25, 81.63],
    }
    for p in projects:
        loc = p.get("location", "")
        coords = [20.59, 78.96]  # Default center of India
        for place, c in location_coords.items():
            if place.lower() in loc.lower():
                coords = c
                break
        geo_data.append({
            "id": p["id"], "title": p["title"], "category": p["category"],
            "location": loc, "lat": coords[0], "lng": coords[1],
            "beneficiary_count": p.get("beneficiary_count", 0),
            "budget": p.get("budget", 0), "raised": p.get("raised", 0),
        })
    tasks = await db.tasks.find({}, {"_id": 0}).to_list(50)
    for t in tasks:
        if t.get("lat") and t.get("lng"):
            geo_data.append({
                "id": t["id"], "title": t["title"], "category": t.get("category", "general"),
                "location": t.get("location", ""), "lat": t["lat"], "lng": t["lng"],
                "type": "task", "beneficiary_count": 0, "budget": 0, "raised": 0,
            })
    return {"geo_data": geo_data}

# Include router and middleware
app.include_router(api_router)
cors_origins_raw = [o.strip() for o in os.environ.get('CORS_ORIGINS', '').split(',') if o.strip()]
if not cors_origins_raw:
    cors_origins_raw = ["http://localhost:3000", "http://127.0.0.1:3000"]
if '*' in cors_origins_raw and len(cors_origins_raw) > 1:
    cors_origins_raw = [o for o in cors_origins_raw if o != '*']
if '*' in cors_origins_raw:
    logger.warning("CORS_ORIGINS is wildcard while credentials are enabled. Restrict this in production.")

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=cors_origins_raw,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "Accept", "Origin", "X-Requested-With"],
)

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()
