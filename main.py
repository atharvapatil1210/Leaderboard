from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
from passlib.context import CryptContext
from pydantic import BaseModel, Field
from typing import List, Optional
from datetime import datetime, timedelta
from bson import ObjectId
import jwt
import subprocess
import asyncio

# Initialize FastAPI
app = FastAPI()

# CORS middleware : connect fronend and backend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# MongoDB Connection
MONGO_URL = "mongodb://localhost:27017"
client = AsyncIOMotorClient(MONGO_URL)
db = client.cli_challenge

# Security
SECRET_KEY = "your-secret-key"  # Change this in production
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Models
class UserBase(BaseModel):
    username: str
    email: str

class UserCreate(UserBase):
    password: str

class User(UserBase):
    id: str = Field(default_factory=lambda: str(ObjectId()))
    points: int = 0
    challenges_completed: int = 0

class Challenge(BaseModel):
    id: str = Field(default_factory=lambda: str(ObjectId()))
    title: str
    description: str
    command: str
    points: int
    expected_output: str
    hints: List[str]
    difficulty: str

class CommandExecution(BaseModel):
    command: str
    challenge_id: Optional[str]

class LeaderboardEntry(BaseModel):
    username: str
    points: int
    challenges_completed: int

# Auth functions
def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user = await db.users.find_one({"username": payload.get("sub")})
        if user is None:
            raise HTTPException(status_code=401)
        return User(**user)
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

# Auth routes
@app.post("/api/auth/register")
async def register(user: UserCreate):
    if await db.users.find_one({"username": user.username}):
        raise HTTPException(status_code=400, detail="Username already registered")
    
    hashed_password = pwd_context.hash(user.password)
    user_dict = user.dict()
    user_dict["password"] = hashed_password
    user_dict["points"] = 0
    user_dict["challenges_completed"] = 0
    
    result = await db.users.insert_one(user_dict)
    return {"id": str(result.inserted_id)}

@app.post("/api/auth/token")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = await db.users.find_one({"username": form_data.username})
    if not user or not pwd_context.verify(form_data.password, user["password"]):
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    
    access_token = create_access_token({"sub": user["username"]})
    return {"access_token": access_token, "token_type": "bearer"}

# Challenge routes
@app.get("/api/challenges/daily")
async def get_daily_challenge(current_user: User = Depends(get_current_user)):
    # Get today's challenge based on UTC date
    today = datetime.utcnow().strftime("%Y-%m-%d")
    challenge = await db.challenges.find_one({"date": today})
    if not challenge:
        raise HTTPException(status_code=404, detail="No challenge for today")
    return Challenge(**challenge)

@app.get("/api/challenges/upcoming")
async def get_upcoming_challenges(current_user: User = Depends(get_current_user)):
    cursor = db.challenges.find({
        "date": {"$gt": datetime.utcnow().strftime("%Y-%m-%d")}
    }).limit(3)
    challenges = await cursor.to_list(length=3)
    return [Challenge(**challenge) for challenge in challenges]

# Terminal routes
@app.post("/api/terminal/execute")
async def execute_command(
    command_exec: CommandExecution,
    current_user: User = Depends(get_current_user)
):
    # Validate and sanitize command
    if any(char in command_exec.command for char in ';&|'):
        raise HTTPException(status_code=400, detail="Invalid command")
    
    try:
        # Execute command in controlled environment
        process = await asyncio.create_subprocess_shell(
            command_exec.command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await process.communicate()
        
        output = stdout.decode() if stdout else stderr.decode()
        
        # If this is part of a challenge, verify the output
        if command_exec.challenge_id:
            challenge = await db.challenges.find_one({"_id": ObjectId(command_exec.challenge_id)})
            if challenge and output.strip() == challenge["expected_output"].strip():
                # Update user progress
                await db.users.update_one(
                    {"_id": ObjectId(current_user.id)},
                    {
                        "$inc": {
                            "points": challenge["points"],
                            "challenges_completed": 1
                        }
                    }
                )
                return {
                    "success": True,
                    "output": output,
                    "points_earned": challenge["points"]
                }
        
        return {"success": True, "output": output}
        
    except Exception as e:
        return {"success": False, "output": str(e)}

# Leaderboard routes
@app.get("/api/leaderboard/{period}")
async def get_leaderboard(period: str, current_user: User = Depends(get_current_user)):
    match period:
        case "week":
            start_date = datetime.utcnow() - timedelta(days=7)
        case "month":
            start_date = datetime.utcnow() - timedelta(days=30)
        case "alltime":
            start_date = datetime.min
        case _:
            raise HTTPException(status_code=400, detail="Invalid period")
    
    pipeline = [
        {
            "$match": {
                "created_at": {"$gte": start_date}
            }
        },
        {
            "$sort": {"points": -1}
        },
        {
            "$limit": 10
        }
    ]
    
    cursor = db.users.aggregate(pipeline)
    leaders = await cursor.to_list(length=10)
    return [LeaderboardEntry(**leader) for leader in leaders]

# Progress routes
@app.get("/api/progress/{user_id}")
async def get_user_progress(
    user_id: str,
    current_user: User = Depends(get_current_user)
):
    if user_id != current_user.id and not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Not authorized")
    
    user = await db.users.find_one({"_id": ObjectId(user_id)})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    completed_challenges = await db.user_challenges.count_documents({
        "user_id": ObjectId(user_id),
        "completed": True
    })
    
    return {
        "points": user["points"],
        "challenges_completed": completed_challenges,
        "rank": await db.users.count_documents({"points": {"$gt": user["points"]}}) + 1
    }

# Startup event to create indexes
@app.on_event("startup")
async def startup_event():
    await db.users.create_index("username", unique=True)
    await db.users.create_index("email", unique=True)
    await db.challenges.create_index([("date", 1)])
    await db.user_challenges.create_index([("user_id", 1), ("challenge_id", 1)])
