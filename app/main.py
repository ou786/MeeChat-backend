from fastapi import FastAPI, Depends, HTTPException, Body
from sqlalchemy.orm import Session
from fastapi.middleware.cors import CORSMiddleware
from email.message import EmailMessage
from aiosmtplib import SMTP
from pydantic import BaseModel, EmailStr
from dotenv import load_dotenv
from . import models, schemas, database
import random, time, os
from passlib.context import CryptContext
from fastapi import status
from fastapi import Request
import time
from datetime import datetime
from .schemas import UserIdPayload  # or from schemas import ...
from .schemas import SeenPayload
from fastapi import BackgroundTasks
from .schemas import PasswordResetRequest
from sqlalchemy import or_
from sqlalchemy import and_






# Load environment variables
load_dotenv()
EMAIL_HOST = os.getenv("EMAIL_HOST")
EMAIL_PORT = int(os.getenv("EMAIL_PORT", 587))
EMAIL_USER = os.getenv("EMAIL_USER")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD")

from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://meechat.vercel.app", "https://meechat-osama-ussaids-projects.vercel.app", "https://meechat-git-master-osama-ussaids-projects.vercel.app"],  # ✅ React dev server
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


models.Base.metadata.create_all(bind=database.engine)

def get_db():
    db = database.SessionLocal()
    try:
        yield db
    finally:
        db.close()

# ──────────────── Typing Indicator ────────────────
typing_status = {}

@app.post("/typing")
def update_typing_status(user_id: int = Body(...), is_typing: bool = Body(...)):
    typing_status[user_id] = {"is_typing": is_typing, "timestamp": time.time()}
    return {"message": "Typing status updated"}

@app.get("/typing_status")
def get_typing_status(user_id: int):
    user_typing = typing_status.get(user_id)
    if not user_typing or time.time() - user_typing["timestamp"] > 3:
        return {"is_typing": False}
    return {"is_typing": user_typing["is_typing"]}

# ──────────────── Email OTP ────────────────
email_otp_store = {}

class EmailPayload(BaseModel):
    email: EmailStr

class OTPVerifyPayload(BaseModel):
    email: EmailStr
    otp: str
@app.post("/send_email_otp")
async def send_email_otp(payload: schemas.EmailOtpRequest):
    otp = str(random.randint(1000, 9999))
    email_otp_store[payload.email] = {"otp": otp, "username": payload.username}
    msg = EmailMessage()
    msg["From"] = EMAIL_USER
    msg["To"] = payload.email
    msg["Subject"] = "Your OTP Code"
    msg.set_content(f"Your OTP is: {otp}")

    smtp = SMTP(hostname=EMAIL_HOST, port=EMAIL_PORT, start_tls=True)
    await smtp.connect()
    await smtp.login(EMAIL_USER, EMAIL_PASSWORD)
    await smtp.send_message(msg)
    await smtp.quit()

    return {"message": "OTP sent"}

@app.post("/verify_email_otp_and_register", response_model=schemas.UserOut)
def verify_otp_and_register(payload: schemas.OtpVerificationRequest, db: Session = Depends(get_db)):
    record = email_otp_store.get(payload.email)
    if not record or record['otp'] != payload.otp:
        raise HTTPException(status_code=400, detail="Invalid OTP")
    
    existing = db.query(models.User).filter_by(email=payload.email).first()
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered.")


    # Hash password
    pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
    hashed_pw = pwd_context.hash(payload.password)

    user = models.User(email=payload.email, username=record['username'], hashed_password=hashed_pw, is_verified=True)
    db.add(user)
    db.commit()
    db.refresh(user)

    email_otp_store.pop(payload.email, None)

    return user

@app.post("/login", response_model=schemas.UserOut)
def login(payload: schemas.LoginRequest, db: Session = Depends(get_db)):
    try:
        user = db.query(models.User).filter(models.User.email == payload.email).first()
        if not user:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password")

        pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

        if not pwd_context.verify(payload.password, user.hashed_password):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password")

        return user

    except Exception as e:
        print("Login Error:", str(e))  # ✅ Log the error to Render logs
        raise HTTPException(status_code=500, detail="Internal Server Error")


@app.post("/request-password-reset")
def request_password_reset(
    payload: PasswordResetRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)  # ✅ Inject BackgroundTasks properly
):
    email = payload.email
    user = db.query(models.User).filter(models.User.email == email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    otp = str(random.randint(100000, 999999))
    user.reset_otp = otp
    user.otp_timestamp = datetime.utcnow()
    db.commit()

    # Email setup
    message = EmailMessage()
    message["From"] = EMAIL_USER
    message["To"] = email
    message["Subject"] = "MeeChat Password Reset OTP"
    message.set_content(f"Your OTP to reset your MeeChat password is: {otp}")

    async def send_mail():
        smtp = SMTP(hostname=EMAIL_HOST, port=EMAIL_PORT, start_tls=True)
        await smtp.connect()
        await smtp.login(EMAIL_USER, EMAIL_PASSWORD)
        await smtp.send_message(message)
        await smtp.quit()

    background_tasks.add_task(send_mail)  # ✅ Use injected object

    return {"message": "OTP sent to your email"}



@app.post("/verify-reset-otp")
def verify_reset_otp(email: EmailStr = Body(...), otp: str = Body(...), db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.email == email).first()
    if not user or user.reset_otp != otp:
        raise HTTPException(status_code=400, detail="Invalid OTP")

    time_diff = (datetime.utcnow() - user.otp_timestamp).total_seconds()
    if time_diff > 600:  # 10 mins expiry
        raise HTTPException(status_code=400, detail="OTP expired")

    return {"message": "OTP verified"}




@app.post("/reset-password")
def reset_password(email: EmailStr = Body(...), new_password: str = Body(...), db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.email == email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    hashed_pw = CryptContext(schemes=["bcrypt"], deprecated="auto").hash(new_password)
    user.hashed_password = hashed_pw
    user.reset_otp = None  # Invalidate OTP
    user.otp_timestamp = None
    db.commit()

    return {"message": "Password updated successfully"}


online_users = {}

@app.post("/online")
def set_online_status(user_id: int = Body(...)):
    online_users[user_id] = time.time()
    return {"status": "updated"}

@app.get("/online_status/{user_id}")
def online_status(user_id: int, db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    now = datetime.utcnow()
    if user.last_seen and (now - user.last_seen).total_seconds() < 10:
        return {"online": True}
    return {"online": False}


@app.get("/online_status")
def online_status(user_id: int, db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    now = datetime.utcnow()
    if user.last_seen and (now - user.last_seen).total_seconds() < 10:
        return {"online": True}
    return {"online": False}



@app.post("/update_last_seen")
def update_last_seen(payload: UserIdPayload, db: Session = Depends(get_db)):
    print("Received user_id:", payload.user_id)

    user = db.query(models.User).filter(models.User.id == payload.user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    user.last_seen = datetime.utcnow()
    db.commit()
    return {"message": "Last seen updated"}

@app.post("/register", response_model=schemas.UserOut)
def register_user(user: schemas.UserCreate, db: Session = Depends(get_db)):
    db_user = db.query(models.User).filter(models.User.username == user.username).first()
    if db_user:
        return db_user  # ✅ Return existing user instead of error
    new_user = models.User(username=user.username,profile_pic=user.profile_pic)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user





@app.get("/users", response_model=list[schemas.UserOut])
def get_users(db: Session = Depends(get_db)):
    return db.query(models.User).all()

@app.delete("/messages/{sender_id}/to/{receiver_id}")
def delete_sent_messages(sender_id: int, receiver_id: int, db: Session = Depends(get_db)):
    db.query(models.Message).filter(
        models.Message.sender_id == sender_id,
        models.Message.receiver_id == receiver_id
    ).delete(synchronize_session=False)  # Added for safety
    db.commit()
    return {"detail": "Sent messages deleted for sender only"}





@app.post("/messages", response_model=schemas.MessageOut)
def send_message(msg: schemas.MessageCreate, db: Session = Depends(get_db)):
    new_msg = models.Message(**msg.dict(), delivered=True)  # ✅ set delivered to True
    db.add(new_msg)
    db.commit()
    db.refresh(new_msg)
    return new_msg

@app.post("/messages/seen")
def mark_messages_as_seen(payload: SeenPayload, db: Session = Depends(get_db)):
    db.query(models.Message).filter(
        models.Message.sender_id == payload.from_user,
        models.Message.receiver_id == payload.to_user,
        models.Message.seen == False
    ).update({models.Message.seen: True})
    db.commit()
    return {"message": "Messages marked as seen"}

@app.get("/messages", response_model=list[schemas.MessageOut])
def get_messages(from_user: int, to_user: int, db: Session = Depends(get_db)):
    return db.query(models.Message).filter(
        ((models.Message.sender_id == from_user) & (models.Message.receiver_id == to_user)) |
        ((models.Message.sender_id == to_user) & (models.Message.receiver_id == from_user))
    ).order_by(models.Message.timestamp).all()

@app.put("/messages/{id}", response_model=schemas.MessageOut)
def update_message(id: int, updated: schemas.MessageCreate, db: Session = Depends(get_db)):
    msg = db.query(models.Message).filter(models.Message.id == id).first()
    if not msg:
        raise HTTPException(status_code=404, detail="Message not found")
    
    msg.content = updated.content
    db.commit()
    db.refresh(msg)
    return msg

@app.delete("/messages/{id}")
def delete_message(id: int, db: Session = Depends(get_db)):
    msg = db.query(models.Message).filter(models.Message.id == id).first()
    if not msg:
        raise HTTPException(status_code=404, detail="Message not found")
    
    db.delete(msg)
    db.commit()
    return {"message": f"Message {id} deleted successfully"}

@app.get("/recent_chats/{user_id}")
def get_recent_chats(user_id: int, db: Session = Depends(get_db)):
    subquery = (
        db.query(models.Message)
        .filter(
            (models.Message.sender_id == user_id) | (models.Message.receiver_id == user_id)
        )
        .order_by(models.Message.timestamp.desc())
        .all()
    )

    seen_users = set()
    recent = []

    for msg in subquery:
        other_id = msg.receiver_id if msg.sender_id == user_id else msg.sender_id
        if other_id not in seen_users:
            user = db.query(models.User).filter(models.User.id == other_id).first()
            if user:
                recent.append({
                    "id": user.id,
                    "username": user.username,
                    "email": user.email,
                    "last_message": {
                        "content": msg.content,
                        "timestamp": msg.timestamp,
                        "sender_id": msg.sender_id,
                        "seen": msg.seen
                    }
                })
                seen_users.add(other_id)

    return recent





@app.get("/")
def read_root():
    return {"message": "FastAPI backend is running!"}

@app.get("/test-cors")
def test():
    return {"msg": "CORS working"}


