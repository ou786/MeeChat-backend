from pydantic import BaseModel
from datetime import datetime
from pydantic import BaseModel, EmailStr, Field


class PasswordResetRequest(BaseModel):
    email: EmailStr

# NEW: Registration - Step 1 (Send OTP)
class EmailOtpRequest(BaseModel):
    email: EmailStr
    username: str  # User chooses a username at registration time

# NEW: Registration - Step 2 (Verify OTP + Set Password)
class OtpVerificationRequest(BaseModel):
    email: EmailStr
    otp: str
    password: str = Field(..., min_length=6, description="Password must be at least 6 characters")


class EmailPayload(BaseModel):
    email: EmailStr

class OTPVerifyPayload(BaseModel):
    email: EmailStr
    otp: str

class UserIdPayload(BaseModel):
    user_id: int

class SeenPayload(BaseModel):
    from_user: int
    to_user: int


# Updated to include username for frontend
class UserOut(BaseModel):
    id: int
    email: EmailStr
    username: str

    class Config:
        from_attributes = True

class UserCreate(BaseModel):
    username: str
    profile_pic: str | None = None

class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class MessageCreate(BaseModel):
    sender_id: int
    receiver_id: int
    content: str
    image: str | None = None

class MessageOut(BaseModel):
    id: int
    sender_id: int
    receiver_id: int
    content: str
    image: str | None
    timestamp: datetime
    seen: bool
    delivered: bool

    class Config:
        from_attributes = True
