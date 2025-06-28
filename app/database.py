from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
from dotenv import load_dotenv
import os


load_dotenv()

# ✅ Use PostgreSQL instead of SQLite
SQLALCHEMY_DATABASE_URL = os.getenv("DATABASE_URL")

# ✅ No need for `connect_args` with PostgreSQL
engine = create_engine(SQLALCHEMY_DATABASE_URL)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()
