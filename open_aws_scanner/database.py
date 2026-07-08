from sqlalchemy import create_engine, Column, Integer, String, Text, Float, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import datetime
import os

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./scanner.db")

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False} if "sqlite" in DATABASE_URL else {})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, expire_on_commit=False, bind=engine)
Base = declarative_base()


class ScanResult(Base):
    __tablename__ = "scan_results"
    id = Column(Integer, primary_key=True, index=True)
    scan_run_id = Column(Integer)
    resource_id = Column(String)
    resource_name = Column(String)
    resource_type = Column(String)
    reason = Column(String)
    estimated_monthly_savings = Column(Float)
    scanned_at = Column(DateTime, default=datetime.datetime.utcnow)
    tags = Column(Text, nullable=True)
    cpu_avg_percent = Column(Float, nullable=True)
    memory_avg_percent = Column(Float, nullable=True)
    network_in_bytes = Column(Float, nullable=True)
    network_out_bytes = Column(Float, nullable=True)
    status = Column(String, default="open")  # open, fixed, dismissed, in_progress
    status_changed_at = Column(DateTime, nullable=True)
    first_seen_at = Column(DateTime, nullable=True)
    region = Column(String, nullable=True)


class ScanRun(Base):
    __tablename__ = "scan_runs"
    id = Column(Integer, primary_key=True, index=True)
    status = Column(String, default="running")
    findings_count = Column(Integer, default=0)
    errors = Column(Text)
    started_at = Column(DateTime, default=datetime.datetime.utcnow)
    completed_at = Column(DateTime)


def init_db():
    Base.metadata.create_all(bind=engine)
