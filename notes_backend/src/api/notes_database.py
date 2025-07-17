"""
notes_database.py

Core implementation code for database models and utilities for the notes management system.

This supports:
- User authentication (register, login)
- CRUD notes
- Organization via folders and tags

Database Engine: SQLite (default for local dev) but can switch to PostgreSQL/MySQL via SQLALCHEMY_DATABASE_URL env variable.

Required Environment Variable:
- SQLALCHEMY_DATABASE_URL: The database connection string. Example (SQLite): "sqlite:///./notes.db"
- For PostgreSQL: "postgresql://user:password@host:port/dbname"

If SQLALCHEMY_DATABASE_URL is not set, defaults to a local file-based SQLite database (notes.db).

Usage:
    from notes_database import (
        get_db, User, Note, Folder, Tag,
        create_user, authenticate_user,
        create_note, get_notes_for_user, update_note, delete_note,
        create_folder, get_folders_for_user,
        create_tag, get_tags_for_user
    )
"""

import os
from typing import Generator, List, Optional

from sqlalchemy import (
    Column, Integer, String, ForeignKey, Text, DateTime, Table
)
from sqlalchemy.orm import declarative_base, relationship, sessionmaker, Session
from sqlalchemy import create_engine, func
from passlib.context import CryptContext

# --- Database setup ---
SQLALCHEMY_DATABASE_URL = os.getenv("SQLALCHEMY_DATABASE_URL", "sqlite:///./notes.db")
engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False} if SQLALCHEMY_DATABASE_URL.startswith("sqlite") else {},
    future=True,
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

# --- Association Tables ---

note_tag_association = Table(
    "note_tag_association",
    Base.metadata,
    Column("note_id", Integer, ForeignKey("notes.id")),
    Column("tag_id", Integer, ForeignKey("tags.id")),
)

# --- Models ---

class User(Base):
    """User account for authentication and ownership of notes/folders/tags."""
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True, nullable=False)
    email = Column(String(120), unique=True, index=True, nullable=False)
    hashed_password = Column(String(128), nullable=False)

    notes = relationship("Note", back_populates="owner")
    folders = relationship("Folder", back_populates="owner")
    tags = relationship("Tag", back_populates="owner")

class Folder(Base):
    """Folder for user note organization."""
    __tablename__ = "folders"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"))

    owner = relationship("User", back_populates="folders")
    notes = relationship("Note", back_populates="folder")

class Tag(Base):
    """Tag for categorizing notes."""
    __tablename__ = "tags"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(50), nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"))

    owner = relationship("User", back_populates="tags")
    notes = relationship(
        "Note",
        secondary=note_tag_association,
        back_populates="tags"
    )

class Note(Base):
    """The main note object."""
    __tablename__ = "notes"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(200), nullable=False)
    content = Column(Text, nullable=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    folder_id = Column(Integer, ForeignKey("folders.id"), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    owner = relationship("User", back_populates="notes")
    folder = relationship("Folder", back_populates="notes")
    tags = relationship(
        "Tag",
        secondary=note_tag_association,
        back_populates="notes"
    )

# --- Password Utility ---
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

# --- Dependency: Acquire DB Session ---
# PUBLIC_INTERFACE
def get_db() -> Generator[Session, None, None]:
    """Yield a database session, closing after use."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# PUBLIC_INTERFACE
def init_db() -> None:
    """
    Initialize the database. Should be called at application start if tables do not exist.
    """
    Base.metadata.create_all(bind=engine)

# --- User Management ---
# PUBLIC_INTERFACE
def get_user_by_username(db: Session, username: str) -> Optional[User]:
    """Get a user by their username."""
    return db.query(User).filter(User.username == username).first()

# PUBLIC_INTERFACE
def get_user_by_email(db: Session, email: str) -> Optional[User]:
    """Get a user by their email."""
    return db.query(User).filter(User.email == email).first()

# PUBLIC_INTERFACE
def create_user(db: Session, username: str, email: str, password: str) -> User:
    """Create a new user account."""
    hashed_password = get_password_hash(password)
    user = User(username=username, email=email, hashed_password=hashed_password)
    db.add(user)
    db.commit()
    db.refresh(user)
    return user

# PUBLIC_INTERFACE
def authenticate_user(db: Session, username: str, password: str) -> Optional[User]:
    """
    Authenticate a user. Returns User if successful, otherwise None.
    """
    user = get_user_by_username(db, username)
    if not user:
        return None
    if not verify_password(password, user.hashed_password):
        return None
    return user

# --- Note CRUD ---
# PUBLIC_INTERFACE
def create_note(db: Session, user_id: int, title: str, content: str = "", folder_id: Optional[int] = None, tag_ids: Optional[List[int]] = None) -> Note:
    """Create a new note."""
    note = Note(title=title, content=content, user_id=user_id, folder_id=folder_id)
    if tag_ids:
        note.tags = db.query(Tag).filter(Tag.id.in_(tag_ids)).all()
    db.add(note)
    db.commit()
    db.refresh(note)
    return note

# PUBLIC_INTERFACE
def get_notes_for_user(db: Session, user_id: int, folder_id: Optional[int] = None) -> List[Note]:
    """Get all notes for a user (optionally filter by folder)."""
    query = db.query(Note).filter(Note.user_id == user_id)
    if folder_id is not None:
        query = query.filter(Note.folder_id == folder_id)
    return query.order_by(Note.created_at.desc()).all()

# PUBLIC_INTERFACE
def update_note(db: Session, note_id: int, title: Optional[str] = None, content: Optional[str] = None, folder_id: Optional[int] = None, tag_ids: Optional[List[int]] = None) -> Optional[Note]:
    """Update a note's fields; returns updated Note or None."""
    note = db.query(Note).filter(Note.id == note_id).first()
    if not note:
        return None
    if title is not None:
        note.title = title
    if content is not None:
        note.content = content
    if folder_id is not None:
        note.folder_id = folder_id
    if tag_ids is not None:
        note.tags = db.query(Tag).filter(Tag.id.in_(tag_ids)).all()
    db.commit()
    db.refresh(note)
    return note

# PUBLIC_INTERFACE
def delete_note(db: Session, note_id: int) -> bool:
    """Delete a note by ID. Returns True if deleted, False otherwise."""
    note = db.query(Note).filter(Note.id == note_id).first()
    if not note:
        return False
    db.delete(note)
    db.commit()
    return True

# --- Folder CRUD ---
# PUBLIC_INTERFACE
def create_folder(db: Session, user_id: int, name: str) -> Folder:
    """Create a new folder for a user."""
    folder = Folder(name=name, user_id=user_id)
    db.add(folder)
    db.commit()
    db.refresh(folder)
    return folder

# PUBLIC_INTERFACE
def get_folders_for_user(db: Session, user_id: int) -> List[Folder]:
    """Get all folders for a user."""
    return db.query(Folder).filter(Folder.user_id == user_id).order_by(Folder.name).all()

# --- Tag CRUD ---
# PUBLIC_INTERFACE
def create_tag(db: Session, user_id: int, name: str) -> Tag:
    """Create a new tag for a user."""
    tag = Tag(name=name, user_id=user_id)
    db.add(tag)
    db.commit()
    db.refresh(tag)
    return tag

# PUBLIC_INTERFACE
def get_tags_for_user(db: Session, user_id: int) -> List[Tag]:
    """Get all tags for a user."""
    return db.query(Tag).filter(Tag.user_id == user_id).order_by(Tag.name).all()

# --- Helper: Search notes ---
# PUBLIC_INTERFACE
def search_notes(db: Session, user_id: int, query_text: str) -> List[Note]:
    """Search user's notes for a string in title or content."""
    return db.query(Note).filter(
        Note.user_id == user_id,
        (Note.title.ilike(f"%{query_text}%")) | (Note.content.ilike(f"%{query_text}%"))
    ).order_by(Note.updated_at.desc(), Note.created_at.desc()).all()


# --- Run database initialization if run directly ---
if __name__ == "__main__":
    print("Initializing database ...")
    init_db()
    print("Initialized!")

