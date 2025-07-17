from fastapi import FastAPI, Depends, HTTPException, status, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, Field, EmailStr
from typing import List, Optional
from datetime import timedelta, datetime
from jose import jwt, JWTError

from src.api.notes_database import (
    get_db, User, Note,
    create_user, authenticate_user,
    create_note, get_notes_for_user, update_note, delete_note,
    create_folder, get_folders_for_user,
    create_tag, get_tags_for_user,
    search_notes
)
from sqlalchemy.orm import Session
import os

# App Config
app = FastAPI(
    title="Notes Management API",
    description="RESTful API for note creation, organization, and search, with user authentication.",
    version="1.0.0",
    openapi_tags=[
        {"name": "Authentication", "description": "User registration and login."},
        {"name": "Notes", "description": "CRUD and search for notes."},
        {"name": "Folders", "description": "Folder management and organization."},
        {"name": "Tags", "description": "Tag creation and usage."},
        {"name": "Users", "description": "User info and profile."}
    ]
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- JWT settings ---
SECRET_KEY = os.getenv("JWT_SECRET_KEY", "dev-secret-do-not-use-in-prod")  # replace in prod
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60*24*7  # 7 days

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login")


# ---------- SCHEMAS ----------
# -- User --
class UserBase(BaseModel):
    username: str = Field(..., max_length=50)
    email: EmailStr

class UserCreate(UserBase):
    password: str = Field(..., min_length=6, max_length=128)

class UserRead(UserBase):
    id: int

    class Config:
        orm_mode = True

# -- Token --
class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: str | None = None

# -- Notes --
class NoteBase(BaseModel):
    title: str = Field(..., max_length=200)
    content: Optional[str] = ""

class NoteCreate(NoteBase):
    folder_id: Optional[int] = None
    tag_ids: Optional[List[int]] = None

class NoteUpdate(BaseModel):
    title: Optional[str] = None
    content: Optional[str] = None
    folder_id: Optional[int] = None
    tag_ids: Optional[List[int]] = None

class NoteRead(NoteBase):
    id: int
    folder_id: Optional[int] = None
    tags: List[str]
    created_at: Optional[datetime]
    updated_at: Optional[datetime] = None

    class Config:
        orm_mode = True

# -- Folder --
class FolderBase(BaseModel):
    name: str = Field(..., max_length=100)

class FolderCreate(FolderBase): pass

class FolderRead(FolderBase):
    id: int
    class Config:
        orm_mode = True

# -- Tag --
class TagBase(BaseModel):
    name: str = Field(..., max_length=50)

class TagCreate(TagBase): pass

class TagRead(TagBase):
    id: int
    class Config:
        orm_mode = True

# --------- JWT UTILITIES ----------
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    """Generate a JWT token."""
    to_encode = data.copy()
    expire = (datetime.utcnow() + expires_delta) if expires_delta else (datetime.utcnow() + timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def decode_access_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
        return username
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

# --------- DEPENDENCIES ----------
def get_current_user(db: Session = Depends(get_db), token: str = Depends(oauth2_scheme)) -> User:
    """Validate JWT and retrieve user from db."""
    username = decode_access_token(token)
    user = User
    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user

# --------- HEALTH CHECK -----------
@app.get("/", tags=["Health"])
def health_check():
    """Simple health check endpoint."""
    return {"message": "Healthy"}

# --------- AUTH ENDPOINTS ----------
@app.post("/auth/register", response_model=UserRead, tags=["Authentication"], summary="Register")
# PUBLIC_INTERFACE
def register(user: UserCreate, db: Session = Depends(get_db)):
    """Register a new user. Returns user info on success."""
    if db.query(User).filter((User.username == user.username) | (User.email == user.email)).first():
        raise HTTPException(status_code=400, detail="Username or email already registered")
    user_obj = create_user(db, user.username, user.email, user.password)
    return user_obj

@app.post("/auth/login", response_model=Token, tags=["Authentication"], summary="Login")
# PUBLIC_INTERFACE
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    """Authenticate user and return JWT if credentials valid."""
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    access_token = create_access_token(
        {"sub": user.username},
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/users/me", response_model=UserRead, tags=["Users"], summary="Current user profile")
# PUBLIC_INTERFACE
def get_me(current_user: User = Depends(get_current_user)):
    """Return current authenticated user profile."""
    return current_user

# --------- NOTE ENDPOINTS ----------
@app.post("/notes/", response_model=NoteRead, tags=["Notes"], summary="Create Note")
# PUBLIC_INTERFACE
def create_note_api(note: NoteCreate, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    """Create a new note for user."""
    note_obj = create_note(
        db=db, user_id=current_user.id,
        title=note.title, content=note.content or "",
        folder_id=note.folder_id, tag_ids=note.tag_ids
    )
    tag_names = [t.name for t in note_obj.tags] if note_obj.tags else []
    return NoteRead(
        id=note_obj.id, title=note_obj.title, content=note_obj.content, folder_id=note_obj.folder_id,
        tags=tag_names, created_at=note_obj.created_at, updated_at=note_obj.updated_at
    )

@app.get("/notes/", response_model=List[NoteRead], tags=["Notes"], summary="List Notes")
# PUBLIC_INTERFACE
def list_notes(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    folder_id: Optional[int] = Query(None, description="Only notes from this folder"),
    sort_by: Optional[str] = Query("created_at", description="Sort by field"),
    order: Optional[str] = Query("desc", description="asc or desc"),
    search: Optional[str] = Query(None, description="Search term in title or content")
):
    """List notes for current user with search, sort, and folder filter."""
    if search:
        notes = search_notes(db, current_user.id, search)
    else:
        notes = get_notes_for_user(db, current_user.id, folder_id)
    # Sorting in Python for now, since the base queries above sort by created/updated desc by default
    if sort_by and hasattr(Note, sort_by):
        notes.sort(key=lambda n: getattr(n, sort_by) or '', reverse=(order == "desc"))
    result = []
    for n in notes:
        result.append(NoteRead(
            id=n.id,
            title=n.title,
            content=n.content,
            folder_id=n.folder_id,
            tags=[t.name for t in n.tags],
            created_at=n.created_at,
            updated_at=n.updated_at
        ))
    return result

@app.get("/notes/{note_id}", response_model=NoteRead, tags=["Notes"], summary="Get Note")
# PUBLIC_INTERFACE
def get_note(note_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    """Get a single note belonging to the current user."""
    n = db.query(Note).filter(Note.id == note_id, Note.user_id == current_user.id).first()
    if not n:
        raise HTTPException(status_code=404, detail="Note not found")
    return NoteRead(
        id=n.id, title=n.title, content=n.content, folder_id=n.folder_id,
        tags=[t.name for t in n.tags], created_at=n.created_at, updated_at=n.updated_at
    )

@app.put("/notes/{note_id}", response_model=NoteRead, tags=["Notes"], summary="Update Note")
# PUBLIC_INTERFACE
def update_note_api(note_id: int, note: NoteUpdate, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    """Update a note. Only the note's owner can update."""
    n = db.query(Note).filter(Note.id == note_id, Note.user_id == current_user.id).first()
    if not n:
        raise HTTPException(status_code=404, detail="Note not found")
    updated = update_note(
        db, note_id=note_id,
        title=note.title, content=note.content,
        folder_id=note.folder_id, tag_ids=note.tag_ids
    )
    tag_names = [t.name for t in updated.tags] if updated and updated.tags else []
    return NoteRead(
        id=updated.id, title=updated.title, content=updated.content, folder_id=updated.folder_id,
        tags=tag_names, created_at=updated.created_at, updated_at=updated.updated_at
    )

@app.delete("/notes/{note_id}", response_model=dict, tags=["Notes"], summary="Delete Note")
# PUBLIC_INTERFACE
def delete_note_api(note_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    """Delete a note explicitly. Only the note's owner can delete."""
    n = db.query(Note).filter(Note.id == note_id, Note.user_id == current_user.id).first()
    if not n:
        raise HTTPException(status_code=404, detail="Note not found")
    res = delete_note(db, note_id)
    return {"status": "deleted" if res else "not found"}

# --------- FOLDER ENDPOINTS ----------
@app.post("/folders/", response_model=FolderRead, tags=["Folders"], summary="Create Folder")
# PUBLIC_INTERFACE
def create_folder_api(folder: FolderCreate, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    """Create a new folder for the currently authenticated user."""
    folder_obj = create_folder(db, current_user.id, folder.name)
    return FolderRead(id=folder_obj.id, name=folder_obj.name)

@app.get("/folders/", response_model=List[FolderRead], tags=["Folders"], summary="List Folders")
# PUBLIC_INTERFACE
def list_folders(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    """List all folders for the current user."""
    folders = get_folders_for_user(db, current_user.id)
    return [FolderRead(id=f.id, name=f.name) for f in folders]

# --------- TAG ENDPOINTS ----------
@app.post("/tags/", response_model=TagRead, tags=["Tags"], summary="Create Tag")
# PUBLIC_INTERFACE
def create_tag_api(tag: TagCreate, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    """Create a new tag for the current user."""
    tag_obj = create_tag(db, current_user.id, tag.name)
    return TagRead(id=tag_obj.id, name=tag_obj.name)

@app.get("/tags/", response_model=List[TagRead], tags=["Tags"], summary="List Tags")
# PUBLIC_INTERFACE
def list_tags(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    """List all tags for the current user."""
    tags_db = get_tags_for_user(db, current_user.id)
    return [TagRead(id=t.id, name=t.name) for t in tags_db]
