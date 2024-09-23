from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sqlalchemy import create_engine, Column, Integer, String, Boolean, ForeignKey, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from passlib.context import CryptContext
from jose import JWTError, jwt
from typing import List
from datetime import datetime, timedelta

# Configuration
DATABASE_URL = "sqlite:///./db.sqlite"
SECRET_KEY = "5e3b0f1a1d2c47c9b0a5eae7a5a27ef1e593f9e0f8582b39a5a4f8e88d457e73"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Database setup
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Models
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    email = Column(String, unique=True, index=True)
    password = Column(String)

class Task(Base):
    __tablename__ = "tasks"
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, index=True)
    description = Column(String, nullable=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    completed = Column(Boolean, default=False)
    due_date = Column(DateTime)  # Changement pour DateTime

Base.metadata.create_all(bind=engine)

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# JWT setup
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

# FastAPI app
app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Pydantic models
class UserCreate(BaseModel):
    username: str
    email: str
    password: str

class UserOut(BaseModel):
    id: int
    username: str
    email: str

class TaskCreate(BaseModel):
    title: str
    description: str = None
    due_date: datetime  # Changement pour DateTime

class TaskOut(TaskCreate):
    id: int
    completed: bool

class TaskStats(BaseModel):
    total_tasks: int
    completed_tasks: int
    incomplete_tasks: int
    completed_on_time: int
    remaining_tasks: int

# Functions

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta=None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_user(db: Session, user_id: int):
    return db.query(User).filter(User.id == user_id).first()

def create_default_users(db: Session):
    users = [
        {"username": "jedade", "email": "jediel@cyberspector.com", "password": "string@@2019"},
        {"username": "user1", "email": "user1@cyberspector.com", "password": "string@@2019"},
        {"username": "user2", "email": "user2@cyberspector.com", "password": "string@@2019"},
    ]
    
    for user_data in users:
        if not db.query(User).filter(User.email == user_data['email']).first():
            hashed_password = get_password_hash(user_data['password'])
            new_user = User(username=user_data['username'], email=user_data['email'], password=hashed_password)
            db.add(new_user)
    
    db.commit()

# Dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Auth
@app.post("/login", response_model=dict)
async def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == form_data.username).first()
    if not user or not verify_password(form_data.password, user.password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials", headers={"WWW-Authenticate": "Bearer"})
    
    access_token = create_access_token(data={"sub": str(user.id)})
    return {"access_token": access_token, "token_type": "bearer"}

# Tasks
@app.post("/tasks", response_model=TaskOut)
async def create_task(task: TaskCreate, db: Session = Depends(get_db), token: str = Depends(oauth2_scheme)):
    user_id = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])["sub"]
    new_task = Task(**task.dict(), user_id=user_id)
    db.add(new_task)
    db.commit()
    db.refresh(new_task)
    return new_task

@app.get("/tasks", response_model=List[TaskOut])
async def get_tasks(db: Session = Depends(get_db), token: str = Depends(oauth2_scheme)):
    user_id = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])["sub"]
    tasks = db.query(Task).filter(Task.user_id == user_id).all()
    return tasks

# Task statistics
@app.get("/tasks/stats", response_model=TaskStats)
async def get_task_statistics(db: Session = Depends(get_db), token: str = Depends(oauth2_scheme)):
    user_id = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])["sub"]
    tasks = db.query(Task).filter(Task.user_id == user_id).all()
    
    total_tasks = len(tasks)
    completed_tasks = len([task for task in tasks if task.completed])
    incomplete_tasks = total_tasks - completed_tasks
    completed_on_time = len([task for task in tasks if task.completed and task.due_date >= datetime.utcnow()])
    remaining_tasks = incomplete_tasks

    return TaskStats(
        total_tasks=total_tasks,
        completed_tasks=completed_tasks,
        incomplete_tasks=incomplete_tasks,
        completed_on_time=completed_on_time,
        remaining_tasks=remaining_tasks
    )

# Update and Delete Tasks
@app.put("/tasks/{task_id}", response_model=TaskOut)
async def update_task(task_id: int, task: TaskCreate, db: Session = Depends(get_db), token: str = Depends(oauth2_scheme)):
    user_id = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])["sub"]
    task_to_update = db.query(Task).filter(Task.id == task_id, Task.user_id == user_id).first()
    if not task_to_update:
        raise HTTPException(status_code=404, detail="Task not found")

    task_to_update.title = task.title
    task_to_update.description = task.description
    task_to_update.due_date = task.due_date
    db.commit()
    return task_to_update

@app.delete("/tasks/{task_id}")
async def delete_task(task_id: int, db: Session = Depends(get_db), token: str = Depends(oauth2_scheme)):
    user_id = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])["sub"]
    task_to_delete = db.query(Task).filter(Task.id == task_id, Task.user_id == user_id).first()
    if not task_to_delete:
        raise HTTPException(status_code=404, detail="Task not found")
    
    db.delete(task_to_delete)
    db.commit()
    return {"message": "Task deleted successfully!"}

@app.patch("/tasks/{task_id}/complete", response_model=TaskOut)
async def complete_task(task_id: int, db: Session = Depends(get_db), token: str = Depends(oauth2_scheme)):
    """
    Mark a task as completed for the logged-in user.
    
    - **task_id**: The ID of the task to be marked as completed.
    """
    user_id = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])["sub"]
    task_to_complete = db.query(Task).filter(Task.id == task_id, Task.user_id == user_id).first()
    if not task_to_complete:
        raise HTTPException(status_code=404, detail="Task not found")

    task_to_complete.completed = True  # Marquer la tâche comme terminée
    db.commit()
    db.refresh(task_to_complete)
    return task_to_complete

# Create default users
@app.on_event("startup")
def startup_event():
    db = SessionLocal()
    create_default_users(db)
    db.close()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=1000)
