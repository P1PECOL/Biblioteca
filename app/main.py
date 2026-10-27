"""Biblioteca Virtual – Colegio Mayor del Cauca. API FastAPI + SQLAlchemy + Gamificación."""
import os, re, hmac, hashlib, base64, json, time, secrets
from datetime import datetime, date, timedelta
from typing import Optional
from fastapi import FastAPI, Depends, HTTPException, Header, Query
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
from sqlalchemy import create_engine, String, Integer, Boolean, Date, DateTime, ForeignKey, UniqueConstraint, select, func
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker, Session

DB_URL = os.getenv("DATABASE_URL", "sqlite:///./biblioteca.db")
SECRET = os.getenv("SECRET_KEY", "dev-secret").encode()
LOAN_DAYS, FINE_PER_DAY, MAX_RENEWALS, MAX_ACTIVE = 7, 500, 2, 3
BOOK_BADGES = {1: ("FIRST_BOOK", "Primer libro", "📖"), 5: ("READER_5", "Lector constante", "📚"),
               10: ("READER_10", "Devorador de libros", "🏅"), 25: ("READER_25", "Maestro lector", "🏆")}
STREAK_BADGES = {3: ("STREAK_3", "Racha de 3 días", "🔥"), 7: ("STREAK_7", "Semana perfecta", "⚡"),
                 30: ("STREAK_30", "Mes imparable", "🌟")}
BADGE_INFO = {c: (n, e) for c, n, e in list(BOOK_BADGES.values()) + list(STREAK_BADGES.values())}

engine = create_engine(DB_URL, connect_args={"check_same_thread": False} if DB_URL.startswith("sqlite") else {})
Session_ = sessionmaker(bind=engine, expire_on_commit=False)

class Base(DeclarativeBase): pass
class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(120))
    code: Mapped[str] = mapped_column(String(30), unique=True)
    email: Mapped[str] = mapped_column(String(120), unique=True)
    pw: Mapped[str] = mapped_column(String(200))
    role: Mapped[str] = mapped_column(String(20), default="student")
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    streak: Mapped[int] = mapped_column(Integer, default=0)
    streak_max: Mapped[int] = mapped_column(Integer, default=0)
    last_read: Mapped[Optional[date]] = mapped_column(Date, nullable=True)
class Book(Base):
    __tablename__ = "books"
    id: Mapped[int] = mapped_column(primary_key=True)
    title: Mapped[str] = mapped_column(String(200)); author: Mapped[str] = mapped_column(String(120))
    isbn: Mapped[str] = mapped_column(String(20), unique=True); category: Mapped[str] = mapped_column(String(60))
    total: Mapped[int] = mapped_column(Integer); available: Mapped[int] = mapped_column(Integer)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
class Loan(Base):
    __tablename__ = "loans"
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id")); book_id: Mapped[int] = mapped_column(ForeignKey("books.id"))
    loaned_at: Mapped[datetime] = mapped_column(DateTime); due_at: Mapped[datetime] = mapped_column(DateTime)
    returned_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    renewals: Mapped[int] = mapped_column(Integer, default=0); finished: Mapped[bool] = mapped_column(Boolean, default=False)
class Penalty(Base):
    __tablename__ = "penalties"
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id")); loan_id: Mapped[int] = mapped_column(ForeignKey("loans.id"))
    days: Mapped[int] = mapped_column(Integer); amount: Mapped[int] = mapped_column(Integer)
    status: Mapped[str] = mapped_column(String(15), default="pendiente")
    created_at: Mapped[datetime] = mapped_column(DateTime); lifted_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
class Badge(Base):
    __tablename__ = "badges"
    __table_args__ = (UniqueConstraint("user_id", "code"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id")); code: Mapped[str] = mapped_column(String(40))
    name: Mapped[str] = mapped_column(String(80)); emoji: Mapped[str] = mapped_column(String(8))
    awarded_at: Mapped[datetime] = mapped_column(DateTime)
class Challenge(Base):
    __tablename__ = "challenges"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(120)); goal: Mapped[int] = mapped_column(Integer)
    start: Mapped[date] = mapped_column(Date); end: Mapped[date] = mapped_column(Date)
class Participation(Base):
    __tablename__ = "participations"
    __table_args__ = (UniqueConstraint("challenge_id", "user_id"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    challenge_id: Mapped[int] = mapped_column(ForeignKey("challenges.id")); user_id: Mapped[int] = mapped_column(ForeignKey("users.id"))

# ---------- utilidades ----------
def hash_pw(p, salt=None):
    salt = salt or secrets.token_hex(8)
    return salt + "$" + hashlib.pbkdf2_hmac("sha256", p.encode(), salt.encode(), 60000).hex()
def check_pw(p, h): return hmac.compare_digest(hash_pw(p, h.split("$")[0]), h)
def make_token(uid):
    body = base64.urlsafe_b64encode(json.dumps({"u": uid, "e": int(time.time()) + 86400}).encode()).decode()
    return body + "." + hmac.new(SECRET, body.encode(), hashlib.sha256).hexdigest()
def read_token(t):
    try:
        body, sig = t.split(".")
        if not hmac.compare_digest(sig, hmac.new(SECRET, body.encode(), hashlib.sha256).hexdigest()): return None
        d = json.loads(base64.urlsafe_b64decode(body))
        return d["u"] if d["e"] > time.time() else None
    except Exception: return None
def get_db():
    db = Session_()
    try: yield db
    finally: db.close()
def current_user(authorization: str = Header(None), db: Session = Depends(get_db)) -> User:
    uid = read_token((authorization or "").replace("Bearer ", ""))
    u = db.get(User, uid) if uid else None
    if not u or not u.active: raise HTTPException(401, "Sesión no válida")
    return u
def staff(u: User = Depends(current_user)):
    if u.role not in ("librarian", "admin"): raise HTTPException(403, "Requiere rol bibliotecario o administrador")
    return u
def admin(u: User = Depends(current_user)):
    if u.role != "admin": raise HTTPException(403, "Requiere rol administrador")
    return u
def uj(u): return {"id": u.id, "name": u.name, "code": u.code, "email": u.email, "role": u.role, "active": u.active}
def bj(b): return {"id": b.id, "title": b.title, "author": b.author, "isbn": b.isbn, "category": b.category, "total": b.total, "available": b.available}
def lj(l, db):
    b, u = db.get(Book, l.book_id), db.get(User, l.user_id)
    late = max(0, (datetime.utcnow() - l.due_at).days) if not l.returned_at else 0
    return {"id": l.id, "book": b.title, "book_id": b.id, "user": u.name, "user_id": u.id, "loaned_at": l.loaned_at.isoformat(),
            "due_at": l.due_at.isoformat(), "returned_at": l.returned_at.isoformat() if l.returned_at else None,
            "renewals": l.renewals, "finished": l.finished, "days_late": late}

# ---------- gamificación ----------
def award(db, user_id, code, name, emoji):
    if db.scalar(select(Badge).where(Badge.user_id == user_id, Badge.code == code)): return None
    db.add(Badge(user_id=user_id, code=code, name=name, emoji=emoji, awarded_at=datetime.utcnow()))
    return {"code": code, "name": name, "emoji": emoji}
def finished_count(db, uid):
    return db.scalar(select(func.count()).select_from(Loan).where(Loan.user_id == uid, Loan.finished == True, Loan.returned_at != None))
def challenge_progress(db, c):
    ids = [p.user_id for p in db.scalars(select(Participation).where(Participation.challenge_id == c.id))]
    if not ids: return 0
    return db.scalar(select(func.count()).select_from(Loan).where(Loan.user_id.in_(ids), Loan.finished == True,
        Loan.returned_at >= datetime.combine(c.start, datetime.min.time()), Loan.returned_at < datetime.combine(c.end + timedelta(days=1), datetime.min.time())))
def evaluate_book_badges(db, uid):
    new = []; n = finished_count(db, uid)
    for th, (code, name, em) in BOOK_BADGES.items():
        if n >= th and (b := award(db, uid, code, name, em)): new.append(b)
    for c in db.scalars(select(Challenge)):
        if challenge_progress(db, c) >= c.goal:
            for p in db.scalars(select(Participation).where(Participation.challenge_id == c.id)):
                b = award(db, p.user_id, f"CHALLENGE_{c.id}", f"Reto: {c.name}", "🤝")
                if b and p.user_id == uid: new.append(b)
    return new

# ---------- app ----------
app = FastAPI(title="Biblioteca Virtual – Colegio Mayor del Cauca", version="1.0")
FAILS: dict = {}

class RegisterIn(BaseModel):
    name: str = Field(min_length=3); code: str = Field(min_length=3)
    email: str = Field(pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$"); password: str = Field(min_length=6)
class LoginIn(BaseModel): email: str; password: str
class BookIn(BaseModel):
    title: str; author: str; isbn: str; category: str; total: int = Field(ge=1)
class ChallengeIn(BaseModel):
    name: str; goal: int = Field(ge=1); start: date; end: date

@app.post("/api/auth/register", status_code=201)
def register(d: RegisterIn, db: Session = Depends(get_db)):
    if db.scalar(select(User).where((User.code == d.code) | (User.email == d.email.lower()))):
        raise HTTPException(409, "El código o el correo ya están registrados")
    u = User(name=d.name, code=d.code, email=d.email.lower(), pw=hash_pw(d.password)); db.add(u); db.commit()
    return {"token": make_token(u.id), "user": uj(u)}
@app.post("/api/auth/login")
def login(d: LoginIn, db: Session = Depends(get_db)):
    k = d.email.lower(); f = FAILS.get(k, (0, 0))
    if f[0] >= 5 and time.time() < f[1]: raise HTTPException(429, "Demasiados intentos. Intenta en unos minutos.")
    u = db.scalar(select(User).where(User.email == k))
    if not u or not u.active or not check_pw(d.password, u.pw):
        FAILS[k] = (f[0] + 1, time.time() + 300); raise HTTPException(401, "Credenciales incorrectas")
    FAILS.pop(k, None); return {"token": make_token(u.id), "user": uj(u)}
@app.get("/api/me")
def me(u: User = Depends(current_user)): return uj(u)

@app.get("/api/students")
def students(_: User = Depends(staff), db: Session = Depends(get_db)): return [uj(u) for u in db.scalars(select(User).order_by(User.name))]
@app.patch("/api/students/{uid}")
def edit_student(uid: int, active: Optional[bool] = None, role: Optional[str] = None, a: User = Depends(admin), db: Session = Depends(get_db)):
    u = db.get(User, uid)
    if not u: raise HTTPException(404, "No existe")
    if active is not None: u.active = active
    if role in ("student", "librarian", "admin"): u.role = role
    db.commit(); return uj(u)

@app.get("/api/books")
def books(q: str = "", db: Session = Depends(get_db), _: User = Depends(current_user)):
    st = select(Book).where(Book.active == True)
    if q: like = f"%{q}%"; st = st.where(Book.title.ilike(like) | Book.author.ilike(like) | Book.category.ilike(like))
    return [bj(b) for b in db.scalars(st.order_by(Book.title))]
@app.post("/api/books", status_code=201)
def add_book(d: BookIn, _: User = Depends(staff), db: Session = Depends(get_db)):
    if db.scalar(select(Book).where(Book.isbn == d.isbn)): raise HTTPException(409, "Ya existe un libro con ese ISBN")
    b = Book(**d.model_dump(), available=d.total); db.add(b); db.commit(); return bj(b)
@app.delete("/api/books/{bid}")
def del_book(bid: int, _: User = Depends(staff), db: Session = Depends(get_db)):
    b = db.get(Book, bid)
    if not b: raise HTTPException(404, "No existe")
    if b.available < b.total: raise HTTPException(409, "Tiene préstamos vigentes")
    b.active = False; db.commit(); return {"ok": True}

@app.post("/api/loans", status_code=201)
def new_loan(book_id: int, user_id: Optional[int] = None, u: User = Depends(current_user), db: Session = Depends(get_db)):
    target = db.get(User, user_id) if (user_id and u.role != "student") else u
    b = db.get(Book, book_id)
    if not b or not b.active: raise HTTPException(404, "Libro no encontrado")
    if b.available < 1: raise HTTPException(409, "No hay ejemplares disponibles")
    if db.scalar(select(Penalty).where(Penalty.user_id == target.id, Penalty.status == "pendiente")):
        raise HTTPException(409, "Tienes sanciones pendientes")
    active = db.scalar(select(func.count()).select_from(Loan).where(Loan.user_id == target.id, Loan.returned_at == None))
    if active >= MAX_ACTIVE: raise HTTPException(409, f"Máximo {MAX_ACTIVE} préstamos simultáneos")
    now = datetime.utcnow(); l = Loan(user_id=target.id, book_id=b.id, loaned_at=now, due_at=now + timedelta(days=LOAN_DAYS))
    b.available -= 1; db.add(l); db.commit(); return lj(l, db)
@app.post("/api/loans/{lid}/return")
def return_loan(lid: int, finished: bool = True, u: User = Depends(current_user), db: Session = Depends(get_db)):
    l = db.get(Loan, lid)
    if not l or (u.role == "student" and l.user_id != u.id): raise HTTPException(404, "Préstamo no encontrado")
    if l.returned_at: raise HTTPException(409, "Ya fue devuelto")
    now = datetime.utcnow(); l.returned_at = now; l.finished = finished; db.get(Book, l.book_id).available += 1
    late = (now - l.due_at).days; penalty = None
    if late > 0:
        penalty = Penalty(user_id=l.user_id, loan_id=l.id, days=late, amount=late * FINE_PER_DAY, created_at=now); db.add(penalty)
    db.flush(); new = evaluate_book_badges(db, l.user_id) if finished else []
    db.commit()
    return {"loan": lj(l, db), "penalty": {"days": late, "amount": late * FINE_PER_DAY} if penalty else None, "new_badges": new if u.id == l.user_id else []}
@app.post("/api/loans/{lid}/renew")
def renew(lid: int, u: User = Depends(current_user), db: Session = Depends(get_db)):
    l = db.get(Loan, lid)
    if not l or (u.role == "student" and l.user_id != u.id): raise HTTPException(404, "Préstamo no encontrado")
    if l.returned_at: raise HTTPException(409, "Préstamo ya devuelto")
    if l.renewals >= MAX_RENEWALS: raise HTTPException(409, f"Máximo {MAX_RENEWALS} renovaciones")
    if l.due_at < datetime.utcnow(): raise HTTPException(409, "El préstamo está vencido")
    l.due_at += timedelta(days=LOAN_DAYS); l.renewals += 1; db.commit(); return lj(l, db)
@app.get("/api/loans")
def loans(all: bool = False, u: User = Depends(current_user), db: Session = Depends(get_db)):
    st = select(Loan).order_by(Loan.loaned_at.desc())
    if not (all and u.role != "student"): st = st.where(Loan.user_id == u.id)
    return [lj(l, db) for l in db.scalars(st)]

@app.get("/api/penalties")
def penalties(u: User = Depends(current_user), db: Session = Depends(get_db)):
    st = select(Penalty).order_by(Penalty.created_at.desc())
    if u.role == "student": st = st.where(Penalty.user_id == u.id)
    return [{"id": p.id, "user": db.get(User, p.user_id).name, "days": p.days, "amount": p.amount, "status": p.status} for p in db.scalars(st)]
@app.post("/api/penalties/{pid}/lift")
def lift(pid: int, _: User = Depends(staff), db: Session = Depends(get_db)):
    p = db.get(Penalty, pid)
    if not p: raise HTTPException(404, "No existe")
    p.status, p.lifted_at = "levantada", datetime.utcnow(); db.commit(); return {"ok": True}

@app.get("/api/reports/summary")
def report(_: User = Depends(staff), db: Session = Depends(get_db)):
    cnt = lambda m, *w: db.scalar(select(func.count()).select_from(m).where(*w))
    top = db.execute(select(Book.title, func.count(Loan.id).label("n")).join(Loan, Loan.book_id == Book.id).group_by(Book.id).order_by(func.count(Loan.id).desc()).limit(5)).all()
    return {"loans_total": cnt(Loan), "loans_active": cnt(Loan, Loan.returned_at == None), "penalties_pending": cnt(Penalty, Penalty.status == "pendiente"),
            "amount_pending": db.scalar(select(func.coalesce(func.sum(Penalty.amount), 0)).where(Penalty.status == "pendiente")),
            "top_books": [{"title": t, "loans": n} for t, n in top], "badges_awarded": cnt(Badge)}

@app.post("/api/reading/checkin")
def checkin(u: User = Depends(current_user), db: Session = Depends(get_db)):
    u = db.get(User, u.id); today = date.today()
    if u.last_read == today: raise HTTPException(409, "Ya registraste tu lectura de hoy")
    u.streak = u.streak + 1 if u.last_read == today - timedelta(days=1) else 1
    u.streak_max = max(u.streak_max, u.streak); u.last_read = today; new = []
    for th, (code, name, em) in STREAK_BADGES.items():
        if u.streak >= th and (b := award(db, u.id, code, name, em)): new.append(b)
    db.commit(); return {"streak": u.streak, "streak_max": u.streak_max, "new_badges": new}
@app.get("/api/gamification/me")
def my_gamification(u: User = Depends(current_user), db: Session = Depends(get_db)):
    u = db.get(User, u.id); n = finished_count(db, u.id)
    streak = u.streak if u.last_read and u.last_read >= date.today() - timedelta(days=1) else 0
    nxt = next((th for th in BOOK_BADGES if th > n), None)
    return {"books_finished": n, "next_badge_at": nxt, "streak": streak, "streak_max": u.streak_max, "checked_today": u.last_read == date.today(),
            "badges": [{"code": b.code, "name": b.name, "emoji": b.emoji, "awarded_at": b.awarded_at.isoformat()} for b in db.scalars(select(Badge).where(Badge.user_id == u.id).order_by(Badge.awarded_at))],
            "catalog": [{"code": c, "name": nm, "emoji": em} for c, (nm, em) in BADGE_INFO.items()]}
@app.get("/api/leaderboard")
def leaderboard(_: User = Depends(current_user), db: Session = Depends(get_db)):
    rows = db.execute(select(User.name, func.count(Loan.id)).join(Loan, Loan.user_id == User.id).where(Loan.finished == True, Loan.returned_at != None).group_by(User.id).order_by(func.count(Loan.id).desc()).limit(5)).all()
    return [{"name": n, "books": c} for n, c in rows]
@app.get("/api/challenges")
def challenges(u: User = Depends(current_user), db: Session = Depends(get_db)):
    out = []
    for c in db.scalars(select(Challenge).order_by(Challenge.end.desc())):
        prog = challenge_progress(db, c)
        out.append({"id": c.id, "name": c.name, "goal": c.goal, "start": c.start.isoformat(), "end": c.end.isoformat(), "progress": prog,
                    "participants": db.scalar(select(func.count()).select_from(Participation).where(Participation.challenge_id == c.id)),
                    "joined": bool(db.scalar(select(Participation).where(Participation.challenge_id == c.id, Participation.user_id == u.id))),
                    "completed": prog >= c.goal})
    return out
@app.post("/api/challenges", status_code=201)
def new_challenge(d: ChallengeIn, _: User = Depends(staff), db: Session = Depends(get_db)):
    if d.end < d.start: raise HTTPException(422, "La fecha de fin debe ser posterior al inicio")
    c = Challenge(**d.model_dump()); db.add(c); db.commit(); return {"id": c.id}
@app.post("/api/challenges/{cid}/join")
def join(cid: int, u: User = Depends(current_user), db: Session = Depends(get_db)):
    if not db.get(Challenge, cid): raise HTTPException(404, "No existe")
    if not db.scalar(select(Participation).where(Participation.challenge_id == cid, Participation.user_id == u.id)):
        db.add(Participation(challenge_id=cid, user_id=u.id)); db.commit()
    return {"ok": True}

# ---------- arranque + datos de ejemplo ----------
@app.on_event("startup")
def startup():
    Base.metadata.create_all(engine)
    with Session_() as db:
        if db.scalar(select(func.count()).select_from(User)): return
        for n, c, e, p, r in [("Administrador", "ADM001", "admin@biblioteca.edu", "admin123", "admin"),
                              ("Bibliotecaria", "BIB001", "biblio@biblioteca.edu", "biblio123", "librarian"),
                              ("Estudiante Demo", "EST001", "estudiante@biblioteca.edu", "estudiante123", "student")]:
            db.add(User(name=n, code=c, email=e, pw=hash_pw(p), role=r))
        for t, a, i, c, n in [("Cien años de soledad", "Gabriel García Márquez", "9780307474728", "Novela", 3), ("El coronel no tiene quien le escriba", "Gabriel García Márquez", "9780060732806", "Novela", 2),
            ("Clean Code", "Robert C. Martin", "9780132350884", "Ingeniería de software", 2), ("Design Patterns", "Erich Gamma et al.", "9780201633610", "Ingeniería de software", 2),
            ("Software Engineering", "Ian Sommerville", "9780133943030", "Ingeniería de software", 3), ("Sistemas de Información Gerencial", "K. Laudon", "9786073221795", "Sistemas", 2),
            ("Fundamentos de Bases de Datos", "Silberschatz", "9788448190330", "Bases de datos", 2), ("Python Crash Course", "Eric Matthes", "9781593279288", "Programación", 3),
            ("Don Quijote de la Mancha", "Miguel de Cervantes", "9788420412146", "Clásicos", 2), ("El Principito", "Antoine de Saint-Exupéry", "9780156012195", "Clásicos", 4),
            ("Redes de Computadoras", "Andrew Tanenbaum", "9786073205825", "Redes", 2), ("Cálculo", "James Stewart", "9786075228822", "Matemáticas", 2)]:
            db.add(Book(title=t, author=a, isbn=i, category=c, total=n, available=n))
        today = date.today(); db.add(Challenge(name="Reto del Mes: 20 libros entre todos", goal=20, start=today.replace(day=1), end=today.replace(day=1) + timedelta(days=45)))
        db.commit()

app.mount("/static", StaticFiles(directory=os.path.join(os.path.dirname(__file__), "static")), name="static")
@app.get("/", include_in_schema=False)
def index(): return FileResponse(os.path.join(os.path.dirname(__file__), "static", "index.html"))
