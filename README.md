# Biblioteca Virtual – Colegio Mayor del Cauca
FastAPI + SQLAlchemy + interfaz web + gamificación (medallas, rachas, desafíos comunitarios).

## Ejecutar con Docker
    docker compose up --build
Abrir http://localhost:8000 (app) y http://localhost:8000/docs (Swagger).

## Ejecutar sin Docker
    pip install -r requirements.txt
    uvicorn app.main:app --reload

## Usuarios de prueba
- admin@biblioteca.edu / admin123
- biblio@biblioteca.edu / biblio123
- estudiante@biblioteca.edu / estudiante123

## PostgreSQL (opcional)
Defina `DATABASE_URL=postgresql://usuario:clave@host:5432/biblioteca`.

## Reglas
Plazo 7 días · multa $500/día de retraso · máx. 3 préstamos activos · máx. 2 renovaciones.
