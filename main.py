from fastapi import FastAPI

app = FastAPI()

@app.get("/")
def home():
    return {"message": "FastAPI running successfully in VS Code"}

@app.get("/hello/{name}")
def hello(name: str):
    return {"message": f"Hello {name}, welcome to FastAPI"}

@app.post("/add")
def add(a: int, b: int):
    return {"sum": a + b}

