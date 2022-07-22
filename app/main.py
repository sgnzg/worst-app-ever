from cgitb import reset
from unittest import result
from pydantic import BaseModel

from fastapi import FastAPI, Form, UploadFile, Response, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import PlainTextResponse, HTMLResponse, FileResponse
import sqlite3
import html
from lxml import etree

users_con = sqlite3.connect("db.sqlite", check_same_thread=False)
users_con.set_trace_callback(print)
user_cur = users_con.cursor()

products_con = sqlite3.connect("db.sqlite", check_same_thread=False)
products_con.set_trace_callback(print)
products_cur = products_con.cursor()

comments_con = sqlite3.connect("db.sqlite", check_same_thread=False)
comments_con.set_trace_callback(print)
comments_cur = comments_con.cursor()

def write_sample_data_to_users_db_sqlite():
    user_cur.execute("DROP TABLE IF EXISTS users")
    user_cur.execute(
        "CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, name TEXT, password TEXT)"
    )
    user_cur.execute("INSERT INTO users (name, password) VALUES ('admin', 'qwerty')")
    users_con.commit()


def write_sample_data_to_products_db_sqlite():
    products_cur.execute("DROP TABLE IF EXISTS products")
    products_cur.execute(
        "CREATE TABLE IF NOT EXISTS products (id INTEGER PRIMARY KEY, category TEXT, name TEXT, price INTEGER, public INTEGER)"
    )
    products_cur.execute(
        "INSERT INTO products (category, name, price, public) VALUES ('Computers', 'Notebook', '1000', '1')"
    )
    products_cur.execute(
        "INSERT INTO products (category, name, price, public) VALUES ('Computers', 'Tablet', '500', '1')"
    )
    products_cur.execute(
        "INSERT INTO products (category, name, price, public) VALUES ('Computers', 'Phone', '300', '1')"
    )
    products_cur.execute(
        "INSERT INTO products (category, name, price, public) VALUES ('Computers', 'Stolen server', '100', '0')"
    )
    products_cur.execute(
        "INSERT INTO products (category, name, price, public) VALUES ('Vehicles', 'Bike', '1000', '1')"
    )
    products_cur.execute(
        "INSERT INTO products (category, name, price, public) VALUES ('Vehicles', 'Scooter', '2000', '1')"
    )
    products_cur.execute(
        "INSERT INTO products (category, name, price, public) VALUES ('Vehicles', 'Motoblok', '10000', '1')"
    )
    products_con.commit()


def write_sample_data_to_comments_db_sqlite():
    comments_cur.execute("DROP TABLE IF EXISTS comments")
    comments_cur.execute("CREATE TABLE IF NOT EXISTS messages (message TEXT)")
    comments_con.commit()


write_sample_data_to_users_db_sqlite()
write_sample_data_to_products_db_sqlite()
write_sample_data_to_comments_db_sqlite()

app = FastAPI()

app.mount("/static", StaticFiles(directory="static"), name="static")


class Credentials(BaseModel):
    name: str
    password: str


class Message(BaseModel):
    message: str


class Command(BaseModel):
    command: str


@app.post("/vulnerable-login/")
async def login(item: Credentials):
    if user_cur.execute(
        f"SELECT * FROM users where name='{item.name}' and password='{item.password}'"
    ).fetchall():
        return "Login successfull"
    return "Access denied"

@app.get("/vulnerable-login/")
async def login(name: str, password: str):
    if user_cur.execute(
        f"SELECT * FROM users where name='{name}' and password='{password}'"
    ).fetchall():
        return "Login successfull"
    return "Access denied"  


@app.post("/login/")
async def login(item: Credentials):
    if user_cur.execute(
        "SELECT * from users where name=:name and password=:password",
        {"name": item.name, "password": item.password},
    ).fetchall():
        return "Login successfull"
    return "Access denied"

@app.get("/login/")
async def login(name: str, password: str):
    if user_cur.execute(
        "SELECT * from users where name=:name and password=:password",
        {"name": name, "password": password},
    ).fetchall():
        return "Login successfull"
    return "Access denied"

@app.get("/vulnerable-products/")
def show_public_products(category: str = None):
    products = products_cur.execute(
        f"SELECT name, price FROM products where category ='{category}' and public=1"
    ).fetchall()
    return products


@app.get("/products/")
def show_public_products(category: str = None):
    products = products_cur.execute(
        "SELECT name, price FROM products where category=:category and public=1",
        {"category": category},
    ).fetchall()
    return products


@app.get("/vulnerable-categories/")
def show_chosen(category: str = None):
    products = products_cur.execute(
        f"SELECT name, price FROM products where category ='{category}' and public=1"
    ).fetchall()
    return products


@app.get("/categories/")
def show_chosen(category: str = None):
    products = products_cur.execute(
        "SELECT name, price FROM products where category=:category and public=1",
        {"category": category},
    ).fetchall()
    return products


@app.get("/vulnerable-print-message/", response_class=HTMLResponse)
def print_message(message: str = None):
    html_page = f"""
    <html>
        <head>
            <title>Some HTML in here</title>
        </head>
        <body>
            { message }
        </body>
    </html>
    """
    return html_page


@app.get("/print-message/", response_class=HTMLResponse)
def print_message(message: str = None):
    html_page = f"""
    <html>
        <head>
            <title>Some HTML in here</title>
        </head>
        <body>
            { html.escape(message) }
        </body>
    </html>
    """
    return html_page


@app.post("/write-message-to-db/")
def write_message(item: Message):
    comments_cur.execute(f"INSERT into messages VALUES ('{ item.message }')")
    return "Message was written to DB"

@app.get("/write-message-to-db/")
def write_message(message: str = None):
    comments_cur.execute(f"INSERT into messages VALUES ('{ message }')")
    return "Message was written to DB"

@app.get("/get-messages-from-db/", response_class=HTMLResponse)
def write_message():
    comments = comments_cur.execute("SELECT * FROM messages").fetchall()
    html_page = f"""
    <html>
        <head>
            <title>Some HTML in here</title>
        </head>
        <body>
            { comments }
        </body>
    </html>
    """
    return html_page


@app.get("/files/")
async def read_file(file_path: str):
    return FileResponse(path=f"static/{file_path}")


@app.post("/vulnerable-parse-xml")
async def submit(request: Request):
    content_type = request.headers["Content-Type"]
    if content_type == "application/xml":
        body = await request.body()
        xml_file = body.decode("utf-8")
        parser = etree.XMLParser(no_network=False)
        try:
            doc = etree.fromstring(str(xml_file), parser)
            parsed_xml = etree.tostring(doc)
        except:
            return "ERROR"
        return Response(content=parsed_xml, media_type="application/xml")
    return "NOT XML"


@app.post("/parse-xml")
async def submit(request: Request):
    content_type = request.headers["Content-Type"]
    if content_type == "application/xml":
        body = await request.body()
        xml_file = body.decode("utf-8")
        parser = etree.XMLParser(no_network=False, resolve_entities=False)
        try:
            doc = etree.fromstring(str(xml_file), parser)
            parsed_xml = etree.tostring(doc)
        except:
            return "ERROR"
        return Response(content=parsed_xml, media_type="application/xml")
    return "NOT XML"


@app.post("/run-command")
def run_command(item: Command):
    print(item.command)
    return "Success"


@app.get("/run-command")
def run_command(command: str):
    print(command)
    return "Success"
