# Inventory_Management_System
Inventory management system backend development using python and fastapi

Using python fastapi, and a virtual environment
```
python -m venv venv;
.\venv\Scripts\activate;
pip install fastapi, uvicorn, pydantic, sqlalchemy, pydantic[email], mysql-connector;
```

create a file called 'secret_keys.py' containing the following and modify the example values to your own values

```
db_username = "example"
db_password = "example"
encrypt_key = "example-secret"
admin_password = "example"
```