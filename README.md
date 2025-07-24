# T-SecureAuth

**Next-generation, plug-and-play authentication for Python web apps.**

---

## 🚀 Why T-SecureAuth?

- **Stronger than JWT:** AES-256-GCM encrypted tokens (not just signed, but fully encrypted)
- **Context-aware:** Optionally bind tokens to IP, device, and more
- **Revocable & Rotating:** Short-lived access tokens, server-side refresh, and revocation
- **Threat Detection:** Brute-force protection, event logging, and more
- **Fully customizable:** User fields, token payload, roles, and DB are all configurable
- **Framework-agnostic core:** Works out of the box with FastAPI, extensible for others
- **Developer-friendly:** One .env file, one function call, and you’re secure

---

## ✨ Features

- AES-256-GCM encrypted tokens (TST)
- Built-in endpoints: `/auth/register`, `/auth/login`, `/auth/logout`, `/auth/refresh`, `/auth/me`
- Context-aware validation (IP, User-Agent, etc.)
- Rotating & revocable tokens
- Role-based access control (admin, user, superadmin, ...)
- Brute-force and threat detection
- Real-time security event logging
- Fully customizable user model and token payload
- Works with PostgreSQL, SQLite, MySQL, and more
- Easy to extend with your own endpoints and logic

---

## ⚡ Quickstart

### 1. Install

```bash
pip install tsecure-auth
```

### 2. Create a `.env` file in your project root

```
ENCRYPTION_KEY=a_super_secret_and_long_enough_key_for_aes_256_gcm
DATABASE_URL=postgresql+asyncpg://user:nobody@localhost:5432/mydatabase
ACCESS_TOKEN_EXPIRE_MINUTES=15
REFRESH_TOKEN_EXPIRE_DAYS=7
VALIDATE_IP=False
VALIDATE_USER_AGENT=False
USER_MODEL_FIELDS=username,email,password,role
TOKEN_PAYLOAD_FIELDS=id,username,email,role
ADMIN_ROLE_NAME=admin
DEFAULT_USER_ROLE=user
```

- **ENCRYPTION_KEY**: Must be at least 32 characters (for AES-256-GCM)
- **DATABASE_URL**: Use PostgreSQL, SQLite, MySQL, etc. (see SQLAlchemy docs)
- **USER_MODEL_FIELDS**: Comma-separated fields for registration (add/remove as needed)
- **TOKEN_PAYLOAD_FIELDS**: Comma-separated fields included in tokens
- **ADMIN_ROLE_NAME**: The role name for admin endpoints
- **DEFAULT_USER_ROLE**: Assigned if no role is provided at registration

### 3. Create your `main.py`

```python
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv
load_dotenv()
from tsecure_auth.core.config import init_auth
from tsecure_auth.routes.auth import create_auth_router

init_auth({})  # Loads all config from .env

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.include_router(create_auth_router(), prefix="/auth", tags=["Authentication"])

@app.get("/")
def root():
    return {"message": "Welcome to the T-SecureAuth  app!"}
```

---

## 🛠️ Customization & Extensibility

- **User fields:** Add/remove fields in `USER_MODEL_FIELDS` in `.env` (e.g., add `phone`, `avatar`, etc.)
- **Token payload:** Control what’s in the token with `TOKEN_PAYLOAD_FIELDS`
- **Roles:** Use any string for roles (`admin`, `superadmin`, `user`, etc.)
- **Database:** Change `DATABASE_URL` to use SQLite, PostgreSQL, MySQL, etc.
- **Override config in code:** Pass any setting to `init_auth({...})` to override `.env`
- **Add your own endpoints:** Mount your own FastAPI routers alongside T-SecureAuth
- **Role-based access:** Use the `role` field in the token/user for custom access control

---

## 🔒 Security Tips

- **Keep your ENCRYPTION_KEY secret and at least 32 characters!**
- **Use HTTPS in production** to protect tokens in transit
- **Rotate your ENCRYPTION_KEY** if you suspect compromise
- **Set strong DB credentials** and use a production-ready DB for real apps
- **Limit CORS origins in production** (don’t use `[*]`)

---

## 🧩 Example: Role-based Access in FastAPI

```python
from fastapi import Depends, HTTPException, status
from tsecure_auth.dependencies import get_current_user
from tsecure_auth.core.config import settings

def require_roles(*roles):
    async def checker(user: dict = Depends(get_current_user)):
        if user.get("role") not in roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Requires one of roles: {roles}"
            )
        return user
    return checker

@app.get("/admin-only")
async def admin_endpoint(user=Depends(require_roles("admin", "superadmin"))):
    return {"message": f"Hello, {user['role']}!"}
```

---

## 📦 .env Example

```
ENCRYPTION_KEY=a_super_secret_and_long_enough_key_for_aes_256_gcm
DATABASE_URL=sqlite+aiosqlite:///./test.db
ACCESS_TOKEN_EXPIRE_MINUTES=15
REFRESH_TOKEN_EXPIRE_DAYS=7
VALIDATE_IP=False
VALIDATE_USER_AGENT=False
USER_MODEL_FIELDS=username,email,password,role
TOKEN_PAYLOAD_FIELDS=id,username,email,role
ADMIN_ROLE_NAME=admin
DEFAULT_USER_ROLE=user
```

---

## 📚 Documentation & Support

- [PyPI Project Page](https://pypi.org/project/tsecure-auth/)
- [GitHub Issues](https://github.com/Temu-Lala/tsecure-auth-TST-.git) 

---

## 📝 License

MIT License. See [LICENSE](./LICENSE).

---

