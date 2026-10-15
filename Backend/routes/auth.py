from fastapi import APIRouter, HTTPException, Request, Response

from Backend.auth import (
    COOKIE_NAME, SESSION_SECONDS, AdminUser, AnalystUser, Credentials, CurrentUser,
    PasswordChange, SessionPublic, UserCreate, UserPublic, UserUpdate,
    audit, authenticate, check_origin, create_user, hash_password, verify_password,
)
from Backend.config import settings
from Backend.database import database_connection

router = APIRouter(prefix="/api/auth", tags=["authentication"])


def clear_cookie(response: Response):
    response.delete_cookie(COOKIE_NAME, path="/", httponly=True,
                           secure=settings.session_cookie_secure, samesite="strict")


@router.post("/login", response_model=SessionPublic)
def login(data: Credentials, request: Request, response: Response):
    check_origin(request)
    # Prevent login CSRF even before a session/CSRF token exists.
    if request.headers.get("x-tethysguard-request") != "1":
        raise HTTPException(status_code=403, detail="Missing application request header")
    source = request.client.host if request.client else "unknown"
    token, result = authenticate(request.app.state.database_path, data, source,
                                 request.cookies.get(COOKIE_NAME, ""))
    response.set_cookie(COOKIE_NAME, token, max_age=SESSION_SECONDS, httponly=True,
                        secure=settings.session_cookie_secure, samesite="strict", path="/")
    return result


@router.get("/me", response_model=SessionPublic)
def me(user: CurrentUser):
    return {"user": user, "csrf_token": user["csrf_token"]}


@router.post("/logout", status_code=204)
def logout(user: CurrentUser, request: Request, response: Response):
    with database_connection(request.app.state.database_path) as connection:
        connection.execute("DELETE FROM sessions WHERE token_hash = ?", (user["token_hash"],))
        audit(connection, user["id"], user["id"], "logout")
    clear_cookie(response)


@router.get("/assignees", response_model=list[UserPublic])
def assignees(user: AnalystUser, request: Request):
    with database_connection(request.app.state.database_path) as connection:
        return [dict(row) for row in connection.execute("""
            SELECT id, username, role, active FROM users
            WHERE active = 1 AND role IN ('admin', 'analyst') ORDER BY username
        """)]


@router.get("/users", response_model=list[UserPublic])
def users(user: AdminUser, request: Request):
    with database_connection(request.app.state.database_path) as connection:
        return [dict(row) for row in connection.execute("SELECT id, username, role, active FROM users ORDER BY id")]


@router.post("/users", response_model=UserPublic, status_code=201)
def post_user(data: UserCreate, user: AdminUser, request: Request):
    try:
        return create_user(request.app.state.database_path, data, actor_id=user["id"])
    except ValueError as error:
        raise HTTPException(status_code=409, detail=str(error)) from error


@router.patch("/users/{user_id}", response_model=UserPublic)
def patch_user(user_id: int, data: UserUpdate, user: AdminUser, request: Request):
    with database_connection(request.app.state.database_path) as connection:
        connection.execute("BEGIN IMMEDIATE")
        existing = connection.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        if existing is None:
            raise HTTPException(status_code=404, detail="User not found")
        if existing["role"] == "admin" and existing["active"] and (data.role != "admin" or not data.active):
            count = connection.execute("SELECT COUNT(*) FROM users WHERE role = 'admin' AND active = 1").fetchone()[0]
            if count <= 1:
                raise HTTPException(status_code=409, detail="Keep at least one active admin")
        if existing["role"] != data.role or bool(existing["active"]) != data.active:
            connection.execute("UPDATE users SET role = ?, active = ? WHERE id = ?", (data.role, data.active, user_id))
            connection.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
            audit(connection, user["id"], user_id, f"user_updated:{data.role}:active={data.active}")
        return dict(connection.execute("SELECT id, username, role, active FROM users WHERE id = ?", (user_id,)).fetchone())


@router.post("/password", status_code=204)
def change_password(data: PasswordChange, user: CurrentUser, request: Request, response: Response):
    path = request.app.state.database_path
    with database_connection(path) as connection:
        stored = connection.execute("SELECT password_hash FROM users WHERE id = ?", (user["id"],)).fetchone()[0]
    if not verify_password(data.current_password.get_secret_value(), stored):
        raise HTTPException(status_code=400, detail="Current password is incorrect")
    replacement = hash_password(data.new_password.get_secret_value())
    with database_connection(path) as connection:
        connection.execute("BEGIN IMMEDIATE")
        changed = connection.execute("UPDATE users SET password_hash = ? WHERE id = ? AND password_hash = ?",
                                     (replacement, user["id"], stored))
        if not changed.rowcount:
            raise HTTPException(status_code=409, detail="Password changed elsewhere; sign in again")
        connection.execute("DELETE FROM sessions WHERE user_id = ?", (user["id"],))
        audit(connection, user["id"], user["id"], "password_changed")
    clear_cookie(response)
