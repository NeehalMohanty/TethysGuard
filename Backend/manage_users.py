"""Local-only account bootstrap and recovery. Passwords are prompted, not CLI arguments."""
import argparse
from getpass import getpass

from pydantic import ValidationError

from Backend.auth import UserCreate, audit, create_user, hash_password
from Backend.config import settings
from Backend.database import database_connection, initialize_database


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["bootstrap", "reset-password"])
    parser.add_argument("--username", required=True)
    args = parser.parse_args()
    password = getpass("Password (15–128 characters): ")
    if password != getpass("Confirm password: "):
        parser.error("Passwords do not match")
    try:
        data = UserCreate(username=args.username, password=password, role="admin")
    except ValidationError:
        parser.error("Use a 3–50 character username (letters/numbers/._-) and a 15–128 character password")
    initialize_database(settings.database_path)
    if args.action == "bootstrap":
        try:
            create_user(settings.database_path, data, bootstrap=True)
        except ValueError as error:
            parser.error(str(error))
        print("First admin created. Sign in through the dashboard.")
    else:
        replacement = hash_password(password)
        with database_connection(settings.database_path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            user = connection.execute("SELECT id FROM users WHERE username = ?", (data.username,)).fetchone()
            if user is None:
                parser.error("User not found")
            connection.execute("UPDATE users SET password_hash = ? WHERE id = ?", (replacement, user["id"]))
            connection.execute("DELETE FROM sessions WHERE user_id = ?", (user["id"],))
            audit(connection, None, user["id"], "local_password_reset")
        print("Password reset and existing sessions revoked. Role and active status unchanged.")


if __name__ == "__main__":
    main()
