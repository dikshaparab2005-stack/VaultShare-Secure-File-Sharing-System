import traceback

import app

app.app.testing = True
with app.connect_db() as db:
    print("latest records:")
    for row in db.execute("SELECT * FROM files ORDER BY id DESC LIMIT 5"):
        print(dict(row))
    users = db.execute("SELECT id,username FROM users").fetchall()
    for user in users:
        client = app.app.test_client()
        with client.session_transaction() as session:
            session["user_id"] = user["id"]
            session["csrf_token"] = "test"
        try:
            response = client.get("/files")
            print("GET /files", user["id"], user["username"], response.status_code)
        except Exception:
            traceback.print_exc()
