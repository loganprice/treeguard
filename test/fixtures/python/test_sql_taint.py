import shlex

def test_vulnerable(request):
    user_id = request.args.get("id")
    query = "SELECT * FROM users WHERE id = " + user_id
    # ruleid: py-sql-injection-taint
    cursor.execute(query)

def test_sanitized(request):
    user_id = request.args.get("id")
    safe_id = shlex.quote(user_id)
    query = "SELECT * FROM users WHERE id = " + safe_id
    # ok: py-sql-injection-taint
    cursor.execute(query)
