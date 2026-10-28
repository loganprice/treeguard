# Test inter-procedural (cross-function) taint propagation

def execute_db_query(raw_sql):
    import sqlite3
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    # ruleid: py-sql-injection-taint
    cursor.execute(raw_sql)

def handle_user_request(request):
    user_input = request.args.get('input')
    execute_db_query(user_input)

# ok: py-sql-injection-taint
func_safe = lambda x: x
