import os
import subprocess
import pickle
import json

def test_sql(db, user_id):
    # ruleid: py-sql-injection
    db.execute("SELECT * FROM users WHERE id = %s" % user_id)

    # ruleid: py-sql-injection
    db.execute("SELECT * FROM users WHERE id = {}".format(user_id))

    # ruleid: py-sql-injection
    db.execute(f"SELECT * FROM users WHERE id = {user_id}")

    # ok: py-sql-injection
    db.execute("SELECT * FROM users WHERE id = %s", (user_id,))


def test_command(cmd):
    # ruleid: py-command-injection
    os.system(cmd)

    # ruleid: py-command-injection
    subprocess.Popen(cmd, shell=True)

    # ok: py-command-injection
    subprocess.Popen(["ls", "-l"], shell=False)


def test_eval(code):
    # ruleid: py-dangerous-eval
    eval(code)

    # ruleid: py-dangerous-eval
    exec(code)

    # ok: py-dangerous-eval
    print("eval is not called here")


def test_pickle(payload):
    # ruleid: py-unsafe-deserialization
    pickle.loads(payload)

    # ok: py-unsafe-deserialization
    json.loads(payload)
