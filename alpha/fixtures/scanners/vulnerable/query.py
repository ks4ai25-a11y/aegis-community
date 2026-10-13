# Trusted inert synthetic source: scanned only, never executed.
def query(db, user_input):
    return db.execute("SELECT * FROM products WHERE name='" + user_input + "'")
