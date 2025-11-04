import oracledb

try:
    conn = oracledb.connect(
        user="securebank",
        password="sbpass",
        dsn="localhost/XEPDB1"
    )
    print("✅ Database connected successfully!")
    conn.close()
except Exception as e:
    print("❌ Database connection failed:", e)
