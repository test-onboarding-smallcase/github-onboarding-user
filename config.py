# config.py (temporary testing-only)
# Put your Atlas connection string here while testing.
# Format: mongodb+srv://user:password@cluster0.xxxxx.mongodb.net/?retryWrites=true&w=majority
MONGO_URI = mongodb+srv://lovishchandan_db_user:nZDrN4tpQXpnkA1A@audit-test.880kul2.mongodb.net/?retryWrites=true&w=majority&appName=Audit-Test

# Database/collection names you created
MONGO_DB_NAME = "Github"
MONGO_ACTIVE_COLLECTION = "active_users"
MONGO_OFFBOARDED_COLLECTION = "offboarded_users"