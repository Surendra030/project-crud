from flask import Flask, request, jsonify
from pymongo import MongoClient
from bson import ObjectId
import os
from bcrypt import hashpw, gensalt, checkpw

app = Flask(__name__)

# MongoDB Atlas Configuration
MONGO_URI = os.getenv("MONGO_URL")
client = MongoClient(MONGO_URI)
db = client['crud_app']  # Database
collection = db['data']  # Data Collection
settings_collection = db['settings']  # Collection for storing password

# Helper function to serialize MongoDB documents
def serialize(doc):
    doc['_id'] = str(doc['_id'])
    return doc

# Initialize password in the database (one-time setup)
@app.route('/init-password', methods=['POST'])
def init_password():
    if settings_collection.find_one({"name": "password"}):
        return jsonify({"error": "Password already set"}), 400
    
    password = request.json.get('password')
    if not password:
        return jsonify({"error": "Password is required"}), 400
    
    hashed_password = hashpw(password.encode(), gensalt())
    settings_collection.insert_one({"name": "password", "hash": hashed_password})
    return jsonify({"message": "Password initialized successfully"}), 201

# Verify Password
def verify_password(provided_password):
    stored_password = settings_collection.find_one({"name": "password"})
    if not stored_password:
        return False
    
    hashed_password = stored_password['hash']
    return checkpw(provided_password.encode(), hashed_password)

# Middleware to check password
def require_password(func):
    def wrapper(*args, **kwargs):
        provided_password = request.headers.get('Password')
        if not provided_password or not verify_password(provided_password):
            return jsonify({"error": "Invalid or missing password"}), 403
        return func(*args, **kwargs)
    wrapper.__name__ = func.__name__  # Ensure the route decorator works
    return wrapper

# Home route for initial test
@app.route('/home', methods=['GET'])
def home():
    return jsonify({"message": "Application working successfully!"}), 200

# Create (Add Data)
@app.route('/data', methods=['POST'])
@require_password
def create_data():
    new_data = request.get_json()
    inserted = collection.insert_one(new_data)
    return jsonify({"message": "Data created successfully", "id": str(inserted.inserted_id)}), 201

# Read (Get Data by ID)
@app.route('/data/<id>', methods=['GET'])
@require_password
def read_data(id):
    data = collection.find_one({"_id": ObjectId(id)})
    if data:
        return jsonify(serialize(data)), 200
    return jsonify({"error": "Data not found"}), 404

# Update (Modify Data by ID)
@app.route('/data/<id>', methods=['PUT'])
@require_password
def update_data(id):
    updated_data = request.get_json()
    result = collection.update_one({"_id": ObjectId(id)}, {"$set": updated_data})
    if result.matched_count:
        return jsonify({"message": "Data updated successfully"}), 200
    return jsonify({"error": "Data not found"}), 404

# Delete (Remove Data by ID)
@app.route('/data/<id>', methods=['DELETE'])
@require_password
def delete_data(id):
    result = collection.delete_one({"_id": ObjectId(id)})
    if result.deleted_count:
        return jsonify({"message": "Data deleted successfully"}), 200
    return jsonify({"error": "Data not found"}), 404

# Get All Data
@app.route('/data', methods=['GET'])
@require_password
def get_all_data():
    all_data = list(collection.find())
    return jsonify([serialize(doc) for doc in all_data]), 200

if __name__ == '__main__':
    app.run(debug=True)
