
from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_jwt_extended import (
    JWTManager,
    create_access_token,
    jwt_required,
    get_jwt_identity,
    get_jwt
)
from werkzeug.security import generate_password_hash, check_password_hash
import pymysql
from pymysql.cursors import DictCursor

from config import DB_CONFIG, JWT_SECRET_KEY

app = Flask(__name__)
app.config["JWT_SECRET_KEY"] = JWT_SECRET_KEY
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = 3600

CORS(app)
jwt = JWTManager(app)


def get_db_connection():
    return pymysql.connect(
        **DB_CONFIG,
        cursorclass=DictCursor,
        autocommit=False
    )


@app.route("/", methods=["GET"])
def home():
    return jsonify({
        "message": "Welcome to LifeLink API",
        "status": "running"
    }), 200


@app.route("/health", methods=["GET"])
def health():
    conn = None
    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            cursor.execute("SHOW TABLES")
            tables = [
                row["Tables_in_lifelink"]
                for row in cursor.fetchall()
            ]

        return jsonify({
            "status": "healthy",
            "database": "connected",
            "tables": tables
        }), 200

    except pymysql.MySQLError:
        app.logger.exception("Health check failed")
        return jsonify({
            "status": "error",
            "database": "disconnected"
        }), 500

    finally:
        if conn:
            conn.close()


@app.route("/register", methods=["POST"])
def register():
    data = request.get_json(silent=True) or {}

    name = data.get("name", "").strip()
    email = data.get("email", "").strip().lower()
    password = data.get("password", "")
    role = data.get("role", "").strip().lower()

    if not all([name, email, password, role]):
        return jsonify({
            "error": "All fields are required"
        }), 400

    if role != "donor":
        return jsonify({
            "error": "Public registration is only available for donors"
        }), 403

    if len(name) > 100 or len(email) > 120:
        return jsonify({
            "error": "Name or email is too long"
        }), 400

    if len(password) < 8:
        return jsonify({
            "error": "Password must be at least 8 characters"
        }), 400

    password_hash = generate_password_hash(
    password,
    method="pbkdf2:sha256"
)
    conn = None

    try:
        conn = get_db_connection()

        with conn.cursor() as cursor:
            cursor.execute(
                "SELECT id FROM users WHERE email = %s",
                (email,)
            )

            if cursor.fetchone():
                return jsonify({
                    "error": "Email is already registered"
                }), 409

            cursor.execute(
                """
                INSERT INTO users
                    (name, email, password_hash, role)
                VALUES (%s, %s, %s, %s)
                """,
                (name, email, password_hash, role)
            )

            user_id = cursor.lastrowid

        conn.commit()

        return jsonify({
            "message": "Registration successful",
            "user_id": user_id,
            "role": role
        }), 201

    except pymysql.MySQLError:
        if conn:
            conn.rollback()

        app.logger.exception("Registration failed")
        return jsonify({
            "error": "Database operation failed"
        }), 500

    finally:
        if conn:
            conn.close()


@app.route("/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}

    email = data.get("email", "").strip().lower()
    password = data.get("password", "")

    if not email or not password:
        return jsonify({
            "error": "Email and password are required"
        }), 400

    conn = None

    try:
        conn = get_db_connection()

        with conn.cursor() as cursor:
            cursor.execute(
                """
                SELECT id, name, email, password_hash, role
                FROM users
                WHERE email = %s
                """,
                (email,)
            )
            user = cursor.fetchone()

        if not user or not check_password_hash(
            user["password_hash"], password
        ):
            return jsonify({
                "error": "Invalid email or password"
            }), 401

        token = create_access_token(
            identity=str(user["id"]),
            additional_claims={"role": user["role"]}
        )

        return jsonify({
            "message": "Login successful",
            "access_token": token,
            "user": {
                "id": user["id"],
                "name": user["name"],
                "email": user["email"],
                "role": user["role"]
            }
        }), 200

    except pymysql.MySQLError:
        app.logger.exception("Login failed")
        return jsonify({
            "error": "Database operation failed"
        }), 500

    finally:
        if conn:
            conn.close()


@app.route("/me", methods=["GET"])
@jwt_required()
def me():
    user_id = get_jwt_identity()
    conn = None

    try:
        conn = get_db_connection()

        with conn.cursor() as cursor:
            cursor.execute(
                """
                SELECT id, name, email, role
                FROM users
                WHERE id = %s
                """,
                (user_id,)
            )
            user = cursor.fetchone()

        if not user:
            return jsonify({"error": "User not found"}), 404

        return jsonify({"user": user}), 200

    except pymysql.MySQLError:
        app.logger.exception("Profile lookup failed")
        return jsonify({
            "error": "Database operation failed"
        }), 500

    finally:
        if conn:
            conn.close()

@app.route("/inventory", methods=["GET"])
@jwt_required()
def get_inventory():
    if get_jwt().get("role") not in ("hospital", "bloodbank"):
        return jsonify({
            "error": "Only hospital and blood bank accounts can view inventory"
        }), 403
    
    connection = get_db_connection()

    try:
        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT
                    bi.id,
                    bi.bank_id,
                    bb.name AS bank_name,
                    bb.city,
                    bi.blood_group,
                    bi.units,
                    bi.updated_at
                FROM blood_inventory AS bi
                JOIN blood_banks AS bb
                    ON bb.id = bi.bank_id
                ORDER BY bb.name, bi.blood_group
            """)

            inventory = cursor.fetchall()

            for item in inventory:
                if item["updated_at"]:
                    item["updated_at"] = item["updated_at"].isoformat()

        return jsonify({"inventory": inventory}), 200

    except pymysql.MySQLError:
        app.logger.exception("Failed to fetch inventory")
        return jsonify({"error": "Could not fetch inventory"}), 500

    finally:
        connection.close()

@app.route("/inventory/low-stock", methods=["GET"])
@jwt_required()
def get_low_stock():
    if get_jwt().get("role") not in ("hospital", "bloodbank"):
        return jsonify({
            "error": "Only hospital and blood bank accounts can view low stock"
        }), 403
    
    connection = get_db_connection()

    try:
        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT
                    blood_group,
                    SUM(units) AS total_units
                FROM blood_inventory
                GROUP BY blood_group
                HAVING SUM(units) < 5
                ORDER BY blood_group
            """)

            low_stock = cursor.fetchall()

        return jsonify({"low_stock": low_stock}), 200

    except pymysql.MySQLError:
        app.logger.exception("Failed to fetch low stock")
        return jsonify({"error": "Could not fetch low stock"}), 500

    finally:
        connection.close()

@app.route("/inventory", methods=["POST"])
@jwt_required()
def add_inventory():
    if get_jwt().get("role") != "bloodbank":
        return jsonify({
            "error": "Only blood bank accounts can add inventory"
        }), 403
    data = request.get_json(silent=True) or {}

    bank_id = data.get("bank_id")
    blood_group = data.get("blood_group")
    units = data.get("units")

    valid_groups = {"A+", "A-", "B+", "B-", "AB+", "AB-", "O+", "O-"}

    if not isinstance(bank_id, int) or isinstance(bank_id, bool) or bank_id <= 0:
        return jsonify({"error": "Valid bank_id is required"}), 400

    if blood_group not in valid_groups:
        return jsonify({"error": "Invalid blood_group"}), 400

    if not isinstance(units, int) or isinstance(units, bool) or units <= 0:
        return jsonify({"error": "units must be a positive integer"}), 400

    connection = get_db_connection()

    try:
        with connection.cursor() as cursor:
            cursor.execute(
               """
                SELECT id
                FROM blood_banks
                WHERE id = %s
                  AND user_id = %s
                """, 
                (bank_id,get_jwt_identity())
            )

            if cursor.fetchone() is None:
                return jsonify({"error": "Blood bank not found or not authorized"}), 403

            cursor.execute("""
                INSERT INTO blood_inventory (bank_id, blood_group, units)
                VALUES (%s, %s, %s)
                ON DUPLICATE KEY UPDATE units = units + %s
            """, (bank_id, blood_group, units, units))

        connection.commit()

        return jsonify({
            "message": "Inventory updated successfully",
            "bank_id": bank_id,
            "blood_group": blood_group,
            "units_added": units
        }), 200

    except pymysql.MySQLError:
        connection.rollback()
        app.logger.exception("Failed to update inventory")
        return jsonify({"error": "Could not update inventory"}), 500

    finally:
        connection.close()
@app.route("/requests", methods=["GET"])
@jwt_required()
def get_requests():
    if get_jwt().get("role") != "hospital":
        return jsonify({
            "error": "Only hospital accounts can view emergency requests"
        }), 403
    connection = get_db_connection()

    try:
        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT
                    r.id,
                    r.hospital_id,
                    h.name AS hospital_name,
                    h.city,
                    r.blood_group,
                    r.units,
                    r.urgency,
                    r.status,
                    r.created_at
                FROM emergency_requests AS r
                JOIN hospitals AS h
                    ON h.id = r.hospital_id
                WHERE h.user_id = %s
                ORDER BY
                    FIELD(r.urgency, 'critical', 'urgent', 'normal'),
                    r.created_at ASC
            """, (get_jwt_identity(),))

            requests = cursor.fetchall()

            for item in requests:
                if item["created_at"]:
                    item["created_at"] = item["created_at"].isoformat()

        return jsonify({"requests": requests}), 200

    except pymysql.MySQLError:
        app.logger.exception("Failed to fetch emergency requests")
        return jsonify({"error": "Could not fetch requests"}), 500

    finally:
        connection.close()
@app.route("/requests", methods=["POST"])
@jwt_required()
def create_request():
    if get_jwt().get("role") != "hospital":
        return jsonify({
            "error": "Only hospital accounts can create emergency requests"
        }), 403
    data = request.get_json(silent=True) or {}

    hospital_id = data.get("hospital_id")
    blood_group = data.get("blood_group")
    units = data.get("units")
    urgency = data.get("urgency", "urgent")

    valid_groups = {"A+", "A-", "B+", "B-", "AB+", "AB-", "O+", "O-"}
    valid_urgencies = {"normal", "urgent", "critical"}

    if not isinstance(hospital_id, int) or isinstance(hospital_id, bool) or hospital_id <= 0:
        return jsonify({"error": "Valid hospital_id is required"}), 400

    if blood_group not in valid_groups:
        return jsonify({"error": "Invalid blood_group"}), 400

    if not isinstance(units, int) or isinstance(units, bool) or units <= 0:
        return jsonify({"error": "units must be a positive integer"}), 400

    if urgency not in valid_urgencies:
        return jsonify({"error": "Invalid urgency"}), 400

    connection = get_db_connection()

    try:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT id 
                 FROM hospitals
                 WHERE id = %s
                   AND user_id = %s
                """,   
                (hospital_id,get_jwt_identity())
            )

            if cursor.fetchone() is None:
                return jsonify({"error": "Hospital not found or not authorized"}), 403

            cursor.execute("""
                INSERT INTO emergency_requests
                    (hospital_id, blood_group, units, urgency, status)
                VALUES (%s, %s, %s, %s, 'pending')
            """, (hospital_id, blood_group, units, urgency))

            request_id = cursor.lastrowid

            cursor.execute("""
                INSERT INTO request_logs (request_id, status, note)
                VALUES (%s, 'pending', %s)
            """, (request_id, "Emergency request created"))

        connection.commit()

        return jsonify({
            "message": "Emergency request created successfully",
            "request_id": request_id,
            "status": "pending"
        }), 201

    except pymysql.MySQLError:
        connection.rollback()
        app.logger.exception("Failed to create emergency request")
        return jsonify({"error": "Could not create emergency request"}), 500

    finally:
        connection.close()
@app.route("/requests/<int:request_id>/allocate", methods=["POST"])
@jwt_required()
def allocate_blood(request_id):
    if get_jwt().get("role") != "hospital":
        return jsonify({
            "error": "Only hospital accounts can allocate blood"
        }), 403
    data = request.get_json(silent=True) or {}
    bank_id = data.get("bank_id")

    if not isinstance(bank_id, int) or isinstance(bank_id, bool) or bank_id <= 0:
        return jsonify({"error": "Valid bank_id is required"}), 400

    connection = get_db_connection()

    try:
        with connection.cursor() as cursor:
            # Lock the request so it cannot be allocated twice concurrently.
           cursor.execute("""
               SELECT r.id, r.hospital_id, r.blood_group, r.units, r.status
               FROM emergency_requests AS r
               JOIN hospitals AS h
                   ON h.id = r.hospital_id
               WHERE r.id = %s
                 AND h.user_id = %s
               FOR UPDATE
               """, (request_id, get_jwt_identity()))

        emergency_request = cursor.fetchone()

        if emergency_request is None:
               connection.rollback()
               return jsonify({
                  "error": "Request not found or not authorized"
               }), 404

        if emergency_request["status"] != "pending":
                connection.rollback()
                return jsonify({"error": "Request is not pending"}), 409

        cursor.execute(
                "SELECT id FROM blood_banks WHERE id = %s",
                (bank_id,)
            )
        bank = cursor.fetchone()

        if bank is None:
                connection.rollback()
                return jsonify({"error": "Blood bank not found"}), 404
            # Find a compatible stock group available at the selected bank.
        cursor.execute("""
                SELECT i.id, i.blood_group, i.units
                FROM blood_inventory AS i
                JOIN blood_compatibility AS c
                  ON c.donor_group = i.blood_group
                WHERE i.bank_id = %s
                  AND c.recipient_group = %s
                  AND i.units >= %s
                ORDER BY (i.blood_group = %s) DESC, i.units DESC, i.id
                LIMIT 1
                FOR UPDATE
            """, (
                bank_id,
                emergency_request["blood_group"],
                emergency_request["units"],
                emergency_request["blood_group"]
            ))
            
        stock = cursor.fetchone()

        if stock is None:
                connection.rollback()
                return jsonify({
                    "error": "No compatible stock available in sufficient quantity"
                }), 409

            # Deduct stock, update the request, and record its history atomically.
        cursor.execute("""
                UPDATE blood_inventory
                SET units = units - %s
                WHERE id = %s AND units >= %s
            """, (
                emergency_request["units"],
                stock["id"],
                emergency_request["units"]
            ))

        if cursor.rowcount != 1:
                connection.rollback()
                return jsonify({"error": "Stock changed; please retry"}), 409

            
        cursor.execute("""
                UPDATE emergency_requests
                SET status = 'fulfilled', fulfilled_by_bank_id = %s
                WHERE id = %s AND status = 'pending'
            """, (bank_id, request_id))

        if cursor.rowcount != 1:
                connection.rollback()
                return jsonify({"error": "Request status changed; please retry"}), 409

        cursor.execute("""
                INSERT INTO request_logs (request_id, status, note)
                VALUES (%s, 'fulfilled', %s)
            """, (
                request_id,
                f"Allocated {emergency_request['units']} units of "
                f"{stock['blood_group']} from bank {bank_id}"
            ))

        connection.commit()

        return jsonify({
            "message": "Blood allocated successfully",
            "request_id": request_id,
            "bank_id": bank_id,
            "blood_group_allocated": stock["blood_group"],
            "units_allocated": emergency_request["units"],
            "status": "fulfilled"
        }), 200

    except pymysql.MySQLError:
        connection.rollback()
        app.logger.exception("Blood allocation failed")
        return jsonify({"error": "Could not allocate blood"}), 500

    finally:
        connection.close()

@app.route("/requests/<int:request_id>/matches", methods=["GET"])
@jwt_required()
def match_donors(request_id):
    if get_jwt().get("role") != "hospital":
        return jsonify({
            "error": "Only hospital accounts can access donor matches"
        }), 403
    connection = get_db_connection()

    try:
        with connection.cursor() as cursor:
            # Fetch the emergency request.
            cursor.execute("""
                SELECT id, blood_group, units, status, hospital_id
                FROM emergency_requests
                WHERE id = %s
                AND hospital_id = (
                      SELECT id FROM hospitals
                      WHERE user_id = %s
                  )
            """, (request_id,get_jwt_identity()))
            emergency_request = cursor.fetchone()

            if not emergency_request:
                return jsonify({"error": "Emergency request not found"}), 404

            # Find compatible, available donors and calculate distance.
            cursor.execute("""
                SELECT
                    d.id AS donor_id,
                    u.name AS donor_name,
                    d.blood_group,
                    d.city,
                    d.latitude,
                    d.longitude,
                    h.latitude AS hospital_latitude,
                    h.longitude AS hospital_longitude,
                    d.last_donation,
                    CASE
                        WHEN d.latitude IS NOT NULL
                         AND d.longitude IS NOT NULL
                         AND h.latitude IS NOT NULL
                         AND h.longitude IS NOT NULL
                        THEN 6371 * 2 * ASIN(SQRT(
                            POWER(SIN(RADIANS(
                                h.latitude - d.latitude
                            ) / 2), 2)
                            + COS(RADIANS(d.latitude))
                            * COS(RADIANS(h.latitude))
                            * POWER(SIN(RADIANS(
                                h.longitude - d.longitude
                            ) / 2), 2)
                        ))
                        ELSE NULL
                    END AS distance_km
                FROM donors d
                JOIN users u ON u.id = d.user_id
                JOIN blood_compatibility bc
                  ON bc.donor_group = d.blood_group
                 AND bc.recipient_group = %s
                JOIN hospitals h ON h.id = %s
                WHERE d.available = 1
                  AND d.eligible = 1
                  AND EXISTS (
                      SELECT 1
                      FROM donor_screening ds
                      WHERE ds.donor_id = d.id
                        AND ds.is_eligible = 1
                )
                AND (
                    d.last_donation IS NULL
                    OR d.last_donation <= CASE
                        WHEN d.sex = 'M'
                            THEN CURDATE() - INTERVAL 90 DAY
                        WHEN d.sex = 'F'
                             THEN CURDATE() - INTERVAL 120 DAY
                        ELSE '1000-01-01'
                     END
                )
              ORDER BY
                    distance_km IS NULL,
                    distance_km ASC,
                    d.id ASC
            """, (
                emergency_request["blood_group"],
                emergency_request["hospital_id"]
            ))

            donors = cursor.fetchall()

        return jsonify({
            "request_id": request_id,
            "requested_blood_group": emergency_request["blood_group"],
            "matches": [
                {
                    "donor_id": donor["donor_id"],
                    "donor_name": donor["donor_name"],
                    "blood_group": donor["blood_group"],
                    "city": donor["city"],
                    "distance_km": (
                        round(float(donor["distance_km"]), 2)
                        if donor["distance_km"] is not None
                        else None
                    ),
                    "last_donation": (
                        donor["last_donation"].isoformat()
                        if donor["last_donation"] is not None
                        else None
                    )
                }
                for donor in donors
            ]
        }), 200

    except pymysql.MySQLError:
        app.logger.exception("Donor matching failed")
        return jsonify({"error": "Could not find donor matches"}), 500

    finally:
        connection.close()

if __name__ == "__main__":
    app.run(debug=True, port=5001)

