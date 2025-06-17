import os
import json
import logging
import threading
import uuid
import time
import psutil
import re
from datetime import datetime, timedelta
from flask import Flask, request, send_from_directory, jsonify, render_template, session, copy_current_request_context
import oracledb
import cx_Oracle
from typing import Any, Dict, Optional
from logging.handlers import TimedRotatingFileHandler , QueueListener, QueueHandler
from queue import Queue
import win32api
import win32con
from werkzeug.middleware.proxy_fix import ProxyFix
import sys
import traceback
import atexit
from flask_session import Session
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import inspect, MetaData
from flask_caching import Cache
import redis

app = Flask(__name__)
print(psutil.Process(os.getpid()))

app.logger.debug("Application Started")

with open('secret_key.txt', 'r') as f:
    secret_key = f.read().strip()
    
app.config['DEBUG'] = True
app.config['SECRET_KEY'] = secret_key

app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

app.config['SESSION_TYPE'] = 'redis'
app.config['SESSION_PERMANENT'] = False
app.config['SESSION_USE_SIGNER'] = True
app.config['SESSION_REDIS'] = 'redis://localhost:6379/0'

Session(app)

app.config['CACHE_TYPE'] = 'RedisCache'
app.config['CACHE_REDIS_HOST'] = 'localhost'
app.config['CACHE_REDIS_PORT'] = 6379 
app.config['CACHE_REDIS_DB'] = 0
app.config['CACHE_REDIS_URL'] = 'redis://localhost:6379/0'

cache = Cache(app)

redis_client = redis.StrictRedis(host='localhost', port=6379, db=0, decode_responses=True)
    
log_file_path = 'application.log'  # Path to the log file

# Configure TimedRotatingFileHandler to rotate logs daily at midnight
handler = TimedRotatingFileHandler(
    log_file_path, when='midnight', interval=1, backupCount=7  # Keep logs for 7 days
)
handler.suffix = "%Y-%m-%d"  # Add a date suffix to rotated log files
handler.extMatch = re.compile(r"^\d{4}-\d{2}-\d{2}$")  # Match the date format

# Set the logging format
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)

# Configure the root logger
logging.basicConfig(
    level=logging.DEBUG,  # Set the logging level
    handlers=[
        handler,  # Use the TimedRotatingFileHandler
        logging.StreamHandler(sys.stdout)  # Also log to stdout
    ]
)

app.logger.debug("Logging configured with daily rotation.")

def handle_exception(exc_type, exc_value, exc_traceback):
    if issubclass(exc_type, KeyboardInterrupt):
        sys.__excepthook__(exc_type, exc_value, exc_traceback)
        return
    app.logger.debug("Critical Error")
    logging.critical("Uncaught exception", exc_info=(exc_type, exc_value, exc_traceback))
    app.logger.debug("Uncaught exception 2", exc_info=(exc_type, exc_value, exc_traceback))
    app.logger.debug("Critical Error")

sys.excepthook = handle_exception

# Redirect print statements to the logging system
class PrintLogger:
    def write(self, message):
        if message.strip():  # Avoid logging empty lines
            logging.info(message.strip())

    def flush(self):
        pass  # No need to implement flush for this use case

sys.stdout = PrintLogger()  # Redirect standard output (print statements)
sys.stderr = PrintLogger()  # Redirect standard error (exceptions, etc.)

with open('validation_config.json') as validation_config_file:
    validation_config = json.load(validation_config_file)


oracle_client_path = r"D:\DataBaseXMLRetrieverRedist\DataBaseXMLRetriever\instantclient_23_6"

# Set the PATH environment variable
os.environ["PATH"] = oracle_client_path + ";" + os.environ["PATH"]

# Initialize Oracle client
cx_Oracle.init_oracle_client(lib_dir=oracle_client_path)

#globals
ongoing_queries = {}
ongoing_requests = {}
recently_canceled_requests = {}
correlation_ids_cache = {}


#maintainance mode flag
MAINTENANCE_MODE = False
ALLOWED_USERS = ["THEAA\\821872"]

@app.before_request
def check_maintenance_mode():
    if MAINTENANCE_MODE:
        if 'REMOTE_USER' in request.environ:
            username = request.environ['REMOTE_USER']
     
        if username not in ALLOWED_USERS:
            return render_template('maintenance.html'), 503

# Configure logging

@app.before_request
def log_request_info():
    app.logger.debug(f"Process ID: {os.getpid()} - Handling request: {request.path}")

log_dir = 'logs'
os.makedirs(log_dir, exist_ok=True)

# Configure the audit log file
audit_log_file = os.path.join(log_dir, f"{datetime.now().strftime('%d-%m-%Y')}_audit_log.log")

# Create a queue for thread-safe logging
log_queue = Queue()

# Configure the TimedRotatingFileHandler to rotate logs daily at midnight
audit_handler = TimedRotatingFileHandler(
    audit_log_file, when='midnight', interval=1, backupCount=28  # Keep logs for 28 days
)
audit_handler.suffix = "%Y-%m-%d"  # Add a date suffix to rotated log files
audit_handler.extMatch = re.compile(r"^\d{4}-\d{2}-\d{2}$")  # Match the date format

# Set the logging format
audit_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
audit_handler.setFormatter(audit_formatter)

# Create a QueueHandler to handle log messages in a thread-safe manner
queue_handler = QueueHandler(log_queue)

# Create a logger for user interactions
user_interaction_logger = logging.getLogger('user_interactions')
user_interaction_logger.setLevel(logging.INFO)
user_interaction_logger.addHandler(queue_handler)

# Create a QueueListener to process log messages from the queue
listener = QueueListener(log_queue, audit_handler)
listener.start()

# Function to log user interactions
def log_interaction(data, action="search", details=None, cids=None, session_id=None, request_id=None, connection_string=None, search_params=None):
    log_entry = {
        "timestamp": datetime.now().isoformat(),
        "username": data.get('username'),
        "action": action,
        "details": details if details else {key: data[key] for key in data if key not in ['username', 'page', 'firstRequest']},
        "cids": cids,
        "session_id": session_id,
        "search_params": search_params
    }
    
    if connection_string:
        log_entry["connection_string"] = connection_string
    
    if request_id:
        log_entry["request_id"] = request_id

    # Log the interaction as a JSON string
    user_interaction_logger.info(json.dumps(log_entry))


with open('config.json') as config_file:
    connection_strings = json.load(config_file) # conn strings are outside of source code
     #ss

# Ensure log directory exists
log_dir = 'xml_error_logs'
os.makedirs(log_dir, exist_ok=True)

def get_windows_username():
    domain_name = win32api.GetComputerNameEx(win32con.ComputerNameDnsDomain)
    user_name = win32api.GetUserName()
    user_name = domain_name.replace(".local","").upper() + "\\\\" + user_name
    print(user_name)
    return user_name

def get_username_test():
    return os.getlogin()

@app.route('/')
def index():
    if 'REMOTE_USER' in request.environ:
        username = request.environ['REMOTE_USER']
        
        if username.startswith('THEAA\\'):
            username = username.replace('THEAA\\', 'THEAA\\\\')
        
        session['username'] = username
        permissions = get_user_permissions(username)
        
        if permissions['status'] == 'success':
            user_type = permissions['user_type']
            
            if user_type in [99, 2, 1]:
                return render_template('DataBaseXMLRetriever.html', username=username, user_type=user_type)
            else:
                # Render a page instructing the user to contact an admin
                return render_template('contact_admin.html', username=username), 403
        else:
            return permissions['message'], 403
    else:
        return 'User not authenticated', 401





@app.route('/favicon.ico')
def favicon():
    favicon_path = os.path.join(app.root_path, 'static', 'image', 'favicon.ico')
    app.logger.debug(f"Favicon path: {favicon_path}")
    
    if not os.path.exists(favicon_path):
        app.logger.error("Favicon file does not exist")
        return "Favicon not found", 404
    
    app.logger.debug("Favicon file found, sending file")
    return send_from_directory(os.path.join(app.root_path, 'static', 'image'), 'favicon.ico')




@app.route('/confirm-receipt/<request_id>', methods=['POST'])
def confirm_receipt(request_id):
    app.logger.debug(f"confirm_receipt called with request_id: {request_id}")
    
    # Check if the request_id exists in Redis
    if redis_client.exists(f"request_{request_id}"):
        # Delete the request from Redis
        redis_client.delete(f"request_{request_id}")
        app.logger.debug(f"Request {request_id} confirmed and removed from Redis")
        return jsonify({'status': 'confirmed'})
    else:
        app.logger.debug(f"Request {request_id} not found in Redis")
        return jsonify({'status': 'not found'}), 404


def get_user_permissions(username):
    try:
        conn_str = connection_strings.get('SIT', {}).get('connection_string')
        if not conn_str:
            raise ValueError("Connection string for 'SIT' not found")
        
        app.logger.debug(f"Connecting to database with connection string: {conn_str}")
        conn = cx_Oracle.connect(conn_str)
        curs = conn.cursor()
        
        query = """
        SELECT USER_TYPE
        FROM DASHBOARD_USER
        WHERE USER_NAME = :username
        """
        full_username = username
        
        app.logger.debug(f"Executing query: {query} with username: {full_username}")
        curs.execute(query, {'username': full_username})
        result = curs.fetchone()
        
        if result:
            user_type = result[0]
            app.logger.debug(f"Retrieved user type: {user_type}")
            return {'status': 'success', 'user_type': user_type}
        else:
            app.logger.debug(f"User {full_username} not found in the database.")
            return {'status': 'error', 'message': 'User not found, Please contact server admin.'}
    except oracledb.DatabaseError as e:
        app.logger.error(f"Database error occurred: {e}")
        return {'status': 'error', 'message': 'Database error'}
    except Exception as e:
        app.logger.error(f"An unexpected error occurred: {e}")
        return {'status': 'error', 'message': f"Unexpected error: {str(e)}"}
    finally:
        if 'curs' in locals():
            curs.close()
        if 'conn' in locals():
            conn.close()


@app.route('/get-min-date', methods=['GET'])
def get_min_date():
    environment = request.args.get('environment')
    if not environment:
        app.logger.error('Environment not provided')
        return jsonify({'status': 'error', 'message': 'Environment not provided'}), 400

    try:
        conn_str = connection_strings.get(environment, {}).get('connection_string')
        if not conn_str:
            raise ValueError(f"Connection string for '{environment}' not found")

        conn = cx_Oracle.connect(conn_str)
        curs = conn.cursor()

        query = "SELECT MIN(log_timestamp) FROM log_audit_field"
        curs.execute(query)
        result = curs.fetchone()

        if result:
            min_date = result[0]
            session["min_date"] = min_date
            return jsonify({'status': 'success', 'min_date': min_date.strftime('%Y-%m-%dT%H:%M')})
        else:
            return jsonify({'status': 'error', 'message': 'No records found'})
    except cx_Oracle.DatabaseError as e:
        app.logger.error(f"Database error occurred: {e}")
        return jsonify({'status': 'error', 'message': 'Database error'})
    except ValueError as e:
        app.logger.error(f"Value error occurred: {e}")
        return jsonify({'status': 'error', 'message': str(e)})
    except Exception as e:
        app.logger.error(f"An unexpected error occurred: {e}")
        return jsonify({'status': 'error', 'message': 'Unexpected error'})
    finally:
        if 'curs' in locals():
            curs.close()
        if 'conn' in locals():
            conn.close()
 
services_results = {}
    
@app.route('/get-services', methods=['GET'])
def get_services():
    environment = request.args.get('environment')
    if not environment:
        return jsonify({'status': 'error', 'message': 'Environment not provided'}), 400

    request_id = str(uuid.uuid4())
    fetch_services(environment, request_id)

    return jsonify({'status': 'started', 'request_id': request_id})
    
def fetch_services(environment, request_id):
    try:
        conn_str = connection_strings.get(environment, {}).get('connection_string')
        if not conn_str:
            raise ValueError(f"Connection string for '{environment}' not found")
            
        app.logger.debug(f"Connecting to database with connection string: {conn_str} for environment: {environment}")

        conn = cx_Oracle.connect(conn_str)
        curs = conn.cursor()

        query = """
        SELECT DISTINCT vs.FRIENDLY_NAME
        FROM LOG l
        JOIN V_SERVICES vs ON l.SERVICE_NAME = vs.SERVICE_NAME
        ORDER BY vs.FRIENDLY_NAME
        """
        app.logger.debug(f"Executing query: {query}")
        curs.execute(query)
        services = [row[0] for row in curs.fetchall()]
        app.logger.debug(f"Query results: {services}")

        
        services_results[request_id] = {'status': 'success', 'services': services}

    except cx_Oracle.DatabaseError as e:
        app.logger.error(f"Database error occurred: {e}")
        
        services_results[request_id] = {'status': 'error', 'message': 'Database error'}
    except Exception as e:
        app.logger.error(f"An unexpected error occurred: {e}")
        
        services_results[request_id] = {'status': 'error', 'message': 'Unexpected error'}
    finally:
        if 'curs' in locals():
            curs.close()
        if 'conn' in locals():
            conn.close()
        app.logger.debug("Connection closed")
  
@app.route('/get-services-status/<request_id>', methods=['GET'])
def get_services_status(request_id):
    try:
        if request_id in services_results:
            return jsonify(services_results[request_id])
        else:
            return jsonify({'status': 'in progress'})
    except Exception as e:
        app.logger.error(f"Error in get_services_status: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/cancel-query/<request_id>', methods=['POST'])
def cancel_query(request_id):
    app.logger.debug(f"cancel_query called with request_id: {request_id}")

    # Check if the request_id exists in Redis
    if redis_client.exists(f"request_{request_id}"):
        # Mark the request as canceled in Redis
        redis_client.hset(f"request_{request_id}", mapping={"status": "canceled", "canceled_at": time.time()})

        # Check if the connection exists in ongoing_queries
        if request_id in ongoing_queries:
            conn = ongoing_queries.pop(request_id)  # Remove and retrieve the connection
            try:
                app.logger.debug(f"Closing database connection for request_id: {request_id}")
                conn.close()  # Close the connection
                app.logger.debug(f"Database connection closed for request_id: {request_id}")
            except Exception as e:
                app.logger.error(f"Error closing connection for request_id {request_id}: {e}")

        return jsonify({'status': 'cancelled'})
    else:
        app.logger.debug(f"Request {request_id} not found in Redis")
        return jsonify({'status': 'not found'}), 404



@app.route('/query-status/<request_id>', methods=['GET'])
def query_status(request_id):
    app.logger.debug(f"query_status route called with request_id: {request_id}, Process ID: {os.getpid()}")

    try:
        # Check if the request_id exists in Redis
        if redis_client.exists(f"request_{request_id}"):
            status = redis_client.hget(f"request_{request_id}", "status")
            app.logger.debug(f"Request {request_id} status: {status}, Process ID: {os.getpid()}")

            if status == "completed":
                results = redis_client.hget(f"request_{request_id}", "results")
                total_cid_count = redis_client.hget(f"request_{request_id}", "total_cid_count")
                elapsed_time = redis_client.hget(f"request_{request_id}", "elapsed_time")
                return jsonify({
                    "status": "completed",
                    "results": json.loads(results),
                    "total_cid_count": int(total_cid_count) if total_cid_count else 0,
                    "elapsed_time": float(elapsed_time) if elapsed_time else 0.0
                })
            elif status == "in progress":
                return jsonify({"status": "in progress"})
            elif status == "canceled":
                canceled_at = redis_client.hget(f"request_{request_id}", "canceled_at")
                return jsonify({
                    "status": "canceled",
                    "message": "The request was canceled by the user.",
                    "canceled_at": float(canceled_at) if canceled_at else None
                })
            elif status == "error":
                message = redis_client.hget(f"request_{request_id}", "message")
                return jsonify({"status": "error", "message": message})
            else:
                app.logger.error(f"Unknown status '{status}' for request_id: {request_id}")
                return jsonify({"status": "unknown", "message": "Unknown request status"}), 500
        else:
            app.logger.debug(f"Request {request_id} not found in Redis, Process ID: {os.getpid()}")
            return jsonify({"status": "not found"}), 404
    except Exception as e:
        app.logger.error(f"Error in query_status for request_id {request_id}: {e}")
        return jsonify({"status": "error", "message": "An unexpected error occurred"}), 500



class SearchTimeoutException(Exception):
    pass

def execute_search_with_timeout(data, request_id, username, page, min_date, timeout=360):
    def target():
        try:
            redis_client.hset(f"request_{request_id}", mapping={"status": "in progress"})
            app.logger.debug(f"Set initial status for request_id {request_id}: in progress")
            execute_search(data, request_id, username, page, min_date)
        except Exception as e:
            redis_client.hset(f"request_{request_id}", mapping={"status": "error", "message": str(e)})
            app.logger.error(f"Error in execute_search_with_timeout for request_id {request_id}: {e}")

    thread = threading.Thread(target=target)
    thread.start()

    # Ensure the correct timeout value is passed here
    thread.join(timeout)

    if thread.is_alive():
        app.logger.error(f"execute_search timed out for request_id: {request_id}")
        redis_client.hset(f"request_{request_id}", mapping={"status": "error", "message": "Search operation timed out"})
        raise SearchTimeoutException("Search operation timed out")


@app.route('/search-by-postcode', methods=['POST'])
def search_by_postcode():
    app.logger.debug(f"session ID: {session.sid}")
    try:
        data = request.get_json()
        request_id = str(uuid.uuid4())
        username = session.get('username')
        min_date = session.get('min_date')
        page = data.get('page', 1)

        app.logger.debug(f"Starting search_by_postcode with request_id: {request_id}, username: {username}, min_date: {min_date}, page: {page}")

        log_interaction(
            data={"username": username},
            action="search_by_postcode",
            details={"page": page, "min_date": min_date},
            request_id=request_id
        )

        # Ensure the timeout is set to 360 seconds here
        threading.Thread(target=execute_search_with_timeout, args=(data, request_id, username, page, min_date, 360)).start()

        # Return the request_id so the frontend can poll for results
        return jsonify({'status': 'started', 'request_id': request_id})
    except Exception as e:
        app.logger.error(f"Error in search_by_postcode: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500




def execute_search(data, request_id, username, page, min_date):
    start_time = time.time()
    app.logger.debug(f"Starting execute_search with request_id: {request_id}, page: {page}")

    try:
        # Extract search parameters
        environment_to_search = data.get('environment', 'dev')
        uuid_to_search = data.get('UUID')
        correlation_id_to_search = data.get('correlationId')
        lastname_to_search = data.get('Name')
        postcode_to_search = data.get('postcode')
        vrn_to_search = data.get('VRN')
        limit_to_search = data.get('limit', 7)
        order_to_search = data.get('order', 'ASC').upper()
        start_date_to_search = data.get('start_date')
        end_date_to_search = data.get('end_date')
        dob_to_search = data.get('dob')
        service_type_to_search = data.get('searchServiceType')
        firstRequest = data.get('firstRequest')
        policyNumber = data.get('policyNumber')

        app.logger.debug(f"Validating data for request_id: {request_id}")
        validate_data(data, username, min_date)

        log_interaction(
            data={"username": username},
            action="execute_search",
            details={
                "environment": environment_to_search,
                "uuid": uuid_to_search,
                "correlation_id": correlation_id_to_search,
                "lastname": lastname_to_search,
                "postcode": postcode_to_search,
                "vrn": vrn_to_search,
                "limit": limit_to_search,
                "order": order_to_search,
                "start_date": start_date_to_search,
                "end_date": end_date_to_search,
                "dob": dob_to_search,
                "service_type": service_type_to_search
            },
            request_id=request_id
        )

        app.logger.debug(f"Service type to search: {service_type_to_search}")

        if dob_to_search:
            try:
                dob_to_search = datetime.strptime(dob_to_search, '%Y-%m-%d').strftime('%d/%m/%Y')
            except ValueError:
                app.logger.error('Invalid date format for DOB')
                redis_client.hset(f"request_{request_id}", mapping={"status": "error", "message": "Invalid date format for DOB"})
                return

        app.logger.debug(f"Received request with environment: {environment_to_search}, uuid: {uuid_to_search}, "
                         f"correlation_id: {correlation_id_to_search}, name: {lastname_to_search}, "
                         f"postcode: {postcode_to_search}, vrn: {vrn_to_search}, limit: {limit_to_search}, "
                         f"order: {order_to_search}, start_date: {start_date_to_search}, end_date: {end_date_to_search}, "
                         f"username: {username}")

        if not (uuid_to_search or correlation_id_to_search or lastname_to_search or postcode_to_search or vrn_to_search or policyNumber):
            app.logger.error('At least one of UUID, Correlation ID, Name, Postcode, or VRN is required')
            redis_client.hset(f"request_{request_id}", mapping={"status": "error", "message": "At least one of UUID, Correlation ID, Name, Postcode, or VRN is required"})
            return

        # Convert datetime-local to Oracle's expected format
        if start_date_to_search:
            start_date_to_search = datetime.strptime(start_date_to_search, '%Y-%m-%dT%H:%M')
        if end_date_to_search:
            end_date_to_search = datetime.strptime(end_date_to_search, '%Y-%m-%dT%H:%M')

        app.logger.debug(f"Attempting to connect to the database for request_id: {request_id}")
        conn_str = connection_strings.get(environment_to_search, {}).get('connection_string')
        host_name = connection_strings.get(environment_to_search, {}).get('host_name')
        app.logger.debug(f"Using connection string: {conn_str} for environment: {environment_to_search}")
        if not conn_str:
            raise ValueError(f"Invalid environment: {environment_to_search}")
        conn = cx_Oracle.connect(conn_str)
        app.logger.debug(f"Database connection established for request_id: {request_id}")

        # Store the connection in the ongoing_queries dictionary
        ongoing_queries[request_id] = conn

        curs = conn.cursor()
        curs.arraysize = 1200
        curs.callproc("DBMS_OUTPUT.ENABLE")  # Enable DBMS_OUTPUT

        # Output cursor
        result_cursor = curs.var(cx_Oracle.CURSOR)
        error_message = curs.var(cx_Oracle.STRING)

        # Call the stored procedure
        if policyNumber:
            curs.callproc("generic_search_payload", [
                policyNumber,
                'BSTI_GenerateMotorQuoteGateway',
                'Policy_PolicyNo',
                start_date_to_search,
                end_date_to_search,
                limit_to_search,
                result_cursor,
                error_message
            ])
        else:
            limit_to_search = str(int(limit_to_search))
            curs.callproc("search_by_criteria", [
                start_date_to_search,
                end_date_to_search,
                limit_to_search,
                correlation_id_to_search,
                uuid_to_search,
                lastname_to_search,
                postcode_to_search,
                vrn_to_search,
                dob_to_search,
                service_type_to_search,
                host_name,
                result_cursor,
                error_message
            ])

        if error_message.getvalue():
            app.logger.error(f"Stored procedure error: {error_message.getvalue()} for request_id: {request_id}")
            redis_client.hset(f"request_{request_id}", mapping={"status": "error", "message": error_message.getvalue()})
            return

        # Fetch DBMS_OUTPUT messages
        dbms_output = []
        line = curs.var(cx_Oracle.STRING)
        status = curs.var(cx_Oracle.NUMBER)

        while True:
            curs.callproc("DBMS_OUTPUT.GET_LINE", [line, status])
            if status.getvalue() != 0:
                break
            dbms_output.append(line.getvalue())

        # Log the DBMS_OUTPUT messages
        for message in dbms_output:
            app.logger.debug(f"DBMS_OUTPUT: {message}")

        # Fetch results
        app.logger.debug(f"Fetching results from stored procedure for request_id: {request_id}")
        raw_data = result_cursor.getvalue().fetchall()
        app.logger.debug(f"Results from stored procedure: {len(raw_data)} rows fetched for request_id: {request_id}")

        # Process results
        raw_data_serializable = []
        for row in raw_data:
            row_serializable = []
            for item in row:
                if isinstance(item, datetime):
                    row_serializable.append(item.strftime('%Y-%m-%d %H:%M:%S'))
                else:
                    row_serializable.append(item)
            raw_data_serializable.append(row_serializable)

        # Extract correlation IDs from raw_data
        correlation_ids_with_timestamps = list(set((row[0], row[1]) for row in raw_data))

        # Remove duplicates based on cid only
        unique_correlation_ids = {}
        for cid, timestamp in correlation_ids_with_timestamps:
            if cid not in unique_correlation_ids:
                unique_correlation_ids[cid] = timestamp

        sorted_correlation_ids_with_timestamps = sorted(unique_correlation_ids.items(), key=lambda x: x[1])

        # Extract sorted correlation IDs
        correlation_ids = [cid for cid, _ in sorted_correlation_ids_with_timestamps]

        # Store total_cid_count in Redis
        total_cid_count = len(correlation_ids)
        redis_client.hset(f"request_{request_id}", mapping={"total_cid_count": total_cid_count})

        if not correlation_ids:
            app.logger.debug(f"No Correlation IDs found for request_id: {request_id}")
            redis_client.hset(f"request_{request_id}", mapping={"status": "completed", "results": json.dumps({}), "elapsed_time": time.time() - start_time})
            return

        # Store correlation IDs in Redis
        redis_client.hset(f"request_{request_id}", mapping={"correlation_ids": json.dumps(correlation_ids)})

        # Second query to get the actual records
        records_per_page = 10
        page = int(page)

        start_index = (page - 1) * records_per_page
        end_index = start_index + records_per_page

        app.logger.debug(f"Page: {page}, Records per page: {records_per_page} for request_id: {request_id}")
        app.logger.debug(f"Start index: {start_index}, End index: {end_index} for request_id: {request_id}")

        if page == 1 and firstRequest == True:
            # For the first page, fetch 20 records
            paginated_correlation_ids = correlation_ids[start_index:end_index + records_per_page]
        else:
            # For subsequent pages, fetch only 10 records
            paginated_correlation_ids = correlation_ids[start_index:end_index]

        # Convert the list of correlation IDs to a format that can be passed to the stored procedure
        correlation_ids_json = json.dumps(paginated_correlation_ids)
        app.logger.debug(f"Correlation IDs JSON: {correlation_ids_json} for request_id: {request_id}")

        # Call the stored procedure to fetch records by correlation IDs
        result_cursor = curs.var(cx_Oracle.CURSOR)
        error_message = curs.var(cx_Oracle.STRING)
        curs.callproc("fetch_records_by_cid", [correlation_ids_json, service_type_to_search, result_cursor, error_message])

        if error_message.getvalue():
            app.logger.error(f"Stored procedure error: {error_message.getvalue()} for request_id: {request_id}")
            redis_client.hset(f"request_{request_id}", mapping={"status": "error", "message": error_message.getvalue()})
            return

        # Fetch results
        app.logger.debug(f"Fetching results from stored procedure for request_id: {request_id}")
        records = result_cursor.getvalue().fetchall()
        app.logger.debug(f"Fetched {len(records)} records from stored procedure for request_id: {request_id}")

        results = {}
        for record in records:
            correlation_id, log_type, message, service_name, xml_content, log_timestamp = record
            if isinstance(xml_content, cx_Oracle.LOB):
                xml_content = xml_content.read()
            if isinstance(log_timestamp, datetime):
                log_timestamp = log_timestamp.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]

            if correlation_id not in results:
                results[correlation_id] = []

            results[correlation_id].append({
                'correlation_id': correlation_id,
                'log_type': log_type,
                'message': message,
                'service_name': service_name,
                'xml_content': xml_content,
                'log_timestamp': log_timestamp
            })

        results = pair_content(results)

        end_time = time.time()
        elapsed_time = end_time - start_time

        # Store results in Redis
        redis_client.hset(f"request_{request_id}", mapping={
            "status": "completed",
            "results": json.dumps(results),
            "elapsed_time": elapsed_time
        })
        app.logger.debug(f"Request {request_id} completed with results: {results}, elapsed_time: {elapsed_time}")

    except cx_Oracle.DatabaseError as e:
        app.logger.error(f"Database error occurred: {e} for request_id: {request_id}")
        redis_client.hset(f"request_{request_id}", mapping={"status": "error", "message": str(e)})
    except Exception as e:
        app.logger.error(f"An unexpected error occurred: {e} for request_id: {request_id}")
        redis_client.hset(f"request_{request_id}", mapping={"status": "error", "message": str(e)})
    finally:
        # Remove the connection from ongoing_queries and close it
        if request_id in ongoing_queries:
            del ongoing_queries[request_id]
        if 'curs' in locals():
            curs.close()
        if 'conn' in locals():
            conn.close()
        app.logger.debug(f"Request {request_id} finished execution")



def pair_content(raw):
    paired_results = {}
    
    for correlation_id, logs in raw.items():
        service_groups = {}
        
        # Group logs by service name
        for log in logs:
            service_name = log['service_name']
            if service_name not in service_groups:
                service_groups[service_name] = []
            service_groups[service_name].append(log)
        
        # Pair requests and responses within each service group
        for service_name, service_logs in service_groups.items():
            requests = [log for log in service_logs if log['log_type'].lower() == 'request']
            responses = [log for log in service_logs if log['log_type'].lower() == 'response']
            
            paired_logs = []
            for request in requests:
                # Find the corresponding response for the request
                response = next((resp for resp in responses if resp['correlation_id'] == request['correlation_id']), None)
                if response:
                    responses.remove(response)
                else:
                    response = {
                        'correlation_id': request['correlation_id'],
                        'log_id': None,
                        'log_type': 'Response',
                        'message': None,
                        'service_name': request['service_name'],
                        'xml_content': None,
                        'log_timestamp': None
                    }
                paired_logs.append((request, response))
            
            if correlation_id not in paired_results:
                paired_results[correlation_id] = []
            paired_results[correlation_id].extend(paired_logs)
    
    return paired_results

# Data validation config, leave null if not required
cid_length = 36
cid_allowed_characters = r'^[a-zA-Z0-9-]+$'
cid_format = r'^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$'

name_min_length = 1
name_max_length = 50
name_allowed_characters = None #r'^[a-zA-Z\s]+$'

postcode_min_length = 5
postcode_max_length = 10
postcode_allowed_characters = None
#postcode_allowed_characters = r'^[a-zA-Z0-9\s]+$'

permission99_searchlimit = 51
permission01_searchlimit = 10
permission02_searchlimit = 10

permission99_env = ["dev01", "dev02", "uat1", "uat2", "uat3", "uat1Broker","uat2Broker","uat3Broker","testBroker01","testBroker02","dev01Broker", "dev02Broker" ]
permission01_env = ["uat1Broker","uat2Broker","uat3Broker","testBroker01","testBroker02","dev01Broker", "dev02Broker"]
permission02_env = ["dev01", "dev02", "uat1", "uat2", "uat3"]

vrn_length = 1
dob_format = '%Y-%m-%d'

fromDate_format = '%Y-%m-%dT%H:%M'
toDate_format = '%Y-%m-%dT%H:%M'
#for potential timezone issues
date_buffer_days_from = 1 #this is the number of days a date will be accepted before the min date/ oldest record in the database eg a value of 1 will make the min date go from 24/01/2025 to 23/01/25
date_buffer_days_to = 1 # this is the numbers of days a added onto a date that will be accepted after the current date

def validate_data(data, real_username, min_date):
    app.logger.debug(f"\n\nStarting validate_data with data: {data}, real_username: {real_username}, min_date: {min_date}\n")
    permissions = get_user_permissions(real_username)
    if permissions['status'] == 'success':
        user_type = permissions['user_type']
        app.logger.debug(f"User type: {user_type}")
    
        cid = data.get('correlationId')
        if cid:
            app.logger.debug(f"Validating Correlation ID: {cid}")
            if not validate_cid(cid):
                raise ValueError("Invalid Correlation ID")
    
        name = data.get('Name')
        if name:
            app.logger.debug(f"Validating Name: {name}")
            if not validate_name(name):
                raise ValueError("Invalid Name")
    
        postcode = data.get('postcode')
        if postcode:
            app.logger.debug(f"Validating Postcode: {postcode}")
            if not validate_postcode(postcode):
                raise ValueError("Invalid Postcode")
    
        username = data.get('username')
        if username:
            app.logger.debug(f"Validating Username: {username}")
            if not validate_username(username, real_username):
                raise ValueError("Invalid Username")

        limit = data.get('limit')
        if limit:
            app.logger.debug(f"Validating Limit: {limit}")
            if not validate_limit(limit, user_type):
                raise ValueError("Invalid Limit")

        env = data.get('environment')
        if env:
            app.logger.debug(f"Validating Environment: {env}")
            if not validate_env(env, user_type):
                raise ValueError("Invalid Environment")

        vrn =data.get('VRN')
        if vrn:
            app.logger.debug(f"Validating VRN: {vrn}")
            if not validate_vrn(vrn):
                raise ValueError("Invalid VRN")

        dob = data.get('dob')
        if dob:
            app.logger.debug(f"Validating DOB: {dob}")
            if not validate_dob(dob):
                raise ValueError("Invalid DOB")

        fromDate = data.get('start_date')
        if fromDate:
            app.logger.debug(f"Validating From Date: {fromDate}")

        toDate = data.get('end_date')
        if toDate:
            app.logger.debug(f"Validating To Date: {toDate}")
            if not validate_toDate(toDate):
                raise ValueError("Invalid To Date")
    else:
        raise ValueError("Permission denied")

def validate_cid(cid):
    # Length Check
    if validation_config['cid_length'] is not None and len(cid) != validation_config['cid_length']:
        return False
    
    # Character Check: Ensure CID contains only allowed characters
    if validation_config['cid_allowed_characters'] is not None and not re.match(validation_config['cid_allowed_characters'], cid):
        return False
    
    # Format Check: Ensure CID follows the specified format
    if validation_config['cid_format'] is not None and not re.match(validation_config['cid_format'], cid):
        return False
    
    return True

def validate_name(name):
    # Length Check
    if validation_config['name_min_length'] is not None and len(name) < validation_config['name_min_length']:
        return False
    if validation_config['name_max_length'] is not None and len(name) > validation_config['name_max_length']:
        return False
    
    # Character Check: Ensure name contains only allowed characters
    if validation_config['name_allowed_characters'] is not None and not re.match(validation_config['name_allowed_characters'], name):
        return False
    
    return True

def validate_postcode(postcode):
    # Length Check
    if validation_config['postcode_min_length'] is not None and len(postcode) < validation_config['postcode_min_length']:
        return False
    if validation_config['postcode_max_length'] is not None and len(postcode) > validation_config['postcode_max_length']:
        return False
    
    # Character Check: Ensure postcode contains only allowed characters
    if validation_config['postcode_allowed_characters'] is not None and not re.match(validation_config['postcode_allowed_characters'], postcode):
        return False
    
    return True

def validate_username(data_username, real_username):
    if data_username == real_username:
        return True
    return False

def validate_limit(limit, user_type):
    try:
        limit = int(limit)
        if user_type == 99 and validation_config['permission99_searchlimit'] is not None and limit >= validation_config['permission99_searchlimit']:
            return False
        if user_type == 1 and validation_config['permission01_searchlimit'] is not None and limit >= validation_config['permission01_searchlimit']:
            return False
        if user_type == 2 and validation_config['permission02_searchlimit'] is not None and limit >= validation_config['permission02_searchlimit']:
            return False
        return True
    except ValueError:
        return False

def validate_env(env, user_type):
    if user_type == 99 and validation_config['permission99_env'] is not None and env in validation_config['permission99_env']:
        return True
    if user_type == 1 and validation_config['permission01_env'] is not None and env in validation_config['permission01_env']:
        return True
    if user_type == 2 and validation_config['permission02_env'] is not None and env in validation_config['permission02_env']:
        return True
    return False

def validate_vrn(vrn):
    if validation_config['vrn_length'] is not None and len(vrn) >= validation_config['vrn_length']:
        return True
    return False

def validate_dob(dob):
    if validation_config['dob_format'] is not None:
        try:
            datetime.strptime(dob, validation_config['dob_format'])
            return True
        except ValueError:
            return False
    return True

def validate_fromDate(fromDate, min_date, buffer_days=validation_config['date_buffer_days_from']):
    if validation_config['fromDate_format'] is not None:
        try:
            from_date_obj = datetime.strptime(fromDate, validation_config['fromDate_format'])
            min_date_obj = datetime.strptime(min_date, validation_config['fromDate_format'])
            if buffer_days is not None:
                min_date_obj -= timedelta(days=buffer_days)  # Add buffer
            app.logger.debug(f"\n\nValidating fromDate: {from_date_obj}\nMin date with buffer: {min_date_obj}\n")
            if from_date_obj < min_date_obj:
                return False
            return True
        except ValueError:
            return False
    return True

def validate_toDate(toDate, buffer_days=validation_config['date_buffer_days_to']):
    if validation_config['toDate_format'] is not None:
        try:
            to_date_obj = datetime.strptime(toDate, validation_config['toDate_format'])
            current_date = datetime.now()
            if buffer_days is not None:
                current_date += timedelta(days=buffer_days)  # Add buffer
            app.logger.debug(f"\n\nValidating toDate: {to_date_obj}\nCurrent date with buffer: {current_date}\n")
            if to_date_obj > current_date:
                app.logger.debug("\n\ntoDate is in the future\n")
                return False
            return True
        except ValueError as e:
            app.logger.debug(f"\n\nValueError in validate_toDate: {e}\n")
            return False
    return True



@app.errorhandler(Exception)
def handle_flask_exception(e):
    app.logger.error("Unhandled Exception", exc_info=e)
    return jsonify({'status': 'error', 'message': str(e)}), 500

if __name__ == '__main__':
    try:
        app.run_server(host='0.0.0.0', port=5998, processes=4)
    except Exception as e:
        logging.critical("Exception running flask", exc_info=e)
        app.logger.debug("Critical Error")