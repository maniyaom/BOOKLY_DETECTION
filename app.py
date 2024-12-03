from flask import Flask, request, jsonify, render_template
import mysql.connector
import pickle
from datetime import datetime
import pytz
import requests
import warnings
import os

db_config = {
    'host': 'mysql-2b9a9625-maniyaom592-fee0.h.aivencloud.com',
    'user': os.getenv('AVIEN_DATABASE_USERNAME'),
    'password': os.getenv('AVIEN_DATABASE_PASSWORD'),
    'database': 'defaultdb',
    'port' : '12116'
}

BAD_WORDS = {
    "<script>", "javascript:", "onload", "onerror", "<img>", "<iframe>", "<body>", "alert()", "document.cookie",
    '<a href="javascript:', "eval()", "<svg>", "<style>", "<meta>", "onfocus", "onmouseover", "innerHTML",
    "XMLHttpRequest", "<input>", "src", "window.location", "parent.location", "top.location", "setTimeout()",
    "setInterval()", "<form>", "<object>", "<embed>", "<video>", "<audio>", "<marquee>", "<table background=",
    "<link>", "select", "delete", "update", "insert", "drop", "alter", "create", "truncate", "union", "group by",
    "order by", "having", "exec", "execute", "declare", "cast", "convert", "use", "shutdown", "xp_cmdshell",
    "sp_executesql", "information_schema", "sysobjects", "syscolumns", "sysdatabases", "sysusers"
}

def get_db_connection():
    connection = mysql.connector.connect(**db_config)
    return connection

def get_ist():
    ist = pytz.timezone('Asia/Kolkata')
    ist_time = datetime.now(ist)
    return ist_time.strftime('%d-%m-%Y %H:%M:%S')

def get_location(ip):
    url = f"http://ip-api.com/json/{ip}"
    response = requests.get(url)
    if response.status_code == 200:
        data = response.json()
        return {
            "ip": data.get("ip"),
            "city": data.get("city"),
            "state": data.get("regionName"),
            "country": data.get("country"),
            "latitude": data.get("lat"),
            "longitude": data.get("lon"),
            "postal": data.get("zip"),
            "ISP": data.get("org")
        }
    else:
        return {
            "error": "Unable to fetch location data",
            "city": None,
            "state": None,
            "country": None,
            "latitude": None,
            "longitude": None,
            "postal": None,
            "ISP": None
        }

# Counts the occurrences of bad words in a given line
def count_bad_words(line):
    return sum(line.count(word) for word in BAD_WORDS)

# Extracts features from the input string for model prediction
def preprocess(data):
    stripped_data = data.strip()
    return [
        stripped_data.count("'"),
        stripped_data.count("\""),
        stripped_data.count("-"),
        stripped_data.count("#"),
        stripped_data.count("*"),
        stripped_data.count("&"),
        stripped_data.count("="),
        count_bad_words(stripped_data),
        stripped_data.count("(") + stripped_data.count(")"),
        stripped_data.count("<") + stripped_data.count(">"),
        stripped_data.count("/")
    ]

app = Flask(__name__)

with open('model.pkl', 'rb') as file:
     model = pickle.load(file)

@app.route('/')
def index():
    # Setting default Options
    intrusion_status = request.args.get('intrusion_status', 'both')
    from_datetime = request.args.get('from')
    to_datetime = request.args.get('to')

    formatted_from_datetime = from_datetime if from_datetime else None
    formatted_to_datetime = to_datetime if to_datetime else None

    # Format the datetime strings if they are not None
    if from_datetime:
        dt = datetime.strptime(from_datetime, '%Y-%m-%dT%H:%M')
        formatted_from_datetime = dt.strftime('%d-%m-%Y %H:%M:%S')
    if to_datetime:
        dt = datetime.strptime(to_datetime, '%Y-%m-%dT%H:%M')
        formatted_to_datetime = dt.strftime('%d-%m-%Y %H:%M:%S')

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        if intrusion_status == 'both':
            if formatted_from_datetime and formatted_to_datetime:
                cursor.execute("SELECT timestamp, payload, ipaddress, status, city, state, country, latitude, longitude, postal, ISP FROM intrusion WHERE timestamp >= %s AND timestamp <= %s ORDER BY timestamp", (formatted_from_datetime, formatted_to_datetime,))
            
            elif formatted_from_datetime:
                cursor.execute("SELECT timestamp, payload, ipaddress, status, city, state, country, latitude, longitude, postal, ISP FROM intrusion WHERE timestamp >= %s ORDER BY timestamp", (formatted_from_datetime,))
            
            elif formatted_to_datetime:
                cursor.execute("SELECT timestamp, payload, ipaddress, status, city, state, country, latitude, longitude, postal, ISP FROM intrusion WHERE timestamp <= %s ORDER BY timestamp", (formatted_to_datetime,))

            else:
                cursor.execute("SELECT timestamp, payload, ipaddress, status, city, state, country, latitude, longitude, postal, ISP FROM intrusion ORDER BY timestamp;")

        elif intrusion_status in ['Intrusion detected', 'Intrusion not detected']:
            if formatted_from_datetime and formatted_to_datetime:
                cursor.execute("SELECT timestamp, payload, ipaddress, status, city, state, country, latitude, longitude, postal, ISP FROM intrusion WHERE status = %s AND timestamp >= %s AND timestamp <= %s ORDER BY timestamp", (intrusion_status, formatted_from_datetime, formatted_to_datetime))

            elif formatted_from_datetime:
                cursor.execute("SELECT timestamp, payload, ipaddress, status, city, state, country, latitude, longitude, postal, ISP FROM intrusion WHERE status = %s AND timestamp >= %s ORDER BY timestamp", (intrusion_status, formatted_from_datetime,))
            
            elif formatted_to_datetime:
                cursor.execute("SELECT timestamp, payload, ipaddress, status, city, state, country, latitude, longitude, postal, ISP FROM intrusion WHERE status = %s AND timestamp <= %s ORDER BY timestamp", (intrusion_status, formatted_to_datetime,))
            
            else:
                cursor.execute("SELECT timestamp, payload, ipaddress, status, city, state, country, latitude, longitude, postal, ISP FROM intrusion WHERE status = %s ORDER BY timestamp", (intrusion_status,))

        intrusion_data = cursor.fetchall()
    except mysql.connector.Error as err:
        print(f"Database error: {err}")
        intrusion_data = []
    finally:
        cursor.close()
        conn.close()

    return render_template('index.html', data=intrusion_data, selected_option=intrusion_status, from_datetime=from_datetime, to_datetime=to_datetime)

@app.route('/predict', methods=['POST'])
def predict():
    data = request.get_json()
    if 'ip_address' not in data:
        return jsonify({"error": "true",
                        "message": "IP address not provided."}), 400
    
    location_data = get_location(data['ip_address'])
    warnings.filterwarnings("ignore", message="X does not have valid feature names")

    if('payload' in data):
        processed_data = preprocess(data['payload'])
        prediction = model.predict([processed_data])
        print(prediction[0])
        if prediction[0] == 0:
             conn = get_db_connection()
             cursor = conn.cursor(dictionary=True)
             insert_query = "INSERT INTO intrusion (timestamp, payload, ipaddress, status, city, state, country, latitude, longitude, postal, ISP) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"
             values = (get_ist(), data['payload'], data['ip_address'], 'Intrusion not detected', location_data['city'], location_data['state'], location_data['country'], location_data['latitude'], location_data['longitude'], location_data['postal'], location_data['ISP'])
             cursor.execute(insert_query, values)
             conn.commit()
             cursor.close()
             conn.close()

             return jsonify({"error": "false",
                    "message": "Intrusion not detected",
                    })
        else:
             conn = get_db_connection()
             cursor = conn.cursor(dictionary=True)
             insert_query = "INSERT INTO intrusion (timestamp, payload, ipaddress, status, city, state, country, latitude, longitude, postal, ISP) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"
             values = (get_ist(), data['payload'], data['ip_address'], 'Intrusion detected', location_data['city'], location_data['state'], location_data['country'], location_data['latitude'], location_data['longitude'], location_data['postal'], location_data['ISP'])
             cursor.execute(insert_query, values)
             conn.commit()
             cursor.close()
             conn.close()
             return jsonify({"error": "false",
                    "message": "Intrusion Detected"
                    })
    else:
        return jsonify({
            "error": "true",
            "message": "The body should contain a payload."
        })

if __name__ == '__main__':
    app.run(debug=True)
