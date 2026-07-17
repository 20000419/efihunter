import requests
import sqlite3
import os

# 从环境变量获取 OpenAI API 密钥，若没有则使用硬编码密钥
api_key = os.environ.get('OPENAI_API_KEY', 'sk-REDACTED_SET_YOUR_OWN_KEY')

def make_request(api_endpoint, messages, model):
    parameters = {
        'messages': messages,
        'temperature': 0.8,
        'model': model,
        'stream': False,
        'max_tokens': 4096,
        'top_p': 0.95,  
        'top_k': 20, 
    }

    headers = {
        "Content-Type": "application/json",
        'Authorization': f"Bearer {api_key}"
    }

    resp = requests.post(
        f'{api_endpoint}/v1/chat/completions',
        headers=headers,
        json=parameters,
    )
    try:
        return resp.json()
    except requests.exceptions.JSONDecodeError:
        print(f"Failed to decode JSON from response: {resp.text}")
        return None


def get_models(api_endpoint):
    headers = {
        "Content-Type": "application/json",
        'Authorization': f"Bearer {api_key}"
    }
    try:
        resp = requests.get(f'{api_endpoint}/v1/models', headers=headers)
        resp.raise_for_status()
        resp_json = resp.json()
        return [m['id'] for m in resp_json.get('data', [])]
    except requests.exceptions.HTTPError as http_err:
        print(f"HTTP error occurred: {http_err}")
    except requests.exceptions.JSONDecodeError as json_err:
        print(f"JSON decoding error occurred: {json_err}")
    except requests.exceptions.RequestException as req_err:
        print(f"Request error occurred: {req_err}")
    return []


def open_db(db_name):
    db = sqlite3.connect(db_name)
    db.execute('''
        CREATE TABLE IF NOT EXISTS result (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            model TEXT NOT NULL,
            dataset TEXT NOT NULL,
            func_name TEXT,
            dataset_type TEXT NOT NULL,
            identifier TEXT NOT NULL,
            query_type TEXT NOT NULL,
            code TEXT NOT NULL,
            finish_reason TEXT NOT NULL,
            content TEXT NOT NULL,
            reference TEXT,
            trial INTEGER NOT NULL,
            hash BLOB NOT NULL,
            prompt_type TEXT NOT NULL
        )
    ''')
    return db


def store_in_sqlite(
    db_path, **data
):
    db = open_db(db_path)
    store_in_sqlite_manual(db, **data)
    db.close()


def store_in_sqlite_manual(
    db, **data
):
    db_key = []
    db_value = []
    for k, v in data.items():
        db_key.append(k)
        db_value.append(v)

    db.execute('''
        INSERT INTO result ({db_key})
        VALUES ({place_holder})
    '''.format(
        db_key=', '.join(db_key),
        place_holder=', '.join(['?'] * len(db_key))
    ), db_value)
    db.commit()


def query_all_data_in_sqlite(db_path, columns):
    db = open_db(db_path)
    cursor = db.execute('''
        SELECT {} FROM result
    '''.format(', '.join(columns)))
    return cursor.fetchall()
    
