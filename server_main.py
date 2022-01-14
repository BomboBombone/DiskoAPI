import os
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import mysql.connector
from datetime import date, timedelta, datetime
from random import randint
import cgi

from key_generator.key_generator import generate

hostName = "127.0.0.1"
serverPort = 8080

config = {
    'user': 'root',
    'password': '1234AbCd0!!!',
    'host': 'localhost',
    'database': 'diskoaio'
}
cwd = os.getcwd()

SQL_Statements = ['\'', '"', 'select', 'insert', '--', '#', ',', '%']

action_types = ['win', 'login', 'logout', 'giveaway', 'join']

def check_SQLI(input: str):
    if input is None or input == '':
        return False
    for statement in SQL_Statements:
        if statement in input:
            return True
    return False


def get_time_range(days: int):
    d = date.today() - timedelta(days=days)
    dt = datetime.strftime(d, "%Y/%m/%d")
    return dt


def get_auth_token(headers: list):
    for header in headers:
        if "Authorization" in header.strip():
            if header.split(':')[1].strip().startswith("Bearer"):
                token = header.split(':')[1].strip().split(' ')[1].strip()
                return token
    return None


def get_content_length(headers: list):
    for header in headers:
        if "content-length" in header.strip().lower():
            length = header.split(':')[1].strip()
            return length
    return None


def get_account(cursor, api_key: str = None, username: str = None, pw: str = None):
    if username is None and pw is None and api_key is not None:
        if check_SQLI(api_key):
            return None
        cursor.execute('SELECT * FROM accounts WHERE (api_key = \'' + api_key + '\') LIMIT 1')
        return cursor.fetchone()
    else:
        if check_SQLI(username) or check_SQLI(pw):
            return None
        if username is None or pw is None:
            return None
        cursor.execute('SELECT * FROM accounts WHERE username = \'' + username + '\' AND pw = \'' + str(pw) + '\' '
                                                                                                              'LIMIT '
                                                                                                              '1')
        return cursor.fetchone()


def post_account(cursor, email: str, password: str, accounts: list = None):
    exec_statement = 'INSERT INTO accounts VALUES '
    try:
        while True:
            seed = randint(1, 1000000000000)
            key = generate(seed=seed)
            api_key = key.get_key()
            cursor.execute('SELECT 1 FROM accounts WHERE api_key = \'' + api_key + '\'')
            result = cursor.fetchone()
            if not result:
                break
        account = [api_key, email, password, str(date.today()), 0, 'NULL', 'NULL', 'NULL']
        account = str(account).replace('[', '(').replace(']', ')').replace('\'NULL\'', 'NULL')
        exec_statement += account
        cursor.execute(exec_statement)

        return True, api_key
    except Exception as ex:
        return False, str(ex)


class MyServer(BaseHTTPRequestHandler):
    def do_GET(self):
        cnx = mysql.connector.connect(**config)
        cursor = cnx.cursor()
        request_type = self.path
        if request_type.startswith('/api'):
            request_type = request_type.replace('/api', '')
        queries = []
        username = ''
        pw = ''
        if '?' in request_type:
            queries = request_type.split('?')[1].split('&')
            request_type = request_type.split('?')[0]
        for query in queries:
            if 'email' in query:
                username = query.split('=')[1].strip()
            elif 'password' in query:
                pw = query.split('=')[1].strip()

        if request_type.startswith('/accounts'):
            if not (pw == '' or username == ''):
                if check_SQLI(pw) or check_SQLI(username):
                    return
                self.get_account_response(cursor, username, pw)
            else:
                self.get_account_response(cursor)
        elif request_type.startswith('/science'):
            pass

        cnx.commit()
        cnx.close()

    def do_POST(self):
        cnx = mysql.connector.connect(**config)
        cursor = cnx.cursor()

        request_type = self.path
        if request_type.startswith('/api'):
            request_type = request_type.replace('/api', '')
        else:
            return
        queries = []
        email = ''
        pw = ''
        if '?' in request_type:
            queries = request_type.split('?')[1].split('&')
            request_type = request_type.split('?')[0]
        for query in queries:
            if 'email' in query:
                email = query.split('=')[1].strip()
            elif 'password' in query:
                pw = query.split('=')[1].strip()
        ctype, pdict = cgi.parse_header(self.headers.get_content_type())

        # refuse to receive non-json content
        if ctype != 'application/json' and (email == '' and pw == ''):
            self.send_response(400, 'Unsupported')
            self.end_headers()
            return
        action_type = None
        if email == '' or pw == '':
            # read the message and convert it into a python dictionary
            length = get_content_length(self.headers.as_string().split('\n'))
            payload = json.loads(self.rfile.read(int(length)))
            action_type = payload["action"]

        if request_type.startswith('/accounts'):
            if check_SQLI(email) or check_SQLI(pw):
                return
            success, api_key = post_account(cursor, email, pw)
            if success:
                self.send_response(200, 'account created successfully')
                self.send_header("Content-type", "application/json")
                self.end_headers()
                self.wfile.write(bytes(api_key, "utf-8"))
            else:
                self.send_error(401, 'Could not create account', 'An error has occurred during the process: ' + api_key)
        elif request_type.startswith('/science'):
            if action_type is None:
                return
            self.post_action(cursor, action_type)

        cnx.commit()
        cnx.close()

    def do_PUT(self):
        cnx = mysql.connector.connect(**config)
        cursor = cnx.cursor()

        request_type = self.path
        if request_type.startswith('/api'):
            request_type = request_type.replace('/api', '')
        else:
            return
        queries = []
        mac = ''
        if '?' in request_type:
            queries = request_type.split('?')[1].split('&')
            request_type = request_type.split('?')[0]
        for query in queries:
            if 'mac' in query:
                mac = query.split('=')[1].strip()
        if request_type.startswith('/accounts'):
            if mac == '':
                self.send_error(407, 'You need to specify a mac address to bind')
                return
            self.put_mac(cursor, mac)
        cnx.commit()
        cnx.close()

    def get_ip(self):
        headers = self.headers.as_string().split('\n')
        for header in headers:
            if header.split(' ')[0] == 'X-Real-IP:':
                ip = header.split(' ')[1]
                if check_SQLI(ip):
                    return '0.0.0.0'
                return ip
        return None

    def put_mac(self, cursor, mac_adrr: str):
        api_key = get_auth_token(self.headers.as_string().split("\n"))
        if check_SQLI(api_key):
            return
        if api_key is None or api_key == '':
            return
        account = get_account(cursor, api_key)

        if account is None:
            self.send_error(400, 'Invalid credentials provided',
                            'Username, password, or api_key inserted were not valid')
            return

        api_key, username, pw, account_creation, hasDisko, mac, ip, disko_expiry = account
        if mac is None or mac == "NULL":
            cursor.execute('update accounts set mac = \'' + str(mac_adrr) + '\' where api_key = \'' + api_key + '\'')
            cursor.execute(
                'update accounts set ip = \'' + str(self.get_ip()) + '\' where api_key = \'' + api_key + '\'')
            self.send_response(204, 'The machine has been successfully bound')
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(bytes(str(""), 'utf-8'))
        else:
            self.send_error(406, 'The account is already bound to another machine, please contact the '
                                 'administrators if you need to rebind your machine')

    def get_account_response(self, cursor, username: str = None, pw: str = None):
        api_key = get_auth_token(self.headers.as_string().split("\n"))
        if username is None or username == '':
            if (api_key is None) or check_SQLI(api_key):
                return
        if not (username is None and pw is None):
            if check_SQLI(username) or check_SQLI(pw):
                return
            account = get_account(cursor, username=username, pw=pw)
        else:
            if api_key is None:
                self.send_error(400)
            account = get_account(cursor, api_key)
        if account is None:
            self.send_error(400, 'Invalid credentials provided',
                            'Username, password, or api_key inserted were not valid')
            return

        api_key, username, pw, account_creation, hasDisko, mac, ip, disko_expiry = account
        today = datetime.today()
        if disko_expiry is not None:
            expiration = str(disko_expiry).split('-')
        else:
            expiration = str(date.today()).split('-')
        if today > datetime(int(expiration[0]), int(expiration[1]), int(expiration[2])):
            hasDisko = '0'
            cursor.execute('update accounts set hasDisko = false where api_key = \'' + api_key + '\'')

        account = {'api_key': api_key, 'username': username, 'pw': pw, 'mac': mac,
                   'creation_date': str(account_creation), 'disko': str(hasDisko)}
        json_account = str(json.dumps(account))
        self.send_response(200)
        self.send_header("Content-type", "application/json")
        self.end_headers()
        self.wfile.write(bytes(json_account, "utf-8"))
        cursor.execute(
            'update accounts set ip = \'' + str(self.get_ip()) + '\' where api_key = \'' + api_key + '\'')

    def post_action(self, cursor, action_type: str):
        api_key = get_auth_token(self.headers.as_string().split("\n"))
        if (api_key is None) or check_SQLI(api_key):
            return
        if action_type not in action_types:
            self.send_error(404, 'Action not found')
            return
        cursor.execute('SELECT * FROM science WHERE api_key = \'' + api_key + '\'')
        result = cursor.fetchone()
        if result is None:
            cursor.execute(f'INSERT INTO science VALUES '
                           f'(\'{api_key}\', 0, \'{datetime.now()}\', \'{datetime.now()}\', 0, 0, 0)')
            time_spent = 0
            last_login = datetime.now()
            last_logout = datetime.now()
            giveaways = 0
            joins = 0
            wins = 0
        else:
            time_spent = int(result[1])
            last_login = result[2]
            last_logout = result[3]
            giveaways = int(result[4])
            joins = int(result[5])
            wins = int(result[6])
        if action_type == action_types[0]: #win
            wins += 1
            cursor.execute(f'UPDATE science SET wins = {wins} WHERE api_key = \'{api_key}\'')
        elif action_type == action_types[1]: #login
            cursor.execute(
                f'UPDATE science SET login = \'{str(datetime.now()).split(".")[0]}\' WHERE api_key = \'{api_key}\'')
            #cursor.execute(f'UPDATE science SET time = {time_spent} WHERE api_key = \'{api_key}\'')
        elif action_type == action_types[2]: #logout
            time_spent = time_spent + int((datetime.now() - datetime.strptime(last_login.split('.')[0], '%Y-%m-%d %H:%M:%S')).seconds / 60)
            cursor.execute(f'UPDATE science SET time = {time_spent} WHERE api_key = \'{api_key}\'')
            cursor.execute(f'UPDATE science SET logout = \'{str(datetime.now()).split(".")[0]}\' WHERE api_key = \'{api_key}\'')
        elif action_type == action_types[3]: #giveaway
            giveaways += 1
            cursor.execute(f'UPDATE science SET giveaways = {giveaways} WHERE api_key = \'{api_key}\'')
        elif action_type == action_types[4]: #join
            joins += 1
            cursor.execute(f'UPDATE science SET joins = {joins} WHERE api_key = \'{api_key}\'')
        self.send_response(201)
        self.send_header("Content-type", "application/json")
        self.end_headers()
        self.wfile.write(bytes(str(""), 'utf-8'))


if __name__ == "__main__":
    webServer = HTTPServer((hostName, serverPort), MyServer)
    print("Server started http://%s:%s" % (hostName, serverPort))

    try:
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass

    webServer.server_close()

    print("Server stopped.")
