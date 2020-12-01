from flask import Flask, request
app = Flask(__name__)

@app.route("/execute_sql", methods=['GET'])
def execute_sql():
    sql_code = request.args.get('sql')
    print(f'DEBUG:\nsql_code={sql_code}')
    return f'Hello World! sql_code={sql_code}'

if __name__ == "__main__":
    app.run(ssl_context='adhoc',
            host='127.0.0.1',
            port=8443)
