import decimal
import glob
import gzip
import json
import smtplib
import ssl
import sys
from datetime import datetime, timedelta, timezone
from json.decoder import JSONDecodeError

import boto3
import ndjson
import requests
import toml
from boto3.dynamodb.conditions import Attr, Key
from eql import PythonEngine
from eql.errors import EqlError, EqlParseError, EqlSyntaxError
from eql.parser import parse_query
from eql.events import Event
from flask import Flask, redirect, render_template, request, send_from_directory, g, url_for
from flaskext.auth import Auth, AuthUser, login_required, logout


# stolen from SO
# https://stackoverflow.com/a/16957370


def decimal_default(obj):
    if isinstance(obj, decimal.Decimal):
        return float(obj)
    raise TypeError


login_url_name = 'user_login'


# App Settings
settings = toml.load("settings.toml")
app = Flask(__name__)
auth = Auth(app, login_url_name)
app.secret_key = settings['secret_key']
app.app_state = {
    "authentication_required": True,
}


# this fixes an error in flaskext.auth where it doesn't handle args for redirects.
def _redirect_to_login(*args, **kwargs):
    return redirect(url_for(login_url_name))


auth.not_logged_in_callback = _redirect_to_login

# User Setup


@app.before_request
def init_users():
    """
    Initializing users from hardcoded credentials from the settings.toml file.
    Looks for [users] with each username and password on a line underneath.
    Example:
        [users]
        admin = "password"
    If no users section is found in the settings file then admin/password will
    be used and auto signed in to create an unauthenticated experience.
    """
    if "users" in settings.keys():
        if settings['users'] is not None:
            settings_users = {}
            for username in settings['users']:
                new_user = AuthUser(username=username)
                # Setting and encrypting the hardcoded password.
                new_user.set_and_encrypt_password(str.encode(settings['users'][username]), salt=b'123')
                # Persisting users for this request.
                app.app_state['authentication_required'] = True
                settings_users[username] = new_user
            g.users = settings_users
            return
    else:
        admin = AuthUser(username='admin')
        # Setting and encrypting the hardcoded password.
        admin.set_and_encrypt_password(b'password', salt=b'123')
        # Persisting users for this request.
        app.app_state['authentication_required'] = False
        g.users = {'admin': admin}


# User Authentication

def user_login():
    if app.app_state['authentication_required'] is False:
        # Authentication Not Required
        username = "admin"
        g.users["admin"].authenticate(str.encode('password'))
        return redirect('/')
    # Authentication Required
    if request.method == 'POST':
        username = request.form['username']
        if username in g.users:
            password = request.form['password']
            password = str.encode(password)
            if g.users[username].authenticate(password):
                return redirect('/')
        return render_template("login.html",
                               error="The username/password combination was not found.",
                               app_state=app.app_state
                               )
    return render_template("login.html", app_state=app.app_state)


def user_logout():
    user_data = logout()
    if user_data is None:
        return redirect('/login')
    return render_template("logout.html", username=user_data['username'], app_state=app.app_state)


# Routes

@login_required()
def serve_static(path):
    return send_from_directory('static', path)


@login_required()
def dashboard():
    # until there is a need for dashboard just redirect to /list_alerts
    # return render_template('dashboard.html', app_state=app.app_state)
    return redirect('/list_alerts')


@login_required()
def http_list_alarms():
    if request.args.get('unack'):
        unack = False
        normal = True
        alerts = get_unacked_alerts()
    else:
        unack = True
        normal = False
        alerts = recent_alerts()
    print(alerts)
    formatted_alerts = format_alerts(alerts)
    print(formatted_alerts)
    return render_template("list_alarms.html",
                           alerts=formatted_alerts,
                           link_unack=unack,
                           link_normal=normal,
                           app_state=app.app_state
                           )


@login_required()
def http_settings():
    return render_template("settings.html", settings=settings, app_state=app.app_state)


@login_required()
def http_list_rules():
    rules = get_toml_from_folder("rules")
    return render_template("list_rules.html", rules=rules, app_state=app.app_state)


@login_required()
def http_show_alert(id):
    alert = fetch_alert(id)
    formatted_alerts = format_alerts(alert, True)
    return render_template("show_alert.html", alert=formatted_alerts, app_state=app.app_state)


@login_required()
def http_past_search():
    current_time = datetime.utcnow().isoformat()
    return render_template("past_search.html", current_time=current_time, app_state=app.app_state)


@login_required()
def http_ack_alert(id):
    ack_alert(id)
    return redirect("/list_alerts")


@login_required()
def http_search_results():
    if request.method == 'GET':
        return redirect("/past_search")
    if request.method == 'POST':
        d = datetime.strptime(request.form["search_time"], "%m/%d/%Y %H:%M")
        mb = int(request.form["minutes_back"])
        eql = request.form["eql_query"]
        logs_fn = list(logs_to_gen(get_logs(d, mb)))
        results = run_eql([eql], logs_fn)[0]
        results = results[:50]  # TODO: Make this a pagination (how? no fucking clue in a performant way without additional io/cache)
        formatted_results = format_alerts(results)
        return render_template("search_results.html", alerts=formatted_results, dt=d, minutes_back=mb, app_state=app.app_state)


@login_required()
def eql_query():
    req_data = request.get_json()
    results = []

    def load_data():
        data = ndjson.loads(req_data["data"])
        for event in data:
            if type(event) == type([]):
                for e in event:
                    yield e
            else:
                yield event

    if req_data["type"] == "json-input":
        json_fn = load_data()

    try:
        results = run_eql([req_data["eql"]], json_fn)[0]
        return json.dumps(results)
    except EqlError as e:
        return(json.dumps({"error": True, "type": "eql", "msg": e.__str__()}))
    except EqlParseError as e:
        return(json.dumps({"error": True, "type": "eql_syntax", "msg": e.__str__()}))
    except JSONDecodeError as e:
        return(json.dumps({"error": True, "type": "json", "msg": e.__str__()}))
    except Exception as e:
        return(json.dumps({"error": True, "type": "error", "msg": e.__str__()}))


# Functions

def format_alerts(alerts, shown=False):
    formatted_results = []
    for result in alerts:
        r = {}
        if "event_id" in result:
            r["id"] = result["event_id"]
        elif "eventID" in result:
            r["id"] = result["eventID"]
        else:
            r["id"] = "No Id."

        if "acked" in result:
            r["acked"] = result["acked"]

        r["shown"] = shown

        if "data" in result:
            data = result["data"]
        else:
            data = result

        fields = []

        if "rule" in result and "title" in result["rule"]:
            # insert clean title
            r["rule_title"] = result["rule"]["title"]

            # insert the select fields for reading
            for key in result["rule"]["fields"].keys():
                fields.append((key, get_result(result["rule"]["fields"][key], result["data"])))

        r["rule_field"] = fields

        r["details"] = json.dumps(data, sort_keys=True, indent=2, separators=(
            ',', ': '), default=decimal_default)

        formatted_results.append(r)
    return formatted_results


def run_eql(eql_text, json_fn=None):
    engines = []
    for e in eql_text:
        def out():
            store = []

            def save_event(event):
                for event in event.events:
                    store.append(event.data)

            return(store, save_event)

        result, sa_event = out()

        config = {"print": False, "hooks": [sa_event]}

        engine = PythonEngine(config)

        eql_query = parse_query(e, implied_any=True, implied_base=True)
        engine.add_query(eql_query)
        engines.append((engine, result))

    for event in json_fn:
        if not isinstance(event, Event):
            event = Event.from_data(event)
        for engine, _results in engines:
            engine.stream_event(event)

    results = []

    for engine, result in engines:
        engine.finalize()
        results.append(result)

    return results


def get_cloudtrail_file(key_prefix):
    s3 = boto3.resource('s3')
    b = s3.Bucket(settings["logs_bucket"])
    result = []
    for obj in b.objects.filter(Prefix=key_prefix):
        print(obj.key)
        s3_object = s3.Object(settings["logs_bucket"], obj.key).get()
        object_content = s3_object['Body'].read()
        results = gzip.decompress(object_content)
        for i in ndjson.loads(results)[0]['Records']:
            i['event_type'] = i['eventType']
            i['event_time'] = int(get_time(i).timestamp())
            result.append(i)
    return result


def get_toml_from_folder(f):
    files = [toml.load(f) for f in glob.glob(f + "**/*.toml", recursive=True)]
    return files


def list_rules():
    rules = get_toml_from_folder("rules")
    for rule in rules:
        print("[%s] %s by %s" %
              (rule["updated"], rule["title"], rule["author"]))


def check_rules():
    fields_required = ["author", "rule",
                       "title", "updated", "created", "fields"]
    rules = [(f, toml.load(f))
             for f in glob.glob("rules" + "**/*.toml", recursive=True)]
    for filename, rule in rules:
        for field in fields_required:
            if field not in rule:
                print("%s doesn't have a field for %s when it is required." %
                      (filename, field))
    for filename, rule in rules:
        try:
            run_eql([rule["rule"]], [])
        except EqlSyntaxError as e:
            print("%s doesn't have valid eql as it's rule, error is:\n%s\n" %
                  (filename, e))


def run_rule_file(json):
    rules = get_toml_from_folder("rules")
    rs = map(lambda x: x["rule"], rules)
    all_results = run_eql(rs, json)
    processing = zip(rules, all_results)
    for rule, result in processing:
        print("{}: {}\n".format(rule["title"], result))
        for r in result:
            already_present = len(fetch_alert(r["eventID"])) > 0
            if not already_present:
                # TODO simplify
                send_slack(build_alert_slack(
                    rule["title"], rule["fields"], r, r["eventID"]))
                send_email(build_alert_email(
                    rule["title"], rule["fields"], r, r["eventID"]))
                save_alert(r["eventID"], r, rule)


def get_result(keys, result):
    # *** TODO *** this needs a special error case to be helpful and not be a a confusing mystry for users.
    r = result
    for i in keys:
        if i in r:
            r = r[i]
        else:
            r = "No Data"
    return r


def build_alert_slack(title, fields, result, id):
    alert = f"*Alert: {title}*\n"
    for key in fields.keys():
        alert += "*{}*:\n{}\n".format(key, get_result(fields[key], result))
    link = settings["base_url"] + f"/alert/{id}"
    alert += f"*Link*:\n{link}\n"
    return alert


def build_alert_email(title, fields, result, id):
    alert = "Alert: {}\n".format(title)
    for key in fields.keys():
        alert += "{}: {}\n".format(key, get_result(fields[key], result))
    link = settings["base_url"] + "/alert/%s" % id
    alert += "link: %s" % link
    return alert


def handle_s3(event, context):
    time = datetime.utcnow()
    logs_fn = logs_to_gen(get_logs(time, settings["minutes_back"]))
    run_rule_file(logs_fn)


def get_times(s, e):
    cur_time = s
    r = []
    while cur_time < e:
        r.append(cur_time)
        cur_time += timedelta(minutes=5)
    return r


def format_datetime_to_aws_log(dt):
    prefixs = []
    for account in settings["accounts"]:
        for region in settings["accounts"][account]:
            pre_dt = "AWSLogs/ACCOUNT/CloudTrail/REGION/%Y/%m/%d/ACCOUNT_CloudTrail_REGION_%Y%m%dT%H%MZ".replace(
                "ACCOUNT", str(account))
            pre_dt = pre_dt.replace("REGION", region)
            prefixs.append(dt.strftime(pre_dt))
    return prefixs


def get_logs(dt, minutes_back):
    before_time = get_time_floor(dt - timedelta(minutes=minutes_back))
    results = []
    for t in get_times(before_time, dt):
        prefixs = format_datetime_to_aws_log(t)
        for prefix in prefixs:
            events = get_cloudtrail_file(prefix)
            for e in events:
                results.append(e)
    return results


def get_time(e):
    # fmt: "2019-06-10T21:49:50Z"
    d = datetime.strptime(
        e["eventTime"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    return d


def logs_to_gen(logs_list):
    logs_list.sort(key=get_time)
    for l in logs_list:
        yield l
    return


def get_time_floor(dt):
    return (dt - timedelta(minutes=dt.minute % 5))


def send_slack(msg):
    if "slack_url" not in settings:
        return
    webhook = settings["slack_url"]
    requests.post(webhook, data=json.dumps({"text": msg}), headers={
                  'Content-Type': 'application/json'})


def send_email(msg):
    if "email" not in settings:
        return
    sender = settings["email"]["sender"]
    receivers = settings["email"]["receivers"]

    port = 465  # For SSL
    smtp_server = settings["email"]["smtp_server"]
    password = settings["email"]["password"]
    message = 'Subject: Varna Alert\n\n%s\n' % msg

    context = ssl.create_default_context()
    with smtplib.SMTP_SSL(smtp_server, port, context=context) as server:
        server.login(sender, password)
        server.sendmail(sender, receivers, message)


def recent_alerts():
    session = boto3.session.Session()

    dynamodb = session.resource('dynamodb')

    table = dynamodb.Table('varna_sent_events_v3')

    items = []
    for account_id in settings["accounts"]:
        response = table.query(
            IndexName="account_id-event_time-index",
            KeyConditionExpression=Key('account_id').eq(account_id) & Key(
                'event_time').lt(int(datetime.utcnow().timestamp())),
            Limit=20
        )

        items.extend(response["Items"])

    items.sort(key=lambda x: x["event_time"], reverse=True)

    return items


def delete_old():
    session = boto3.session.Session()
    dynamodb = session.resource('dynamodb')
    table = dynamodb.Table('varna_sent_events_v3')

    time_back = int(
        (datetime.utcnow() - timedelta(days=settings["age_off"])).timestamp())

    for account_id in settings["accounts"]:
        response = table.query(
            IndexName="account_id-event_time-index",
            KeyConditionExpression=Key('account_id').eq(account_id) & Key(
                'event_time').lt(time_back),
        )

        for item in response["Items"]:
            alert_id = item["event_id"]
            table.delete_item(
                Key={"event_id": alert_id}
            )

    return


def replace_item(obj, key, replace_value):
    for k, v in obj.items():
        if v == key:
            obj[k] = replace_value
        if isinstance(v, dict):
            obj[k] = replace_item(v, key, replace_value)
    return obj


def save_alert(alert_id, alert_body, rule):
    session = boto3.session.Session()

    # Get the service resource.
    dynamodb = session.resource('dynamodb')

    table = dynamodb.Table('varna_sent_events_v3')

    alert_body = replace_item(alert_body, "", None)

    table.put_item(
        Item={
            'account_id': alert_body["recipientAccountId"],
            'event_time': alert_body["event_time"],
            'event_id': alert_id,
            'data': alert_body,
            'rule': rule,
        }
    )


def fetch_alert(alert_id):
    # TODO: don't use weird creds for this.
    session = boto3.session.Session()

    # Get the service resource.
    dynamodb = session.resource('dynamodb')

    table = dynamodb.Table('varna_sent_events_v3')
    response = table.query(
        KeyConditionExpression=Key('event_id').eq(alert_id),
    )
    if 'Items' in response:
        return response['Items']
    else:
        return None


def ack_alert(alert_id):
    session = boto3.session.Session()

    dynamodb = session.resource('dynamodb')

    table = dynamodb.Table('varna_sent_events_v3')

    response = table.update_item(
        Key={
            'event_id': alert_id,
        },
        UpdateExpression="set acked = :a",
        ExpressionAttributeValues={
            ":a": True,
        },
        ReturnValues="UPDATED_NEW"
    )

    return response


def get_unacked_alerts():
    session = boto3.session.Session()
    dynamodb = session.resource('dynamodb')
    table = dynamodb.Table('varna_sent_events_v3')

    fe = Attr("acked").not_exists()

    response = table.scan(FilterExpression=fe)
    data = response['Items']

    while 'LastEvaluatedKey' in response:
        response = table.scan(
            ExclusiveStartKey=response['LastEvaluatedKey'], FilterExpression=fe)
        data.extend(response['Items'])

    return data


def send_slack_unacked_alerts():
    count = len(get_unacked_alerts())
    if count > 1:
        url = settings["base_url"] + "/?unack=True"
        send_slack(
            "You have %s unacked alerts at the moment.\nlink: %s" % (count, url))


def get_table_size():
    # TODO: don't use weird creds for this.
    session = boto3.session.Session()

    # Get the service resource.
    dynamodb = session.resource('dynamodb')

    table = dynamodb.Table('varna_sent_events_v3')

    return table.item_count


def check_settings_item(item):
    if item not in settings:
        print("%s is required in the settings file, consult documentation about format." % item)
        exit(2)


def check_settings():
    manditory_settings = ["minutes_back", "age_off",
                          "accounts", "base_url", "logs_bucket"]
    for s in manditory_settings:
        check_settings_item(s)
    if "slack_url" not in settings and "email_url" not in settings:
        print("You must defined either slack_url or email_url for notifications.")
        exit(2)
    for item in settings["accounts"]:
        if not type([]) == type(settings["accounts"][item]):
            print(
                "Structure of accounts in settings looks wrong, please consult documentation.")
            exit(2)
    print("Settings looks to be correct.")


def command_handle_s3():
    handle_s3(None, None)


actions = {"list-rules": list_rules, "run-server": app.run,
           "check-rules": check_rules, "check-settings": check_settings, "handle-s3": command_handle_s3}


def display_overall_help():
    list_of_rules = list(actions.keys())
    words = ", ".join(list_of_rules)
    print("potential commands are: %s." % words)


# Register Flask Routes

# Public Routes
app.add_url_rule('/static/', 'serve_static', serve_static, methods=['GET'])
app.add_url_rule('/login', 'user_login', user_login, methods=['GET', 'POST'])
app.add_url_rule('/logout', 'user_logout', user_logout, methods=['GET'])


# Private Routes
app.add_url_rule('/', 'dashboard', dashboard, methods=['GET'])
app.add_url_rule('/list_alerts', 'http_list_alarms', http_list_alarms, methods=['GET'])
app.add_url_rule('/list_rules', 'http_list_rules', http_list_rules, methods=['GET'])
app.add_url_rule('/settings', 'settings', settings, methods=['GET'])
app.add_url_rule('/alert/<id>', 'http_show_alert', http_show_alert, methods=['GET'])
app.add_url_rule('/past_search', 'http_past_search', http_past_search, methods=['GET'])
app.add_url_rule('/ack_alert/<id>', 'http_ack_alert', http_ack_alert, methods=['GET'])
app.add_url_rule('/search_results', 'http_search_results', http_search_results, methods=['GET', 'POST'])
app.add_url_rule('/evaluate', 'eql_query', eql_query, methods=['POST'])


if __name__ == '__main__':
    if len(sys.argv) < 2:
        display_overall_help()
    else:
        if sys.argv[1] in actions:
            actions[sys.argv[1]]()
        else:
            print("Sorry, that command couldn't be found.")
            display_overall_help()
