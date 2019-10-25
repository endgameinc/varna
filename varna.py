from flask import Flask, jsonify, request, render_template, redirect
import boto3
from boto3.dynamodb.conditions import Key, Attr, NotEquals
import json
from json.decoder import JSONDecodeError
from eql import PythonEngine
from eql.errors import EqlError, EqlParseError, EqlSyntaxError
from eql.parser import parse_query
from eql.utils import stream_file_events, stream_json_lines
import gzip
import ndjson
import toml
import requests
from datetime import datetime, timedelta, timezone
import glob
import sys
import decimal
import smtplib, ssl

# stolen from SO
# https://stackoverflow.com/a/16957370
def decimal_default(obj):
  if isinstance(obj, decimal.Decimal):
    return float(obj)
  raise TypeError

app = Flask(__name__)

settings = toml.load("settings.toml")

@app.route('/static/')
def serve_static(path):
  return send_from_directory('static', path)

@app.route('/list_rules')
def http_list_rules():
  rules = get_toml_from_folder("rules")
  return render_template("list_rules.html", rules = rules)

@app.route('/list_alarms')
def http_list_alarms():
  if request.args.get('unack'):
    unack = False
    normal = True
    alerts = get_unacked_alerts()
  else:
    unack = True
    normal = False
    alerts = recent_alerts()
  formatted_alerts = format_alerts(alerts)
  return render_template("list_alarms.html", alerts = formatted_alerts, link_unack = unack, link_normal = normal)

@app.route('/')
def http_overview():
  return redirect("/list_alarms")
  # tablesize = get_table_size()
  # rulesize = len(get_toml_from_folder("rules"))
  # avg_length = 5.1
  # return render_template("overview.html", tablesize = tablesize, rulesize = rulesize, avg_length = avg_length)

@app.route('/settings')
def http_settings():
  return render_template("settings.html", settings = settings)

@app.route('/alert/<id>')
def http_show_alert(id):
  alert = fetch_alert(id)
  formatted_alerts = format_alerts(alert, True)
  return render_template("list_alarms.html", alerts = formatted_alerts)

@app.route('/past_search', methods=['GET'])
def http_past_search():
  current_time = datetime.utcnow().isoformat()
  return render_template("past_search.html")

@app.route('/ack_alert/<id>')
def http_ack_alert(id):
  ack_alert(id)
  return redirect("/list_alarms")

@app.route('/search_results', methods=['POST', 'GET'])
def http_search_results():
  if request.method == 'GET':
    return redirect("/past_search")
  d = datetime.strptime(request.form["search_time"], "%m/%d/%Y %H:%M")
  mb = int(request.form["minutes_back"])
  eql = request.form["eql_query"]
  logs_fn = list(logs_to_gen(get_logs(d, mb)))
  results = run_eql(eql, logs_fn)
  results = results[:50]
  formatted_results = format_alerts(results)
  return render_template("search_results.html", alerts = formatted_results, dt = d, minutes_back = mb)

@app.route('/evaluate', methods=['POST'])
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
  else:
    json_fn = get_metal_result(req_data["data"])

  try:
    results = run_eql(req_data["eql"], json_fn)
    return json.dumps(results)
  except EqlError as e:
    return(json.dumps({ "error" : True, "type" : "eql", "msg" : e.__str__()}))
  except ParseError as e:
    return(json.dumps({ "error" : True, "type" : "eql_syntax", "msg" : e.__str__()}))
  except JSONDecodeError as e:
    return(json.dumps({ "error" : True, "type" : "json", "msg" : e.__str__()}))
  except Exception as e:
    return(json.dumps({ "error" : True, "type" : "error", "msg" : e.__str__()}))

def format_alerts(alerts, shown = False):
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
    r["details"] = json.dumps(data, sort_keys = True, indent = 2, separators = (',', ': '), default=decimal_default)
    formatted_results.append(r)
  return formatted_results

def run_eql(eql_text, json_fn=None):
  results = []

  def save_event(event):
    for event in event.events:
      results.append(event.data)

  config = {"print": False, "hooks" : [save_event]}

  engine = PythonEngine(config)

  eql_query = parse_query(eql_text, implied_any=True, implied_base=True)
  engine.add_query(eql_query)

  if json_fn:
    engine.stream_events(json_fn, finalize=False)
  engine.finalize()

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
    print("[%s] %s by %s" % (rule["updated"], rule["title"], rule["author"]))

def check_rules():
  # TODO Validate that the eql is valid
  fields_required = ["author", "rule", "title", "updated", "created", "fields"]
  rules = [(f, toml.load(f)) for f in glob.glob("rules" + "**/*.toml", recursive=True)]
  for filename, rule in rules:
    for field in fields_required:
      if field not in rule:
        print("%s doesn't have a field for %s when it is required." % (filename, field))
  for filename, rule in rules:
    try:
      run_eql(rule["rule"], [])
    except EqlSyntaxError as e:
      print("%s doesn't have valid eql as it's rule, error is:\n%s\n" % (filename, e))

def run_rule_file(json, alert = True):
  rules = get_toml_from_folder("rules")
  all_results = []
  for rule in rules:
    results = run_eql(rule["rule"], json)
    print(results)
    if not alert:
      results = results[:20]
    for r in results:
      all_results.append(r)
      already_present = len(fetch_alert(r["eventID"])) > 0
      if alert and not already_present:
        send_slack(build_alert_slack(rule["title"], rule["fields"], r, r["eventID"]))
        send_email(build_alert_email(rule["title"], rule["fields"], r, r["eventID"]))
        save_alert(r["eventID"], r)
  return results

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
  alert = "*Alert: {}*\n".format(title)
  for key in fields.keys():
    alert += "*{}*:\n{}\n".format(key, get_result(fields[key], result))
  link = settings["base_url"] + "/alert/%s" % id
  alert += "*link*:\n%s\n" % link
  return alert

def build_alert_email(title, fields, result, id):
  alert = "Alert: {}\n".format(title)
  for key in fields.keys():
    alert += "{}: {}\n".format(key, get_result(fields[key], result))
  link = settings["base_url"] + "/alert/%s" % id
  alert += "link: %s" % link
  return alert

def handle_s3(event, context):
  for r in event["Records"]:
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
      pre_dt = "AWSLogs/ACCOUNT/CloudTrail/REGION/%Y/%m/%d/ACCOUNT_CloudTrail_REGION_%Y%m%dT%H%MZ".replace("ACCOUNT", str(account))
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
  d = datetime.strptime(e["eventTime"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
  return d

def logs_to_gen(logs_list):
  logs_list.sort(key = get_time)
  for l in logs_list:
    yield l
  return

def get_time_floor(dt):
  return (dt - timedelta(minutes=dt.minute % 5))

def send_slack(msg):
  if not settings["slack_url"]:
    return
  webhook = settings["slack_url"]
  requests.post(webhook, data=json.dumps({"text" : msg}), headers={'Content-Type': 'application/json'})

def send_email(msg):
  if not settings["email"]:
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
      KeyConditionExpression=Key('account_id').eq(account_id) & Key('event_time').lt(int(datetime.utcnow().timestamp())),
      Limit=20,
    )

    items.extend(response["Items"])

  items.sort(key = lambda x: x["event_time"], reverse = True)

  return items

def delete_old():
  session = boto3.session.Session()
  dynamodb = session.resource('dynamodb')
  table = dynamodb.Table('varna_sent_events_v3')

  time_back = int((datetime.utcnow() - timedelta(days=settings["age_off"])).timestamp())

  for account_id in settings["accounts"]:
    response = table.query(
     IndexName="account_id-event_time-index",
     KeyConditionExpression=Key('account_id').eq(account_id) & Key('event_time').lt(int(datetime.utcnow().timestamp())),
    )

    for item in response["Items"]:
      alert_id = item["event_id"]
      table.delete_item(
          Key={"event_id": alert_id}
      )

  return

def save_alert(alert_id, alert_body):
  session = boto3.session.Session()

  # Get the service resource.
  dynamodb = session.resource('dynamodb')

  table = dynamodb.Table('varna_sent_events_v3')

  table.put_item(
      Item={
        'account_id': alert_body["recipientAccountId"],
        'event_time': alert_body["event_time"],
        'event_id': alert_id,
        'data': alert_body,
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
    response = table.scan(ExclusiveStartKey=response['LastEvaluatedKey'], FilterExpression=fe)
    data.extend(response['Items'])

  return data

def send_slack_unacked_alerts():
  count = len(get_unacked_alerts())
  if count > 1:
      url = settings["base_url"] + "/list_alarms?unack=True"
      send_slack("You have %s unacked alerts at the moment.\nlink: %s" % (count, url))

def get_table_size():
  # TODO: don't use weird creds for this.
  session = boto3.session.Session()

  # Get the service resource.
  dynamodb = session.resource('dynamodb')

  table = dynamodb.Table('varna_sent_events_v3')

  return table.item_count

def check_settings_item(item):
  if not item in settings:
    print("%s is required in the settings file, consult documentation about format." % item)
    exit(2)

def check_settings():
  manditory_settings = ["minutes_back", "age_off", "accounts", "base_url", "logs_bucket"]
  for s in manditory_settings:
    check_settings_item(s)
  if not "slack_url" in settings and not "email_url" in settings:
    print("You must defined either slack_url or email_url for notifications.")
    exit(2)
  for item in settings["accounts"]:
    if not type([]) == type(settings["accounts"][item]):
      print("Structure of accounts in settings looks wrong, please consult documentation.")
      exit(2)
  print("Settings looks to be correct.")

actions = {"list-rules": list_rules, "run-server": app.run, "check-rules": check_rules, "check-settings": check_settings}

def display_overall_help():
  list_of_rules = list(actions.keys())
  words = ", ".join(list_of_rules)
  print("potential commands are: %s." % words)

if __name__ == '__main__':
  if len(sys.argv) < 2:
    display_overall_help()
  else:
    if sys.argv[1] in actions:
      actions[sys.argv[1]]()
    else:
      print("Sorry, that command couldn't be found.")
      display_overall_help()
