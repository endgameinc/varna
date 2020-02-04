## Varna

Varna is an AWS serverless cloud security tool that parses and alerts on CloudTrail logs using Event Query Language (EQL). Varna is deployed as a lambda function, for scanning and serving web requests, and a dynamodb table, for keeping track of seen alerts. Varna is cheap & efficient to run, costing less than 15 dollars a month with proper configuration and ingesting alerts as soon as CloudTrail stores them in S3.

You can find more information to install on how to install Varna in the [install.md](install.md).

All of the rules can be found in the `rules` folder and should be fairly understandable.

Features:

* Quick setup, takes less than 10 minutes to setup & deploy using Zappa.
* Easy to enable slack & email notifications.
* Rules are quick to write and easy to understand.
* Easy to enable user authentication.
* Simple code, readable by a single human in a couple of hours.
* Past search in the web console for finding additional context.

Varna is basically feature complete for our needs, the only outstanding work that might be done is incorporating SAML authentication or a method for bulk past search. If you have questions or would like to discuss a new feature, feel free to email me.

Some quick screenshots of the web interface:

![List Alarms](/screenshots/varna-dev-list-alarms-example.png)
![Past Search](/screenshots/varna-dev-search-query-example.png)
