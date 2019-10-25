So Varna is pretty simple to install, it requires a couple different lambdas, a dynamodb table and some access.

First let's start with the dynamodb table, make one called `varna_sent_events_v3` that is keyed off of `event_id` with no sort key. I leave this at the default settings of 5 read and 5 write. You will also need to make a GSI for this table, if your in the web console, it's in the index tab. Make a secondary index that is named `account_id-event_time-index` and is keyed off of `account_id` and `event_time`. I also leave this one at default settings regarding size.

You will need to make the bundle for deploying Varna right now. With all the rules in place and the settings file modified, you will need to modify `zappa_settings.json` if needed and then run `zappa package` in your python environment. This will produce a zipfile. Upload this zip file and make 4 lambdas with it, `varna-web`, `varna-s3`, `varna-unack`, and `varna-delete`. For all of these, you will need to increase the timeout. 2 minutes seems to be about right. The entry points are as follows

`varna-web` -> `handler.lambda_handler`
`varna-s3` -> `varna.handle_s3`
`varna-unack` -> `varna.send_slack_unacked_alerts`
`varna-delete` -> `varna.delete_old`

Now it's just a matter of wiring it up, for the web lambda, alb is probably the best choice. Set the s3 lambda to run on new files being created in the s3 folder. Next up is setting the unack and delete to run as often as you want, recommended is once a day for both.

There you go, if you visit the website you setup, you should now see a working installation of Varna. Feel free to do some activity that should alert and confirm that it alerts.
