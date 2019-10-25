`minutes_back` is how long back you want the search to go, it is mostly important because it determines the max lenght of sequences or joins that you can detect.

`slack_url` is the webhook that you would like to fire slack alerts at. You need either this or email for varna to work.

`age_off` is the number of days before alerts get deleted.

`base_url` where the application is hosted, used for links in notifications.

`logs_bucket` is the bucket where the cloudtrail logs are stored.

`accounts` a list of accounts that are associated with a list of regions that you would like to scan in them, check the sample settings.toml for exact formatting.

`email` Only SSL on port 465, you need a sender, receivers (list of emails), a smtp_server and a password. Check the sample settings.toml for exact formatting.
