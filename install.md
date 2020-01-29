So Varna is pretty simple to install, it requires a couple different lambdas, a dynamodb table and some access.

# Getting Started

## Prerequisites

1. AWS Account
2. CloudTrail

## AWS Configuration

1. Create a new DynamoDB table called `varna_sent_events_v3` with the partition key named `event_id` and no sort key. Leave the default settings of 5 read and 5 write.
2. Create a new Global Secondary Indexes (GSI) for this table. Navigate to Indexes tab after creating the DynamoDB table. Click create new index with the index name being `account_id-event_time-index` and the partition key as `account_id` and the sort key as `event_time`. Leave the default settings of 5 read and 5 write.
3. Create a Cloudtrail trail, or use an existing one. See the below screenshots for our settings of the new trail. In addition, make a note of the bucket name.

## Application Setup

1. Copy `example_settings.toml` to `settings.toml` and configure to your environment.
2. Copy `zappa_settings.json.template` to `zappa_settings.json` and configure to your environment.

## Slack Setup

1. Create an incoming webhook to use for Slack channel notification. Use the webhook url in the `settings.toml` file for `slack_url`.


## Zappa Setup

1. You will need to modify the zappa_settings.json file to include settings for an ssl certificate, details on this can be found in the Zappa documentation.
2. Run `zappa deploy`
3. Run `zappa certify`
4. You should now be able to access Varna and be receiving alerts.

There you go, if you visit the website you setup, you should now see a working installation of Varna. Feel free to do some activity that should alert and confirm that it alerts.
