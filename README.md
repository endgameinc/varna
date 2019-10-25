## Varna

Varna: Custom, robust AWS monitoring for cents a day using EQL

Varna is a lambda based tool for monitoring Amazon Web Services (AWS) CloudTrail using Event Query Language (EQL) costing less than 50 cents a day to run. It supports fully customizable rules that get evaluated within seconds of a new log file being deposited. In addition, Varna supports EQL search over historical logs that were already archived in an AWS account. Upon finding an event to alert upon, it uses one or multiple alert methods to notify a security team of suspicion action. Varna supports 1-click acknowledgment as well to reduce alert fatigue for benign actions. Varna includes a web interface for configuration of rules and review of alerts.

EQL provides some amazing benefits in being the query language of choice for Varna. EQL allows both joins and sequences over a series of log events, this allows writing rules that may require multiple events to fire or a specific chain of events. In addition, EQL is easy to learn and robust enough to handle complex queries. AWS accounts are becoming increasingly important in most organizations security model but sadly remain one of the least focused on from a security perspective. Risks include developers leaking credentials via code commits, 3rd party software exposing account credentials, or permission misconfiguration. Varna helps avoid this by alerting security teams quickly to suspicious behavior and increasing visibility into AWS accounts.

Varna also comes bundled with a set of prewritten EQL rules designed to alert on suspicion behavior present in an AWS account.
