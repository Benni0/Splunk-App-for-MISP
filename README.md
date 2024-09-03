# TA_misp
The main purpose of this Splunk App is the import of attributes/IOCs from MISP into a Splunk index.
In order to use these IOCs for detection either as lookup or in Splunk Enterprise Security, the App provides some reports to generate IOC lookup-tables.
These lookup-tables are compatible with the Threat Intelligence Framework of Splunk Enterprise Security.

## Configuration

Before the App can be used, the MISP instance must be configured. The configuration can be found under **App Settings -> Configuration**.

### Accounts

At least one instance must be configured.

| Parameter                      | Description                                                  |
| ------------------------------ | ------------------------------------------------------------ |
| Instance Name                  | A unique name for the account.                               |
| MISP Url                       | Url of the MISP instance                                     |
| Auth Key                       | MISP Authentication Key                                      |
| TLS Verify                     | Verify if TLS certificate is valid.                          |
| Ignore Proxy                   | Ignore Proxy settings for this instance.                     |
| Limit (Events per Request)     | Events are queried page by page. Limit of Events which should be fetched per request (default: 1k, max: 1M). |
| Limit (Attributes per Request) | Attributes are queried page by page. Limit of Attributes which should be fetched per request (default: 1k, max: 1M) |

In **App Settings -> MISP App Settings** a default instance can be set (maybe a browser refresh is necessary if the instance is recently configured). This instance is used per default for all custom commands and for the alert action if no instance is specified.

## Importing IOCs into Splunk
The App provides two modular inputs for importing MISP attributes/IOCs an MISP events.
Both inputs are supporting pulling the MISP data by batches, which should avoid HTTP request limits or memory limits.
Additional these inputs uses checkpoints, so the import process starts where the last execution has stopped.
To restart the input from the beginning, you have to manually clean the checkpoint using `splunk clean inputdata <input_name>` as documented here: (Set-up-checkpointing)[https://dev.splunk.com/enterprise/docs/developapps/manageknowledge/custominputs/modinputsscript/#Set-up-checkpointing].
The inputs can be configured in the App UI under **App Settings -> Inputs**.

### MISP Event Input
The MISP Event Input imports MISP event data. The Events are imported regarding their publish timestamp, so it may be not possible to import unpublished events.

| Parameter                           | Description                                                  |
| ----------------------------------- | ------------------------------------------------------------ |
| MISP Instance                       | Select one of the configured MISP instances. (Instance Name) |
| Name                                | Name of the input (is used as name for the checkpoint)       |
| Index                               | Index in which the events should be ingested                 |
| Sourcetype                          | Sourcetype which the events should have                      |
| Interval                            | Import interval in seconds, all events which are published since the last execution will be imported. Limits may apply. |
| Max Requests (Events per execution) | Must be a multiple of the depending request limit. Max amount of Events  from which events should be imported each import execution (max is 100k) |
| Import Period                       | Period over which events should be imported. If older events (event timestamp not publish timestamp) are published in MISP, these events will be ignored. |
| Published                           | Import only events which are currently published.            |
| Continuous Importing                | Continuous Importing is the default mode, import continues from last  imported event import timestamp, so only new or modified events are  imported. Disabling continuous importing would result in importing all  events during each execution which makes only sense if the amount of  events is lower than the limits. Max Events is used as maximum amount of requests in this case. |
| Override Timestamps                 | Force to use ingest time instead of event timestamp.         |
| Normalize Field Names               | Normalize event field names, each field name will begin with "misp_*" and the datastructure will be flatteneds. |
| Prefix for normalized fields        | Defines the prefix for normaized fields, which is "misp_" by default. |
| Expand Tags                         | Expand each misp event tag to a single event to avoid mvexpand. |



### MISP Indicator Input

The MISP Indicator Input imports MISP indicators. The Indicators are imported regarding their events publish timestamp, so it may be not possible to import indicators from unpublished events.

| Attribute                           | Description                                                  |
| ----------------------------------- | ------------------------------------------------------------ |
| MISP Instance                       | Select one of the configured MISP instances.                 |
| Name                                | Name of the input (is used as name for the checkpoint)       |
| Index                               | Index in which the attributes should be ingested             |
| Sourcetype                          | Sourcetype which the attributes should have                  |
| Interval                            | Import interval in seconds, all events which are published since the last execution will be imported. Limits may apply. |
| Max Requests (Events per execution) | Must be a multiple of the depending request limit. Max amount of Events  from which Attributes should be imported each import execution (max is  100k) |
| Import Period                       | Import period over which indicators should be imported in day(s), month(s) or year(s) (`<int>`d\|h\|m). If older events (event timestamp not publish timestamp) are published in MISP, these events will be ignored. |
| Types                               | MISP type filter, e.g.: "domain,domain", only Indicators which match one of these types. |
| To IDS                              | If enabled, only attributes with to_ids=true are imported.   |
| Published                           | Only ingest attributes which are published.                  |
| Include Tags                        | MISP tag include filter, e.g.: "tlp:red,tlp:amber"           |
| Exclude Tags                        | MISP tag include filter, e.g.: "tlp:white,tlp:amber"         |
| Enforce Warninglists                | Prevents ingestion of Attributes which are in a warninglist. |
| Continuous Importing                | Continuous Importing is the default mode, import continues from last  imported event import timestamp, so only attributes from new or modified events are imported. Disabling continuous importing would result in  importing all attributes during each execution which makes only sense if the amount of attributes is lower than the limits. Max Events is used  as maximum amount of requests in this case. |
| Override Timestamps                 | Force to use ingest time instead of attribute timestamp.     |
| Normalize Field Names               | Normalize attribute field names, each field name will begin with "misp_*" and the data structure will be flattened. |
| Prefix for normalized fields        | Defines the prefix for normalized fields, which is "misp_" by default. |

> [!NOTE]
>
> Before indicators are ingested, the events  are queried by publish timestamp and for each events all attributes are pulled (filters may apply). If one Event, from which the attributes are already ingested, is published another time, all attributes will also be ingested another time, regardless of their attribute timestamps.



## Setup Examples

To have an up to date IOC list, it is possible to setup the indicator input using a small import interval, like 5 minutes (300 seconds). Then schedule the provided reports also by frequent schedule, maybe 10 minutes. This will keep your IOC lookup-tables up 2 date.

By default the provided reports use a linear decaying score starting by 100 and decaying over 180 days (100 for hashes). This calculation can be modified direct in the report or also in the misp_decaying_scores.csv lookup-table for specific tags or organisations. It is also possible to set a static value. Due to this implementation the weight is calculated each time when the report is scheduled. IOCs where the score is zero or lower, are ignored.

### False Positives and Critical IOCs

It is possible to handle false positives by tagging them in MISP and set the weight for this tag to zero using misp_decaying_scores.csv lookup-table. In this case it is important, that these Attributes stay in Splunk continuously, which also may apply for critical IOCs. This can be achieved by adding another indicator input, which filters the tags for false positives and critical iocs. The input should be scheduled once a day, **shouldn't** use continuous importing and **should** override the attribute timestamps. With this configuration these indicators are ingested each days with the actual timestamp and are active as long the tag exists.

## Commands

### Search Attributes

Search for MISP attributes on a MISP instance using the MISP API. 

Queries a list of MISP attributes and provides filter and data normaization features. It is possible to filter tags, events, values, timestamps, to_ids etc. and to normalize the output using normalize_fields (enabled by default).

#### Syntax

```spl
| mispsearchattributes (misp_instance=<string>)? (limit=<int>)? (normalize_fields=(t|f))? (publish_date=<YYYY-MM-DD>)?
| mispsearchattributes (published=(t|f))? (include_context=(t|f))? (value=<string>)?
```

### Search Events

Search for MISP events on a MISP instance using the MISP API.

Searches for all MISP events which include the given ioc value. 
You may specify the misp instance with "misp_instance" parameter, otherwise the configured default_instance is used.

#### Syntax

```spl
| mispsearchevents (misp_instance=<str>)? (ioc=<str>)?
```



## Alerts

### Add Sighting

Adds a sighting to MISP Attribute by its value

## Thanks to CIRCL

Many thanks to CIRCL for maintaining MISP, providing it for free, merge most of my pull requests and for the permission to use their logo for this app. 
