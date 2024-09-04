import json
import logging

from solnlib import conf_manager, log
from splunklib import modularinput as smi

import re
import requests
import math
from datetime import datetime, timedelta

import splunk_generic
from splunk_generic import get_bool_val
from misp_client import MISPHTTPClient
from state_store import FileStateStore

from input_utils import SplunkEventIngestor

ADDON_NAME = "TA_misp"

def logger_for_input(input_name: str) -> logging.Logger:
    return log.Logs().get_logger(f"{ADDON_NAME.lower()}_{input_name}")

def validate_input(definition: smi.ValidationDefinition):
    session_key = definition.__dict__.get('metadata').get('session_key')
    proxies = splunk_generic.get_proxy_config(session_key)
    misp_instance = definition.parameters.get('misp_instance')
    account = splunk_generic.get_account(session_key, misp_instance)
    misp_url = account.get('misp_url', None)
    if not misp_url:
        raise Exception(f"MISP Url for account {misp_instance} not found")

    misp_client = MISPHTTPClient(
        misp_url,
        account['auth_key'],
        False,
        proxies
    )
    result = misp_client.get_events(
            limit=1,
            page=0
        )
    if not result:
        raise Exception(f"MISP Url returned {json.dumps(result)}")
    return


def stream_events(inputs: smi.InputDefinition, event_writer: smi.EventWriter):
    # inputs.inputs is a Python dictionary object like:
    # {
    #   "misp_indicator_input://<input_name>": {
    #     "account": "<account_name>",
    #     "disabled": "0",
    #     "host": "$decideOnStartup",
    #     "index": "<index_name>",
    #     "interval": "<interval_value>",
    #     "python.version": "python3",
    #   },
    # }
    session_key = inputs.metadata["session_key"]
    proxies = splunk_generic.get_proxy_config(session_key)

    for input_name, input_item in inputs.inputs.items():
        normalized_input_name = input_name.split("/")[-1]

        state_store = FileStateStore(
            ADDON_NAME,
            inputs.metadata.get("checkpoint_dir"),
            normalized_input_name
        )

        logger = logger_for_input(normalized_input_name)
        splunk_generic.set_log_level(session_key, logger)            
        log.modular_input_start(logger, normalized_input_name)

        try:
            account = splunk_generic.get_account(session_key, input_item['misp_instance'])
            misp_url = account.get('misp_url', None)
            if not misp_url:
                raise Exception(f"MISP Url for account {input_item['misp_instance']} not found")
            
            request_event_limit = int(account.get('request_event_limit', 1000))
            ignore_proxy = get_bool_val(account.get('ignore_proxy', "0"))
            max_requests = int(input_item.get('max_requests', 1000))
            continuous_importing = get_bool_val(input_item.get('continuous_importing', True))
            override_timestamps = get_bool_val(input_item.get('override_timestamps', False))
            normalize_field_names = get_bool_val(input_item.get('normalize_field_names', True))
            normalized_field_prefix = input_item.get('normalized_field_prefix', "misp_")
            expand_tags = get_bool_val(input_item.get('expand_tags', False))

            if ignore_proxy:
                proxies = None

            # time conversation
            input_duration = input_item.get('import_period', '180d')
            if input_duration == 'all':
                earliest_timestamp = 0
            else:
                input_duration = re.search('^([0-9]+)(d|m|y)$', input_duration)
                input_duration_days = int(input_duration.group(1))
                if input_duration.group(2) == 'm':
                    input_duration_days *= 30
                if input_duration.group(2) == 'y':
                    input_duration_days *= 365
            
                earliest_timestamp = datetime.now() - timedelta(days=input_duration_days)
                earliest_timestamp = int(earliest_timestamp.timestamp())

            # initialize MISP CLient
            misp_client = MISPHTTPClient(
                misp_url,
                account['auth_key'],
                get_bool_val(account['tls_verify']),
                proxies
            )

            log.log_event(logger, {'Action': 'override', 'override_timestamps': override_timestamps, 'input_item': input_item, 'account': account}, logging.DEBUG)

            event_ingestor = SplunkEventIngestor(
                event_writer,
                input_item.get('index'),
                misp_url.split('/')[-1],
                input_item.get('sourcetype'),
                override_timestamps            
            )

            # continuous importing
            if continuous_importing:
                # initialize state
                state = state_store.get_state()
            if not state:
                state = {
                    'publish_timestamp': earliest_timestamp,
                    'ts_imported_events': []
                }
                if continuous_importing: state_store.update_state(state)
            log.log_event(logger, state, logging.INFO)

            # pull events in 1000 event batches
            for i in range(0, max_requests):
                page = i+1
                events = misp_client.get_events(
                    limit=request_event_limit,
                    page=page,
                    publish_timestamp=state['publish_timestamp'],
                    #include_context=include_context,
                    #published=get_bool_val(input_item.get('published', True))
                )['response']

                if normalize_field_names:
                    mapping_function=lambda x:MISPHTTPClient.map_event(x, normalized_field_prefix)
                else:
                    mapping_function=lambda x:x

                if expand_tags:
                    expanded_events = []
                    for event in events:
                        event = event['Event']
                        if 'Tag' not in event:
                            event['Tag'] = []

                        if len(event['Tag']) >= 1:
                            for tag in event['Tag']:
                                expanded_event = event.copy()
                                expanded_event['Tag'] = tag
                                expanded_events.append({'Event': expanded_event})
                        else:
                            expanded_event = event.copy()
                            expanded_event['Tag'] = None
                            expanded_events.append({'Event': expanded_event})
                    events = expanded_events

                event_ingestor.ingest_items(
                    events,
                    extract_function=lambda x:x['Event'],
                    mapping_function=mapping_function,
                    skip_check=lambda x:x['id'] in state['ts_imported_events'] and int(x['publish_timestamp']) == state['publish_timestamp']
                )

                # Update state
                if continuous_importing and len(events) > 0:
                    state['publish_timestamp'] = min(events, key=lambda x:int(x['Event']['publish_timestamp']))['Event']['publish_timestamp']
                    state['ts_imported_events'] = [event['Event']['id'] for event in events if int(event['Event']['publish_timestamp']) == state['publish_timestamp']]
                    log.log_event(logger, state, logging.INFO)
                
            log.log_event(logger, event_ingestor.get_stats(), logging.INFO)

            log.events_ingested(
                logger,
                input_name,
                input_item.get('sourcetype'),
                event_ingestor.get_stats()['event_count'],
                input_item.get('index'),
                account=input_item.get("account"),
            )
            log.modular_input_end(logger, normalized_input_name)

        except Exception as e:
            log.log_exception(logger, e, "TA_MISP_event_input", msg_before="Exception raised while ingesting data for misp_event_input: ")