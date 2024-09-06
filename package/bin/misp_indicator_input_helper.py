import json
import logging

from solnlib import conf_manager, log
from splunklib import modularinput as smi

import re
import requests
import math
from datetime import datetime, timedelta

from splunk_generic import get_bool_val
import splunk_generic
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
    ignore_proxy = get_bool_val(account.get('ignore_proxy', "0"))

    if not misp_url:
        raise Exception(f"MISP Url for account {misp_instance} not found")

    if ignore_proxy:
        proxies = None

    misp_client = MISPHTTPClient(
        misp_url,
        account['auth_key'],
        get_bool_val(account['tls_verify']),
        proxies
    )
    result = misp_client.get_attributes(
            limit=1,
            page=0
        )
    if not result:
        raise Exception(f"MISP Url returned {json.dumps(result)}")
    return


def ingest_attributes(
        event_ingestor: SplunkEventIngestor, misp_client, logger, request_limit, page_limit, event_id, types, to_ids, published, 
        include_tags, exclude_tags, enforce_warninglist, timestamp, normalize_field_names, normalized_field_prefix, expand_tags):
    page = 0
    empty_page_count = 0
    attribute_count = 0
    while page_limit == None or page < page_limit:
        page += 1
        result = misp_client.get_attributes(
            limit=request_limit,
            page=page,
            event_id=event_id,
            types=types,
            to_ids=to_ids,
            published=published,                    
            include_tags=include_tags,
            exclude_tags=exclude_tags,
            enforce_warninglist=enforce_warninglist,
            include_context=False,
            timestamp=timestamp
        )
        attributes = result['response'].get('Attribute', [])      
        attribute_count +=  len(attributes) 
        log.log_event(logger, {'Action': 'attributes fetched', 'event_id': event_id, 'count': len(attributes), 'request_body': result.get('request_body')}, logging.DEBUG)

        if normalize_field_names:
             mapping_function=lambda x:MISPHTTPClient.map_attribute(x, normalized_field_prefix)
        else:
            mapping_function=lambda x:x

        if expand_tags:
            expanded_attributes = []
            for attribute in attributes:
                if 'Tag' not in attribute:
                    attribute['Tag'] = []                    

                if len(attribute['Tag']) >= 1:
                    for tag in attribute['Tag']:
                        expanded_attribute = attribute.copy()
                        expanded_attribute['Tag'] = tag
                        expanded_attributes.append(expanded_attribute)
                else:
                    expanded_attribute = attribute.copy()
                    expanded_attribute['Tag'] = None
                    expanded_attributes.append(expanded_attribute)
            attributes = expanded_attributes

        event_ingestor.ingest_items(
            attributes,
            mapping_function=mapping_function,
            skip_check=lambda x:int(x['timestamp']) < timestamp
        )

        # Abort
        if len(attributes) == 0:
            empty_page_count += 1
        if empty_page_count > 4: # safeguard when bug fixed
            break

        if 'X-Skipped-Elements-Count' in result['headers']:
            # if MISP support X-Skipped-Elements-Count this is the exact abort condition
            if len(attributes) + int(result['headers']['X-Skipped-Elements-Count']) < request_limit:
                break
            x_result_count = 0
        elif 'X-Result-Count' in result['headers']:
            x_result_count = int(result['headers']['X-Result-Count'])
        elif 'x-result-count' in result['headers']:
            x_result_count = int(result['headers']['x-result-count'])
        else:
            x_result_count = 0
        if (x_result_count-1)%request_limit == 0 and len(attributes) == 0:
        # hacky breakup condition might relay on a MISP bug
        # see https://github.com/MISP/MISP/issues/9175
            break
    log.log_event(logger, {'Action': 'attributes fetched', 'event_id': event_id, 'count': attribute_count, 'pages': page, 'empty_pages': empty_page_count}, logging.INFO)



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
            
            request_attribute_limit = int(account.get('request_attribute_limit', 1000))
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

            # initialize MISP Client
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
                "{}_{}".format(input_name, misp_url.split('/')[-1]),
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
                events = []
                for i in range(0, math.ceil(max_requests/request_event_limit)):
                    page = i+1
                    event_batch = misp_client.get_events(
                        limit=request_event_limit,
                        page=page,
                        publish_timestamp=state['publish_timestamp']
                    )
                    events.extend(event_batch['response'])
                    if len(event_batch) < request_event_limit:
                        break

                for event in events:
                    event = event['Event']
                    if event['id'] in state['ts_imported_events'] and int(event['publish_timestamp']) == state['publish_timestamp']:
                        # ignore already imported events when timestamp has not changed
                        log_event = {
                            'info': "Event already imported",
                            'event_id': event['id'],
                            'publish_timestamp': event['publish_timestamp']
                        }
                        log.log_event(logger, log_event, logging.INFO)
                        continue

                    log.log_event(logger, {'Action': 'fetch attributes started', 'event_id': event['id'], 'publish_timestamp': event['publish_timestamp']}, logging.DEBUG)

                    ingest_attributes(
                        event_ingestor,
                        misp_client,
                        logger,
                        request_attribute_limit,
                        None, # Page Limit - m,ust ingest all pages here
                        event['id'],
                        input_item.get('types', None),
                        get_bool_val(input_item.get('to_ids', True)),
                        get_bool_val(input_item.get('published', True)),                    
                        input_item.get('include_tags', None),
                        input_item.get('exclude_tags', None),
                        get_bool_val(input_item.get('warning_list', True)),
                        earliest_timestamp,
                        normalize_field_names,
                        normalized_field_prefix,
                        expand_tags
                    )

                    # Update state
                    event_publish_timestamp = int(event['publish_timestamp'])
                    if state['publish_timestamp'] > event_publish_timestamp:
                        log_event = {
                            'info': "Older Event detected",
                            'event_id': event['id'],
                        }
                        log.log_event(logger, log_event, logging.ERROR)

                    if state['publish_timestamp'] < event_publish_timestamp:
                        state['publish_timestamp'] = event_publish_timestamp
                        state['ts_imported_events'] = [event['id']]
                    else:
                        # Store ingested events with this timestamp to avoid double ingesting
                        state['ts_imported_events'].append(event['id'])                
                    state_store.update_state(state)
                    log.log_event(logger, state, logging.INFO)

            else:
                ingest_attributes(
                        event_ingestor,
                        misp_client,
                        logger,
                        request_attribute_limit,
                        request_event_limit,
                        None, # EventID
                        input_item.get('types', None),
                        input_item.get('to_ids', True),
                        input_item.get('published', True),                    
                        input_item.get('include_tags', None),
                        input_item.get('exclude_tags', None),
                        input_item.get('warning_list', True),
                        earliest_timestamp,
                        normalize_field_names,
                        normalized_field_prefix,
                        expand_tags
                    )
                
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
            log.log_exception(logger, e, "TA_MISP_indicator_input", msg_before="Exception raised while ingesting data for misp_indicator_input: ")