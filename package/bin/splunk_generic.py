from solnlib import conf_manager, log
import time
import json

from collections import OrderedDict
from itertools import chain

ADDON_NAME = "TA_misp"

def get_bool_val(value):
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return bool(value)
    if isinstance(value, str):
        return value != "0" and value != "false"

def get_account(session_key: str, account_name: str):
    cfm = conf_manager.ConfManager(
        session_key,
        ADDON_NAME,
        realm=f"__REST_CREDENTIAL__#{ADDON_NAME}#configs/conf-{ADDON_NAME.lower()}_account",
    )
    account_conf_file = cfm.get_conf(f"{ADDON_NAME.lower()}_account")
    return account_conf_file.get(account_name)


def get_log_level(session_key: str, logger):
    return conf_manager.get_log_level(
        logger=logger,
        session_key=session_key,
        app_name=ADDON_NAME,
        conf_name=f'{ADDON_NAME.lower()}_settings'
    )

def set_log_level(session_key: str, logger):
    log_level = get_log_level(session_key, logger)
    logger.setLevel(log_level)

def get_global_config(session_key):
    cfm = conf_manager.ConfManager(
        session_key,
        ADDON_NAME,
        realm=f"__REST_CREDENTIAL__#{ADDON_NAME}#configs/conf-local/{ADDON_NAME.lower()}_settings"    
    )
    settings_conf_file = cfm.get_conf(f"{ADDON_NAME.lower()}_settings")
    return settings_conf_file.get('global_settings')

def get_proxy_config(session_key):
    cfm = conf_manager.ConfManager(
        session_key,
        ADDON_NAME,
        realm=f"__REST_CREDENTIAL__#{ADDON_NAME}#configs/conf-local/{ADDON_NAME.lower()}_settings"        
    )
    settings_conf_file = cfm.get_conf(f"{ADDON_NAME.lower()}_settings")
    proxy_settings = settings_conf_file.get('proxy')

    if get_bool_val(proxy_settings.get('proxy_enabled', False)):
        
        proxy_credentials = ""
        if proxy_settings.get('proxy_username', False) and proxy_settings.get('proxy_password', False):
            proxy_credentials = "{}:{}@".format(
                proxy_settings['proxy_username'],
                proxy_settings['proxy_password']
                )
        proxy_port = ""
        if proxy_settings.get('proxy_port', False):
            proxy_port = ":{}".format(proxy_settings['proxy_port'])


        proxy_uri = "{}://{}{}{}".format(
            proxy_settings.get('proxy_type', 'http'),
            proxy_credentials,
            proxy_settings.get('proxy_url'),
            proxy_port
            )
        return {
            "http": proxy_uri,
            "https": proxy_uri
        }
    
    return None



def normalize_data(key, value):
    normalized_data = list()
    if isinstance(value, str) or isinstance(value, int) or isinstance(value, float):
        normalized_data.append((key, value))
    if isinstance(value, list):
        for item in value:
            normalized_data.extend(normalize_data(key, item))
    if isinstance(value, dict):
        for k,v in value.items():
            normalized_data.extend(normalize_data(k,v))
    return normalized_data    

def generate_record(data, time=time.time(), generator=None):
    encoder = json.JSONEncoder(ensure_ascii=False, separators=(',', ':'))

    data_dict = dict()
    data_dict['_time'] = time
    data_dict['_raw'] = encoder.encode(data)
    record = normalize_data('none', data)
    for key,val in record:
        val = str(val)
        key = str(key)
        if key in data_dict:
            if isinstance(data_dict[key], list):
                data_dict[key].append(val)
            else:
                data_dict[key] = [data_dict[key], val]
        else:
            data_dict[key] = val

    if generator:
        return generator.gen_record(**data_dict)
    return data_dict

