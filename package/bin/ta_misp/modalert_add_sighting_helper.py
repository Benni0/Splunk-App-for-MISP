# encoding = utf-8

import import_declare_test

import splunk_generic
from splunk_generic import get_bool_val
from misp_client import MISPHTTPClient

def process_event(helper, *args, **kwargs):

    helper.log_info("Alert action add_sighting started.")
    
    session_key = helper.session_key
    general_settings = splunk_generic.get_global_config(session_key)
    proxies = splunk_generic.get_proxy_config(session_key)

    misp_instance = helper.get_param('misp_instance')
    ioc = helper.get_param('ioc')
    sighting_type = helper.get_param('sighting_type')

    if not misp_instance:
            misp_instance = general_settings.get('default_instance', None)

    if not misp_instance:
        raise Exception('Either parameter "misp_instance" or setting "default_instance" must be specified')
    
    account = splunk_generic.get_account(session_key, misp_instance)
    # MISP Client
    misp_client = MISPHTTPClient(
        account.get('misp_url', None),
        account.get('auth_key'),
        get_bool_val(account.get('tls_verify')),
        proxies
    )

    misp_client.add_sighting(ioc, int(sighting_type))

    return 0
