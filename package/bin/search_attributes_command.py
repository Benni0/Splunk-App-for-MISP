#!/usr/bin/env python

import import_declare_test

import sys
import os
import json

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))

from splunklib.searchcommands import \
    dispatch, GeneratingCommand, Configuration, Option, validators

import splunk_generic
from splunk_generic import get_bool_val
from misp_client import MISPHTTPClient
from datetime import datetime
import re
import math

@Configuration(distributed=False)
class SearchMISPAttributesCommand(GeneratingCommand):
    """ Search for MISP attributes on a MISP instance using the MISP API.

    ##Syntax
    -- code-block::
    | mispsearchattributes (misp_instance=<string>)? (limit=<int>)? (normalize_fields=(t|f))? (publish_date=<YYYY-MM-DD>)?
    | mispsearchattributes (published=(t|f))? (include_context=(t|f))? (value=<string>)?

    ##Description
    Queries a list of MISP attributes and provides filter and data normaization features.
    It is possible to filter tags, events, values, timestamps, to_ids etc. and to normalize the output using normalize_fields (enabled by default)
    """

    misp_instance = Option(
        doc='''
        **Syntax:** **misp_instance=InstanceName*
        **Description:** Name of the Instance
        default_instance is used if parameter is not provided
        ''',
        require=False,
        default=None
    )

    limit = Option(
        doc='''
        **Syntax:** **limit=<int>*
        **Description:** Minimal amount of attributes which should be fetched
        **Default:** 1000
        ''',
        require=False,
        default=1000,
        validate=validators.Integer()
    )

    start_date = Option(
        doc='''
        **Syntax:** **start_date=YYYY-MM-dd*
        **Description:** Date for Attribute filter in ISO 8601 (YYYY-MM-dd)
        **Default:** 2000-01-01
        ''',
        require=False,
        default="2000-01-01",
        validate=validators.Match("start_date", r"^([0-9]{4}-[0-1][0-9]-[0-3][0-9])|([0-9]+)$")
    )

    publish_date = Option(
        doc='''
        **Syntax:** **publish_date=YYYY-MM-dd*
        **Description:** Date for Attribute filter in ISO 8601 (YYYY-MM-dd)
        **Default:** 2000-01-01
        ''',
        require=False,
        default="2000-01-01",
        validate=validators.Match("publish_date", r"^([0-9]{4}-[0-1][0-9]-[0-3][0-9])|([0-9]+)$")
    )

    types = Option(
        doc='''
        **Syntax:** **types=<string>,<string>,...*
        **Description:** MISP type filter, e.g.: \"domain,domain|ip\"
        ''',
        require=False,
        validate=validators.Match("types", r"^[a-zA-Z0-9,|-]+$")
    )

    to_ids = Option(
        doc='''
        **Syntax:** **to_ids=<1|y|Y|t|true|True|0|n|N|f|false|False>*
        **Description:** If enabled, only attributes with to_ids=true are imported
        **Default:** False
        ''',
        require=False,
        default=False,
        validate=validators.Boolean()
    )

    published = Option(
        doc='''
        **Syntax:** **published=<1|y|Y|t|true|True|0|n|N|f|false|False>*
        **Description:** Only ingest attributes which are published.
        **Default:** True
        ''',
        require=False,
        default=True,
        validate=validators.Boolean()
    )

    include_tags = Option(
        doc='''
        **Syntax:** **include_tags=\"tlp:red,tlp:amber\"*
        **Description:** MISP tag include filter, e.g.: \"tlp:red,tlp:amber\"
        ''',
        require=False,
        validate=validators.Match("include_tags", r"^[a-zA-Z0-9,|:-]+$")
    )

    exclude_tags = Option(
        doc='''
        **Syntax:** **exclude_tags=\"tlp:red,tlp:amber\"*
        **Description:** MISP tag exclude filter, e.g.: \"tlp:red,tlp:amber\"
        ''',
        require=False,
        validate=validators.Match("exclude_tags", r"^[a-zA-Z0-9,|:-]+$")
    )

    warning_list = Option(
        doc='''
        **Syntax:** **warning_list=<1|y|Y|t|true|True|0|n|N|f|false|False>*
        **Description:** Prevents ingestion of Attributes which are in a warninglist.
        **Default:** True
        ''',
        require=False,
        default=True,
        validate=validators.Boolean()
    )
    
    include_context = Option(
        doc='''
        **Syntax:** *include_context=<1|y|Y|t|true|True|0|n|N|f|false|False>*
        **Description:** Includes Attribute Context (Event).
        **Default:** True
        ''',
        require=False,
        default=True,
        validate=validators.Boolean()
    )

    normalize_fields = Option(
        doc='''
        **Syntax:** *normalize_fields=<1|y|Y|t|true|True|0|n|N|f|false|False>*
        **Description:** Normalize attribute field names, each field name will begin with "misp_*" and the datastructure will be flatteneds.
        **Default:** True
        ''',
        require=False,
        default=True,
        validate=validators.Boolean()
    )

    normalize_fields_prefix = Option(
        doc='''
        **Syntax:** **normalize_fields_prefix=\"misp_\"*
        **Description:** Defines the prefix for normaized fields, which is "misp_" by default.
        ''',
        require=False,
        default="misp_",
        validate=validators.Match("normalize_fields_prefix", r"^[a-zA-Z0-9_]+$")
    )

    value = Option(
        doc='''value=<string>*
        **Description:** MISP search for specific attribute value"
        ''',
        require=False
    )

    event_id = Option(
        doc='''
        **Syntax:** **event_id=<int>*
        **Description:** Event ID to fetch attributes from
        ''',
        require=False,
        validate=validators.Match("event_id", r"^[a-zA-Z0-9\-]+$")
    )

    order = Option(
        doc='''order=<string>*
        **Description:** MISP search for specific attribute value"
        ''',
        require=False
    )

    def generate(self):
        session_key = self._metadata.searchinfo.session_key
        general_settings = splunk_generic.get_global_config(session_key)
        proxies = splunk_generic.get_proxy_config(session_key)
        log_level = splunk_generic.get_log_level(session_key, self.logger)
        self.logger.setLevel(log_level)

        if not self.misp_instance:
            self.misp_instance = general_settings.get('default_instance', None)

        if not self.misp_instance:
            raise Exception('Either parameter "misp_instance" or setting "default_instance" must be specified')

        account = splunk_generic.get_account(session_key, self.misp_instance)
        request_attribute_limit = int(account.get('request_attribute_limit', 1000))
        
        # MISP Client
        misp_client = MISPHTTPClient(
            account['misp_url'],
            account['auth_key'],
            get_bool_val(account['tls_verify']),
            proxies
        )

    	# convert start_date to timestamp
        if self.start_date:
            if isinstance(self.start_date, int):
                self.start_date = self.start_date
            elif re.match("^[0-9]+$", self.start_date):
                self.start_date = int(self.start_date)
            else:
                self.start_date = int(datetime.strptime(self.start_date, '%Y-%m-%d').timestamp())

        last=None
        if self.publish_date:
            if isinstance(self.publish_date, int):
                self.publish_date = self.start_date
            elif re.match("^[0-9]+$", self.publish_date):
                self.publish_date = int(self.publish_date)
            else:
                self.publish_date = int(datetime.strptime(self.publish_date, '%Y-%m-%d').timestamp())
            last = f'{math.ceil((datetime.now().timestamp() - int(self.publish_date)) / 86400)}d'



        page_count = 0
        attribute_count = 0
        while attribute_count < self.limit:
            page_count += 1
            try:
                result = misp_client.get_attributes(
                    request_attribute_limit,
                    page_count,                    
                    self.event_id,
                    self.published,
                    self.start_date,
                    self.to_ids,
                    self.warning_list,
                    self.include_context,
                    self.types,                  
                    self.include_tags,
                    self.exclude_tags,                    
                    value=self.value,
                    order=self.order,
                    last=last
                )
            except Exception as e:
                yield {'_raw': str(e)}
                return

            attributes = result['response'].get('Attribute', [])
            attribute_count += len(attributes)
            for attribute in attributes:
                splunk_ts = attribute['timestamp']
                if self.normalize_fields:
                    attribute = MISPHTTPClient.map_attribute(attribute, self.normalize_fields_prefix)

                yield splunk_generic.generate_record(
                    attribute,
                    splunk_ts,
                    self
                )
            if 'X-Result-Count' in result['headers']:
                x_result_count = int(result['headers']['X-Result-Count'])
            elif 'x-result-count' in result['headers']:
                x_result_count = int(result['headers']['x-result-count'])
            else:
                x_result_count = 0
            if (x_result_count-1)%self.limit == 0 and len(attributes) == 0:
                # hacky breakup condition might relay on a MISP bug
                break

        self.logger.debug(f"MISP fetched {attribute_count} attributes in {page_count} pages")


dispatch(SearchMISPAttributesCommand, sys.argv, sys.stdin, sys.stdout, __name__)