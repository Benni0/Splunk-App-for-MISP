import json
import requests
import re
from datetime import datetime
from functools import reduce

class MISPHTTPClient:
    def __init__(self, misp_url, auth_key, verify_ssl, proxies) -> None:
        self.misp_url = misp_url
        self.auth_key = auth_key
        self.verify_ssl = verify_ssl
        self.proxies = proxies

    def _perform_request(self, method, endpoint, **kwargs):
        headers = {
            'Authorization': self.auth_key,
            'Accept': 'application/json'
        }

        if method == 'post':
            headers['Content-Type'] = 'application/json'

        if not endpoint.startswith('/'):
            endpoint = f"/{endpoint}"
        url = self.misp_url + '/' + endpoint

        request_function = getattr(requests, method)
        try:
            response = request_function(
                url,
                headers=headers,
                verify=self.verify_ssl,
                proxies = self.proxies,
                **kwargs
            )
        except Exception as e:
            raise e
        
        if response.status_code > 299:
            raise Exception(f"HTTP Status: {response.status_code}, Content: {response.text}, Data: {json.dumps(kwargs.get('data', ''))}")
        data = response.json()
        data['headers'] = dict(response.headers)
        return data
    

    def check_connectivity(self):
        self._perform_request(
            method='get',
            endpoint='/servers/getPyMISPVersion.json'
        )

    def get_events(self, limit, page, published=True, metadata=True, order="publish_timestamp", timestamp=None, publish_timestamp=None, include_context=False, event_id=None, value=None):
        request_body = {
            "page": page,
            "limit": limit,
            "published": published,
            "metadata": metadata,
            "order": order,
            "timestamp": timestamp,
            "publish_timestamp": publish_timestamp,
            "includeContext": include_context,
            "eventid": event_id,
            "value": value
        }

        result = self._perform_request(
            method='post',
            endpoint='/events/restSearch',
            data=json.dumps(request_body)
        )

        if 'response' in result:
            return result
        else:
            raise Exception(result)


    def get_attributes(
            self, 
            limit, 
            page, 
            event_id=None, 
            published=True, 
            timestamp=None, 
            to_ids=True, 
            enforce_warninglist=True, 
            include_context=False, 
            types=None,
            include_tags="",
            exclude_tags="",
            value=None,
            order=None,
            last=None
            ):
        request_body = {
            'page': page,
            'limit': limit,
            'eventid': event_id,
            'published': published,
            'timestamp': timestamp,
            'to_ids': to_ids,
            'enforceWarninglist': enforce_warninglist,
            'includeContext': include_context,
            'returnFormat': 'json',
            'value': value,
            'order': order,
            'includeEventTags': True,
            'includeEventUuid': True,
            'last': last
        }
        if types:
            request_body['type'] = {'OR': types.split(',')}

        if include_tags or exclude_tags:
            request_body['tags'] = {}
            if include_tags:
                request_body['tags']['OR'] = include_tags.split(',')
            if exclude_tags:
                request_body['tags']['NOT'] = exclude_tags.split(',')

        result = self._perform_request(
            method='post',
            endpoint='/attributes/restSearch',
            data=json.dumps(request_body)
        )

        if 'response' in result:
            result['request_body'] = request_body
            return result
        else:
            raise Exception(result)

        
    def search_attributes(
            self, 
            limit, 
            page,             
            types, 
            to_ids, 
            published, 
            include_tags, 
            exclude_tags, 
            enforce_warninglist,
            start_date=None,
            publish_timestamp=None, 
            value=None,
            include_context=False, 
            order="timestamp ASC",
            logger=None
        ):
        request_body = {
            'page': page,
            'limit': limit,
            'includeEventTags': True,
            'includeEventUuid': True,
            'to_ids': to_ids,
            'published': published,
            'returnFormat': 'json',
            'order': order,
            'enforceWarninglist': enforce_warninglist,
            'includeContext': include_context,
        }

        if value:
            request_body['value'] = value

        if start_date:
            if isinstance(start_date, int):
                request_body['attribute_timestamp'] = start_date
            elif re.match("^[0-9]+$", start_date):
                request_body['attribute_timestamp'] = int(start_date)
            else:
                request_body['attribute_timestamp'] = datetime.strptime(start_date, '%Y-%m-%d').timestamp()

        if publish_timestamp:
            if isinstance(publish_timestamp, int):
                request_body['publish_timestamp'] = publish_timestamp
            elif re.match("^[0-9]+$", publish_timestamp):
                request_body['publish_timestamp'] = int(publish_timestamp)
            else:
                request_body['publish_timestamp'] = datetime.strptime(publish_timestamp, '%Y-%m-%d').timestamp()

        if types:
            request_body['type'] = {'OR': types.split(',')}

        if include_tags or exclude_tags:
            request_body['tags'] = {}
            if include_tags:
                request_body['tags']['OR'] = include_tags.spit(',')
            if exclude_tags:
                request_body['tags']['NOT'] = exclude_tags.spit(',')

        result = self._perform_request(
            method='post',
            endpoint='/attributes/restSearch',
            data=json.dumps(request_body)
        )

        if 'response' in result:
            return result
        else:
            raise Exception(result)


    @staticmethod
    def map_attribute(attribute_dict, prefix="misp_"):
        mapping = {
            'category': 'category',
            'comment': 'comment',
            'distribution': 'attribute_distribution',
            'event_id': 'event_id',
            'event_uuid': 'event_uuid',
            'id': 'attribute_id',
            'object_id': 'object_id',
            'object_relation': 'object_relation',
            'sharing_group_id': 'sharing_group_id',
            'timestamp': 'timestamp',
            'to_ids': 'to_ids',
            'type': 'type',
            'value': 'value',
            'Event.distribution': 'event_distribution',
            'Event.id': 'event_id',
            'Event.info': 'event_info',
            'Event.org_id': 'org_id',
            'Event.orgc_id': 'orgc_id',
            'Event.uuid': 'event_uuid',
            'deleted': 'deleted',
            'first_seen': 'first_seen',
            'Event.Orgc.name': 'event_orgc_name',
            'Event.Orgc.uuid': 'event_orgc_uuid',
            'Event.analysis': 'event_analysis',
            'Event.date': 'event_date',
            'Event.timestamp': 'event_timestamp',
            'Event.publish_timestamp': 'event_publish_timestamp',
            'Event.published': 'event_published',
            'Event.threat_level_id': 'event_threat_level'
        }

        attribute = dict()
        for key, value in mapping.items():
            try:
                attribute[f'{prefix}{value}'] = reduce(lambda acc,i: acc[i], key.split('.'), attribute_dict)
            except:
                pass
                #attribute[f'{prefix}{value}'] = None

        if 'Tag' in attribute_dict:
            if isinstance(attribute_dict['Tag'], list):
                attribute[f'{prefix}tag'] = list()
                for tag in attribute_dict.get('Tag', []):
                    attribute[f'{prefix}tag'].append(tag['name'].strip())
            elif isinstance(attribute_dict['Tag'], dict):
                attribute[f'{prefix}tag'] = attribute_dict['Tag']['name'].strip()


        hash_types = ['impfuzzy', 'imphash', 'md5', 'pehash', 'sha1', 'sha224', 'sha256', 'sha3-224', 'sha3-224', 'sha3-384', 'sha3-512', 'sha384', 'sha512', 'sha512/224', 'sha512/224', 'ssdeep', 'tlsh', 'vhash']
        ip_types = ['ip', 'ip-dst', 'ip-src', ]
        email_types = ['dns-soa-email', 'email', 'email-dst', 'email-src', 'email-replay-to', 'target-email', 'whois-registrant-email']
        values = attribute_dict['value'].split('|')
        types = attribute_dict['type'].split('|')
        for value, misp_type in zip(values, types):
            if misp_type in hash_types:
                attribute[f'{prefix}hash'] = value
            if misp_type in ip_types:
                attribute[f'{prefix}ip'] = value
            if misp_type in email_types:
                attribute[f'{prefix}email'] = value
            misp_type = misp_type.replace('-', '_')
            attribute[f'{prefix}{misp_type}'] = value
           
        return attribute


    @staticmethod
    def map_event(event_dict, prefix="misp_"):
        mapping = {
                'id': 'event_id',
                'orgc_id': 'orgc_id',
                'org_id': 'org_id',
                'date': 'event_date',
                'threat_level_id': 'event_threat_level',
                'info': 'event_info',
                'published': 'event_published',
                'uuid': 'event_uuid',
                'attribute_count': 'event_attribute_count',
                'analysis': 'event_analysis',
                'timestamp': 'event_timestamp',
                'distribution': 'event_distribution',
                'publish_timestamp': 'event_publish_timestamp',
                'sharing_group_id': 'misp_sharing_group_id',
                'Org.name': 'event_org_name',
                'Org.uuid': 'event_org_uuid',
                'Orgc.name': 'event_orgc_name',
                'Orgc.uuid': 'event_orgc_uuid',
                'Galaxy': 'event_galaxy'
            }
        
        event = dict()
        for key, value in mapping.items():
            try:
                event[f'{prefix}{value}'] = reduce(lambda acc,i: acc[i], key.split('.'), event_dict)
            except:
                pass
                #event[f'{prefix}{value}'] = None

        if 'Tag' in event_dict:
            if isinstance(event_dict['Tag'], list):
                event[f'{prefix}tag'] = list()
                for tag in event_dict.get('Tag', []):
                    event[f'{prefix}tag'].append(tag['name'].strip())
            elif isinstance(event_dict['Tag'], dict):
                event[f'{prefix}tag'] = event_dict['Tag']['name'].strip()

        return event

