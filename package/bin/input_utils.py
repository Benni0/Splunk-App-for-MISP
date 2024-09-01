
from datetime import datetime
import json
from splunklib import modularinput as smi

class SplunkEventIngestor:
    def __init__(self, event_writer, index, source, sourcetype, override_timestamps=False):
        self.event_writer = event_writer
        self.index = index
        self.source = source
        self.sourcetype = sourcetype
        self.override_timestamps = override_timestamps

        # event stats
        self.event_count = 0
        self.skipped_item_count = 0
        self.total_items = 0

    def ingest_event(self, event_data, event_time):
        if self.override_timestamps:
            event_time = int(datetime.now().timestamp())
        
        self.event_writer.write_event(
            smi.Event(
                data=json.dumps(
                    event_data,
                    ensure_ascii=False,
                    default=str
                ),
                index=self.index,
                source=self.source,
                sourcetype=self.sourcetype,
                time=event_time
            )
        )
        self.event_count += 1

    def ingest_items(self, items, extract_function=lambda x:x, mapping_function=lambda x:x, skip_check=lambda x:False, timestamp_function=lambda x:x['timestamp']):
        self.total_items += len(items)
        
        for item in items:
            item = extract_function(item)
            if skip_check(item):
                self.skipped_item_count += 1
                continue

            event_data = mapping_function(item)
            event_timestamp = timestamp_function(item)

            self.ingest_event(event_data, event_timestamp)

    def get_stats(self):
        return {
            'event_count': self.event_count,
            'total_items': self.total_items,
            'skipped_item_count': self.skipped_item_count
        }