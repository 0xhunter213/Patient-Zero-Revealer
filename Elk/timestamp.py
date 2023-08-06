# this module for timestamp operation
# used on elasticsearch query

from datetime import datetime,timedelta


def timestamp(hours=0,minutes=0,seconds=0):
        timeline = datetime.strptime(timestamp,"%Y-%m-%dT%H:%M:%S.%fZ") - timedelta(hours=hours,minutes=minutes,seconds=seconds)
        min_timestamp = timeline.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        return min_timestamp