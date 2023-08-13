# this module for timestamp operation
# used on elasticsearch query

from datetime import datetime,timedelta


def timestamp_delta(timestamp=None,hours=0,minutes=0,seconds=0):
    """
            subtraction of a delta time from timestamp
            if timestamp was None will be replaced by present time `datetime.now`
    """

    if timestamp == None:
        timestamp = datetime.now().strftime("%Y-%m-%dT%H:%M:%S.%fZ")

    timeline = datetime.strptime(timestamp,"%Y-%m-%dT%H:%M:%S.%fZ") - timedelta(hours=hours,minutes=minutes,seconds=seconds)
    min_timestamp = timeline.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    return min_timestamp

def timestamp_add(timestamp=None,hours=0,minutes=0,seconds=0):
    """
            addition of a delta time from timestamp
            if timestamp was None will be replaced by present time `datetime.now`
    """

    if timestamp == None:
        timestamp = datetime.now().strftime("%Y-%m-%dT%H:%M:%S.%fZ")

    timeline = datetime.strptime(timestamp,"%Y-%m-%dT%H:%M:%S.%fZ") + timedelta(hours=hours,minutes=minutes,seconds=seconds)
    min_timestamp = timeline.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    return min_timestamp