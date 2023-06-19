# encoding = utf-8


import os


import sys


import time


import datetime


import json


import requests


from urllib.parse import urljoin, urlparse


'''



    IMPORTANT



    Edit only the validate_input and collect_events functions.



    Do not edit any other part in this file.



    This file is generated only once when creating the modular input.



'''


'''



# For advanced users, if you want to create single instance mod input, uncomment this method.



def use_single_instance_mode():



    return True



'''


date_format_str = '%Y-%m-%dT%H:%M:%S'


def validate_input(helper, definition):
    """Implement your own validation logic to validate the input stanza configurations"""

    pass


def uri_validator(url):

    try:

        result = urlparse(url)

        return all([result.scheme, result.netloc])

    except:

        return False


def get_sfmc_url(host_url, path):

    if uri_validator(host_url):

        url = urljoin(host_url, path)

        return urlparse(url)._replace(scheme="https").geturl()

    else:

        raise ValueError("URL format error")


def collect_events(helper, ew):

    # get Credentials

    global_account = helper.get_arg('global_account')

    client_Id = global_account['username']

    client_Secret = global_account['password']

    payload = {'client_id': client_Id, 'client_secret': client_Secret,

               'grant_type': 'client_credentials'}

    url = get_sfmc_url(helper.get_arg("auth_api_url"), "/v2/token")

    auth_resp = requests.post(url, data=payload)

    resp = auth_resp.json()

    if auth_resp.status_code == 200:

        token = resp['access_token']

        expiresIn = resp['expires_in']

        auth_token_header_value = "Bearer %s" % token

        auth_token_header = {"Authorization": auth_token_header_value}

    else:

        raise Exception(

            f"Failed to get Auth token, status_code={resp.status_code}")

    # Security Events URL

    security_events_path = "/data/v1/audit/securityEvents"

    security_events_url = get_sfmc_url(

        helper.get_arg("rest_api_url"), security_events_path)

    security_sourcetype = "sfmc:security:json"

    # Security Events Checkpoint

    sec_checkpoint_name = "sfmc_security_events_checkpoint"

    helper.log_info('checkpoint name: ' + sec_checkpoint_name)

    # helper.delete_check_point(sec_checkpoint_name)

    # Audit Events URL

    audit_events_path = "/data/v1/audit/auditEvents"

    audit_events_url = get_sfmc_url(

        helper.get_arg("rest_api_url"), audit_events_path)

    audit_sourcetype = "sfmc:audit:json"

    # Audit Events Checkpoint

    audit_checkpoint_name = "sfmc_audit_events_checkpoint"

    helper.log_info('checkpoint name: ' + audit_checkpoint_name)

    # helper.delete_check_point(audit_checkpoint_name)

    get_sfmc_events(helper, auth_token_header, security_events_url,

                    sec_checkpoint_name, ew, security_sourcetype)

    get_sfmc_events(helper, auth_token_header, audit_events_url,

                    audit_checkpoint_name, ew, audit_sourcetype)


def get_sfmc_events(helper, header, url, checkpoint_name, ew, sourcetype):

    # Yest date time in UTC
    date_yest = datetime.datetime.now(
        datetime.timezone.utc) - datetime.timedelta(days=1)

    date_yest = date_yest.strftime(date_format_str)

    checkpoint = helper.get_check_point(checkpoint_name)

    if checkpoint is None:

        helper.log_info('set first checkpoint: ' + date_yest)

        helper.save_check_point(checkpoint_name, date_yest)

        checkpoint = date_yest

    helper.log_info('current checkpoint: ' +

                    checkpoint_name+'::' + str(checkpoint))

    r_parameters = {'$page': 1, '$pageSize': 100,

                    '$orderby': 'createdDate desc', 'startdate': checkpoint}

    sfmc_events_response = requests.get(

        url, headers=header, params=r_parameters)

    sfmc_events_resp_json = sfmc_events_response.json()

    sfmc_events_resp_status_code = sfmc_events_response.status_code

    is_error = 1

    is_zero = 1

    next_checkpoint = checkpoint

    if sfmc_events_resp_status_code == 200:

        is_error = 0

        num_of_pages = 1

        if sfmc_events_resp_json['count'] > 0:

            is_zero = 0

            record_count = sfmc_events_resp_json['count']

            page_size = sfmc_events_resp_json['pageSize']

            num_of_pages = record_count / page_size

            next_checkpoint = sfmc_events_resp_json['items'][0]['createdDate']

            helper.log_info('record_count: ' + str(record_count) + ' page_size: '+str(page_size)+' num_of_pages:' +

                            str(num_of_pages)+' cur_checkpoint:'+str(checkpoint)+' next_Checkpoint:'+str(next_checkpoint))

            if (checkpoint != next_checkpoint):

                # write events from first page to splunk

                for item in sfmc_events_resp_json['items']:

                    evt = helper.new_event(json.dumps(item), time=None, host=None, index=None,

                                           source=None, sourcetype=sourcetype, done=True, unbroken=True)

                    ew.write_event(evt)

        else:

            helper.log_info("Record Count is Zero")

    if not is_error:

        page = 2

        if not is_zero:

            try:

                # while(page<=(num_of_pages+1)):
                while (page <= (num_of_pages+1)):

                    helper.log_info('page::'+str(page) +

                                    ' num_of_pages::'+str(num_of_pages))

                    r_parameters = {



                        '$page': page,



                        '$pageSize': 100,



                        '$orderby': 'createdDate desc',



                        'startdate': checkpoint



                    }

                    sfmc_events_response = requests.get(

                        url, headers=header, params=r_parameters)

                    sfmc_events_resp_json = sfmc_events_response.json()

                    sfmc_events_resp_status_code = sfmc_events_response.status_code

                    if sfmc_events_resp_status_code == 200:

                        for item in sfmc_events_resp_json['items']:

                            evt = helper.new_event(json.dumps(

                                item), time=None, host=None, index=None, source=None, sourcetype=sourcetype, done=True, unbroken=True)

                            ew.write_event(evt)

                    page = page+1

            except Exception as e:

                helper.log_error(

                    "Problem while making a call to SFMC API: " + str(e))

            helper.save_check_point(checkpoint_name, next_checkpoint)

    else:

        helper.log_error(

            "Recieved error response from the API call: " + str(sfmc_events_resp_json))
