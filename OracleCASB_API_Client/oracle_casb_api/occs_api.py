#!/usr/bin/env python
"""
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
    http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

import time, sys, requests, json, logging, arrow, time, os, logging.handlers, socket
from requests_toolbelt.utils import dump

CRED_TMP_FILE='/tmp/OCCS_cred.dat'


def send_syslog(server,json_events_list):
    '''takes a list of events and send it to a syslog server'''
    syslogger = logging.getLogger('syslogger')
    #syslogger.setLevel(logging.WARNING)
    syslogger.setLevel(logging.DEBUG)
    #use UDP
    handler = logging.handlers.SysLogHandler(address = (server,514),  socktype=socket.SOCK_DGRAM)
    syslogger.addHandler(handler)
    print('Sending', end =" ") 
    for event in json_events_list:
        syslog_header = str(arrow.now())+' Oracle-CASB-Cloud-Service '
        syslog = '|'.join('{}={}'.format(key, val) for key, val in event.items())
        syslog = syslog_header + syslog
        syslogger.error(syslog)
        syslogger.handlers[0].flush()
        print('.', end =" ") 
    print()
    syslogger.handlers.clear()


def prepare_users_risk_scores_for_syslog(json_data):
    ''' Takes a json results and format it as a syslog ready list'''
    events_list=[]
    for item in json_data:
        if 'userRiskDetails' in item:
            user_risk_details = item['userRiskDetails']
            if len(user_risk_details) > 0:
                del item['userRiskDetails']
                risk_event=item
                for detail in user_risk_details:
                    risk_event.update({detail['displayname'].replace(' ','_'):detail['value'].replace("'","_")})
                item = risk_event
        events_list.append(item)
    return events_list

def prepare_risk_events_for_syslog(json_data):
    ''' Takes a json results and format it as a syslog ready list'''
    events_list=[]
    for item in json_data:
        if 'additionalDetails' in item:
            risk_event_details = item['additionalDetails'][0]['Details']
            #log_data = json.loads(item['additionalDetails'][0]['Logdata'])
            if len(risk_event_details) > 0:
                del item['additionalDetails']
                risk_event=item
                for detail in risk_event_details:
                    risk_event.update({detail['name'].replace(' ','_'):detail['value'].replace("'"," ")})
                #consider {**risk_event,**log_data} # if Logdata dict is needed, merge results

                item = risk_event
        events_list.append(item)
    return events_list
        

def save_credentials(cred):
    ''' Saves authentication credentials to env '''
    try:
        with open(CRED_TMP_FILE, "w") as cred_file:
            cred_file.write(json.dumps(cred))
        return cred
    except IOError:
        sys.exit('Cannot save credentials')


def load_credentials():
    ''' loads authentication credentials to env '''
    try:
        with open(CRED_TMP_FILE) as cred_file:
            credentials = cred_file.read()

        try:
            credentials = json.loads(credentials)    
        except ValueError as e:
            print('Cannot read json: {}'.format(e))

    except IOError:
        print('Cannot read credentials')
        return None
    
    if int(credentials['expiresAt']) > time.time():
        return credentials
    else:
        print('Token expired\n{}'.format(credentials['expiresAt']))
        return None

class OracleCasbCS(object):
    ''' Main API Client Class '''
    def __init__(self,
                 base_url,                 
                 access_key,
                 access_secret,
                 verify_ssl=False,
                 logger=None
                 ):
        self.occs_logging = self.set_logger(logger)
        self.occs_access_key = access_key
        self.occs_access_secret = access_secret
        self.base_url = base_url
        self.verify_ssl = self.set_verify_ssl(verify_ssl)
        self.token_expires_at = ''
        self.request_timeout = 20
        self.headers = {
            'user-agent': 'autobot',
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'Authorization':'',
            'X-Apprity-Tenant-Id':'',
            'expiresAt':''
        }
        credentials = load_credentials()
        if isinstance(credentials,dict):
            self.occs_logging.debug('Use existing credentials until {}'.format(credentials))     
            self.headers=credentials
        else:
            self.login()
                

    def set_logger(self, logger):
        if logger is None:
            logging.basicConfig(level=logging.DEBUG)
            new_logger = logging.getLogger('API_Logger')
            return new_logger
        else:
            return logger

    def set_verify_ssl(self, ssl_status):
        if isinstance(ssl_status,str):
            ssl_status.lower()
        if ssl_status in ["true", True]:
            return True
        elif ssl_status in ["false", False]:
            return False
        else:
            return True

    def login(self):
        ''' Fetches bearer token and tenant_id '''
        try:
            response = requests.post(
            self.base_url+'/api/v1/token',
            headers=self.headers,
            json={
              "accessKey": self.occs_access_key,
              "accessSecret": self.occs_access_secret 
            },
            verify=self.verify_ssl,
            timeout=self.request_timeout
            )        
            #self.occs_logging.debug('REQUESTS_DUMP:\n{}'.format(dump.dump_all(response).decode('utf-8')))

            if response and response.status_code in [200, 201]:
                json_response = response.json()
                self.headers['Authorization'] = 'Bearer ' + json_response['accessToken']
                self.headers['X-Apprity-Tenant-Id'] = json_response['tenantId']
                self.token_expires_at = arrow.get(json_response['expiresAt']).timestamp
                self.headers['expiresAt'] = str(self.token_expires_at)
                self.occs_logging.info('Authentication successful. it will be valid until: {}'.format(json_response['expiresAt']))
                # TODO: Find an alternative to env to store auth data to avoid re-auth each time
                save_credentials(self.headers)
                


            else:
                self.occs_logging.exception('Authentication Failed {}'.format(response.content))


        except requests.exceptions.HTTPError as errh:
            self.occs_logging.exception("Http Error:",errh)
        except requests.exceptions.ConnectionError as errc:
            self.occs_logging.exception("Error Connecting:",errc)
        except requests.exceptions.Timeout as errt:
            self.occs_logging.exception("Timeout Error:",errt)
        except requests.exceptions.RequestException as err:
            self.occs_logging.exception("OOps: Something went wrong...",err)


    def make_rest_call(self, endpoint, params=None, data=None, method='GET'):
        '''make_rest_call'''

        url = '{0}{1}'.format(self.base_url, endpoint)

        self.occs_logging.info('Request URL {}'.format(url))

        try:
            response = requests.request(method,
                                        url,
                                        json=data,
                                        headers=self.headers,
                                        verify=self.verify_ssl,
                                        params=params,
                                        timeout=self.request_timeout
                                        )
            
            self.occs_logging.debug('REQUESTS_DUMP:\n{}'.format(dump.dump_all(response).decode('utf-8')))

            if response.ok:
                return response.json() if response.content else ''
            else:
                self.occs_logging.exception("REST Request Failed: {}".format(response.content))

        except requests.exceptions.HTTPError as errh:
            self.occs_logging.exception("Http Error:",errh)
        except requests.exceptions.ConnectionError as errc:
            self.occs_logging.exception("Error Connecting:",errc)
        except requests.exceptions.Timeout as errt:
            self.occs_logging.exception("Timeout Error:",errt)
        except requests.exceptions.RequestException as err:
            self.occs_logging.exception("OOps: Something went wrong...",err)

    def get_risk_events(self, start_date, page_size="100"):
        ''' Fetches risk events and apply pagination when required. max page size : 100'''
        risk_events = []
        total_count = 0
        params = {
                  'pagesize' : page_size,
                  'startDate' : start_date
                  }
        response = self.make_rest_call('/api/v1/events/riskevents',params)
        
        total_count = response['maxCount']
        next_marker_position = response['nextMarkerPosition']

        if total_count <= 100:
            return response['riskevents']
        else:
            risk_events = response['riskevents']
            params = {
                      'pagesize' : "100",
                      'markerPosition' : next_marker_position
                      }            
            for result in range(total_count // 100):                
                response = self.make_rest_call('/api/v1/events/riskevents',params)
                risk_events += response['riskevents']
                params['markerPosition'] = response['nextMarkerPosition']
            
            self.occs_logging.debug('Max count: {}'.format(total_count))            
            return risk_events

    def get_user_risk_score_report(self, report_name='userrisk',startperiod=None,endperiod=None, page_size="100"):
        ''' Fetches user risk score report'''

        users_risk_scores = []
        total_count = 0

        params = {
                  'pagesize' : page_size
                  }

        if startperiod is not None:
            params.update({'startperiod':startperiod})

        if endperiod is not None:
            params.update({'endperiod':endperiod})

        response = self.make_rest_call('/api/v1/reports/details/'+report_name,params)
       
        total_count = response['totalCount']
        next_marker_position = response['nextMarkerPosition']

        if total_count <= 100:
            return response['userRiskScores']
        else:
            users_risk_scores = response['userRiskScores']
            params = {
                      'pagesize' : page_size,
                      'markerPosition' : next_marker_position
                      }            
            for result in range(total_count // 100):                
                response = self.make_rest_call('/api/v1/reports/details/'+report_name,params)
                users_risk_scores += response['userRiskScores']
                params['markerPosition'] = response['nextMarkerPosition']
            
            self.occs_logging.debug('Max count: {}'.format(total_count))            
            return users_risk_scores





        
