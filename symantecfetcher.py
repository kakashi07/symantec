from urllib import request
import requests
import json
import os
from datetime import datetime, timedelta

LOG_IDENTIFIER = 'SymantecEndpointSecurityFetcher'

base_url ="https://api.sep.securitycloud.symantec.com/v1"
token = "TzJJRC5YLW1VWGNQaVNybWRlZFhGdFVuVndRLkdYRUxmclE3VDVhQzRZTi1kZnBCWWcuazFxZ2xxbnY3a2Q1dDB1ZW9rNTJscXNrbTY6azZ1NmFjZDE0OThmZmpqOW41YW5zaGVuN3M4NXRlbDBnbW0="

class Symantec:

    def __init__(self,base_url,api_token) -> None:
        self.base_url = base_url
        self.api_token = api_token
        self.start_time  = "00:00:00"
        self.end_time    = "23:59:59"
        
        
    def get_access_token(self):
        auth_header = {'accept': 'application/json',
                      'authorization': 'Basic {}'.format(self.api_token),
                      'content-type': 'application/x-www-form-urlencoded'
                      }
        auth_url = os.path.join(self.base_url,"oauth2/tokens")

        try:
            response = requests.post(auth_url,headers = auth_header)
            accessToken = (json.loads(response.text))['access_token']
            
            return accessToken
        
        except Exception as e:
            print("Error occurred during API call; url={}; error={}".format(auth_url, e))
            return auth_url,e
        
    def event_search(self,start_date,end_date,next,limit):
        event_url = os.path.join(self.base_url,"event-search")
        token = self.get_access_token()
        device_req_headers=  {
                              'authorization': token ,
                              'content-type':'application/json'
                             }
        request_data = "{ \"start_date\": \"" + start_date + "T" + self.start_time + ".000+0000\",  \"end_date\": \"" + end_date + "T" + self.end_time + ".000+0000\", \"next\": " + str(next) + ", \"limit\": " + str(limit) + ", \"product\":\"SAEP\", \"feature_name\":\"ALL\" }"
        event_response = (requests.post(event_url,headers=device_req_headers,data=request_data)).json()

        return event_response


    def get_incidents(self,start_date,end_date,next,limit):
        incident_url = os.path.join(self.base_url,"incidents")
        incident_req_headers={'authorization': self.get_access_token() , 'content-type':'application/json'}
        query       = "state_id: 1 OR state_id: 2  OR state_id: 3 OR state_id: 4 OR state_id: 5"


        request_data = "{ \"start_date\": \"" + start_date + "T" + self.start_time + ".000+0000\",  \"end_date\": \"" + end_date + "T" + self.end_time + ".000+0000\",  \"next\": " + str(next) + ", \"limit\": " + str(limit) + ",  \"include_events\": true, \"query\": \"" + query + "\" }"
        incident_response  = requests.post(incident_url,headers=incident_req_headers,data=request_data).json()
        
        return incident_response

        
    def get_incident_events(self,start_date,end_date,next,limit):
        incident_url = os.path.join(self.base_url,"incidents/events")
        incident_event_req_headers={'authorization': self.get_access_token() , 'content-type':'application/json','accept':'application/json'}


        request_data = "{ \"start_date\": \"" + start_date + "T" + self.start_time + ".000+0000\",  \"end_date\": \"" + end_date + "T" + self.end_time + ".000+0000\",  \"next\": " + str(next) + ", \"limit\": " + str(limit) + "}"
        incident_event_response  = requests.post(incident_url,headers=incident_event_req_headers,data=request_data).json()

        return incident_event_response

        

class SymantecFetcher(Symantec):
    def __init__(self,base_url,token):
        super().__init__(base_url,token)

    def event_fetcher(self,start_date,end_date,next,limit):
        #eg. event_fetcher(start_date='2022-02-24',end_date='2022-03-02',next = 0, limit=1)
        event_response = self.event_search(start_date,end_date,next,limit)

        try:
            # event_response = self.event_search(start_date,end_date,next,limit)  #next and limit are for pagination : limit = number of results and next is the index (starts from 0)
            total_events =event_response['total']
            next_index = event_response['next']
            event_data = event_response['events']
            event_data = [{'SymantecEndpointSecurity':x} for x in event_data]

            return event_data,next_index

        except Exception as e:
            if event_response['total'] == 0:
                print("No events in the given time range, select a different time range")

    def incident_fetcher(self,start_date,end_date,next,limit):
        incident_response = self.get_incidents(start_date,end_date,next,limit)
        try:
            next_index = incident_response['next']
            total_incidents =incident_response['total']
            incident_data = incident_response['incidents']
            incident_data = [{'SymantecEndpointSecurity':x} for x in incident_data]
            
            return incident_data,next_index

        except Exception as e:
            if incident_response['total'] == 0:
                print("No incidents in the given time range, select a different time range")

            return e
    
    def incindent_events_fetcher(self,start_date,end_date,next,limit):
        incident_event_response = self.get_incident_events(start_date,end_date,next,limit)

        try:
            next_index = incident_event_response['next']
            total_event_incidents =incident_event_response['total']

            incident_event_data = incident_event_response['events']
            incident_event_data = [{'SymantecEndpointSecurity':x} for x in incident_event_data]
        
            return incident_event_data,next_index

        except Exception as e:
            if incident_event_response['total'] ==0:
                print("No incidents in the given time range, select a different time range")

            return e

    def paginagte_events(self, next=0):
        return {'events': '100 eventss'}

    def fetch_job(self):
        next = 0
        while True:
            events = self.paginagte_events(next)
            next += 100
            self.prepare_event()

            
fetcher = SymantecFetcher(base_url,token)
print(fetcher.incident_fetcher(start_date='2022-02-10',end_date='2022-03-02',next = 0, limit=1))