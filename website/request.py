'''Implementation of the logic for representing the requests and logging them.'''

import datetime # to set the time 
import sqlite3 
import pandas as pd
import json
import os # to open any path 
from pymongo import MongoClient
from dotenv import load_dotenv

load_dotenv()

class Request(object):  #object is the mother of all classes in Python. It is a new-style class, so inheriting from object makes Table a new-style class.
    def __init__(self, id = None , timestamp = None , origin = None, host = None, request = None, body = None, method = None, headers = None, threats = None, geo_location={} , threat_state={}):

        self.id = id
        self.timestamp = timestamp
        self.origin = origin
        self.host = host
        self.request = request
        self.body = body
        self.method = method
        self.headers = headers
        self.threats = threats
        self.geo_location = geo_location
        self.threat_state = threat_state

    def to_json(self):
        output = {}

        if self.request != None and self.request != '':
            output['request'] = self.request

        if self.body != None and self.body != '':
            output['body'] = self.body


        # self.headers = {"name":"abddddd" , "age": 40 , "conutry" : "KSF"}
        if self.headers != None:
            for header, value in self.headers.items():
                output[header] = value

        # if self.headers != None:
        #     for header in self.headers:
        #         for value in self.headers[header]:
        #             output[header] = value

        # print(json.dumps(output))
        return json.dumps(output) # to convert from dict into str

        #output= {"request" : "value"  , "bode" :  "value"  , "header" : {"key" : "value" } }



#----------------------------------------------- class 2 --------------------------------------------------------------------
#-----------------
#-----------------
#----------------------------------------------------------------------------------------------------------------------------



class DBController(object):
    """
    used to save the parse Request in database (used it for Dashboard web-site)
    """

    def __init__(self):
        self.connect_to_mongodb = MongoClient(os.getenv("MONGODB_URI"))  # connect to database
        # name of database
        self.db = self.connect_to_mongodb["Web_Application_Firewall"]
        self.collection_logs = self.db["logs"]  # collection name
        self.collection_threats = self.db["threats"]  # collection name
        self.collection_header = self.db["full_header"]
        self.collection_location = self.db["geo_location"]
        self.collection_stat = self.db["stat"]
        self.collection_threat_location=self.db['threat_location']


    def save(self, obj):  # to take only request
        if not isinstance(obj, Request):
            raise TypeError("Object should be a Request!!!")


        #======================================================================================================================================
        obj.timestamp = datetime.datetime.now()  # take from Request
        try:
            highest_id = self.collection_logs.find_one(
                sort=[('_id', -1)])['_id']
        except (TypeError, KeyError):
            highest_id = 0

        obj.id = highest_id+1
        #======================================================================================================================================


        #======================================================================================================================================
        document = {'_id':obj.id ,"timestamb": obj.timestamp,
                    "origin": obj.origin, "host": obj.host, "method": obj.method}

        self.collection_logs.insert_one(document)
        #======================================================================================================================================

        #======================================================================================================================================
        for threat, location in obj.threats.items():
            collection_threats = self.db["threats"]
            document_two = {'_id':obj.id,
                "threat_type": threat, "location": location}
            collection_threats.insert_one(document_two)

        #======================================================================================================================================
        headers = {'_id':obj.id }
        for key , value in obj.headers.items():
            headers[key]=value

        self.collection_header.insert_one(headers)

        #======================================================================================================================================
        geo_location = {'_id':obj.id, 'threat_state':obj.threat_state }
        for key , value in obj.geo_location.items():
            geo_location[key]=value

        
        self.collection_location.insert_one(geo_location)
        # self.collection_location.insert_one(obj.threat_state)
        
        #======================================================================================================================================


        df = pd.DataFrame(list(collection_threats.find()))


        valid_count_pres = df['threat_type'].value_counts()['valid'] / df['threat_type'].value_counts().sum() *100
        xss_count_pres = df['threat_type'].value_counts()['xss']    / df['threat_type'].value_counts().sum() *100
        sql_count_pres = df['threat_type'].value_counts()['sqli'] / df['threat_type'].value_counts().sum() *100
        cmdi_count_pres = df['threat_type'].value_counts()['cmdi'] / df['threat_type'].value_counts().sum() *100
        pathTrav_count_pres = df['threat_type'].value_counts()['path-traversal'] / df['threat_type'].value_counts().sum() *100
        sum_att = (xss_count_pres + sql_count_pres + cmdi_count_pres + pathTrav_count_pres)


        stat = {'_id':obj.id ,'valid':valid_count_pres , 'xss' :xss_count_pres , 'sql':sql_count_pres , 'cmdi':cmdi_count_pres , 'path-traversal':pathTrav_count_pres , 'sum_Attacks': sum_att}
       
        self.collection_stat.insert_one(stat)

        # print(valid_count_pres)
        # print(xss_count_pres)
        # print(sql_count_pres)

        # # ------------------------------------------------------------- Dashboard Data Location ------------------------------------------------

        Request_count = df["location"].value_counts()["Request"] / df["location"].value_counts().sum() * 100

        Body_count = df["location"].value_counts()["Body"] / df["location"].value_counts().sum() * 100

        Cookie_count = df["location"].value_counts()["Cookie"] / df["location"].value_counts().sum() * 100

        User_Agent_count = df["location"].value_counts()["User_Agent"] / df["location"].value_counts().sum() * 100

        Accept_Encoding_count = df["location"].value_counts()["Accept_Encoding"] / df["location"].value_counts().sum() * 100

        Accept_Language_count = df["location"].value_counts()["Accept_Language"] / df["location"].value_counts().sum() * 100

        document_three = { '_id':obj.id ,"Request": Request_count, "Body": Body_count, "Cookie": Cookie_count,
                          "User_Agent": User_Agent_count, "Accept_Encoding": Accept_Encoding_count, "Accept_Language": Accept_Language_count}

        self.collection_threat_location.insert_one(document_three) # 6
