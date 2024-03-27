import requests
import pandas as pd
from pymongo import MongoClient
import os
# from .request import Request, DBController
from dotenv import load_dotenv

load_dotenv()

connect_to_mongodb = MongoClient(os.getenv("MONGODB_URI"))
db =connect_to_mongodb["Web_Application_Firewall"]
collection_logs = db["logs"]  # collection name
collection_threats = db["threats"]  # collection name
collection_header = db["full_header"]
collection_location = db["geo_location"]

# print(pd.DataFrame(collection_logs.find_one()))

# for x in collection_threats.find():
#     print(x.json())
    # x = pd.DataFrame(x, index=0)
    # print(pd.DataFrame(x,index=[0]))

df = pd.DataFrame(list(collection_threats.find()))


valid_count_pres = df['threat_type'].value_counts()['valid'] / df['threat_type'].value_counts().sum() *100
xss_count_pres = df['threat_type'].value_counts()['xss']    / df['threat_type'].value_counts().sum() *100
sql_count_pres = df['threat_type'].value_counts()['sqli'] / df['threat_type'].value_counts().sum() *100
cmdi_count_pres = df['threat_type'].value_counts()['cmdi'] / df['threat_type'].value_counts().sum() *100
pathTrav_count_pres = df['threat_type'].value_counts()['path-traversal'] / df['threat_type'].value_counts().sum() *100


stat = {'valid':valid_count_pres , 'xss' :xss_count_pres , 'sql':sql_count_pres , 'cmdi':cmdi_count_pres , 'path-traversal':pathTrav_count_pres}


print(df['threat_type'].value_counts())
# print(xss_count_pres)
# print(sql_count_pres)

    

