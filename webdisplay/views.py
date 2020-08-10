from django.shortcuts import render
from django.http import HttpResponse
from django.template import loader
from django.views.generic.edit import CreateView
#from .forms import *
from django.http import HttpResponseRedirect
from .models import *
from django.views.generic import TemplateView
from django.db.models import QuerySet
from django.http import FileResponse, Http404
from django.core.files.storage import FileSystemStorage
import json
import os
from jira import JIRA
import jira.client
from jira.client import JIRA
import zipfile
from urllib.request import urlopen
import urllib.request
import datetime
import glob
import shutil
from pyaxmlparser import APK
from shutil import copyfile
import requests
import subprocess
import hashlib
from requests_toolbelt.multipart.encoder import MultipartEncoder
import sqlite3
from django.db.models import Count
from django.views.decorators.csrf import csrf_exempt
from django.shortcuts import redirect


#########Global Variables####################
BASE = os.getcwd()
v2_DIR = BASE
data_DIR = os.path.join(BASE, "scanautomation")
queueapk_DIR = os.path.join(BASE, "queue")

##########functions##############################
##logger function to write logs to txt file
##this can be used to display in logs or analyse
def logger(text):
    try:
        logfile = os.path.join(data_DIR,"logger.txt")
        num_lines = 0
        with open(logfile, "r") as fo:
            for line in fo:
                num_lines += 1
        #if logger file is more than 65 lines, clear file                
        if(num_lines>65):
            open(logfile,"w").close()
         
        f = open(logfile, "a")
        f.write(text)
        f.write("\n")
        f.close()
    except:
        logfile = os.path.join(data_DIR,"logger.txt")

#full permission
def full_permission(addr):
    subprocess.run(["chmod","777",addr])

#clear temp folder
def cleartemp():
    try:
        path = os.path.join(data_DIR,"data/temp/*")
        files = glob.glob(path)
        for f in files:
            if os.path.isdir(f):
                shutil.rmtree(f)
            else:
                os.remove(f)
    except:
        return render(request, 'wrong_cleartemp',)

#for error handling. If app is not added while scanning. 
#add now
def addcustomtodb(md5hash):
    try:
        new_db = os.path.join(v2_DIR, "new_db.sqlite3")
        mobsf_db = os.path.join(v2_DIR, "Mobile-Security-Framework-MobSF","db.sqlite3")
        new_db = sqlite3.connect(new_db)
        cursor = new_db.cursor()
        print("connected")
        cursor.execute('''ATTACH DATABASE ? AS mobsf''',(mobsf_db,))
        query = '''INSERT INTO project(MD5,app_name,Manifest_json,Permission_json,SHA1,SHA256,size,package_name,main_activity,target_sdk,max_sdk,min_sdk,androvername,androver,cnt_act,cnt_pro,cnt_ser,cnt_bro,e_act,e_cnt,e_ser,e_bro,cert_info,bin_anal_json) SELECT MD5,APP_NAME,MANIFEST_ANAL,PERMISSIONS,SHA1,SHA256,SIZE,PACKAGENAME,MAINACTIVITY,TARGET_SDK,MAX_SDK,MIN_SDK,ANDROVERNAME,ANDROVER,CNT_ACT,CNT_PRO,CNT_SER,CNT_BRO,E_ACT,E_CNT,E_SER,E_BRO,CERT_INFO,BIN_ANALYSIS FROM StaticAnalyzer_staticanalyzerandroid WHERE MD5 = ?'''
        dta = [md5hash]
        cursor.execute(query, dta)
        new_db.commit()
        print("Added to database \n")
        new_db.close()
    except sqlite3.IntegrityError:
        print("This already exists as it is ! or samefile with different name already exists in db \n")
        new_db.close()
    except:
        print("failed to add again to db")


#explode apk in temp. find apks recursively
def explodetemp(templocation):
    path = os.path.join(templocation, "*")
    filesintemp = glob.glob(path)
    for f in filesintemp:
        if(os.path.isfile(f)):
            ext = f.split(".")[-1]
            if(ext=="apk"):
                namef = f.split("/")[-1]
                newpath = os.path.join(data_DIR,"data/temp")
                newpath = os.path.join(newpath, namef)
                #if it finds any apk move it temp root folder
                subprocess.run(["mv",f, newpath])
            else:
                os.remove(f)
        elif(os.path.isdir(f)):
            explodetemp(f)
        else:
            print("something not right. It should be file or folder")

#unzip zip files from 1st arg to 2nd arg destination
def unzipzip(name,path, newpath):
    cleartemp()
    subprocess.run(["mv",path,newpath])
    with zipfile.ZipFile(newpath, "r") as zip_ref:
        zip_ref.extractall(os.path.join(data_DIR,"data/temp/"))
    os.remove(newpath)
    queueapks = os.path.join(queueapk_DIR,name)
    subprocess.run(["mkdir",queueapks])
    #explode apk in temp. i.e find apks inside folder inside folder
    explodetemp(os.path.join(data_DIR,"data/temp"))
    filesglob = os.path.join(data_DIR, "data/temp/*.apk")
    filesintemp = glob.glob(filesglob)
    if(filesintemp==[]):
        logger("No APK found to scan")
    else:
        logger("All apks in zip Queued for scan")
        for f in filesintemp:
            justname = f.split("/")[-1]
            newpath = os.path.join(queueapks,justname)
            subprocess.run(["mv",f,newpath])
        
    cleartemp()

#when apk is uploaded for just scan
def apkscan(name):
    logger("\n")
    logger("New apk scan")
    logger(name)
    path = os.path.join(data_DIR, "data/queueupload/")
    path = os.path.join(path, name)
    #full_permission(path)
    newpath = os.path.join(queueapk_DIR,name)
    #subprocess.run(["mv",path,newpath])
    shutil.move(path,newpath)
    logger("Queued for scan")

#when zip is uploaded for just scan
def zipscan(name):
    logger("\n")
    logger("New ZIP scan")
    logger(name)
    path = os.path.join(data_DIR, "data/queueupload/")
    path = os.path.join(path, name)
    #full_permission(path)
    newpath = os.path.join(data_DIR, "data/temp/")
    newpath = os.path.join(newpath, name)
    #path is the current path of the zip file
    #newpath is temp folder where zip will be extracted
    unzipzip(name,path,newpath)
    
    

#when zip is uploaded for scan+version check
def scanversionzip(name):
    logger("\n")
    logger("New ZIP scan and version check")
    logger(name)
    path = os.path.join(data_DIR, "data/queueupload/")
    path = os.path.join(path, name)
    #full_permission(path)
    newpath = os.path.join(data_DIR, "data/temp/")
    newpath = os.path.join(newpath, name)
    #first creating txt file in data/project_version_dic with package name and apk version
    #path is zip current path
    #do not delete path file, since it will be used to queue for scans
    cleartemp()
    subprocess.run(["cp",path,newpath])
    with zipfile.ZipFile(newpath, "r") as zip_ref:
        zip_ref.extractall(os.path.join(data_DIR,"data/temp/"))
    os.remove(newpath)
    #find apks recursively inside folders
    explodetemp(os.path.join(data_DIR,"data/temp"))
    tempapk = os.path.join(data_DIR,"data/temp/*.apk")
    allapks = glob.glob(tempapk)
    #path for dic txt file
    path_dic = os.path.join(data_DIR, "data/project_version_dic/")
    path_dic = os.path.join(path_dic, name)
    #extracting package name and apk version 
    dic_version = {}
    if(allapks==[]):
        logger("Could not find any APK to scan. Please recheck file and re-upload.")
    if(allapks!=[]):
        for f in allapks:
            try:
                apk = APK(f)
                packagename_current = apk.package
                versioncode_current = apk.version_name
                dic_version[packagename_current] = versioncode_current
            except:
                dic_version["Not able to parse XML file"] = "versionName not found"
        g = open(path_dic,"w")
        g.write(str(dic_version))
        g.close()
        logger("Version dict created for this project")
    dic_version.clear()
    #creating folder in queue with project name if not exist
    queueapks = os.path.join(queueapk_DIR,name)
    if(os.path.isfile(queueapks)==False and os.path.isdir(queueapks)==False):
        subprocess.run(["mkdir",queueapks])
    #add apk from temp to this folder
    filesglob = os.path.join(data_DIR, "data/temp/*.apk")
    filesintemp = glob.glob(filesglob)
    for f in filesintemp:
        justname = f.split("/")[-1]
        newpath = os.path.join(queueapks,justname)
        subprocess.run(["mv",f,newpath])
    cleartemp()
    #remove original file. this was retained. Since if fails in process. RESTART
    os.remove(path)
    logger("All valid apks in zip are Queued for scan")


# Create your views here.
def home(request):
    return HttpResponse(data_DIR)
