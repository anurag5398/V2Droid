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
    
    def versionzip(name):
        return HttpResponse("WIP")

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

###function req to add from onedb to my db
#copying to our db using current hash txt
#check currentscan.txt use md5 of apk to copy to DB(result)
def addmd5todb(mdd5):
    #hashfile = open(os.path.join(v2_DIR, "scanautomation", "current_scan.txt"), "r")
    #mdhash = hashfile.readline()
    try:
        new_db = os.path.join(v2_DIR, "new_db.sqlite3")
        cursor = new_db.cursor()

        
        #new_db.execute('''CREATE TABLE IF NOT EXISTS project (
        #MD5 text ,
        #app_name text ,
        #date text DEFAULT (date('now','localtime')),
        #time text DEFAULT (time('now')),
        #Manifest_json text,
        #Permission_json text,
        #SHA1 text,
        #SHA256 text,
        #size text,
        #package_name text,
        #main_activity text,
        #target_sdk text,
        #max_sdk text,
        #min_sdk text,
        #androvername text,
        #androver text,
        #cnt_act text,
        #cnt_pro text,
        #cnt_ser text,
        #cnt_bro text,
        #e_act text,
        #e_cnt text,
        #e_ser text,
        #e_bro text,
        #cert_info text,
        #bin_anal_json text); ''')

        #new_db.commit()
        mobsf_db = os.path.join(v2_DIR, "Mobile-Security-Framework-MobSF/db.sqlite3")
        cursor.execute('''ATTACH DATABASE ? AS mobsf''',(mobsf_db,))
        print("This is the hash",str(mdd5),".")
        #checking if in the db
        check = cursor.fetchall()[0][0]
        if(check == 1):
            cursor.execute("SELECT EXISTS(SELECT 1 FROM project where md5=?)",(mdd5,))
            
            query = '''INSERT INTO project(MD5,app_name,Manifest_json,Permission_json,SHA1,SHA256,size,package_name,main_activity,target_sdk,max_sdk,min_sdk,androvername,androver,cnt_act,cnt_pro,cnt_ser,cnt_bro,e_act,e_cnt,e_ser,e_bro,cert_info,bin_anal_json) SELECT MD5,APP_NAME,MANIFEST_ANAL,PERMISSIONS,SHA1,SHA256,SIZE,PACKAGENAME,MAINACTIVITY,TARGET_SDK,MAX_SDK,MIN_SDK,ANDROVERNAME,ANDROVER,CNT_ACT,CNT_PRO,CNT_SER,CNT_BRO,E_ACT,E_CNT,E_SER,E_BRO,CERT_INFO,BIN_ANALYSIS FROM StaticAnalyzer_staticanalyzerandroid WHERE MD5 = ?'''
            dta = str(mdd5)
            cursor.execute(query,dta)
    
            new_db.commit()
            print("Added to database \n")
            print("This is the hash",dta,".")
            logger("added to db")
        else:
            logger("Some problem occured in adding to the DB")
    except sqlite3.IntegrityError:
        print("This already exists as it is ! or samefile with different name already exists in db \n")
        logger("Already in Database")
    except Exception as e:
        new_db.rollback()
        print("Some Internal Error. Please re-scan ")
        print(e.message)
        logger("Internal Error, Please open Project Page in Results to fix this")
        raise
    finally:
        new_db.close()

#takes md5 returns name from db
def spitappname(md5):
    new_db = os.path.join(v2_DIR, "new_db.sqlite3")
    new_db = sqlite3.connect(new_db)
    cursor = new_db.cursor()
    cursor.execute("SELECT EXISTS(SELECT 1 FROM project where md5=?)",(md5,))
    check = cursor.fetchall()[0][0]
    if(check==1):
        cursor.execute("SELECT app_name FROM project where md5=?",(md5,))
        name = cursor.fetchall()[0][0]
        new_db.close()
        return name
    else:
        new_db.close()
        return 0

#find element in a string#returns 1 if found
def findinlist(astr,alist):
    found = 0
    for a in alist:
        if(a==astr):
            found = 1
    return found

#add to our db
def addtodatabase(hash):
    mobsf_db = os.path.join(v2_DIR, "Mobile-Security-Framework-MobSF/db.sqlite3")
    #adding to my DB
    new_db = sqlite3.connect(mobsf_db)
    cursor = new_db.cursor()
    query1 = '''SELECT * FROM StaticAnalyzer_staticanalyzerandroid WHERE Md5 = ?'''
    dta1 = [hash]
    cursor.execute(query1,dta1)
    aa = cursor.fetchall()[0]
    new_db.close()
    print("name of the app ",aa[2])
    
    #fields to be added
    try:
        Md5 = hash
    except:
        Md5 = ""
    try:
        AppName = aa[2]
    except:
        AppName = ""
    try:
        ManifestJson = aa[14]
    except:
        ManifestJson = ""
    try:
        PermissionJson = aa[15]
    except:
        PermissionJson = ""
    try:
        Sha1 = aa[5]
    except:
        Sha1 = ""
    try:
        Sha256 = aa[6]
    except:
        Sha256 = ""
    try:
        Size = aa[3]
    except:
        Size = ""
    try:
        PackageName = aa[7]
    except:
        PackageName = ""
    try:
        MainActivity = aa[8]
    except:
        MainActivity = ""
    try:
        TargetSdk = aa[9]
    except:
        TargetSdk = ""
    try:
        MaxSdk = aa[10]
    except:
        MaxSdk = ""
    try:
        MinSdk = aa[11]
    except:
        MinSdk = ""
    try:
        Androvername = aa[12]
    except:
        Androvername = ""
    try:
        Androver = aa[13]
    except:
        Androver = ""
    try:
        CntAct = aa[27]
        CntPro = aa[28]
        CntSer = aa[29]
        CntBro = aa[30]
    except:
        CntAct = ""
        CntPro = ""
        CntSer = ""
        CntBro = ""
    try:
        EAct = aa[43]
        ECnt = aa[46]
        ESer = aa[44]
        EBro = aa[45]
    except:
        EAct = ""
        ECnt = ""
        ESer = ""
        EBro = ""
    try:
        CertInfo = aa[18]
    except:
        CertInfo = ""
    try:
        BinaryAnalysisJson = aa[16]
    except:
        BinaryAnalysisJson = ""
    try:
        CodeAnalysis = aa[35]
    except:
        CodeAnalysis = ""

    temp_db = os.path.join(v2_DIR, "new_db.sqlite3")
    new_db2 = sqlite3.connect(temp_db)
    cursor2 = new_db2.cursor()
    cursor2.execute("SELECT EXISTS(SELECT 1 FROM project where md5=?)",(hash,))
    check2 = cursor2.fetchall()[0][0]
    if(check2 != 1):
        query2 = '''INSERT INTO project(MD5,app_name,Manifest_json,Permission_json,SHA1,SHA256,size,package_name,main_activity,target_sdk,max_sdk,min_sdk,androvername,androver,cnt_act,cnt_pro,cnt_ser,cnt_bro,e_act,e_cnt,e_ser,e_bro,cert_info,bin_anal_json) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)'''
        dta2 = [Md5,AppName,ManifestJson,PermissionJson,Sha1,Sha256,Size,PackageName,MainActivity,TargetSdk,MaxSdk,MinSdk,Androvername,Androver,CntAct,CntPro,CntSer,CntBro,EAct,ECnt,ESer,EBro,CertInfo,BinaryAnalysisJson]
        cursor2.execute(query2,dta2)
        new_db2.commit()
        print(AppName," is added successfully")
        logging.info("Added to DB successfully")
    new_db2.close()


###########templates##############################################

##upload function for upload.html(/upload/)
@csrf_exempt
def upload(request):
    #try:
        scan = 0       
        if request.method == 'POST':
            uploaded_file = request.FILES.get('apkdocument', None)
            uploaded_file_version = request.FILES.get('zipdocument', None)
            zipversion_file = request.FILES.get('zipversiondocument',None)
            #first case when it is uploaded for scanning without version scan
            if(uploaded_file!=None and uploaded_file_version==None and zipversion_file==None):
                fs = FileSystemStorage()
                name = fs.save(uploaded_file.name, uploaded_file)
                name_ext = str(name.split(".")[-1])
                if(name_ext=="apk"):
                    apkscan(name)
                    scan = 1
                elif(name_ext=="zip"):
                    zipscan(name)
                    scan = 1                                    
                else:
                    file_path = os.path.join(data_DIR, "data/queueupload")
                    file_path = os.path.join(file_path, name)
                    os.remove(file_path)
                    return render(request, 'wrong_format.html',)
                    #second case where zip is uploaded for scan+version scan
            elif(uploaded_file==None and uploaded_file_version!=None and zipversion_file==None):
                fs = FileSystemStorage()
                name = fs.save(uploaded_file_version.name, uploaded_file_version)
                name_ext = str(name.split(".")[-1])
                if(name_ext=="zip"):
                    scanversionzip(name)
                    scan = 1
                else:
                    return render(request,'wrong_format_zip.html',)
            elif(uploaded_file==None and uploaded_file_version==None and zipversion_file!=None):
                fs = FileSystemStorage()
                name = fs.save(zipversion_file.name, zipversion_file)
                name_ext = str(name.split(".")[-1])
                if(name_ext=="zip"):
                    versionzip(name)
                    scan = 1
            #4th where both places something is uploaded. Invalid method
            else:
				#open token
                return HttpResponse("Don't upload everywhere")

        if(scan==0):
            return render(request,'upload.html',)
        if(scan==1):
            #putting full logsview() here
            logs = []
            try:
                with open(os.path.join(data_DIR, "logger.txt")) as f:
                    for line in f:
                        logs.append(line)
                logs.reverse()
                context = {
                        'file_content' : logs,
                          }
            except:
                context = {
                        'file_content' : logs,
                        }
            return redirect(logsview)

##display results using data from db. data is cleaned here(/report/)
def eachoutput(request):
    try:
        #title
        title = []
        desc = []
        stat = []
        perm_title = []
        perm_stat = []
        perm_info = []
        perm_desc = []
        eachdic = {}
        eachpermdic = {}
        issue_info_manifest = []
        issue_info_permission = []
        issue_info_bin = []
        global appname_global
        #check previous url and take string accordingly. if from
        #or save the global app name
        appname = str(request.GET.get('locations'))
        appname_global = appname
        print("location = ",appname)
        #print(appname)
        query_result = Project.objects.filter(md5=appname_global).first()
        #print(query_result)
        app_name = query_result.app_name
        issue_info = []

        #sorting manifest_json
        mani = query_result.manifest_json[:-1]
        mani = mani[1:]
        eachdic = mani.split("}, {")
        if(len(eachdic)!=0):
            for e in eachdic:
                if(e!=''):
                    intrim = e.split("title",1)[1]
                    intrim = intrim[4:]
                    title1 = intrim.split(", 'stat",1)[0]
                    title1 = title1.replace("<br>"," ")
                    title1 = title1.replace("<strong>"," ")
                    title1 = title1.replace("</strong>"," : ")
                    title1 = title1.replace("</br>"," ")
                    title.append(title1[:-1])

                    intrim2 = e.split("desc",1)[1]
                    intrim2 = intrim2[4:]
                    desc1 = intrim2.split(", 'name",1)[0]
                    desc.append(desc1[:-1])

                    intrim3 = e.split("stat':",1)[1]
                    intrim3 = intrim3[2:]
                    #print(intrim3)
                    stat1 = intrim3.split("desc",1)[0]
                    #print(stat1)
                    stat.append(stat1[:-4])
                    #for exporting full_info to jira
                    full_info = "title::" + title1[:-1] +"__desc::" + desc1[:-1] + "__stat::" + stat1[:-4]
                    full_info = full_info.replace(" ","%20")
                    issue_info_manifest.append(full_info)

            #sorting permission_json
            perm = query_result.permission_json[:-2]
            perm = perm[2:]
            eachpermdic = perm.split("}, '")
            for e in eachpermdic:
                if(e!=''):
                    intrim = e.split("': {'status'",1)[0]
                    perm_title.append(intrim)

                    intrim2 = e.split("', 'info'",1)[0]
                    intrim2 = intrim2.split("'status': '",1)[1]
                    perm_stat.append(intrim2)

                    intrim3 = e.split("description'",1)[0]
                    intrim3 = intrim3.split("'info': ",1)[1]
                    perm_info.append(intrim3[1:-4])

                    intrim4 = e.split("'description':",1)[1]
                    intrim4 = intrim4[2:]
                    perm_desc.append(intrim4[:-1])

                    #set full_info as value of each checkbox to export to jira
                    full_info = "title::" + intrim +"__desc::" + intrim4[:-1] + "__stat::" + intrim2 + "__info::" + intrim3[1:-4]
                    full_info = full_info.replace(" ","%20")
                    #print(full_info)
                    issue_info_permission.append(full_info)


            test_app_name = query_result.app_name          
            sha1 = query_result.sha1
            md5 = query_result.md5
            sha256 = query_result.sha256
            size = query_result.size
            package_name = query_result.package_name
            main_activity = query_result.main_activity
            target_sdk = query_result.target_sdk
            max_sdk = query_result.max_sdk
            min_sdk = query_result.min_sdk
            androvername = query_result.androvername
            androver = query_result.androver
            cnt_act = query_result.cnt_act
            cnt_pro = query_result.cnt_pro
            cnt_ser = query_result.cnt_ser
            cnt_bro = query_result.cnt_bro
            e_act = query_result.e_act
            e_cnt = query_result.e_cnt
            e_ser = query_result.e_ser
            e_bro = query_result.e_bro
            cert_info =query_result.cert_info
            bin_anal_json = query_result.bin_anal_json

            cert_info = cert_info.replace("<br>","\n")
            cert_info = cert_info.replace("</br>","\n")

            bin_title = []
            bin_desc = []
            bin_stat = []
            bin_file = []
            bin_anal_json = bin_anal_json[2:-2]
            eachbin = bin_anal_json.split("}, {")
            if(eachbin!=['']):
                for e in eachbin:
                    if(e!=''):
                        intrim = e.split("itle': '",1)[1]
                        intrim = intrim.split("', 'stat'",1)[0]
                        bin_title.append(intrim)

                        intrim2 = e.split("'stat': '",1)[1]
                        intrim2 = intrim2.split("', 'desc'")[0]
                        bin_stat.append(intrim2)

                        intrim3 = e.split("'desc': '",1)[1]
                        intrim3 = intrim3.split("', 'file'",1)[0]
                        bin_desc.append(intrim3)

                        intrim4 = e.split("'file': '",1)[1]
                        intrim4 = intrim4.replace("'","")
                        bin_file.append(intrim4)

                        full_info = "title::" + intrim +"__desc::" + intrim3 + "__stat::" + intrim2 + "__info::" + intrim4
                        full_info = full_info.replace(" ","%20")
                        issue_info_bin.append(full_info)



            #cert_stat = cert_info.split("Algorithm: [",1)[1]
            #cert_stat = cert_stat.split("]",1)[0]
            #if(cert_stat=="SHA1withRSA"):
            #    cert_key = "Bad (Collision Issue)"
            #elif(cert_stat=="SHA256withRSA"):
            #    cert_key="ok"
            #else:
            #    cert_key = "stable"
            cert_key = ""
            #print(cert_stat)
            #print(cert_key)
            if 'jira_user' in request.session:
                loggedin = str("yes")
            else:
                loggedin = str("no")

            dic = {'md5':md5,'title': title, 'stat': stat, 'desc':desc, 'appname':test_app_name,'bin_title':bin_title, 'bin_stat':bin_stat, 'bin_desc': bin_desc, 'bin_file':bin_file, 'perm_title':perm_title, 'perm_stat':perm_stat, 'perm_info':perm_info, 'perm_desc':perm_desc,
                    'sha1':sha1,'sha256':sha256,'size':size,'package_name':package_name,'main_activity':main_activity,'target_sdk':target_sdk,'max_sdk':max_sdk,'min_sdk':min_sdk,
                    'androvername':androvername,'androver':androver,'cnt_act':cnt_act,'cnt_pro':cnt_pro,'cnt_ser':cnt_ser,'cnt_bro':cnt_bro,'e_act':e_act,'e_cnt':e_cnt,'e_ser':e_ser,'e_bro':e_bro,'cert_info':cert_info,'bin_anal_json':bin_anal_json, 'cert_key':cert_key, 'issue_info_manifest':issue_info_manifest, 'issue_info_bin':issue_info_bin, 'issue_info_permission': issue_info_permission, 'loggedin':loggedin}
            dic['manifest'] = zip(dic['title'],dic['stat'],dic['desc'],dic['issue_info_manifest'])
            dic['permission'] = zip(dic['perm_title'],dic['perm_stat'],dic['perm_info'],dic['perm_desc'],dic['issue_info_permission'])
            dic['bin_anal'] = zip(dic['bin_title'],dic['bin_stat'], dic['bin_desc'],dic['bin_file'],dic['issue_info_bin'])
        return render(request, 'eachoutput.html', dic)
    except:
       return render(request,'eachoutput_error.html',)  


##page with all the scanned results.(/recentscan/)
def tableoutput(request):
    try:
        appname = request.GET.get('locations')
        query_result = Project.objects.all()
        if 'jira_user' in request.session:
            loggedin = str("yes")
        else:
            loggedin = str("no")
        #sending all entries and loggedin status to template
        context = {
            'query_result' : query_result,
            'loggedin' : loggedin,
        }
        return render(request, 'scanresult.html', context)
    except:
        return render(request, 'failscanresult.html',)


##dashboard
def dashboard(request):
    totalscans = Project.objects.all().count()
    #no of files in completed
    projfiles = glob.glob(os.path.join(data_DIR, "data/completed/*.zip"))
    totalprojects = len(projfiles)

    total, used, free = shutil.disk_usage(__file__)
    totalspace = int(total/1073741824)
    freespace = int(free/1073741824)
    usedspace = int(used/1073741824)
    usedspacepercentage = usedspace/totalspace
    freespacepercentage = freespace/totalspace

    z = datetime.datetime.now()
    datetoday = int(z.strftime("%d"))
    daystomaintain = 35 - datetoday

    context = {
        'totalscans': totalscans,
        'totalprojects': totalprojects,
        'freespacepercentage': freespacepercentage,
        'usedspacepercentage': usedspacepercentage,
        'daystomaintain' : daystomaintain,

    }
    return render(request,'dashboard.html',context) 

def home(request):
    return HttpResponse(data_DIR)
