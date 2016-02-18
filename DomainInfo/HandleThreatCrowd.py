import os
import sys
import logging
import traceback
import platform
import subprocess
import configparser
import re
import json
import urllib.request
import http.client
from collections import defaultdict
from gzip import GzipFile

from ExcelInfo import *

class CThreatCrowd :
    class CThreatCrowdResolutionItem :
        def __init__( aSelf , aResolutionItem ) :
            aSelf.m_strIpAddr = None
            aSelf.m_strLastResolved = None
            aSelf.m_lsLastResolved = []
            
            if "ip_address" in aResolutionItem :
                aSelf.m_strIpAddr = aResolutionItem["ip_address"]
            if "last_resolved" in aResolutionItem :
                aSelf.m_strLastResolved = aResolutionItem["last_resolved"]
                aSelf.m_lsLastResolved.append( aResolutionItem["last_resolved"] )
            else :
                aSelf.m_strLastResolved = "Unknown"
                aSelf.m_lsLastResolved.append( Unknown )
        def __str__( aSelf ) :
            return "{} ({})".format( aSelf.m_strIpAddr , ", ".join(aSelf.m_lsLastResolved) )
        def __repr__( aSelf ) :
            return aSelf.__str__()
        def __lt__( aSelf , aRhs ) : 
            return aSelf.m_lsLastResolved[0] < aRhs.m_lsLastResolved[0]

    def __init__( aSelf ) :
        aSelf.m_dictCache = {}    #<key , value> = <domain , domain properties dict>
        aSelf.m_strRawResult = None

    def Query( aSelf , aDomain , aTimeout = 10 , aRetryCnt = 5 ) :
        if not aDomain :
            return None
        elif aDomain in aSelf.m_dictCache.keys() :
            logging.info( "{}: Cache hit".format(aDomain) )
            return aSelf.m_dictCache[aDomain]
        else :
            while aRetryCnt > 0 :
                try :
                    req = urllib.request.Request( "http://www.threatcrowd.org/searchApi/v2/domain/report/?domain={}".format(aDomain) )
                    rsp = urllib.request.urlopen( req )
                    strEncoding = rsp.info().get( "Content-Encoding" )
                    if strEncoding and strEncoding.lower() == "gzip" :
                        result = GzipFile( fileobj = rsp ).read()
                    else :
                        result = rsp.read()
                    result = result.decode( "utf-8" ) if result else "<NULL>"
                    #result = r'{"response_code":"1","resolutions":[{"last_resolved":"2014-11-24","ip_address":"74.125.230.68"},{"last_resolved":"2014-12-13","ip_address":"173.194.67.101"},{"last_resolved":"2015-11-24","ip_address":"74.125.230.68"},{"last_resolved":"2015-01-01","ip_address":"216.58.208.32"},{"last_resolved":"2015-02-02","ip_address":"74.125.235.206"},{"last_resolved":"2015-02-03","ip_address":"216.58.208.46"},{"last_resolved":"2015-02-04","ip_address":"216.58.210.46"},{"last_resolved":"2014-07-15","ip_address":"64.233.183.139"},{"last_resolved":"2014-08-28","ip_address":"64.233.182.102"},{"last_resolved":"2014-07-31","ip_address":"64.233.182.101"},{"last_resolved":"2014-08-12","ip_address":"64.233.181.139"},{"last_resolved":"2013-07-19","ip_address":"173.194.66.100"},{"last_resolved":"2014-12-16","ip_address":"173.194.116.100"},{"last_resolved":"2014-12-23","ip_address":"185.50.69.10"},{"last_resolved":"2013-07-26","ip_address":"173.194.78.113"},{"last_resolved":"2014-10-18","ip_address":"173.194.45.224"},{"last_resolved":"2013-08-16","ip_address":"173.194.40.128"},{"last_resolved":"2013-08-23","ip_address":"173.194.40.130"},{"last_resolved":"2014-10-15","ip_address":"74.125.229.128"},{"last_resolved":"2015-02-18","ip_address":"216.58.217.142"},{"last_resolved":"2015-02-26","ip_address":"74.125.236.36"},{"last_resolved":"2013-10-14","ip_address":"212.140.233.53"},{"last_resolved":"2013-11-28","ip_address":"62.253.3.93"},{"last_resolved":"2013-07-30","ip_address":"173.194.41.163"},{"last_resolved":"2014-06-20","ip_address":"206.111.1.122"},{"last_resolved":"2013-08-10","ip_address":"173.194.34.101"},{"last_resolved":"2015-02-06","ip_address":"216.58.219.142"},{"last_resolved":"2014-09-10","ip_address":"173.194.121.34"},{"last_resolved":"2014-10-14","ip_address":"74.125.229.226"},{"last_resolved":"2014-11-07","ip_address":"74.125.225.3"},{"last_resolved":"2013-08-02","ip_address":"173.194.34.66"},{"last_resolved":"2013-08-01","ip_address":"173.194.34.161"},{"last_resolved":"2014-10-04","ip_address":"74.125.225.104"},{"last_resolved":"2013-10-03","ip_address":"173.194.34.102"},{"last_resolved":"2014-03-03","ip_address":"62.253.3.113"},{"last_resolved":"2014-11-09","ip_address":"173.194.46.103"},{"last_resolved":"2014-11-06","ip_address":"173.194.125.41"},{"last_resolved":"2014-10-26","ip_address":"173.194.37.5"},{"last_resolved":"2014-10-07","ip_address":"74.125.229.232"},{"last_resolved":"2014-09-11","ip_address":"173.194.121.41"},{"last_resolved":"2014-09-09","ip_address":"173.194.121.36"},{"last_resolved":"2014-08-22","ip_address":"173.194.121.37"},{"last_resolved":"2014-01-17","ip_address":"173.194.34.129"},{"last_resolved":"2013-11-03","ip_address":"173.194.41.72"},{"last_resolved":"2013-11-02","ip_address":"173.194.41.64"},{"last_resolved":"2013-09-28","ip_address":"173.194.34.97"},{"last_resolved":"2013-09-27","ip_address":"173.194.34.100"},{"last_resolved":"2014-12-22","ip_address":"74.125.137.100"},{"last_resolved":"2014-12-03","ip_address":"173.194.125.9"},{"last_resolved":"2014-11-15","ip_address":"173.194.125.66"},{"last_resolved":"2015-01-30","ip_address":"216.58.216.206"}],"hashes":["000269bab6833d37ca78b7445c9a3373","00032b34bc1b54e0fc807d868356bd29","0005dc85113a714bb13741ffd0cc0a09","0005f36601ca5acf335c2291aae77cc6","0006d38b765eea58c3ce7a3aedf77095","000ab25117792150a13a087a265d46c8","000ac527f5f9b223f093a74fc9e28bff","000b6f4e0c4ed2f3a48dcf2c1b01cecc","000bfa648b2d26acfc3ab12a903b749a","000de2e9973823f7613b3bbb4c3b6abe","0013d79a7550b053894335f0ecd253ef","001f7e981e87b887db67a60f297253b2","0024c7149b256a6b678810189cc5914c","00294f530951831b3ed394cb06115969","002b60c52d7570a40807d23bf4bd059d","002d5e98f2c6b3bd3b010a7a9e45dc6c","002ee2db250940a1a3ec6f772d6697ae","002f9189ff9fc0cff0acf6b7115d9ce8","003095222bfa1e91a0adf62c941edbc1","0032a9625396ec0eb1b604f82d71b087","00334d4def120132663f58f3589b6087","003638d7d2b9f6f6f0ab48c8d7cb71ea","0036e101d1fe85681e1139b8cc654525","003fc92bf9c8c933b6f32e708f0a1d2c","0043e39e24590149441fba4d8091caa4","004a95dfc236054fac217e0a00db6eb7","004e0b19513b76d70a1408ffd441b960","00573225d6c2f6f0df925f1ad5b840ee","005854a029473ee91bf612927bf641bb","0067868109c1280e63b3c95ed14194f5","006d0ffd3b1d3d76ec75608d51653f9c","00709b7c5c91f5bb043bfb61eab8b31d","00729a127bc2ca8cd5439fa1c4ef3225","0072de37e1b15943d6289a63b19bef1f","00732f18727e5a406d8e6308d37beef6","00742faf994a8410dc4712ce9a62a523","00747b8b4434328a14f2b01076401547","0074f5fe7a38106d9ab66f188a8c30ea","00758e0782742b9e7654b8334e6a65fc","00785d3ed44c5242394b335d08bcb622","007ab2359d4cc46b0c57c8d6c222f18f","007c2bc54302446e8b413cd93e4137f5","007de67e18c4a12aa39f1a66c33df377","007e2f45ffe5a446393fce2790c7da1d","007f17a835a8c33a87f7aa4db0fef224","00806d510017d099f18ed0e5ebf1fa4f","00820ff07976943ebe6604f6dc7fc90c","0082f0dd6f5440f253d44f36fb06a487","00831e473b1816a19fbd42f2c41ba6f6","0084747bb4ec11b5a27ba7fe3db53c87"],"emails":["contact-admin@google.com"],"references":[],"permalink":"https:\/\/www.threatcrowd.org\/domain.php?domain=google.com"}'
                    aSelf.m_strRawResult = result
                    return aSelf.Parse( aDomain , result )
                except ( urllib.error.HTTPError , urllib.error.URLError , http.client.HTTPException ) as err :
                    logging.warning( err )
                    nRetryCnt -= 1
                except Exception as err :
                    print( traceback.format_exc() )
                    logging.exception( err )
                    break
            return None

    def GetRawResult( aSelf ) :
        return aSelf.m_strRawResult

    def Parse( aSelf , aDomain , aThreatCrowdRet ) :
        if aDomain in aSelf.m_dictCache.keys() :
            return aSelf.m_dictCache[aDomain]
        else :
            d = defaultdict( set )
            parsed = json.loads( aThreatCrowdRet )
            if "resolutions" in parsed :
                lsResolutions = []
                lsResolutionsStr = []
                for record in parsed["resolutions"] :
                    recordItem = aSelf.CThreatCrowdResolutionItem( record )
                    for item in lsResolutions :
                        if ( recordItem.m_strIpAddr == item.m_strIpAddr and
                             len( recordItem.m_strLastResolved ) > 0 and
                             recordItem.m_strLastResolved not in item.m_lsLastResolved ) :
                            item.m_lsLastResolved.append( recordItem.m_strLastResolved )
                            item.m_lsLastResolved.sort( reverse = True )
                            break
                    else :
                        lsResolutions.append( recordItem )
                lsResolutions.sort( reverse = True )

                for record in lsResolutions :
                    lsResolutionsStr.append( str(record) )
                d["resolutions"] = lsResolutionsStr

            lsSimpleFields = [ "emails" , "hashes" , "references" ]
            for field in lsSimpleFields :
                if field in parsed and 0 < len(parsed[field]) :
                    d[field] = parsed[field]

            aSelf.m_dictCache[aDomain] = d
            return d



def HandleThreatCrowd( aDomains , aConfig , aExcel , aExcelFmts ) :
    #Get config
    nTimeout = aConfig.getint( "General" , "QueryTimeout" ) / 1000
    nMaxRetryCnt = aConfig.getint( "General" , "QueryRetryCnt" )
    bWriteExcel = ( False != aConfig.getboolean( "General" , "WriteExcel" ) )
    bWriteDetail = ( False != aConfig.getboolean( "Debug" , "WriteDetail" ) )

    #Set interesting fields information
    lsSheetInfo = [ CExcelSheetInfo( 0 , "A" , "Domain" , 32 , aExcelFmts["Vcenter"] ) ,
                    CExcelSheetInfo( 1 , "B" , "Email" , 46 , aExcelFmts["WrapTop"] ) ,
                    CExcelSheetInfo( 2 , "C" , "Hash" , 46 , aExcelFmts["WrapTop"] ) ,
                    CExcelSheetInfo( 3 , "D" , "Resolution" , 46 , aExcelFmts["WrapTop"] ) ,
                    CExcelSheetInfo( 4 , "E" , "Reference" , 32 , aExcelFmts["Top"] ) ,
                    CExcelSheetInfo( 5 , "F" , "Raw" , 100 , aExcelFmts["WrapTop"] )
                  ]
    lsColNameMapping = { "emails" : "Email" ,
                         "hashes" : "Hash" , 
                         "resolutions" : "Resolution" ,
                         "references" : "Reference"
                       }

    #Initialize sheet info
    if bWriteExcel :
        SHEET_NAME = "ThreatCrowd"
        sheet = None
        for sheet in aExcel.worksheets() :
            if sheet.get_name() == SHEET_NAME :
                break
        if sheet == None or sheet.get_name() != SHEET_NAME :
            sheet = aExcel.add_worksheet( SHEET_NAME )
        
        #Set column layout in excel    
        for info in lsSheetInfo :
            sheet.set_column( "{}:{}".format(info.strColId,info.strColId) , info.nColWidth , info.strColFormat )

    #Start to get domain information
    uCount = 0
    for strDomain in aDomains :
        print( "Checking ThreatCrowd for {}".format( strDomain ) )
        if bWriteExcel :
            sheet.write( uCount + 1 , lsSheetInfo[0].nColIndex , strDomain )

        threatcrowd = CThreatCrowd()
        result = threatcrowd.Query( strDomain , nTimeout , nMaxRetryCnt )
        if result :
            for key , value in result.items() :
                print( "{} = {}".format( key , value ) )
                if bWriteExcel :
                    nColIndex = -1
                    for info in lsSheetInfo :
                        if info.strColName == lsColNameMapping[key] :
                            nColIndex = info.nColIndex
                            break
                    sheet.write( uCount + 1 , nColIndex , os.linesep.join(value) )
            if bWriteExcel :
                sheet.write( uCount + 1 , lsSheetInfo[-1].nColIndex , threatcrowd.GetRawResult() )

        print( "\n" )
        uCount = uCount + 1
        
    #Make an excel table so one can find correlations easily
    if bWriteExcel :
        lsColumns = []
        for info in lsSheetInfo :
            lsColumns.append( { "header" : info.strColName } )
        sheet.add_table( "{}1:{}{}".format(lsSheetInfo[0].strColId , lsSheetInfo[-1].strColId , uCount+1) , 
                         { "header_row" : True , "columns" : lsColumns } 
                       )
        sheet.freeze_panes( 1 , 1 )