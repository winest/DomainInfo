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
        m_strIpAddr = None
        m_strLastResolved = None
        def __init__( aSelf , aResolutionItem ) :
            if "ip_address" in aResolutionItem :
                aSelf.m_strIpAddr = aResolutionItem["ip_address"]
            if "last_resolved" in aResolutionItem :
                aSelf.m_strLastResolved = aResolutionItem["last_resolved"]
        def __str__( aSelf ) :
            return "{} ({})".format( aSelf.m_strIpAddr , aSelf.m_strLastResolved )
        def __repr__( aSelf ) :
            return aSelf.__str__()
        def __lt__( aSelf , aRhs ) : 
            return aSelf.m_strLastResolved < aRhs.m_strLastResolved

    m_dictCache = {}    #<key , value> = <domain , domain properties dict>
    m_strRawResult = None

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
                    lsResolutions.append( aSelf.CThreatCrowdResolutionItem(record) )
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