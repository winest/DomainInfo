import os
import platform
import sys
import subprocess
import configparser
import fnmatch
import logging
import time
import hashlib
import xlsxwriter
import whois
import re
from collections import defaultdict



class CWhois :
    class CWhoisQueryItem :
        m_re = None
        m_nRegexGroup = None
        def __init__( aSelf , aRegex , aRegexGroup ) :
            aSelf.m_re = aRegex
            aSelf.m_nRegexGroup = aRegexGroup

    m_strCmd = None
    m_lsFields = []   #Use list to keep the comparison order. Each element tuple is the form of <FeildName , CWhoisQueryItem>
    m_bWriteDetail = False
    m_dictCache = {}    #<key , value> = <domain , domain properties dict>
    m_strRawResult = None
    def __init__( aSelf ) :
        if platform.system().strip().lower() == "windows" :
            aSelf.m_strCmd = "_Tools/Windows/whois"
        else :
            aSelf.m_strCmd = "_Tools/Linux/whois"

        if ( False != g_config.getboolean( "Debug" , "WriteDetail" ) ) :
            aSelf.m_bWriteDetail = True

    def AddField( aSelf , aName , aRegex , aRegexGroup ) :
        #Don't add duplicate field
        for first , second in aSelf.m_lsFields :
            if first == aName :
                return False
        aSelf.m_lsFields.append( ( aName ,  aSelf.CWhoisQueryItem( aRegex , aRegexGroup ) ) )
        return True

    def Query( aSelf , aDomain , aTimeout = 10 , aRetryCnt = 5 ) :
        if not aDomain :
            return None
        elif aDomain in aSelf.m_dictCache.keys() :
            logging.info( "{}: Cache hit".format(aDomain) )
            return aSelf.m_dictCache[aDomain]
        else :
            while aRetryCnt > 0 :
                try :
                    p = subprocess.Popen( [aSelf.m_strCmd , aDomain] , stdout=subprocess.PIPE , stderr=subprocess.STDOUT )
                    result = p.communicate( timeout = aTimeout )[0].decode( errors=r"ignore" )
                    aSelf.m_strRawResult = result if result else ""
                    if p.returncode != 0 :
                        logging.error( "{}: ReturnCode is {}".format(aDomain , p.returncode) )
                        return None
                    else :
                        return aSelf.Parse( aDomain , result )
                except subprocess.TimeoutExpired as err :
                    logging.warning( "{}: {}".format(aDomain , err) )
                    aRetryCnt -= 1
            return None

    def GetRawResult( aSelf ) :
        return aSelf.m_strRawResult

    def Parse( aSelf , aDomain , aWhoisRet ) :
        if aDomain in aSelf.m_dictCache.keys() :
            return aSelf.m_dictCache[aDomain]
        else :
            d = defaultdict( set )
            for line in aWhoisRet.split( os.linesep ) :
                for key , value in aSelf.m_lsFields :
                    field = value.m_re.match( line )
                    if field :
                        strData = field.group( value.m_nRegexGroup ).strip()
                        if len( strData ) > 0 :
                            if aSelf.m_bWriteDetail :
                                d[key].add( "{}\n({})".format( strData , line.strip() ) )
                            else :
                                d[key].add( strData )
                        break
            aSelf.m_dictCache[aDomain] = d
            return d


class CExcelSheetInfo :
    strSheetName = None
    nColIndex = None
    strColId = None
    strColName = None
    nColWidth = None
    strColFormat = None
    def __init__( aSelf , aSheetName , aColIndex , aColId , aColName , aColWidth , aColFormat ) :
        aSelf.strSheetName = aSheetName
        aSelf.nColIndex = aColIndex
        aSelf.strColId = aColId
        aSelf.strColName = aColName
        aSelf.nColWidth = aColWidth
        aSelf.strColFormat = aColFormat

    



if __name__ == "__main__" :
    logging.basicConfig( format="[%(asctime)s][%(levelname)s][%(process)d:%(thread)d][%(filename)s][%(funcName)s_%(lineno)d]: %(message)s" , level=logging.DEBUG )

    if len( sys.argv ) <= 1 :
        print( "Usage: {} <DomainsSperateBy\";\">".format( os.path.basename( sys.argv[0] ) ) )
        exit( 0 )

    g_strMainDir = os.path.dirname( sys.argv[0] )
    if ( 0 == len( g_strMainDir ) ) :
        g_strMainDir = "."
    g_config = configparser.ConfigParser()

    try :
        print( "Load config from {}\\{}".format( g_strMainDir , "DomainInfo.ini" ) )
        g_config.read( "{}\\{}".format( g_strMainDir , "DomainInfo.ini" ) )
        logging.getLogger().setLevel( g_config["Debug"]["LogLevel"] )
    
        setDomains = set( sys.argv[1].split( ";" ) )
        bWriteExcel = ( False != g_config.getboolean( "General" , "WriteExcel" ) )

        
        #Create excel if needed
        if bWriteExcel :
            workbook = xlsxwriter.Workbook( "{}\\DomainInfo-{}.xlsx".format(g_strMainDir , time.strftime("%Y%m%d_%H%M%S")) )
            worksheet = workbook.add_worksheet()
            fmtWrapTop = workbook.add_format( {"text_wrap" : 1 , "valign" : "top"} )
            fmtWrapCenter = workbook.add_format( {"text_wrap" : 1 , "valign" : "vcenter"} )
            fmtTop = workbook.add_format( {"valign" : "top"} )
            fmtCenter = workbook.add_format( {"valign" : "vcenter"} )
        else :
            fmtWrapTop = None
            fmtWrapCenter = None
            fmtTop = None
            fmtCenter = None

        #Initialize sheet info
        lsSheetInfo = []
        lsSheetInfo.append( CExcelSheetInfo( "Whois" , 0 , "A" , "Domain" , 32 , fmtCenter ) )
        lsSheetInfo.append( CExcelSheetInfo( "Whois" , 1 , "B" , "Email" , 46 , fmtWrapTop ) )
        lsSheetInfo.append( CExcelSheetInfo( "Whois" , 2 , "C" , "Country" , 8 , fmtWrapTop ) )
        lsSheetInfo.append( CExcelSheetInfo( "Whois" , 3 , "D" , "Registrar" , 26 , fmtWrapTop ) )
        lsSheetInfo.append( CExcelSheetInfo( "Whois" , 4 , "E" , "Registrant" , 26 , fmtWrapTop ) )
        lsSheetInfo.append( CExcelSheetInfo( "Whois" , 5 , "F" , "CreationTime" , 20 , fmtWrapTop ) )
        lsSheetInfo.append( CExcelSheetInfo( "Whois" , 6 , "G" , "UpdateTime" , 20 , fmtWrapTop ) )
        lsSheetInfo.append( CExcelSheetInfo( "Whois" , 7 , "H" , "ExpireTime" , 20 , fmtWrapTop ) )
        lsSheetInfo.append( CExcelSheetInfo( "Whois" , 8 , "I" , "Raw" , 100 , fmtTop ) )

        #Set column layout in excel
        if bWriteExcel :
            for info in lsSheetInfo :
                worksheet.set_column( "{}:{}".format(info.strColId,info.strColId) , info.nColWidth , info.strColFormat )

        #Initialize CWhois object, be aware of the sequence of regex, put more accurate regex at first
        who = CWhois()
        who.AddField( lsSheetInfo[1].strColName , re.compile(r"^.+\s+([^@, ]+@[^@, ]+\.[^@, ]+)\s*$" , re.IGNORECASE) , 1 )
        who.AddField( lsSheetInfo[2].strColName , re.compile(r"^.*?Country\s*:\s*?(.+)\s*$" , re.IGNORECASE) , 1 )
        who.AddField( lsSheetInfo[3].strColName , re.compile(r"^.*?(Registrar|Company)\s*?(Name|Organization)?:\s*?(.+)\s*$" , re.IGNORECASE) , 3 )
        who.AddField( lsSheetInfo[4].strColName , re.compile(r"^.*?(Registrant|Company)\s*?(Name|Organization)?:\s*?(.+)\s*$" , re.IGNORECASE) , 3 )
        who.AddField( lsSheetInfo[7].strColName , re.compile(r"^.*?Expir([ey][ds]?|ation)\s*(Date)?.*?(:\s*?|\s+?on\s+?)(.*[0-9]{4}.*)\s*$" , re.IGNORECASE) , 4 )
        who.AddField( lsSheetInfo[6].strColName , re.compile(r"^.*?(Last(-|\s)?)?(Record\s)?Update.*?(Date)?(:\s*?|\s+?on\s+?)(.*[0-9]{4}.*)\s*$" , re.IGNORECASE) , 6 )
        who.AddField( lsSheetInfo[5].strColName , re.compile(r"^.*?(Record)?\s*?(Creat.*?|Registration)\s*?(Date)?.*?(:\s*?|\s+?on\s+?)(.*[0-9]{4}.*)\s*" , re.IGNORECASE) , 5 )

        #Start to get domain information
        g_uCount = 0
        for strDomain in setDomains :
            print( "Checking {}".format( strDomain ) )
            if bWriteExcel :
                worksheet.write( g_uCount + 1 , lsSheetInfo[0].nColIndex , strDomain )

            result = who.Query( strDomain )
            if result :
                for key , value in result.items() :
                    print( "{} = {}".format( key , value ) )
                    if bWriteExcel :
                        nColIndex = -1
                        for info in lsSheetInfo :
                            if info.strColName == key :
                                nColIndex = info.nColIndex
                                break
                        worksheet.write( g_uCount + 1 , nColIndex , os.linesep.join(value) )
                if bWriteExcel :
                    worksheet.write( g_uCount + 1 , lsSheetInfo[-1].nColIndex , who.GetRawResult() )

            print( "\n" )
            g_uCount = g_uCount + 1

        
        #Make an excel table so one can find correlations easily
        if bWriteExcel :
            lsColumns = []
            for info in lsSheetInfo :
                lsColumns.append( { "header" : info.strColName } )
            worksheet.add_table( "{}1:{}{}".format(lsSheetInfo[0].strColId , lsSheetInfo[-1].strColId , g_uCount+1) , 
                                 { "header_row" : True , "columns" : lsColumns } 
                               )
            worksheet.freeze_panes( 1 , 1 )
            workbook.close()
    except Exception as ex :
        logging.exception( ex )
    print( "Press any key to leave" )
    input()