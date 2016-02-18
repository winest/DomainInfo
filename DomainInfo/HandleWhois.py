import os
import sys
import logging
import traceback
import platform
import subprocess
import configparser
import re
from collections import defaultdict

from ExcelInfo import *



class CWhois :
    class CWhoisQueryItem :
        def __init__( aSelf , aRegex , aRegexGroup ) :
            aSelf.m_re = aRegex
            aSelf.m_nRegexGroup = aRegexGroup
   
    def __init__( aSelf , aWriteDetail = False ) :
        if platform.system().strip().lower() == "windows" :
            aSelf.m_strCmd = "_Tools/Windows/whois"
        else :
            aSelf.m_strCmd = "_Tools/Linux/whois"

        aSelf.m_lsFields = []   #Use list to keep the comparison order. Each element tuple is the form of <FeildName , CWhoisQueryItem>
        aSelf.m_dictCache = {}    #<key , value> = <domain , domain properties dict>
        aSelf.m_strRawResult = None
        aSelf.m_bWriteDetail = aWriteDetail

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
                    aSelf.m_strRawResult = result if result else "<NULL>"
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
                                d[key].add( "{}{}({})".format( strData , os.linesep , line.strip() ) )
                            else :
                                d[key].add( strData )
                        break
            aSelf.m_dictCache[aDomain] = d
            return d



def HandleWhois( aDomains , aConfig , aExcel , aExcelFmts ) :
    #Get config
    nTimeout = aConfig.getint( "General" , "QueryTimeout" ) / 1000
    nMaxRetryCnt = aConfig.getint( "General" , "QueryRetryCnt" )
    bWriteExcel = ( False != aConfig.getboolean( "General" , "WriteExcel" ) )
    bWriteDetail = ( False != aConfig.getboolean( "Debug" , "WriteDetail" ) )

    #Set interesting fields information
    lsSheetInfo = [ CExcelSheetInfo( 0 , "A" , "Domain" , 32 , aExcelFmts["Vcenter"] ) ,
                    CExcelSheetInfo( 1 , "B" , "Email" , 46 , aExcelFmts["WrapTop"] ) ,
                    CExcelSheetInfo( 2 , "C" , "Country" , 8 , aExcelFmts["WrapTop"] ) ,
                    CExcelSheetInfo( 3 , "D" , "Registrar" , 26 , aExcelFmts["WrapTop"] ) ,
                    CExcelSheetInfo( 4 , "E" , "Registrant" , 26 , aExcelFmts["WrapTop"] ) ,
                    CExcelSheetInfo( 5 , "F" , "CreationTime" , 20 , aExcelFmts["WrapTop"] ) ,
                    CExcelSheetInfo( 6 , "G" , "UpdateTime" , 20 , aExcelFmts["WrapTop"] ) ,
                    CExcelSheetInfo( 7 , "H" , "ExpireTime" , 20 , aExcelFmts["WrapTop"] ) ,
                    CExcelSheetInfo( 8 , "I" , "Raw" , 100 , aExcelFmts["Top"] )
                  ]

    #Initialize sheet info
    if bWriteExcel :
        SHEET_NAME = "Whois"
        sheet = None
        for sheet in aExcel.worksheets() :
            if sheet.get_name() == "Whois" :
                break
        if sheet == None or sheet.get_name() != SHEET_NAME :
            sheet = aExcel.add_worksheet( "Whois" )

        #Set column layout in excel    
        for info in lsSheetInfo :
            sheet.set_column( "{}:{}".format(info.strColId,info.strColId) , info.nColWidth , info.strColFormat )

    #Initialize CWhois object, be aware of the sequence of regex, put more accurate regex at first
    who = CWhois( bWriteDetail )
    who.AddField( lsSheetInfo[1].strColName , re.compile(r"^.+\s+([^@, ]+@[^@, ]+\.[^@, ]+)\s*$" , re.IGNORECASE) , 1 )
    who.AddField( lsSheetInfo[2].strColName , re.compile(r"^.*?Country\s*:\s*?(.+)\s*$" , re.IGNORECASE) , 1 )
    who.AddField( lsSheetInfo[3].strColName , re.compile(r"^.*?(Registrar|Company)\s*?(Name|Organization)?:\s*?(.+)\s*$" , re.IGNORECASE) , 3 )
    who.AddField( lsSheetInfo[4].strColName , re.compile(r"^.*?(Registrant|Company)\s*?(Name|Organization)?:\s*?(.+)\s*$" , re.IGNORECASE) , 3 )
    who.AddField( lsSheetInfo[7].strColName , re.compile(r"^.*?Expir([ey][ds]?|ation)\s*(Date)?.*?(:\s*?|\s+?on\s+?)(.*[0-9]{4}.*)\s*$" , re.IGNORECASE) , 4 )
    who.AddField( lsSheetInfo[6].strColName , re.compile(r"^.*?(Last(-|\s)?)?(Record\s)?Update.*?(Date)?(:\s*?|\s+?on\s+?)(.*[0-9]{4}.*)\s*$" , re.IGNORECASE) , 6 )
    who.AddField( lsSheetInfo[5].strColName , re.compile(r"^.*?(Record)?\s*?(Creat.*?|Registration)\s*?(Date)?.*?(:\s*?|\s+?on\s+?)(.*[0-9]{4}.*)\s*" , re.IGNORECASE) , 5 )

    

    #Start to get domain information
    uCount = 0
    for strDomain in aDomains :
        print( "Checking Whois for {}".format( strDomain ) )
        if bWriteExcel :
            sheet.write( uCount + 1 , lsSheetInfo[0].nColIndex , strDomain )        

        result = who.Query( strDomain , nTimeout , nMaxRetryCnt )
        if result :
            for key , value in result.items() :
                print( "{} = {}".format( key , value ) )
                if bWriteExcel :
                    nColIndex = -1
                    for info in lsSheetInfo :
                        if info.strColName == key :
                            nColIndex = info.nColIndex
                            break
                    sheet.write( uCount + 1 , nColIndex , os.linesep.join(value) )
            if bWriteExcel :
                sheet.write( uCount + 1 , lsSheetInfo[-1].nColIndex , who.GetRawResult() )

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