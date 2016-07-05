import os
import sys
import logging
import traceback
import platform
import subprocess
import configparser
import fnmatch
import time
import hashlib
import re
import xlsxwriter

from HandleWhois import *
from HandleThreatCrowd import *





if __name__ == "__main__" :
    logging.basicConfig( format="[%(asctime)s][%(levelname)s][%(process)04X:%(thread)04X][%(filename)s][%(funcName)s_%(lineno)d]: %(message)s" , level=logging.DEBUG )

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
    
        #Get the list of domains
        g_setDomains = set( sys.argv[1].split( ";" ) )
        
        #Create excel if needed
        g_bWriteExcel = ( False != g_config.getboolean( "General" , "WriteExcel" ) )
        g_excel = None
        g_excelFmt = { "Top" : None , "Vcenter" : None , "WrapTop" : None , "WrapVcenter" : None }
        if g_bWriteExcel :
            g_excel = xlsxwriter.Workbook( "{}\\DomainInfo-{}.xlsx".format(g_strMainDir , time.strftime("%Y%m%d_%H%M%S")) )
            g_excelFmt["Top"] = g_excel.add_format( {"valign" : "top"} )
            g_excelFmt["Vcenter"] = g_excel.add_format( {"valign" : "vcenter"} )
            g_excelFmt["WrapTop"] = g_excel.add_format( {"text_wrap" : 1 , "valign" : "top"} )
            g_excelFmt["WrapVcenter"] = g_excel.add_format( {"text_wrap" : 1 , "valign" : "vcenter"} )
        
        #Start to get domain information
        if ( False != g_config.getboolean( "Features" , "Whois" ) ) :
            HandleWhois( g_setDomains , g_config , g_excel , g_excelFmt )
        if ( False != g_config.getboolean( "Features" , "ThreatCrowd" ) ) :
            HandleThreatCrowd( g_setDomains , g_config , g_excel , g_excelFmt )
        
        #Close the excel
        if g_bWriteExcel :
            g_excel.close()
    except Exception as ex :
        print( traceback.format_exc() )
        logging.exception( ex )
    print( "Press any key to leave" )
    input()