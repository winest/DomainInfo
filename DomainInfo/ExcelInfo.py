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
import urllib.request
from collections import defaultdict

import xlsxwriter



class CExcelSheetInfo :
    nColIndex = None
    strColId = None
    strColName = None
    nColWidth = None
    strColFormat = None
    def __init__( aSelf , aColIndex , aColId , aColName , aColWidth , aColFormat ) :
        aSelf.nColIndex = aColIndex
        aSelf.strColId = aColId
        aSelf.strColName = aColName
        aSelf.nColWidth = aColWidth
        aSelf.strColFormat = aColFormat