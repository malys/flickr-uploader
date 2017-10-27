#!/usr/bin/env python

"""
    XXX: Being updated to use flickrapi and OAUTH
    XXX: To double check the DRY-RUN option.
    XXX: An invalid FOLDER defined in .INI file will delete all files! Fixed!
    XXX: RE-upload pictures removed from flickr.

    flickr-uploader designed for Synology Devices
    Upload a directory of media to Flickr to use as a backup to your local storage.

    Features:

    -Uploads both images and movies (JPG, PNG, GIF, AVI, MOV, 3GP files)
    -Stores image information locally using a simple SQLite database
    -Automatically creates "Sets" based on the folder name the media is in
    -Ignores ".picasabackup" directory
    -Automatically removes images from Flickr when they are removed from your local hard drive

    Requirements:

    -Python 2.7+
    -flicrkapi module
    -File write access (for the token and local database)
    -Flickr API key (free)

    Setup:

    Go to http://www.flickr.com/services/apps/create/apply and apply for an API key Edit the following variables in the uploadr.ini

    FILES_DIR = "files/"
    FLICKR = { "api_key" : "", "secret" : "", "title" : "", "description" : "", "tags" : "auto-upload", "is_public" : "0", "is_friend" : "0", "is_family" : "1" }
    SLEEP_TIME = 1 * 60
    DRIP_TIME = 1 * 60
    DB_PATH = os.path.join(FILES_DIR, "fickerdb")
    Place the file uploadr.py in any directory and run:

    $ ./uploadr.py

    It will crawl through all the files from the FILES_DIR directory and begin the upload process.

    Upload files placed within a directory to your Flickr account.

   Inspired by:
        https://github.com/sybrenstuvel/flickrapi
        http://micampe.it/things/flickruploadr
        https://github.com/joelmx/flickrUploadr/blob/master/python3/uploadr.py

   Usage:

   cron entry (runs at the top of every hour )
   0  *  *  *  * /full/path/to/uploadr.py > /dev/null 2>&1

   This code has been updated to use the new Auth API from flickr.

   You may use this code however you see fit in any form whatsoever.


"""

# ----------------------------------------------------------------------------
# Import section
#
import httplib
import sys
import argparse
import mimetools
import mimetypes
import os
import time
# Check if it is still required
import urllib
# Check if it is still required
import urllib2
# Check if it is still required
import webbrowser
import sqlite3 as lite
# Check if it is still required
import json
from xml.dom.minidom import parse
import hashlib
import fcntl
import errno
import subprocess
import re
import ConfigParser
from multiprocessing.pool import ThreadPool
import flickrapi
import xml
import os.path
import logging
import pprint

# ----------------------------------------------------------------------------
# Python version must be greater than 2.7 for this script to run
#
if sys.version_info < (2, 7):
    sys.stderr.write("This script requires Python 2.7 or newer.\n")
    sys.stderr.write("Current version: " + sys.version + "\n")
    sys.stderr.flush()
    sys.exit(1)

# ----------------------------------------------------------------------------
# Constants class
#
# List out the constants to be used
#
class UPLDRConstants:
    """ UPLDRConstants class
    """

    TimeFormat = '%Y.%m.%d %H:%M:%S'
    
    def __init__(self):
        """ Constructor
        """
        pass

# ----------------------------------------------------------------------------
# Global Variables
#   nutime = for working with time module (import time)
#   nuflickr = object for flicks API module (import flickrapi)
#
nutime = time
nuflickr = None

# -----------------------------------------------------------------------------
# isThisStringUnicode
#
# Returns true if String is Unicode
#
def isThisStringUnicode( s):
    """
    Determines if a string is Unicode (return True) or not (returns False) to allow correct print operations.
    Example:
        print(u'File ' + file.encode('utf-8') + u'...') if isThisStringUnicode( file) else ("File " + file + "...")
    """
    if isinstance(s, unicode):
        return True
    elif isinstance(s, str):
        return False
    else:
        return False

# -------------------------------------------------------------------------
# niceprint 
#
# Print a message with the format:
#   [2017.10.25 22:32:03]:[PRINT   ]:[uploadr] Some Message
#
def niceprint(s):
    """
    Print a message with the format:
        [2017.10.25 22:32:03]:[PRINT   ]:[uploadr] Some Message
    """
    # print(u'DEBUG--->UTF-8:'.encode('utf-8') + s.encode('utf-8')) if isThisStringUnicode( s) else ('DEBUG--->ASCII:' + s)
    print('[{!s}]:[{!s:8s}]:[{!s}] {!s}'.format(
            nutime.strftime(UPLDRConstants.TimeFormat),
            'PRINT',
            'uploadr',
            s.encode('utf-8') if isThisStringUnicode(s) else s))
# ----------------------------------------------------------------------------
# Read Config from config.ini file
#
# Obtain configuration from uploadr.ini
# Refer to contents of uploadr.ini for explanation on configuration parameters
#
config = ConfigParser.ConfigParser()
config.read(os.path.join(os.path.dirname(sys.argv[0]), "uploadr.ini"))
# FILES_DIR = eval(config.get('Config', 'FILES_DIR'))
if config.has_option('Config', 'FILES_DIR'):
    FILES_DIR = eval(config.get('Config', 'FILES_DIR'))
else:
    FILES_DIR = ""
FLICKR = eval(config.get('Config', 'FLICKR'))
SLEEP_TIME = eval(config.get('Config', 'SLEEP_TIME'))
DRIP_TIME = eval(config.get('Config', 'DRIP_TIME'))
DB_PATH = eval(config.get('Config', 'DB_PATH'))
TOKEN_CACHE = eval(config.get('Config', 'TOKEN_CACHE'))
LOCK_PATH = eval(config.get('Config', 'LOCK_PATH'))
TOKEN_PATH = eval(config.get('Config', 'TOKEN_PATH'))
EXCLUDED_FOLDERS = eval(config.get('Config', 'EXCLUDED_FOLDERS'))
IGNORED_REGEX = [re.compile(regex) for regex in eval(config.get('Config', 'IGNORED_REGEX'))]
ALLOWED_EXT = eval(config.get('Config', 'ALLOWED_EXT'))
RAW_EXT = eval(config.get('Config', 'RAW_EXT'))
FILE_MAX_SIZE = eval(config.get('Config', 'FILE_MAX_SIZE'))
MANAGE_CHANGES = eval(config.get('Config', 'MANAGE_CHANGES'))
RAW_TOOL_PATH = eval(config.get('Config', 'RAW_TOOL_PATH'))
CONVERT_RAW_FILES = eval(config.get('Config', 'CONVERT_RAW_FILES'))
FULL_SET_NAME = eval(config.get('Config', 'FULL_SET_NAME'))
SOCKET_TIMEOUT = eval(config.get('Config', 'SOCKET_TIMEOUT'))
MAX_UPLOAD_ATTEMPTS = eval(config.get('Config', 'MAX_UPLOAD_ATTEMPTS'))
# LOGGING_LEVEL = eval(config.get('Config', 'LOGGING_LEVEL'))
LOGGING_LEVEL = (config.get('Config', 'LOGGING_LEVEL')
                 if config.has_option('Config', 'LOGGING_LEVEL')
                 else logging.WARNING)

# ----------------------------------------------------------------------------
# Logging
#
# Obtain configuration level from Configuration file.
# If not available or not valid assume WARNING level and notify of that fact.
# Two uses:
#   Simply log message at approriate level
#       logging.warning('Status: {!s}'.format('Setup Complete'))
#   Control additional specific output depending on level
#       if LOGGING_LEVEL <= logging.INFO:
#            logging.info('Output for {!s}:'.format('uploadResp'))
#            xml.etree.ElementTree.dump(uploadResp)
#            <generate any further output>
#
if (int(LOGGING_LEVEL) if str.isdigit(LOGGING_LEVEL) else 99) not in [
                        logging.NOTSET,
                        logging.DEBUG,
                        logging.INFO,
                        logging.WARNING,
                        logging.ERROR,
                        logging.CRITICAL]:
    LOGGING_LEVEL = logging.WARNING
    sys.stderr.write('[{!s}]:[WARNING ]:[uploadr] LOGGING_LEVEL not defined or incorrect '
                     'on INI file: [{!s}]. '
                     'Assuming WARNING level.\n'.format(
                            nutime.strftime(UPLDRConstants.TimeFormat),
                            os.path.join(os.path.dirname(sys.argv[0]),
                                         "uploadr.ini")))
# Force conversion of LOGGING_LEVEL into int() for later use in conditionals
LOGGING_LEVEL = int(LOGGING_LEVEL)
logging.basicConfig(stream=sys.stderr,
                    level=int(LOGGING_LEVEL),
                    datefmt=UPLDRConstants.TimeFormat,
                    format='[%(asctime)s]:[%(levelname)-8s]:[%(name)s] '
                           '%(message)s')
                           # '\n\t%(message)s')

# ----------------------------------------------------------------------------
# Test section for logging.
#   Only applicable if LOGGING_LEVEL is INFO or below (DEBUG, NOTSET)
#
if LOGGING_LEVEL <= logging.INFO:
    logging.info(u'sys.getfilesystemencoding:[{!s}]'.
                    format(sys.getfilesystemencoding()))
    logging.info( 'LOGGING_LEVEL Value: {!s}'.format(LOGGING_LEVEL))
    if LOGGING_LEVEL <= logging.WARNING:
        logging.critical('Message with {!s}'.format(
                                    'CRITICAL UNDER min WARNING LEVEL'))
        logging.error('Message with {!s}'.format(
                                    'ERROR UNDER min WARNING LEVEL'))
        logging.warning('Message with {!s}'.format(
                                    'WARNING UNDER min WARNING LEVEL'))
        logging.info('Message with {!s}'.format(
                                    'INFO UNDER min WARNING LEVEL'))
if LOGGING_LEVEL <= logging.INFO:
    logging.info('Message with {!s}'.format(
                                'FLICKR Configuration:'))
    pprint.pprint(FLICKR)
    
# ----------------------------------------------------------------------------
# APIConstants class
#
# To be removed.
#
class APIConstants:
    """ APIConstants class
    """

    base = "https://api.flickr.com/services/"
    rest = base + "rest/"
    auth = base + "auth/"
    upload = base + "upload/"
    replace = base + "replace/"

    def __init__(self):
        """ Constructor
        """
        pass

api = APIConstants()

# ----------------------------------------------------------------------------
# FileWithCallback class
#
# For use with flickrapi upload for showing callback progress information
# Check function callback definition
# 
class FileWithCallback(object):
    def __init__(self, filename, callback):
        self.file = open(filename, 'rb')
        self.callback = callback
        # the following attributes and methods are required
        self.len = os.path.getsize(filename)
        self.fileno = self.file.fileno
        self.tell = self.file.tell

    def read(self, size):
        if self.callback:
            self.callback(self.tell() * 100 // self.len)
        return self.file.read(size)
 
# ----------------------------------------------------------------------------
# callback
#
# For use with flickrapi upload for showing callback progress information
# Check function FileWithCallback definition
# 
def callback(progress):
    # only print rounded percentages: 0, 10, 20, 30, up to 100
    # adapt as required
    if ((progress % 30) == 0):
        print(progress)

# ----------------------------------------------------------------------------
# Uploadr
#
#   Main class for uploading of files.
#   
class Uploadr:
    """ Uploadr class
    """

    # Flicrk connection authentication token
    token = None
    perms = ""

    def __init__(self):
        """ Constructor
        """
        self.token = self.getCachedToken()

    # Maybe removed after migration to flickrapi
    def signCall(self, data):
        """
        Signs args via md5 per http://www.flickr.com/services/api/auth.spec.html (Section 8)
        """
        keys = data.keys()
        keys.sort()
        foo = ""
        for a in keys:
            foo += (a + data[a])

        f = FLICKR["secret"] + "api_key" + FLICKR["api_key"] + foo
        # f = "api_key" + FLICKR[ "api_key" ] + foo

        return hashlib.md5(f).hexdigest()

    def urlGen(self, base, data, sig):
        """ urlGen
        """
        data['api_key'] = FLICKR["api_key"]
        data['api_sig'] = sig
        encoded_url = base + "?" + urllib.urlencode(data)
        return encoded_url

    # -------------------------------------------------------------------------
    # authenticate
    #
    # Authenticates via flicrapi on flicr.com
    #
    def authenticate(self):
        """
        Authenticate user so we can upload files
        """
        global nuflickr 

        # instantiate nuflickr for connection to flickr via flickrapi
        nuflickr = flickrapi.FlickrAPI(FLICKR["api_key"], FLICKR["secret"], token_cache_location=TOKEN_CACHE)

        print("Getting new token")
        
        # Get request token
        nuflickr.get_request_token(oauth_callback='oob')
    
        # Show url. Copy and paste it in your browser
        authorize_url = nuflickr.auth_url(perms=u'delete')
        print(authorize_url)
    
        # Prompt for verifier code from the user 
        verifier = unicode(raw_input('Verifier code: '))
    
        if LOGGING_LEVEL <= logging.WARNING:
            logging.warning('Verifier: {!s}'.format(verifier))
    
        # Trade the request token for an access token
        print(nuflickr.get_access_token(verifier))

        if LOGGING_LEVEL <= logging.WARNING:
            logging.critical('{!s} with {!s} permissions: {!s}'.format(
                                        'Check Authentication',
                                        'delete',
                                        nuflickr.token_valid(perms='delete')))
            logging.critical('Token Cache: {!s}', nuflickr.token_cache.token)

    # -------------------------------------------------------------------------
    # getCachedToken
    #
    # If available, obtains the flicrapi Cached Token from local file.
    # Saves the token on the Class global variable "token"
    #
    def getCachedToken(self):
        """
        Attempts to get the flickr token from disk.
        """
        global nuflickr
        
        if LOGGING_LEVEL <= logging.INFO:
            logging.info('Obtaining Cached tokens')
        nuflickr = flickrapi.FlickrAPI(FLICKR["api_key"], FLICKR["secret"], token_cache_location=TOKEN_CACHE)

        try:
            if nuflickr.token_valid(perms='delete'):
                if LOGGING_LEVEL <= logging.INFO:
                    logging.info('Cached token obtained: {!s}'.format(
                                        nuflickr.token_cache.token))
                return nuflickr.token_cache.token
            else:
                if LOGGING_LEVEL <= logging.INFO:
                    logging.info('Token Non-Existant.')
                return None
        except:
            niceprint( "Unexpected error:" + sys.exc_info()[0])
            raise

    # -------------------------------------------------------------------------
    # checkToken
    #
    # If available, obtains the flicrapi Cached Token from local file.
    #
    # Returns
    #   true: if global token is defined and allows flicr 'delete' operation
    #   false: if  global token is not defined of flicr 'delete' is not allowed
    #
    def checkToken(self):
        """ checkToken
        flickr.auth.checkToken

        Returns the credentials attached to an authentication token.
        """
        global nuflickr

        if (self.token == None):
            return False
        else:
            nuflickr = flickrapi.FlickrAPI(FLICKR["api_key"], FLICKR["secret"], token_cache_location=TOKEN_CACHE)

            if nuflickr.token_valid(perms='delete'):
                return True
            else:
                logging.warning('Authentication required.')
                return False            

    #--------------------------------------------------------------------------
    # removeIgnoreMedia
    #
    # When EXCLUDED_FOLDERS defintion changes. You can run the -g
    # or --remove-ignored option in order to remove files previously loaded
    # files from
    # 
    def removeIgnoredMedia(self):
        niceprint('*****Removing ignored files*****')

        if (not self.checkToken()):
            self.authenticate()
        con = lite.connect(DB_PATH)
        con.text_factory = str

        with con:
            cur = con.cursor()
            cur.execute("SELECT files_id, path FROM files")
            rows = cur.fetchall()

            for row in rows:
                if (self.isFileIgnored(row[1].decode('utf-8'))):
                    success = self.deleteFile(row, cur)
        niceprint('*****Completed ignored files*****')

    #--------------------------------------------------------------------------
    # removeDeleteMedia
    #
    # Remove files deleted at the local source
    # 
    def removeDeletedMedia(self):
        """
        Remove files deleted at the local source
            loop through database
            check if file exists
            if exists, continue
            if not exists, delete photo from fickr (flickr.photos.delete.html)
        """

        niceprint('*****Removing deleted files*****')

        if (not self.checkToken()):
            self.authenticate()
        con = lite.connect(DB_PATH)
        con.text_factory = str

        with con:
            cur = con.cursor()
            cur.execute("SELECT files_id, path FROM files")
            rows = cur.fetchall()

            for row in rows:
                if (not os.path.isfile(row[1].decode('utf-8'))):
                    success = self.deleteFile(row, cur)
                    if LOGGING_LEVEL <= logging.WARNING:
                        logging.warning('deleteFile result: {!s}'.format(
                                                    success))

        niceprint('*****Completed deleted files*****')

    def upload(self):
        """ upload
        Add files to flickr and into their sets(Albums)
        If enabled CHANGE_MEDIA, checks for file changes and updates flickr
        """

        niceprint("*****Uploading files*****")

        allMedia = self.grabNewFiles()
        # If managing changes, consider all files
        if MANAGE_CHANGES:
            changedMedia = allMedia
        # If not, then get just the new and missing files
        else:
            con = lite.connect(DB_PATH)
            with con:
                cur = con.cursor()
                cur.execute("SELECT path FROM files")
                existingMedia = set(file[0] for file in cur.fetchall())
                changedMedia = set(allMedia) - existingMedia

        changedMedia_count = len(changedMedia)
        print("Found " + str(changedMedia_count) + " files")

        if args.processes:
            pool = ThreadPool(processes=int(args.processes))
            pool.map(self.uploadFile, changedMedia)
        else:
            count = 0
            for i, file in enumerate(changedMedia):
                if LOGGING_LEVEL <= logging.INFO:
                    logging.info('file:[{!s}] type(file):[{!s}]'.
                                    format( file,
                                            type(file)))
                #print u'file.type' + str(type(file)).encode('utf-8')
                success = self.uploadFile(file)
                if args.drip_feed and success and i != changedMedia_count - 1:
                    print("Waiting " + str(DRIP_TIME) + " seconds before next upload")
                    nutime.sleep(DRIP_TIME)
                count = count + 1;
                if (count % 100 == 0):
                    print("   " + str(count) + " files processed (uploaded, md5ed or timestamp checked)")
            if (count % 100 > 0):
                print("   " + str(count) + " files processed (uploaded, md5ed or timestamp checked)")

        niceprint("*****Completed uploading files*****")

    def convertRawFiles(self):
        
        # MSP: Not converted... not being used at this time as I do not use RAW Files.
        
        """ convertRawFiles
        """
        if (not CONVERT_RAW_FILES):
            return

        niceprint('*****Converting files*****')
        for ext in RAW_EXT:
            print(u'About to convert files with extension: ' + ext.encode('utf-8') + u' files.') if isThisStringUnicode( ext) else ("About to convert files with extension: " + ext + " files.")

            for dirpath, dirnames, filenames in os.walk(unicode(FILES_DIR, 'utf-8'), followlinks=True):
                if '.picasaoriginals' in dirnames:
                    dirnames.remove('.picasaoriginals')
                if '@eaDir' in dirnames:
                    dirnames.remove('@eaDir')
                for f in filenames:

                    fileExt = f.split(".")[-1]
                    filename = f.split(".")[0]
                    if (fileExt.lower() == ext):

                        if (not os.path.exists(dirpath + "/" + filename + ".JPG")):
                            if isThisStringUnicode( dirpath):
                                if isThisStringUnicode( f):
                                    print(u'About to create JPG from raw ' + dirpath.encode('utf-8') + u'/' + f.encode('utf-8'))
                                else:
                                    print(u'About to create JPG from raw ' + dirpath.encode('utf-8') + u'/'),
                                    print( f)
                            elif isThisStringUnicode( f):
                                print("About to create JPG from raw " + dirpath + "/"),
                                print( f.encode('utf-8'))
                            else:
                                print("About to create JPG from raw " + dirpath + "/" + f)

                            flag = ""
                            if ext is "cr2":
                                flag = "PreviewImage"
                            else:
                                flag = "JpgFromRaw"

                            command = RAW_TOOL_PATH + "exiftool -b -" + flag + " -w .JPG -ext " + ext + " -r '" + dirpath + "/" + filename + "." + fileExt + "'"
                            # print(command)

                            p = subprocess.call(command, shell=True)

                        if (not os.path.exists(dirpath + "/" + filename + ".JPG_original")):
                            if isThisStringUnicode( dirpath):
                                if isThisStringUnicode( f):
                                    print(u'About to copy tags from ' + dirpath.encode('utf-8') + u'/' + f.encode('utf-8') + u' to JPG.')
                                else:
                                    print(u'About to copy tags from ' + dirpath.encode('utf-8') + u'/'),
                                    print( f + " to JPG.")
                            elif isThisStringUnicode( f):
                                print("About to copy tags from " + dirpath + "/"),
                                print( f.encode('utf-8') + u' to JPG.')
                            else:
                                print("About to copy tags from " + dirpath + "/" + f + " to JPG.")


                            command = RAW_TOOL_PATH + "exiftool -tagsfromfile '" + dirpath + "/" + f + "' -r -all:all -ext JPG '" + dirpath + "/" + filename + ".JPG'"
                            # print(command)

                            p = subprocess.call(command, shell=True)

                            print("Finished copying tags.")

            print(u'Finished converting files with extension:' + ext.encode('utf-8') + u'.') if isThisStringUnicode( ext) else ("Finished converting files with extension:" + ext + ".")

        niceprint('*****Completed converting files*****')

    def grabNewFiles(self):
        """ grabNewFiles
        """

        files = []
        for dirpath, dirnames, filenames in os.walk(unicode(FILES_DIR, 'utf-8'), followlinks=True):
            for f in filenames:
                filePath = os.path.join(dirpath, f)
                if self.isFileIgnored(filePath):
                    continue
                if any(ignored.search(f) for ignored in IGNORED_REGEX):
                    continue
                ext = os.path.splitext(os.path.basename(f))[1][1:].lower()
                if ext in ALLOWED_EXT:
                    fileSize = os.path.getsize(dirpath + "/" + f)
                    if (fileSize < FILE_MAX_SIZE):
                        files.append(os.path.normpath(dirpath.encode('utf-8') + "/" + f.encode(' utf-8')).replace("'", "\'"))
                    else:
                        niceprint("Skipping file due to size restriction: " +
                                    ( os.path.normpath( dirpath.encode('utf-8') +
                                    "/" + f.encode('utf-8'))))
        files.sort()
        if LOGGING_LEVEL <= logging.INFO:
            logging.info('Output for {!s}:'.format('files'))
            pprint.pprint(files)

        return files

    #--------------------------------------------------------------------------
    # isFileIgnored
    #
    # Check if a filename is within the list of EXCLUDED_FOLDERS. Returns:
    #   true = if filename's folder is within one of the EXCLUDED_FOLDERS
    #   false = if filename's folder not on one of the EXCLUDED_FOLDERS
    #
    def isFileIgnored(self, filename):
        for excluded_dir in EXCLUDED_FOLDERS:
            if excluded_dir in os.path.dirname(filename):
                return True
        
        return False
    #--------------------------------------------------------------------------
    # uploadFile
    #
    # uploads a file into flickr
    #
    def uploadFile(self, file):
        """ uploadFile
        upload file into flickr
        """

        global nuflickr

        if ( args.dry_run == True):
            print(u'file.type=' + str(type(file)).encode('utf-8'))
            print(u'Dry Run Uploading ', file, '...')
            return True

        success = False
        con = lite.connect(DB_PATH)
        con.text_factory = str
        with con:
            cur = con.cursor()
            if LOGGING_LEVEL <= logging.DEBUG:
                logging.debug('Output for {!s}:'.format('uploadFILE SELECT'))
                logging.debug('{!s}: {!s}'.format('SELECT rowid,files_id,path,'
                                                 'set_id,md5,tagged,'
                                                 'last_modified FROM '
                                                 'files WHERE path = ?',
                                                 file))

            cur.execute('SELECT rowid,files_id,path,set_id,md5,tagged,'
                        'last_modified FROM files WHERE path = ?', (file,))
            row = cur.fetchone()
            if LOGGING_LEVEL <= logging.DEBUG:
                logging.debug('row {!s}:'.format(row))

            last_modified = os.stat(file).st_mtime;
            if row is None:
#                print("Uploading " + file.encode('utf-8') + "...")
#                print u'file.type=' + str(type(file)).encode('utf-8') + str(isThisStringUnicode( file))
                print(u'Uploading ' + file.encode('utf-8') + u'...') if isThisStringUnicode( file) else ("Uploading " + file + "...")

                if FULL_SET_NAME:
                    setName = os.path.relpath(os.path.dirname(file), unicode(FILES_DIR, 'utf-8'))
                else:
                    head, setName = os.path.split(os.path.dirname(file))
                try:
                    #print u'setName' + str(type(setName)).encode('utf-8')
                    print(u'setName: ' + setName.encode('utf-8') ) if isThisStringUnicode( setName) else ("setName: " + setName )
                    if isThisStringUnicode( file):
                        photo = ('photo', file.encode('utf-8'), open(file, 'rb').read())
                    else:
                        photo = ('photo', file, open(file, 'rb').read())
                    if args.title:  # Replace
                        FLICKR["title"] = args.title
                    if args.description:  # Replace
                        FLICKR["description"] = args.description
                    if args.tags:  # Append
                        FLICKR["tags"] += " "

                    # if FLICKR["title"] is empty...
                    # if filename's exif title is empty...
                    #   Can't check without import exiftool
                    # set it to filename OR do not load it up in order to
                    # allow flickr.com itself to set it up
                    # NOTE: an empty title forces flickrapi/auth.py
                    # code like 280 to encode into utf-8 the filename
                    # this causes an error
                    # UnicodeDecodeError: 'ascii' codec can't decode byte 0xc3 in position 11: ordinal not in range(128)
                    # Will try to workaround it by forcing the title
                    if FLICKR["title"] == "":
                        path_filename, title_filename = os.path.split(file)
                        if LOGGING_LEVEL <= logging.WARNING:
                            logging.warning('path:[{!s}] '
                                            'filename:[{!s}]'.format(
                                                path_filename,
                                                title_filename))
                        # title_filename = title_filename.split(".")[0]
                        title_filename = os.path.splitext( title_filename)[0]
                        print('TITLEFILENAME', title_filename)
                        if LOGGING_LEVEL <= logging.WARNING:
                            logging.warning('path:[{!s}] '
                                            'filename no ext:[{!s}]'.format(
                                                path_filename,
                                                title_filename))
                    else:
                        title_filename = FLICKR["title"]
                        if LOGGING_LEVEL <= logging.WARNING:
                            logging.warning('title '
                                            'from INI file:[{!s}]'.format(
                                                title_filename))
                    
                    file_checksum = self.md5Checksum(file)
                    
                    #     # replace commas to avoid tags conflicts
                    #     # "tags": '{} {} checksum:{}'.format(FLICKR["tags"], setName.encode('utf-8'), file_checksum).replace(',', ''),
                    #     # MSP: Remove SetName from tags
                    #     "tags": '{} checksum:{}'.format(FLICKR["tags"], file_checksum).replace(',', ''),

                    res = None
                    search_result = None
                    for x in range(0, MAX_UPLOAD_ATTEMPTS):
                        try:
                            if FLICKR["title"] == "":
                                uploadResp = nuflickr.upload(
                                        filename = file, \
                                        fileobj = FileWithCallback( file, callback), \
                                        title = title_filename, \
                                        description=str(FLICKR["description"]), \
                                        tags='{} checksum:{}'.format(FLICKR["tags"], file_checksum).replace(',', ''), \
                                        is_public=str(FLICKR["is_public"]), \
                                        is_family=str(FLICKR["is_family"]), \
                                        is_friend=str(FLICKR["is_friend"]) )
                            else:
                                uploadResp = nuflickr.upload(
                                        filename = file, \
                                        fileobj = FileWithCallback( file, callback), \
                                        # title = title_filename, \
                                        title=str(FLICKR["title"]), \
                                        description=str(FLICKR["description"]), \
                                        tags='{} checksum:{}'.format(FLICKR["tags"], file_checksum).replace(',', ''), \
                                        is_public=str(FLICKR["is_public"]), \
                                        is_family=str(FLICKR["is_family"]), \
                                        is_friend=str(FLICKR["is_friend"]) )
                            if LOGGING_LEVEL <= logging.WARNING:
                                logging.warning('uploadResp: ')
                                xml.etree.ElementTree.dump(uploadResp)
                            photo_id = uploadResp.findall('photoid')[0].text
                            if LOGGING_LEVEL <= logging.WARNING:
                                logging.warning('OK. Flickr id '
                                                '= {!s}'.format(photo_id))
                            search_result = None
                            
                            # TEST SEARCH TO CONFIRM LOADED
                            search_result = self.photos_search(file_checksum)
                            if self.isGood( search_result):
                                print("search_result:OK")
                            else:
                                print("search_result:NOT OK")
                            
                            break
                        except (IOError, httplib.HTTPException):
                            print(str(sys.exc_info()))
                            print("Check is file already uploaded")
                            print("MSP: just before time.sleep(DRIP_TIME)...15")
                            nutime.sleep(15)
                            print("MSP: just after time.sleep(DRIP_TIME)...15")

                            # on error, check if exists a photo
                            # with file_checksum 
                            search_result = self.photos_search(file_checksum)
                            if not self.isGood(search_result):
                                raise IOError(search_result)

                            # if int(search_result["photos"]["total"]) == 0:
                            if int(search_result.find('photos').attrib['total']) == 0:
                                if x == MAX_UPLOAD_ATTEMPTS - 1:
                                    raise ValueError('Reached maximum number '
                                                     'of attempts to upload, '
                                                     'skipping')
                                niceprint('Not found, reuploading.')
                                continue

                            # if int(search_result["photos"]["total"]) > 1:
                            if int(search_result.find('photos').attrib['total']) > 1:
                                raise IOError('More then one file with same '
                                              'checksum, collisions? ' +
                                              search_result)

                            # if int(search_result["photos"]["total"]) == 1:
                            if int(search_result.find('photos').attrib['total']) == 1:
                                niceprint('Found, continuing.')
                                break

                    # if not search_result and res.documentElement.attributes['stat'].value != "ok":
                    #     print(u'A problem occurred while attempting to upload the file: ' + file.encode('utf-8')) if isThisStringUnicode( file) else ("A problem occurred while attempting to upload the file:  " + file )
                    #     raise IOError(str(res.toxml()))

                    # if not search_result and uploadResp.attrib['stat'] != "ok":
                    if not search_result and not self.isGood(uploadResp):
                        niceprint(  'A problem occurred while attempting to '
                                    'upload the file: ' +
                                    file.encode('utf-8')
                                    if isThisStringUnicode( file)
                                    else ('A problem occurred while '
                                          'attempting to upload the file: ' +
                                          file ))
                        raise IOError(str(uploadResp.toxml()))

                    # Successful update
                    niceprint(  u'Successfully uploaded the file: ' +
                                file.encode('utf-8')
                                if isThisStringUnicode( file)
                                else ('Successfully uploaded the '
                                      'file: ' +
                                      file))
                    # Unsuccessful update given that search_result is not None
                    if search_result:
                        # file_id = int(search_result["photos"]["photo"][0]["id"])
                        file_id = uploadResp.findall('photoid')[0].text
                        if LOGGING_LEVEL <= logging.INFO:
                            logging.info('Output for {!s}:'.
                                format('uploadResp'))
                            xml.etree.ElementTree.dump(uploadResp)
                        if LOGGING_LEVEL <= logging.WARNING:
                            logging.warning('SEARCH_RESULT file_id={!s}'.
                                format(file_id))
                    else:
                        # Successful update given that search_result is None
                        # file_id = int(str(uploadResp.getElementsByTagName('photoid')[0].firstChild.nodeValue))
                        file_id = int(str(uploadResp.findall('photoid')[0].text))

                    # Add to db the file uploaded
                    cur.execute(
                        'INSERT INTO files (files_id, path, md5, last_modified, tagged) VALUES (?, ?, ?, ?, 1)',
                        (file_id, file, file_checksum, last_modified))
                    
                    # Update Date/Time on Flickr for Video files
                    import mimetypes
                    import time
                    filetype = mimetypes.guess_type(file)
                    if LOGGING_LEVEL <= logging.INFO:
                        logging.info('filetype:[{!s}]:'.format(filetype))

                    if 'video' in filetype[0]:
                        video_date = time.strftime(
                                        '%Y-%m-%d %H:%M:%S',
                                        time.localtime(last_modified))
                        if LOGGING_LEVEL <= logging.INFO:
                            logging.info('video_date:[{!s}]'.
                                         format(video_date))

                        try:
                            res_set_date = flick.photos_set_dates(
                                                file_id,
                                                video_date)
                            if self.isGood( res_set_date):
                                niceprint("Set date ok")
                        except (IOError, ValueError, httplib.HTTPException):
                            print(str(sys.exc_info()))
                            print("Error setting date")
                        if not self.isGood( res_set_date):
                            raise IOError(res_set_date)
                        #print("Successfully set date for pic number: " + str(file_id) + " File: " + file.encode('utf-8') + " date:" + video_date)    
                        niceprint(u'Successfully set date for pic number: ' +
                                    file.encode('utf-8') +
                                    u' date:' +
                                    video_date
                                        if isThisStringUnicode(file)
                                        else ('Successfully set date for pic '
                                              'number: ' +
                                              file +
                                              ' date:' +
                                              video_date))
                    success = True
                # except:
                #     print(str(sys.exc_info()))
                except flickrapi.exceptions.FlickrError as ex:
                    print("Error code: %s" % ex.code)
                    print("Error code:", ex)
                    print(str(sys.exc_info()))
                    
            elif (MANAGE_CHANGES):
                if (row[6] == None):
                    cur.execute('UPDATE files SET last_modified = ? WHERE files_id = ?', (last_modified, row[1]))
                    con.commit()
                if (row[6] != last_modified):
                    fileMd5 = self.md5Checksum(file)
                    if (fileMd5 != str(row[4])):
                        self.replacePhoto(file, row[1], row[4], fileMd5, last_modified, cur, con);
            return success

    def replacePhoto(self, file, file_id, oldFileMd5, fileMd5, last_modified, cur, con):

        if args.dry_run :
            print(u'Dry Run Replace file ' + file.encode('utf-8') + u'...') if isThisStringUnicode( file) else ("Dry Run Replace file " + file + "...")
            return True

        success = False
        print(u'Replacing the file: ' + file.encode('utf-8') + u'...') if isThisStringUnicode( file) else ("Replacing the file: " + file + "...")
        try:
            if isThisStringUnicode( file):
                photo = ('photo', file.encode('utf-8'), open(file, 'rb').read())
            else:
                photo = ('photo', file, open(file, 'rb').read())

            d = {
                "auth_token": str(self.token),
                "photo_id": str(file_id)
            }
            sig = self.signCall(d)
            d["api_sig"] = sig
            d["api_key"] = FLICKR["api_key"]
            url = self.build_request(api.replace, d, (photo,))

            # Update Date/Time on Flickr for Video files
            import mimetypes
            import time
            filetype = mimetypes.guess_type(file)
            if 'video' in filetype[0]:
                video_date = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(last_modified))
                try:
                    res_set_date = flick.photos_set_dates(file_id, video_date)
                    if self.isGood(res_set_date):
                        print("Set date ok")
                except (IOError, ValueError, httplib.HTTPException):
                    print(str(sys.exc_info()))
                    print("Error setting date")
                if not self.isGood(res_set_date):
                    raise IOError(res_set_date)
                #print("Successfully set date for pic number: " + str(file_id) + " File: " + file.encode('utf-8') + " date:" + video_date)
                print(u'Successfully set date for pic number: ' + str(file_id) + u' File: ' + file.encode('utf-8') + u' date:' + video_date) if isThisStringUnicode( file) else ("Successfully set date for pic number: " + str(file_id) + ' File: ' + file + " date:" + video_date)

            res = None
            res_add_tag = None
            res_get_info = None

            for x in range(0, MAX_UPLOAD_ATTEMPTS):
                try:
                    res = parse(urllib2.urlopen(url, timeout=SOCKET_TIMEOUT))
                    if res.documentElement.attributes['stat'].value == "ok":
                        res_add_tag = self.photos_add_tags(file_id, ['checksum:{}'.format(fileMd5)])
                        if res_add_tag['stat'] == 'ok':
                            res_get_info = flick.photos_get_info(file_id)
                            if res_get_info['stat'] == 'ok':
                                tag_id = None
                                for tag in res_get_info['photo']['tags']['tag']:
                                    if tag['raw'] == 'checksum:{}'.format(oldFileMd5):
                                        tag_id = tag['id']
                                        break
                                if not tag_id:
                                    print("Can't find tag {} for file {}".format(tag_id, file_id))
                                    break
                                else:
                                    self.photos_remove_tag(tag_id)
                    break
                except (IOError, ValueError, httplib.HTTPException):
                    print(str(sys.exc_info()))
                    print("Replacing again")
                    nutime.sleep(5)

                    if x == MAX_UPLOAD_ATTEMPTS - 1:
                        raise ValueError("Reached maximum number of attempts to replace, skipping")
                    continue

            if res.documentElement.attributes['stat'].value != "ok" \
                    or res_add_tag['stat'] != 'ok' \
                    or res_get_info['stat'] != 'ok':
                print(u'A problem occurred while attempting to upload the file: ' + file.encode('utf-8')) if isThisStringUnicode( file) else ("A problem occurred while attempting to upload the file: " + file)

            if res.documentElement.attributes['stat'].value != "ok":
                raise IOError(str(res.toxml()))

            if res_add_tag['stat'] != 'ok':
                raise IOError(res_add_tag)

            if res_get_info['stat'] != 'ok':
                raise IOError(res_get_info)

            print(u'Successfully replaced the file: ' + file.encode('utf-8')) if isThisStringUnicode( file) else ("Successfully replaced the file: " + file )

            # Add to set
            cur.execute('UPDATE files SET md5 = ?,last_modified = ? WHERE files_id = ?',
                        (fileMd5, last_modified, file_id))
            con.commit()
            success = True
        except:
            print(str(sys.exc_info()))

        return success

    #--------------------------------------------------------------------------
    # deletefile
    #
    # When EXCLUDED_FOLDERS defintion changes. You can run the -g
    # or --remove-ignored option in order to remove files previously loaded
    # files from
    # 
    def deleteFile(self, file, cur):
        """ deleteFile
        delete file from flickr
        cur represents the control dabase cursor to allow, for example,
            deleting empty sets
        """
        
        global nuflickr

        if args.dry_run :
            print(u'Deleting file: ' + file[1].encode('utf-8')) if isThisStringUnicode( file[1]) else ("Deleting file: " + file[1])
            return True

        success = False
        print(u'Deleting file: ' + file[1].encode('utf-8')) if isThisStringUnicode( file[1]) else ("Deleting file: " + file[1])

        try:
            deleteResp = nuflickr.photos.delete(
                                        photo_id = str(file[0]) )
            if LOGGING_LEVEL <= logging.WARNING:
                logging.warning('[{!s}] deleteResp: ')
                xml.etree.ElementTree.dump(deleteResp)
            if (self.isGood(deleteResp)):
                # Find out if the file is the last item in a set, if so, remove the set from the local db
                cur.execute("SELECT set_id FROM files WHERE files_id = ?", (file[0],))
                row = cur.fetchone()
                cur.execute("SELECT set_id FROM files WHERE set_id = ?", (row[0],))
                rows = cur.fetchall()
                if (len(rows) == 1):
                    print("File is the last of the set, deleting the set ID: " + str(row[0]))
                    cur.execute("DELETE FROM sets WHERE set_id = ?", (row[0],))

                # Delete file record from the local db
                cur.execute("DELETE FROM files WHERE files_id = ?", (file[0],))
                print("Successful deletion.")
                success = True
            else:
                if (res['code'] == 1):
                    # File already removed from Flicker
                    cur.execute("DELETE FROM files WHERE files_id = ?", (file[0],))
                else:
                    self.reportError(res)
        except:
            # If you get 'attempt to write a readonly database', set 'admin' as owner of the DB file (fickerdb) and 'users' as group
            print(str(sys.exc_info()))
        return success

    def logSetCreation(self, setId, setName, primaryPhotoId, cur, con):
        """
        Creates on flickrdb local database a SetName(Album)
        """

        if LOGGING_LEVEL <= logging.INFO:
            logging.info('setName:[{!s}] setName.type:[{!s}]'.
                            format( setName,
                                    type(setName)))
            # niceprint u'setName.type=' + str(type(setName)).encode('utf-8')
            logging.warning('Adding set: [{!s}] to log.'.format(setName))
    
        success = False
        cur.execute("INSERT INTO sets (set_id, name, primary_photo_id) VALUES (?,?,?)",
                    (setId, setName, primaryPhotoId))
        cur.execute("UPDATE files SET set_id = ? WHERE files_id = ?", (setId, primaryPhotoId))
        con.commit()
        return True

    def build_request(self, theurl, fields, files, txheaders=None):
        """
        build_request/encode_multipart_formdata code is from www.voidspace.org.uk/atlantibots/pythonutils.html

        Given the fields to set and the files to encode it returns a fully formed urllib2.Request object.
        You can optionally pass in additional headers to encode into the opject. (Content-type and Content-length will be overridden if they are set).
        fields is a sequence of (name, value) elements for regular form fields - or a dictionary.
        files is a sequence of (name, filename, value) elements for data to be uploaded as files.
        """

        content_type, body = self.encode_multipart_formdata(fields, files)
        if not txheaders: txheaders = {}
        txheaders['Content-type'] = content_type
        txheaders['Content-length'] = str(len(body))

        return urllib2.Request(theurl, body, txheaders)

    def encode_multipart_formdata(self, fields, files, BOUNDARY='-----' + mimetools.choose_boundary() + '-----'):
        """ Encodes fields and files for uploading.
        fields is a sequence of (name, value) elements for regular form fields - or a dictionary.
        files is a sequence of (name, filename, value) elements for data to be uploaded as files.
        Return (content_type, body) ready for urllib2.Request instance
        You can optionally pass in a boundary string to use or we'll let mimetools provide one.
        """

        CRLF = '\r\n'
        L = []
        if isinstance(fields, dict):
            fields = fields.items()
        for (key, value) in fields:
            L.append('--' + BOUNDARY)
            L.append('Content-Disposition: form-data; name="%s"' % key)
            L.append('')
            L.append(value)
        for (key, filename, value) in files:
            filetype = mimetypes.guess_type(filename)[0] or 'application/octet-stream'
            L.append('--' + BOUNDARY)
            L.append('Content-Disposition: form-data; name="%s"; filename="%s"' % (key, filename))
            L.append('Content-Type: %s' % filetype)
            L.append('')
            L.append(value)
        L.append('--' + BOUNDARY + '--')
        L.append('')
        body = CRLF.join(L)
        content_type = 'multipart/form-data; boundary=%s' % BOUNDARY  # XXX what if no files are encoded
        return content_type, body

    #--------------------------------------------------------------------------
    # isGood
    #
    def isGood(self, res):
        """ isGood
        
            Returns true if attrib['stat'] == "ok" for a given XML object
        """

        if (not res == "" and res.attrib['stat'] == "ok"):
            return True
        else:
            return False

    def reportError(self, res):
        """ reportError
        """

        try:
            print("Error: " + str(res['code'] + " " + res['message']))
        except:
            print("Error: " + str(res))

    def getResponse(self, url):
        # MSP: Probably not required any more
        """
        Send the url and get a response.  Let errors float up
        """
        res = None
        try:
            res = urllib2.urlopen(url, timeout=SOCKET_TIMEOUT).read()
        except urllib2.HTTPError, e:
            print(e.code)
        except urllib2.URLError, e:
            print(e.args)
        return json.loads(res, encoding='utf-8')

    #--------------------------------------------------------------------------
    # run
    # 
    # run in daemon mode. runs upload every SLEEP_TIME
    #
    def run(self):
        """ run
            Run in daemon mode. runs upload every SLEEP_TIME seconds.
        """

        while (True):
            self.upload()
            print("Last check: " + str(nutime.asctime(time.localtime())))
            nutime.sleep(SLEEP_TIME)

    #--------------------------------------------------------------------------
    # createSets
    #
    def createSets(self):
        """
            Creates a set (Album) in Flickr
        """
        niceprint('*****Creating Sets*****')

        if args.dry_run :
                return True

        con = lite.connect(DB_PATH)
        con.text_factory = str
        with con:
            cur = con.cursor()
            cur.execute("SELECT files_id, path, set_id FROM files")

            files = cur.fetchall()

            for row in files:
                if FULL_SET_NAME:
                    setName = os.path.relpath(os.path.dirname(row[1]), unicode(FILES_DIR, 'utf-8'))
                else:
                    head, setName = os.path.split(os.path.dirname(row[1]))
                newSetCreated = False

                cur.execute("SELECT set_id, name FROM sets WHERE name = ?", (setName,))

                set = cur.fetchone()

                if set == None:
                    setId = self.createSet(setName, row[0], cur, con)
                    print(u'Created the set: ' + setName.encode('utf-8')) if isThisStringUnicode( setName) else ("Created the set: " + setName)
                    newSetCreated = True
                else:
                    setId = set[0]

                if row[2] == None and newSetCreated == False:
                    print(u'adding file to set ' + row[1].encode('utf-8') + u'...') if isThisStringUnicode( row[1]) else ("adding file to set " + row[1])
                    
                    self.addFileToSet(setId, row, cur)
        niceprint('*****Completed creating sets*****')

    #--------------------------------------------------------------------------
    # addFiletoSet
    #
    def addFileToSet(self, setId, file, cur):
        """
            adds a file to set...
        """
        
        global nuflickr
        
        if args.dry_run :
                return True
        try:
            # d = {
            #     "auth_token": str(self.token),
            #     "perms": str(self.perms),
            #     "format": "json",
            #     "nojsoncallback": "1",
            #     "method": "flickr.photosets.addPhoto",
            #     "photoset_id": str(setId),
            #     "photo_id": str(file[0])
            # }
            # sig = self.signCall(d)
            # url = self.urlGen(api.rest, d, sig)
            # 
            # res = self.getResponse(url)
            # 
            addPhotoResp = nuflickr.photosets.addPhoto(
                                photoset_id = str(setId),
                                photo_id = str(file[0]))
                                
            if LOGGING_LEVEL <= logging.WARNING:
                logging.warning('addPhotoResp: ')
                xml.etree.ElementTree.dump(addPhotoResp)
            
            if (self.isGood(addPhotoResp)):
                #print("Successfully added file " + str(file[1]).encode('utf-8') + " to its set.")
                print(u'Successfully added file ' + file[1].encode('utf-8') + u' to its set.') if isThisStringUnicode( file[1]) else ("Successfully added file " + file[1] + " to its set.")

                cur.execute("UPDATE files SET set_id = ? WHERE files_id = ?", (setId, file[0]))
            else:
                if (addPhotoResp['code'] == 1):
                    print("Photoset not found, creating new set...")
                    if FULL_SET_NAME:
                        setName = os.path.relpath(os.path.dirname(file[1]), unicode(FILES_DIR, 'utf-8'))
                    else:
                        head, setName = os.path.split(os.path.dirname(file[1]))
                    con = lite.connect(DB_PATH)
                    con.text_factory = str
                    self.createSet(setName, file[0], cur, con)
                elif (addPhotoRest['code'] == 3):
                    print("Photo already in set... updating DB")
                    print(addPhotoRest['message'] + "... updating DB")
                    cur.execute("UPDATE files SET set_id = ? WHERE files_id = ?", (setId, file[0]))
                else:
                    self.reportError(res)
        except:
            print(str(sys.exc_info()))

    #--------------------------------------------------------------------------
    # createSet
    #
    def createSet(self, setName, primaryPhotoId, cur, con):
        
        global nuflickr
        
        niceprint(u'setName.type=' + str(type(setName)).encode('utf-8'))
        niceprint( u'Creating new set: '.encode('utf-8') + str(setName) )
        #print("Creating new set: ", str(setName).encode('utf-8'))

        if args.dry_run :
            return True

        try:
            # d = {
            #     "auth_token": str(self.token),
            #     "perms": str(self.perms),
            #     "format": "json",
            #     "nojsoncallback": "1",
            #     "method": "flickr.photosets.create",
            #     "primary_photo_id": str(primaryPhotoId),
            #     "title": setName
            # }
            # sig = self.signCall(d)
            # url = self.urlGen(api.rest, d, sig)
            # res = self.getResponse(url)
            
            createResp = nuflickr.photosets.create (
                            title = setName,
                            primary_photo_id = str(primaryPhotoId))
            if LOGGING_LEVEL <= logging.WARNING:
                logging.warning('createResp: ')
                xml.etree.ElementTree.dump(createResp)
                
            if (self.isGood(createResp)):
                if LOGGING_LEVEL <= logging.WARNING:
                    # logging.warning('createResp["photoset"]["id"]'.
                    #                     format(createResp["photoset"]["id"]))
                    logging.warning('createResp["photoset"]["id"]'.
                                        format(createResp.
                                                    find('photoset').
                                                    attrib['id']))
                self.logSetCreation(createResp.find('photoset').attrib['id'],
                                    setName,
                                    primaryPhotoId,
                                    cur,
                                    con)
                return createResp.find('photoset').attrib['id']
            else:
                if LOGGING_LEVEL <= logging.WARNING:
                    logging.warning('createResp: ')
                    xml.etree.ElementTree.dump(createResp)
                self.reportError(createResp)
        except:
            print(str(sys.exc_info()))
        return False

    #--------------------------------------------------------------------------
    # setupDB
    #
    # Creates the control database
    #
    def setupDB(self):
        """
            setupDB
            
            Creates the control database
        """
        niceprint("Setting up the database: " + DB_PATH)
        con = None
        try:
            con = lite.connect(DB_PATH)
            con.text_factory = str
            cur = con.cursor()
            cur.execute('CREATE TABLE IF NOT EXISTS files (files_id INT, path TEXT, set_id INT, md5 TEXT, tagged INT)')
            cur.execute('CREATE TABLE IF NOT EXISTS sets (set_id INT, name TEXT, primary_photo_id INTEGER)')
            cur.execute('CREATE UNIQUE INDEX IF NOT EXISTS fileindex ON files (path)')
            cur.execute('CREATE INDEX IF NOT EXISTS setsindex ON sets (name)')
            con.commit()
            cur = con.cursor()
            cur.execute('PRAGMA user_version')
            row = cur.fetchone()
            if (row[0] == 0):
                niceprint('Adding last_modified column to database');
                cur = con.cursor()
                cur.execute('PRAGMA user_version="1"')
                cur.execute('ALTER TABLE files ADD COLUMN last_modified REAL');
                con.commit()
            con.close()
        except lite.Error, e:
            niceprint("Error: %s" % e.args[0])
            if con != None:
                con.close()
            sys.exit(1)
        finally:
            niceprint('Completed database setup')

    def md5Checksum(self, filePath):
        with open(filePath, 'rb') as fh:
            m = hashlib.md5()
            while True:
                data = fh.read(8192)
                if not data:
                    break
                m.update(data)
            return m.hexdigest()

    # -------------------------------------------------------------------------
    # Method to clean unused sets
    #   Sets are Albums.
    def removeUselessSetsTable(self):
        niceprint('*****Removing empty Sets from DB*****')
        if args.dry_run :
                return True

        con = lite.connect(DB_PATH)
        con.text_factory = str
        with con:
            cur = con.cursor()
            cur.execute("SELECT set_id, name FROM sets WHERE set_id NOT IN\
                        (SELECT set_id FROM files)")
            unusedsets = cur.fetchall()

            for row in unusedsets:
                print("Unused set spotted about to be deleted: " + str(row[0]) + " (" + row[1].decode('utf-8') + ")")
                cur.execute("DELETE FROM sets WHERE set_id = ?", (row[0],))
            con.commit()

        niceprint('*****Completed removing empty Sets from DB*****')

    # -------------------------------------------------------------------------
    # Display Sets
    #
    def displaySets(self):
        con = lite.connect(DB_PATH)
        con.text_factory = str
        with con:
            cur = con.cursor()
            cur.execute("SELECT set_id, name FROM sets")
            allsets = cur.fetchall()
            for row in allsets:
                print("Set: " + str(row[0]) + "(" + row[1] + ")")

    #--------------------------------------------------------------------------
    # Get sets from Flickr
    #
    # Selects the flickrSets from Flickr
    # for each flickrSet
    #   Selects the localDBSet from local flickrdb database
    #   if localDBSet is None INSERTs flickrset into flickrdb
    #
    def getFlickrSets(self):
        """
            getFlickrSets
            
            Gets list of FLickr Sets (Albums) and populates
            local DB accordingly
        """   
        global nuflickr
        
        niceprint('*****Adding Flickr Sets to DB*****')
        if args.dry_run :
                return True

        con = lite.connect(DB_PATH)
        con.text_factory = str
        try:
            sets = nuflickr.photosets_getList()
            
            if LOGGING_LEVEL <= logging.INFO:
                logging.info('Output for {!s}'.format('photosets_getList:'))
                xml.etree.ElementTree.dump(sets)

            """

sets = flickr.photosets.getList(user_id='73509078@N00')

sets.attrib['stat'] => 'ok'
sets.find('photosets').attrib['cancreate'] => '1'

set0 = sets.find('photosets').findall('photoset')[0]

+-------------------------------+-----------+
| variable                      | value     |
+-------------------------------+-----------+
| set0.attrib['id']             | u'5'      |
| set0.attrib['primary']        | u'2483'   |
| set0.attrib['secret']         | u'abcdef' |
| set0.attrib['server']         | u'8'      |
| set0.attrib['photos']         | u'4'      |
| set0.title[0].text            | u'Test'   |
| set0.description[0].text      | u'foo'    |
| set0.find('title').text       | 'Test'    |
| set0.find('description').text | 'foo'     |
+-------------------------------+-----------+

... and similar for set1 ...

            """

            # print "Before isGood"
            # # print self.isGood(sets)
            # print sets.find('photosets').findall('photoset')[0].find('title').text
            # print "After isGood"

            if (self.isGood(sets)):
                cur = con.cursor()
                # print "Before Title"
                # title  = sets['photosets']['photoset'][0]['title']['_content']
                # print "After Title"

                # print('First set title: %s' % title)

                for row in sets.find('photosets').findall('photoset'):
                    if LOGGING_LEVEL <= logging.INFO:
                        logging.info('Output for {!s}:'.format('row'))
                        xml.etree.ElementTree.dump(row)

                    setId = row.attrib['id']
                    setName = row.find('title').text
                    primaryPhotoId = row.attrib['primary']
                    # print( 'no encode commas', setId, setName, primaryPhotoId)
                    # print( 'no encode plus' + setId + setName + primaryPhotoId)
                    # print(u'encode commas',
                    #         setId.encode('utf-8'),
                    #         setName.encode('utf-8'),
                    #         primaryPhotoId.encode('utf-8'))
                    # print(u'encode plus unicode '.encode('utf-8') +
                    #         setId.encode('utf-8') + 
                    #         setName +
                    #         primaryPhotoId.encode('utf-8'))
                    if LOGGING_LEVEL <= logging.INFO:
                        logging.info('isThisStringUnicode [{!s}]:{!s}'.
                                     format('setId',
                                            isThisStringUnicode(setId)))
                        logging.info('isThisStringUnicode [{!s}]:{!s}'.
                                     format('setName',
                                            isThisStringUnicode(setName)))
                        logging.info('isThisStringUnicode [{!s}]:{!s}'.
                                     format('primaryPhotoId',
                                            isThisStringUnicode(primaryPhotoId)))
                    # niceprint('id=' + setId +
                    #           'setName=' + setName +
                    #           'prim=' + primaryPhotoId)
                    niceprint(u'id='.encode('utf-8') +
                              setId.encode('utf-8') + u' ' +
                              u'setName='.encode('utf-8') +
                              setName + u' ' +
                              u'primaryPhotoId='.encode('utf-8') +
                              primaryPhotoId.encode('utf-8'))
                    if LOGGING_LEVEL <= logging.INFO:
                        logging.info('setId:[{!s}] '
                                     'setName:[{!s}] '
                                     'primaryPhotoId:[{!s}]'.
                                     format(setId,
                                            setName.encode('utf-8'),
                                            primaryPhotoId))
                    
                    # print( "Before setId")
                    # print( setId, setName, primaryPhotoId)
                    # print( "After setId")
                    cur.execute("SELECT set_id FROM sets WHERE set_id = '"
                                + setId + "'")
                    foundSets = cur.fetchone()
                    if LOGGING_LEVEL <= logging.INFO:
                        logging.info('Output for {!s}:'.format('foundSets'))
                        print foundSets

                    if foundSets == None:
                        print(u"Adding set #{0} ({1}) with primary photo #{2}".
                              format(setId, setName, primaryPhotoId))
                        cur.execute('INSERT INTO sets (set_id, name, '
                                    'primary_photo_id) VALUES (?,?,?)',
                                    (setId, setName, primaryPhotoId))
                
                con.commit()
                niceprint('Sleep...3...to allow Commit... TO BE REMOVED?')
                nutime.sleep(3)
                niceprint('After Sleep...3...to allow Commit')
                con.close()
            else:
                xml.etree.ElementTree.dump(sets)
                self.reportError(sets)
            
        except flickrapi.exceptions.FlickrError as ex:
            print("Error code: %s" % ex.code)
            print("Error code:", ex)
            print(str(sys.exc_info()))

        # except:
        #     print "EXCEPTION"
        #     FlickrError
        #     print(str(sys.exc_info()))
        niceprint('*****Completed adding Flickr Sets to DB*****')

    #--------------------------------------------------------------------------
    # photos_search
    #
    # Searchs for image with on tag:checksum 
    #
    def photos_search(self, checksum):
        """
            photos_search
            Searchs for image with on tag:checksum 
        """
        
        global nuflickr
        
        if LOGGING_LEVEL <= logging.INFO:
            logging.info('FORMAT checksum:{!s}:'.format(checksum))

        searchResp = nuflickr.photos.search(tags = 'checksum:{}'.format(checksum))
        # Debug
        if LOGGING_LEVEL <= logging.INFO:
            logging.info('Search Results SearchResp:')
            xml.etree.ElementTree.dump(searchResp)

        return searchResp
    
    #--------------------------------------------------------------------------
    # people_get_photos
    #
    def people_get_photos(self):
        """
        """
        
        global nuflickr
        
        # data = {
        #     "auth_token": str(self.token),
        #     "perms": str(self.perms),
        #     "format": "json",
        #     "nojsoncallback": "1",
        #     "user_id": "me",
        #     "method": "flickr.people.getPhotos",
        #     "per_page": "1"
        # }
        # 
        # url = self.urlGen(api.rest, data, self.signCall(data))
        # return self.getResponse(url)
        
        getPhotosResp = nuflickr.people.getPhotos( user_id = "me", per_page = 1)
        return getPhotosResp

    #--------------------------------------------------------------------------
    # photos_get_not_in_set
    #
    def photos_get_not_in_set(self):
        """
        """
        
        global nuflickr

        # data = {
        #     "auth_token": str(self.token),
        #     "perms": str(self.perms),
        #     "format": "json",
        #     "nojsoncallback": "1",
        #     "method": "flickr.photos.getNotInSet",
        #     "per_page": "1"
        # }
        # 
        # url = self.urlGen(api.rest, data, self.signCall(data))
        # return self.getResponse(url)
    
        notinsetResp = nuflickr.photos.getNotInSet ( per_page = 1)
        return notinsetResp

    def photos_add_tags(self, photo_id, tags):
        tags = [tag.replace(',', '') for tag in tags]
        data = {
            "auth_token": str(self.token),
            "perms": str(self.perms),
            "format": "json",
            "nojsoncallback": "1",
            "method": "flickr.photos.addTags",
            "photo_id": str(photo_id),
            "tags": ','.join(tags)
        }

        url = self.urlGen(api.rest, data, self.signCall(data))
        return self.getResponse(url)

    def photos_get_info(self, photo_id):
        data = {
            "auth_token": str(self.token),
            "perms": str(self.perms),
            "format": "json",
            "nojsoncallback": "1",
            "method": "flickr.photos.getInfo",
            "photo_id": str(photo_id),
        }

        url = self.urlGen(api.rest, data, self.signCall(data))
        return self.getResponse(url)

    def photos_remove_tag(self, tag_id):
        data = {
            "auth_token": str(self.token),
            "perms": str(self.perms),
            "format": "json",
            "nojsoncallback": "1",
            "method": "flickr.photos.removeTag",
            "tag_id": str(tag_id),
        }

        url = self.urlGen(api.rest, data, self.signCall(data))
        return self.getResponse(url)

    #--------------------------------------------------------------------------
    # photos_set_dates
    #
    # Update Date/Time Taken on Flickr for Video files
    #
    def photos_set_dates(self, photo_id, datetxt):
        """
        Update Date/Time Taken on Flickr for Video files
        """
        global nuflickr
        
        # data = {
        #     "auth_token": str(self.token),
        #     "perms": str(self.perms),
        #     "format": "json",
        #     "nojsoncallback": "1",
        #     "method": "flickr.photos.setDates",
        #     "photo_id": str(photo_id),
        #     "date_taken": str(datetxt)
        # }
        # url = self.urlGen(api.rest, data, self.signCall(data))
        
        respDate = nuflickr.photos.setdates(photo_id = photo_id,
                                                date_taken = datetxt)
        if LOGGING_LEVEL <= logging.INFO:
            logging.info('Output for {!s}:'.format('respDate'))
            xml.etree.ElementTree.dump(respDate)

        return respDate
    
    #--------------------------------------------------------------------------
    # print_stat
    #
    def print_stat(self):
        """ print_stat
        Shows Total photos and Photos Not in Sets on Flickr
        """
        con = lite.connect(DB_PATH)
        con.text_factory = str
        with con:
            cur = con.cursor()
            cur.execute("SELECT Count(*) FROM files")

            print( 'Total photos on local: {}'.format(cur.fetchone()[0]))

        res = self.people_get_photos()
        if not self.isGood(res):
            raise IOError(res)
        print('DEBUG print people_get_photos')
        xml.etree.ElementTree.dump(res)
       
        print('Total photos on flickr: {}'.
                format(res.find('photos').attrib['total']))

        res = self.photos_get_not_in_set()
        if not self.isGood(res):
            raise IOError(res)
        print('DEBUG print get_not_in_set')
        xml.etree.ElementTree.dump(res)

        print('Photos not in sets on flickr: {}'.
                format(res.find('photos').attrib['total']))

#------------------------------------------------------------------------------
# Main code
#
nutime = time

niceprint("--------- Start time: " + nutime.strftime(UPLDRConstants.TimeFormat) + " ---------")
if __name__ == "__main__":
    # Ensure that only once instance of this script is running
    f = open(LOCK_PATH, 'w')
    try:
        fcntl.lockf(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except IOError, e:
        if e.errno == errno.EAGAIN:
            # sys.stderr.write('[%s] Script already running.\n' % time.strftime('%c'))
            sys.stderr.write('[{!s}] Script already running.\n'.format(
                                    nutime.strftime(UPLDRConstants.TimeFormat)))
            sys.exit(-1)
        raise
    parser = argparse.ArgumentParser(description='Upload files to Flickr.')
    parser.add_argument('-d', '--daemon', action='store_true',
                        help='Run forever as a daemon')
    parser.add_argument('-i', '--title', action='store',
                        help='Title for uploaded files')
    parser.add_argument('-e', '--description', action='store',
                        help='Description for uploaded files')
    parser.add_argument('-t', '--tags', action='store',
                        help='Space-separated tags for uploaded files')
    parser.add_argument('-r', '--drip-feed', action='store_true',
                        help='Wait a bit between uploading individual files')
    parser.add_argument('-p', '--processes',
                        help='Number of photos to upload simultaneously')
    parser.add_argument('-n', '--dry-run', action='store_true',
                        help='Dry run')
    parser.add_argument('-g', '--remove-ignored', action='store_true',
                        help='Remove previously uploaded files, now ignored')
    args = parser.parse_args()
    if LOGGING_LEVEL <= logging.INFO:
        logging.info('Output for {!s}'.format('args:'))
        pprint.pprint(args)

    # instantiate call Uploadr
    flick = Uploadr()

    if LOGGING_LEVEL <= logging.WARNING:
        logging.warning('FILES_DIR: [{!s}]'.format(FILES_DIR))
    if FILES_DIR == "":
        print('Please configure the name of the folder in the script with '
              'media available to sync with Flickr.')
        sys.exit()
    else:
        if not os.path.isdir(FILES_DIR):
            print('Please configure the name of an existant folder '
                  'in the script with media available to sync with Flickr.')
            sys.exit()

    if FLICKR["api_key"] == "" or FLICKR["secret"] == "":
        print("Please enter an API key and secret in the script file (see README).")
        sys.exit()

    flick.setupDB()
    
    if args.daemon:
        # Will run in daemon mode every SLEEP_TIME seconds
        if LOGGING_LEVEL <= logging.WARNING:
            logging.warning('Will run in daemon mode every {!s} seconds'.format(SLEEP_TIME))
        flick.run()
    else:
        if not flick.checkToken():
            flick.authenticate()

        flick.removeUselessSetsTable()
        flick.getFlickrSets()        
        flick.convertRawFiles()
        flick.upload()

        flick.removeDeletedMedia()
        if args.remove_ignored:
            flick.removeIgnoredMedia()

        flick.createSets()
        flick.print_stat()

niceprint("--------- End time: " + time.strftime(UPLDRConstants.TimeFormat) + " ---------")
