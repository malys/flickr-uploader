#!/usr/bin/env python

"""
    XXX: Replacephoto did not delte previouse checksum on IMG_3326
         It added a second checksum
    XXX: Functions to be migrates...
            convertRawFiles
    XXX: double check parentesis on some niceprint with if else!!! (not parentises at the end or is IT? as it is with print)??
    XXX: Being updated to use flickrapi and OAUTH
    XXX: NEed to double check raw dry run
    XXX: Multiprocessing.Process + Lock + particular logging
         multiprocessing... use controled variable to control loaded photos
         issue that on allMedia processing and chunk size split...
         only a few processes endup loading files at the end.
         Could sort  the CnuChangeMedia to allow a differnrent split of chunks?
         anyhow there is work to be done by all processes!
         but when changes are on the end of th elist (updated files) one can
         get less performance.
    XXX: Double check all options... -d, -i, -e, -t, -r, -t, -n. Working: -g -l
    XXX: RE-upload pictures removed from flickr.
    XXX: Use raw to convert png to jpg for proper date handling...
    XXX: Problem with files with same name on different folders: or same filename and different extentions
        Note to self... this is not an issue for uploadr but it is for PhoShare (form Mac Photos into folders!!!)
    XXX: If one changes the FILES_DIR folder and do not DELETE all from flickr, uploadr WILL not delete the files.
    XXX: Update ALL tags on replacePhoto
    XXX: niceprint messages vs logging messages... final review required
        ***** section informative
        === Multiprocessing related
        +++ Exception related
    XXX: Check error handling
            Report the files not loaded due to error: 5 from flickr:Error: 5: Filetype was not recognised]
            database is locked
            error set in date
            error 5: Filetype was not recognised'
            error 502: flickrapi
            error 504: flickrapi
            ==> Possibly generate a list of failed loads for checking...

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

   cron entry (runs at the top of every hour)
   0  *  *  *  * /full/path/to/uploadr.py > /dev/null 2>&1

   This code has been updated to use the new Auth API from flickr.

   You may use this code however you see fit in any form whatsoever.


"""

# ----------------------------------------------------------------------------
# Import section
#
# Check if it is still required
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
# Check if it is still required
from xml.dom.minidom import parse
# Check if it is still required
import hashlib
# Check if it is still required
import fcntl
# Check if it is still required
import errno
# Check if it is still required
import subprocess
import re
import ConfigParser
import multiprocessing
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
#   nutime   = for working with time module (import time)
#   nuflickr = object for flickr API module (import flickrapi)
#   nulockDB = multiprocessing Lock for access to Database
#
nutime = time
nuflickr = None
nulockDB = None

# -----------------------------------------------------------------------------
# isThisStringUnicode
#
# Returns true if String is Unicode
#
def isThisStringUnicode(s):
    """
    Determines if a string is Unicode (return True) or not (returns False)
    to allow correct print operations.
    Example:
        print(u'File ' + file.encode('utf-8') + u'...') \
              if isThisStringUnicode(file) else ("File " + file + "...")
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
        [2017.10.25 22:32:03]:[PID]:[PRINT   ]:[uploadr] Some Message
        Accounts for UTF-8 Messages
    """
    print('[{!s}]:[{!s}][{!s:8s}]:[{!s}] {!s}'.format(
            nutime.strftime(UPLDRConstants.TimeFormat),
            os.getpid(),
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
IGNORED_REGEX = [re.compile(regex) for regex in \
                 eval(config.get('Config', 'IGNORED_REGEX'))]
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
#   Control additional specific output to stderr depending on level
#       if LOGGING_LEVEL <= logging.INFO:
#            logging.info('Output for {!s}:'.format('uploadResp'))
#            logging.info( xml.etree.ElementTree.tostring(
#                                                    addPhotoResp,
#                                                    encoding='utf-8',
#                                                    method='xml'))
#            <generate any further output>
#   Control additional specific output to stdout depending on level
#       if LOGGING_LEVEL <= logging.INFO:
#            niceprint ('Output for {!s}:'.format('uploadResp'))
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
    sys.stderr.write('[{!s}]:[WARNING ]:[uploadr] LOGGING_LEVEL '
                     'not defined or incorrect on INI file: [{!s}]. '
                     'Assuming WARNING level.\n'.format(
                            nutime.strftime(UPLDRConstants.TimeFormat),
                            os.path.join(os.path.dirname(sys.argv[0]),
                                         "uploadr.ini")))
# Force conversion of LOGGING_LEVEL into int() for later use in conditionals
LOGGING_LEVEL = int(LOGGING_LEVEL)
logging.basicConfig(stream=sys.stderr,
                    level=int(LOGGING_LEVEL),
                    datefmt=UPLDRConstants.TimeFormat,
                    format='[%(asctime)s]:[%(processName)s][%(levelname)-8s]'
                           ':[%(name)s] %(message)s')

# ----------------------------------------------------------------------------
# Test section for logging.
#   Only applicable if LOGGING_LEVEL is INFO or below (DEBUG, NOTSET)
#
if LOGGING_LEVEL <= logging.INFO:
    logging.info(u'sys.getfilesystemencoding:[{!s}]'.
                    format(sys.getfilesystemencoding()))
    logging.info('LOGGING_LEVEL Value: {!s}'.format(LOGGING_LEVEL))
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
    logging.info('Pretty Print for {!s}'.format(
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
    # if ((progress % 10) == 0):
    if ((progress % 40) == 0):
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

    # MSP: May be removed after migration to flickrapi
    # def signCall(self, data):
    #     """
    #     Signs args via md5 per http://www.flickr.com/services/api/auth.spec.html (Section 8)
    #     """
    #     keys = data.keys()
    #     keys.sort()
    #     foo = ""
    #     for a in keys:
    #         foo += (a + data[a])
    #
    #     f = FLICKR["secret"] + "api_key" + FLICKR["api_key"] + foo
    #     # f = "api_key" + FLICKR[ "api_key" ] + foo
    #
    #     return hashlib.md5(f).hexdigest()

    # MSP: May be removed after migration to flickrapi
    # def urlGen(self, base, data, sig):
    #     """ urlGen
    #     """
    #     data['api_key'] = FLICKR["api_key"]
    #     data['api_sig'] = sig
    #     encoded_url = base + "?" + urllib.urlencode(data)
    #     return encoded_url

    # -------------------------------------------------------------------------
    # authenticate
    #
    # Authenticates via flickrapi on flickr.com
    #
    def authenticate(self):
        """
        Authenticate user so we can upload files
        """
        global nuflickr

        # instantiate nuflickr for connection to flickr via flickrapi
        nuflickr = flickrapi.FlickrAPI(FLICKR["api_key"],
                                       FLICKR["secret"],
                                       token_cache_location=TOKEN_CACHE)
        # Get request token
        niceprint('Getting new token.')
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
        nuflickr = flickrapi.FlickrAPI(FLICKR["api_key"],
                                       FLICKR["secret"],
                                       token_cache_location=TOKEN_CACHE)

        try:
            # XXX MSP If cached does it make sense to check if permissions are correct?
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
            niceprint("Unexpected error:" + sys.exc_info()[0])
            raise

    # -------------------------------------------------------------------------
    # checkToken
    #
    # If available, obtains the flicrapi Cached Token from local file.
    #
    # Returns
    #   true: if global token is defined and allows flicrk 'delete' operation
    #   false: if  global token is not defined of flicrk 'delete' is not allowed
    #
    def checkToken(self):
        """ checkToken
        flickr.auth.checkToken

        Returns the credentials attached to an authentication token.
        """
        global nuflickr

        if LOGGING_LEVEL <= logging.WARNING:
            logging.warning('checkToken is (self.token == None):[{!s}]'.
                                format(self.token == None))

        if (self.token == None):
            return False
        else:
            nuflickr = flickrapi.FlickrAPI(FLICKR["api_key"],
                                           FLICKR["secret"],
                                           token_cache_location=TOKEN_CACHE)
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

        # XXX MSP Changed from self to flick
        # if (not self.checkToken()):
        #     self.authenticate()
        if (not flick.checkToken()):
            flick.authenticate()
        con = lite.connect(DB_PATH)
        con.text_factory = str

        with con:
            cur = con.cursor()
            cur.execute("SELECT files_id, path FROM files")
            rows = cur.fetchall()

            for row in rows:
                if (self.isFileIgnored(row[1].decode('utf-8'))):
                    success = self.deleteFile(row, cur)

        # Closing DB connection
        if con != None:
            con.close()

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

        # XXX MSP Changed from self to flick
        # if (not self.checkToken()):
        #     self.authenticate()
        if (not flick.checkToken()):
            flick.authenticate()
        con = lite.connect(DB_PATH)
        con.text_factory = str

        with con:
            cur = con.cursor()
            cur.execute("SELECT files_id, path FROM files")
            rows = cur.fetchall()

            niceprint(str(len(rows)) + ' will be checked for Removal...')

            count = 0
            for row in rows:
                if (not os.path.isfile(row[1].decode('utf-8'))):
                    success = self.deleteFile(row, cur)
                    if LOGGING_LEVEL <= logging.WARNING:
                        logging.warning('deleteFile result: {!s}'.format(
                                                    success))
                    count = count + 1
                    if (count % 3 == 0):
                        niceprint('\t' + str(count) + ' files removed...')
            if (count % 100 > 0):
                niceprint('\t' + str(count) + ' files removed.')

        # Closing DB connection
        if con != None:
            con.close()

        niceprint('*****Completed deleted files*****')


    def upload(self):
        """ upload
        Add files to flickr and into their sets(Albums)
        If enabled CHANGE_MEDIA, checks for file changes and updates flickr
        """

        global nulockDB

        niceprint("*****Uploading files*****")

        allMedia = self.grabNewFiles()
        # If managing changes, consider all files
        if MANAGE_CHANGES:
            logging.warning('MANAGED_CHANGES is True. Reviewing allMedia.')
            changedMedia = allMedia
        # If not, then get just the new and missing files
        else:
            logging.warning('MANAGED_CHANGES is False. Reviewing only '
                            'changedMedia.')
            con = lite.connect(DB_PATH)
            with con:
                cur = con.cursor()
                cur.execute("SELECT path FROM files")
                existingMedia = set(file[0] for file in cur.fetchall())
                changedMedia = set(allMedia) - existingMedia

        changedMedia_count = len(changedMedia)
        niceprint('Found ' + str(changedMedia_count) + ' files to upload.')

        # running in multi processing mode
        if (args.processes and args.processes > 0):
            logging.debug('Running Pool of [{!s}] processes...'.
                            format(args.processes))
            logging.debug('__name__:[{!s}] to prevent recursive calling)!'.
                            format(__name__))

            # To prevent recursive calling, check if __name__ == '__main__'
            if __name__ == '__main__':
                l = multiprocessing.Lock()

                logging.debug('===Multiprocessing=== Setting up logger!')
                multiprocessing.log_to_stderr()
                logger = multiprocessing.get_logger()
                logger.setLevel(LOGGING_LEVEL)

                logging.debug('===Multiprocessing=== Lock defined!')

                from itertools import islice
                def chunk(it, size):
                    it = iter(it)
                    # lambda: creates a returning expression function
                    # whic returns slices
                    # iter, with the second argument () stops creating
                    # iterators when it reaches the end
                    return iter(lambda: tuple(islice(it, size)), ())

                uploadPool = []
                nulockDB = multiprocessing.Lock()

                # for i in range(int(args.processes)):

                sz = (len(changedMedia) / int(args.processes)) \
                     if ((len(changedMedia) / int(args.processes)) > 0) \
                     else 1

                logging.debug('len(changedMedia):[{!s}] '
                              'int(args.processes):[{!s}] '
                              'sz per process:[{!s}]'.
                              format(len(changedMedia),
                                     int(args.processes),
                                     sz))

                # Split the Media in chunks to distribute accross Processes
                for nuChangeMedia in chunk(changedMedia, sz):
                    logging.info('===Actual/Planned Chunk size: [{!s}]/[{!s}]'.
                                    format(len(nuChangeMedia), sz))
                    logging.debug(type(nuChangeMedia))

                    logging.debug('===Job/Task Process: Creating...')
                    uploadTask = multiprocessing.Process(
                                        target=self.uploadFileX,
                                        args=(nulockDB, nuChangeMedia,))
                    uploadPool.append(uploadTask)
                    logging.debug('===Job/Task Process: Starting...')
                    uploadTask.start()
                    logging.debug('===Job/Task Process: Started')

                # Check status of jobs/tasks in the Process Pool
                if LOGGING_LEVEL <= logging.DEBUG:
                    logging.debug('===Checking Processes launched/status:')
                    for j in uploadPool:
                        niceprint('%s.is_alive = %s' % (j.name, j.is_alive()))

                # Regularly print status of jobs/tasks in the Process Pool
                # Exits when all jobs/tasks are done.
                while (True):
                    if not (any(multiprocessing.active_children())):
                        logging.debug('===No active children Processes.')
                        break
                    for p in multiprocessing.active_children():
                        logging.debug('==={!s}.is_alive = {!s}'.
                                        format(p.name, p.is_alive()))
                        uploadTaskActive=p
                    niceprint('===Will wait for 60 on {!s}.is_alive = {!s}'.
                                format(uploadTaskActive.name,
                                       uploadTaskActive.is_alive()))

                    uploadTaskActive.join(timeout=60)
                    niceprint('===Waited for 60s on {!s}.is_alive = {!s}'.
                                format(uploadTaskActive.name,
                                       uploadTaskActive.is_alive()))

                # Wait for join all jobs/tasks in the Process Pool
                # All should be done by now!
                for j in uploadPool:
                    j.join()
                    niceprint('===%s (is alive: %s).exitcode = %s' %\
                              (j.name, j.is_alive(), j.exitcode))
                if LOGGING_LEVEL <= logging.WARNING:
                    logging.warning('===Multiprocessing=== pool joined!'
                                    'All processes finished.')
            else:
                niceprint('Pool not in __main__ process. '
                          'Windows or recursive?'
                          'Not possible to run Multiprocessing mode')
            # No longer used
            # else:
            #     pool = ThreadPool(processes=int(args.processes))
            #     pool.map(self.uploadFile, changedMedia)
        # running in single processing mode
        else:
            count = 0
            for i, file in enumerate(changedMedia):
                logging.debug('file:[{!s}] type(file):[{!s}]'.
                                format(file,
                                       type(file)))
                # lock parameter not used (set to None) under single processing
                success = self.uploadFile(None, file)
                if args.drip_feed and success and i != changedMedia_count - 1:
                    print("Waiting " +
                          str(DRIP_TIME) +
                          " seconds before next upload")
                    nutime.sleep(DRIP_TIME)
                count = count + 1;
                if (count % 100 == 0):
                    niceprint('\t' +
                              str(count) +
                              ' files processed (uploaded, md5ed '
                              'or timestamp checked)')
            if (count % 100 > 0):
                niceprint('\t' +
                          str(count) +
                          ' files processed (uploaded, md5ed '
                          'or timestamp checked)')

        niceprint("*****Completed uploading files*****")

    #--------------------------------------------------------------------------
    # convertRawFiles
    #
    def convertRawFiles(self):

        # MSP: Not converted... not being used at this time as I do not use RAW Files.

        """ convertRawFiles
        """
        if (not CONVERT_RAW_FILES):
            return

        niceprint('*****Converting files*****')
        for ext in RAW_EXT:
            print(u'About to convert files with extension: ' + ext.encode('utf-8') + u' files.') if isThisStringUnicode(ext) else ("About to convert files with extension: " + ext + " files.")

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
                            if isThisStringUnicode(dirpath):
                                if isThisStringUnicode(f):
                                    print(u'About to create JPG from raw ' + dirpath.encode('utf-8') + u'/' + f.encode('utf-8'))
                                else:
                                    print(u'About to create JPG from raw ' + dirpath.encode('utf-8') + u'/'),
                                    print(f)
                            elif isThisStringUnicode(f):
                                print("About to create JPG from raw " + dirpath + "/"),
                                print(f.encode('utf-8'))
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
                            if isThisStringUnicode(dirpath):
                                if isThisStringUnicode(f):
                                    print(u'About to copy tags from ' + dirpath.encode('utf-8') + u'/' + f.encode('utf-8') + u' to JPG.')
                                else:
                                    print(u'About to copy tags from ' + dirpath.encode('utf-8') + u'/'),
                                    print(f + " to JPG.")
                            elif isThisStringUnicode(f):
                                print("About to copy tags from " + dirpath + "/"),
                                print(f.encode('utf-8') + u' to JPG.')
                            else:
                                print("About to copy tags from " + dirpath + "/" + f + " to JPG.")


                            command = RAW_TOOL_PATH + "exiftool -tagsfromfile '" + dirpath + "/" + f + "' -r -all:all -ext JPG '" + dirpath + "/" + filename + ".JPG'"
                            # print(command)

                            p = subprocess.call(command, shell=True)

                            print("Finished copying tags.")

            print(u'Finished converting files with extension:' + ext.encode('utf-8') + u'.') if isThisStringUnicode(ext) else ("Finished converting files with extension:" + ext + ".")

        niceprint('*****Completed converting files*****')

    #--------------------------------------------------------------------------
    # grabNewFiles
    #
    def grabNewFiles(self):
        """ grabNewFiles
        
            Select files from FILES_DIR taking into consideration
            EXCLUDED_FOLDERS and IGNORED_REGEX filenames.
            Returns sorted file list.
        """

        files = []
        for dirpath, dirnames, filenames in os.walk(unicode(FILES_DIR, 'utf-8'), followlinks=True):
            for f in filenames:
                filePath = os.path.join(dirpath, f)
                if self.isFileIgnored(filePath):
                    if LOGGING_LEVEL <= logging.DEBUG:
                        logging.debug('File {!s} in EXCLUDED_FOLDERS:'.
                                        format(filePath.encode('utf-8')))
                    continue
                if any(ignored.search(f) for ignored in IGNORED_REGEX):
                    if LOGGING_LEVEL <= logging.DEBUG:
                        logging.debug('File {!s} in IGNORED_REGEX:'.
                                       format(filePath.encode('utf-8')))
                    continue
                ext = os.path.splitext(os.path.basename(f))[1][1:].lower()
                if ext in ALLOWED_EXT:
                    fileSize = os.path.getsize(dirpath + "/" + f)
                    if (fileSize < FILE_MAX_SIZE):
                        files.append(
                            os.path.normpath(
                                dirpath.encode('utf-8') +
                                "/" +
                                f.encode(' utf-8')).replace("'", "\'"))
                    else:
                        niceprint('Skipping file due to size restriction: ' +
                                  (os.path.normpath(dirpath.encode('utf-8') +
                                            '/' + f.encode('utf-8'))))
        files.sort()
        if LOGGING_LEVEL <= logging.DEBUG:
            logging.debug('Pretty Print Output for {!s}:'.format('files'))
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
    # uploadFileX
    #
    # uploadFile wrapper for multiprocessing purposes
    #
    def uploadFileX(self, lock, filelist):
        """ uploadFileX

            Wrapper function for multiprocessing support to call uploadFile
            with a chunk of the files.
        """

        for f in filelist:
            logging.debug('===First element of Chunk: [{!s}]'.format(f))
            self.uploadFile(lock, f)


    #--------------------------------------------------------------------------
    # uploadFile
    #
    # uploads a file into flickr
    #   lock = parameter for multiprocessing control of access to DB.
    #          if args.processes = 0 then lock can be None as it is not used
    #   file = fie to be uploaded
    #
    def uploadFile(self, lock, file):
        """ uploadFile
        upload file into flickr
        """

        global nuflickr

        if (args.dry_run == True):
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

            # use file modified timestamp to check for changes
            last_modified = os.stat(file).st_mtime;
            if row is None:
                niceprint(u'Uploading ' + file.encode('utf-8') + u'...'
                            if isThisStringUnicode(file)
                            else ("Uploading " + file + "..."))

                if FULL_SET_NAME:
                    setName = os.path.relpath(os.path.dirname(file), unicode(FILES_DIR, 'utf-8'))
                else:
                    head, setName = os.path.split(os.path.dirname(file))
                try:
                    #print u'setName' + str(type(setName)).encode('utf-8')
                    niceprint(u'setName: ' + setName.encode('utf-8'))\
                              if isThisStringUnicode(setName)\
                              else ('setName: ' + setName)
                    if isThisStringUnicode(file):
                        photo = ('photo', file.encode('utf-8'),
                                 open(file, 'rb').read())
                    else:
                        photo = ('photo', file,
                                 open(file, 'rb').read())
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
                    # UnicodeDecodeError: 'ascii' codec can't decode byte 0xc3
                    # in position 11: ordinal not in range(128)
                    # Worked around it by forcing the title to filename
                    if FLICKR["title"] == "":
                        path_filename, title_filename = os.path.split(file)
                        if LOGGING_LEVEL <= logging.WARNING:
                            logging.warning('path:[{!s}] '
                                            'filename:[{!s}] '
                                            'ext=[{!s}]'.format(
                                                path_filename,
                                                title_filename,
                                                os.path.splitext(
                                                        title_filename)[1]))
                        title_filename = os.path.splitext(title_filename)[0]
                        if LOGGING_LEVEL <= logging.WARNING:
                            logging.warning('title_name:[{!s}] '.
                                                format(title_filename))
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

                    # Perform actual upload of the file
                    res = None
                    search_result = None
                    for x in range(0, MAX_UPLOAD_ATTEMPTS):
                        try:
                            if FLICKR["title"] == "":
                                uploadResp = nuflickr.upload(
                                        filename = file,
                                        fileobj = FileWithCallback(file,
                                                                   callback),
                                        title = title_filename,
                                        description=str(FLICKR["description"]),
                                        tags='{} checksum:{}'.
                                                format(
                                                    FLICKR["tags"],
                                                    file_checksum
                                                    ).replace(',', ''),
                                        is_public=str(FLICKR["is_public"]),
                                        is_family=str(FLICKR["is_family"]),
                                        is_friend=str(FLICKR["is_friend"])
                                        )
                            else:
                                uploadResp = nuflickr.upload(
                                        filename = file,
                                        fileobj = FileWithCallback(file,
                                                                   callback),
                                        title=str(FLICKR["title"]),
                                        description=str(FLICKR["description"]),
                                        tags='{} checksum:{}'.
                                                format(FLICKR["tags"],
                                                       file_checksum
                                                       ).replace(',', ''),
                                        is_public=str(FLICKR["is_public"]),
                                        is_family=str(FLICKR["is_family"]),
                                        is_friend=str(FLICKR["is_friend"])
                                        )
                            if LOGGING_LEVEL <= logging.WARNING:
                                logging.warning('uploadResp: ')
                                logging.warning(xml.etree.ElementTree.tostring(
                                                    uploadResp,
                                                    encoding='utf-8',
                                                    method='xml'))
                            if self.isGood(uploadResp):
                                logging.info('search_result:OK')
                            else:
                                logging.info('search_result:NOT OK')
                            photo_id = uploadResp.findall('photoid')[0].text
                            logging.warning('uploaded OK. Flickr id='
                                            '[{!s}]'.format(photo_id))

                            # Debug search for photo with checksum to confirm loaded
                            search_result = None
                            if LOGGING_LEVEL <= logging.DEBUG:
                                search_result = self.photos_search(file_checksum)
                                if self.isGood(search_result):
                                    logging.info('search_result:OK')
                                else:
                                    logging.info('search_result:NOT OK')

                            break

                        # Exceptions for flickr.upload function call...
                        except (IOError, httplib.HTTPException):
                            niceprint('+++ #01 Caught IOError, HTTP expcetion')
                            niceprint('Sleep 10 and check if file is '
                                      'already uploaded')
                            nutime.sleep(10)

                            # on error, check if exists a photo
                            # with file_checksum
                            search_result = self.photos_search(file_checksum)
                            if not self.isGood(search_result):
                                raise IOError(search_result)

                            # if int(search_result["photos"]["total"]) == 0:
                            if int(search_result.find('photos').
                                        attrib['total']) == 0:
                                if x == MAX_UPLOAD_ATTEMPTS - 1:
                                    niceprint('Reached maximum number '
                                              'of attempts to upload, '
                                              'file: [{!s}]'.format(file))
                                    raise ValueError('Reached maximum number '
                                                     'of attempts to upload, '
                                                     'skipping')
                                niceprint('Not found, reuploading '
                                          '[{!s}/{!s} attempts].'.
                                            format(x, MAX_UPLOAD_ATTEMPTS))
                                continue

                            # if int(search_result["photos"]["total"]) > 1:
                            if int(search_result.find('photos').
                                        attrib['total']) > 1:
                                raise IOError('More then one file with same '
                                              'checksum! Any collisions? ' +
                                              search_result)

                            # if int(search_result["photos"]["total"]) == 1:
                            if int(search_result.find('photos').
                                        attrib['total']) == 1:
                                niceprint('Found, continuing with next image.')
                                break

                    # if not search_result and res.documentElement.attributes['stat'].value != "ok":
                    #     print(u'A problem occurred while attempting to upload the file: ' + file.encode('utf-8')) if isThisStringUnicode(file) else ("A problem occurred while attempting to upload the file:  " + file)
                    #     raise IOError(str(res.toxml()))

                    # if not search_result and uploadResp.attrib['stat'] != "ok":
                    if not search_result and not self.isGood(uploadResp):
                        niceprint('A problem occurred while attempting to '
                                    'upload the file: ' +
                                    file.encode('utf-8')
                                    if isThisStringUnicode(file)
                                    else ('A problem occurred while '
                                          'attempting to upload the file: ' +
                                          file))
                        raise IOError(str(uploadResp.toxml()))

                    # Successful update
                    niceprint(u'Successfully uploaded the file: ' +
                                file.encode('utf-8')
                                if isThisStringUnicode(file)
                                else ('Successfully uploaded file: ' +
                                      file))
                    # Unsuccessful update given that search_result is not None
                    if search_result:
                        # file_id = int(search_result["photos"]["photo"][0]["id"])
                        file_id = uploadResp.findall('photoid')[0].text
                        logging.info('Output for {!s}:'.format('uploadResp'))
                        logging.info(xml.etree.ElementTree.tostring(
                                            uploadResp,
                                            encoding='utf-8',
                                            method='xml'))
                        logging.warning('SEARCH_RESULT file_id={!s}'.
                            format(file_id))
                    else:
                        # Successful update given that search_result is None
                        # file_id = int(str(uploadResp.getElementsByTagName('photoid')[0].firstChild.nodeValue))
                        file_id = int(str(uploadResp.findall('photoid')[0].text))

                    # Add to db the file uploaded
                    # Control for when running multiprocessing set locking
                    if (args.processes and args.processes > 0):
                        logging.debug('===Multiprocessing=== in.lock.acquire')
                        lock.acquire()
                        logging.warning('===Multiprocessing=== '
                                        'out.lock.acquire')

                    cur.execute(
                        'INSERT INTO files (files_id, path, md5, '
                        'last_modified, tagged) VALUES (?, ?, ?, ?, 1)',
                        (file_id, file, file_checksum, last_modified))

                    # Control for when running multiprocessing release locking
                    if (args.processes and args.processes > 0):
                        logging.debug('===Multiprocessing=== in.lock.release')
                        lock.release()
                        logging.warning('===Multiprocessing=== '
                                        'out.lock.release')

                    # Update Date/Time on Flickr for Video files
                    # import mimetypes
                    # import time

                    filetype = mimetypes.guess_type(file)
                    logging.info('filetype:[{!s}]:'.format(filetype[0])) \
                                if not (filetype[0] is None) \
                                else ('filetype is None!!!')

                    if (not filetype[0] is None) and ('video' in filetype[0]):
                        res_set_date = None
                        video_date = nutime.strftime(
                                        '%Y-%m-%d %H:%M:%S',
                                        nutime.localtime(last_modified))
                        logging.info('video_date:[{!s}]'.format(video_date))

                        try:
                            res_set_date = flick.photos_set_dates(
                                                file_id,
                                                video_date)
                            if self.isGood(res_set_date):
                                niceprint("Set date ok")
                        except (IOError, ValueError, httplib.HTTPException):
                            print(str(sys.exc_info()))
                            print("Error setting date")
                            raise
                        if not self.isGood(res_set_date):
                            raise IOError(res_set_date)
                        #print("Successfully set date for pic number: " + str(file_id) + " File: " + file.encode('utf-8') + " date:" + video_date)
                        niceprint(u'Successfully set date for pic number: ' +
                                  file.encode('utf-8') +
                                  u' date:' +
                                  video_date)\
                                  if isThisStringUnicode(file)\
                                  else ('Successfully set date for pic '
                                        'number: ' +
                                        file +
                                        ' date:' +
                                        video_date)
                    success = True
                except flickrapi.exceptions.FlickrError as ex:
                    niceprint('+++ #02 Caught flickrapi exception')
                    niceprint('Error code: [{!s}]'.format(ex.code))
                    niceprint('Error code: [{!s}]'.format(ex))
                    niceprint(str(sys.exc_info()))
                except lite.Error as e:
                    print "A DB error occurred:", e.args[0]
                    if (args.processes and args.processes > 0):
                        logging.debug('===Multiprocessing==='
                                      'lock.release (in Error)')
                        lock.release()
                        logging.debug('===Multiprocessing==='
                                      'lock.release (in Error)')
                    return False

            elif (MANAGE_CHANGES):
                # we have a file from disk which is found on the database also
                # row[6] is last_modified date/timestamp
                # row[1] is files_id
                # row[4] is md5
                #   if DB/last_modified is None update it with current
                #   file/last_modified value and do nothing else
                #
                #   if DB/lastmodified is different from file/lastmodified
                #   then: if md5 has changed then perform replacePhoto
                #   operation on Flickr
                try:
                    if (row[6] == None):
                        # Update db the last_modified time of file

                        # Control for when running multiprocessing set locking
                        if (args.processes and args.processes > 0):
                            logging.debug('===Multiprocessing=== in.lock.acquire')
                            lock.acquire()
                            logging.warning('===Multiprocessing=== '
                                            'out.lock.acquire')

                        cur.execute('UPDATE files SET last_modified = ? '
                                    'WHERE files_id = ?', (last_modified, row[1]))
                        con.commit()

                        # Control for when running multiprocessing release locking
                        if (args.processes and args.processes > 0):
                            logging.debug('===Multiprocessing=== in.lock.release')
                            lock.release()
                            logging.warning('===Multiprocessing=== '
                                            'out.lock.release')
                    if (row[6] != last_modified):
                        # Update db both the new file/md5 and the
                        # last_modified time of file by by calling replacePhoto

                        fileMd5 = self.md5Checksum(file)
                        if (fileMd5 != str(row[4])):
                            self.replacePhoto(lock, file, row[1], row[4],
                                              fileMd5, last_modified, cur, con);
                except lite.Error as e:
                    print "A DB error occurred:", e.args[0]
                    if (args.processes and args.processes > 0):
                        logging.debug('===Multiprocessing==='
                                      'lock.release (in Error)')
                        lock.release()
                        logging.debug('===Multiprocessing==='
                                      'lock.release (in Error)')


        # Closing DB connection
        if con != None:
            con.close()
        return success

    #--------------------------------------------------------------------------
    # replacePhoto
    #   Should be only called frmo uploadFile
    #
    #   lock            = parameter for multiprocessing control of access to DB.
    #                     if args.processes = 0 then lock can be None as it is not used
    #   file            = file to be uploaded to replace existing file
    #   file_id         = ID of the photo being replaced
    #   oldfileMd5      = Old file MD5 (required to update checksum tag
    #                     on Flikr)
    #   fileMd5         = New file MD5
    #   last_modified   = date/time last modification of the file to update
    #                     database
    #   cur             = current cursor for updating Database
    #   con             = current DB connection
    #
    def replacePhoto(self, lock, file, file_id,
                     oldFileMd5, fileMd5, last_modified, cur, con):
        """ replacePhoto
        lock            = parameter for multiprocessing control of access to DB.
                          if args.processes = 0 then lock can be None as it is not used
        file            = file to be uploaded to replace existing file
        file_id         = ID of the photo being replaced
        oldfileMd5      = Old file MD5 (required to update checksum tag
                          on Flikr)
        fileMd5         = New file MD5
        last_modified   = date/time last modification of the file to update
                          database
        cur             = current cursor for updating Database
        con             = current DB connection
        """

        global nuflickr

        if args.dry_run :
            print(u'Dry Run Replace file ' + file.encode('utf-8') + u'...') \
                  if isThisStringUnicode(file) \
                  else ("Dry Run Replace file " + file + "...")
            return True

        success = False
        niceprint(u'Replacing the file: ' + file.encode('utf-8') + u'...')\
                  if isThisStringUnicode(file)\
                  else ("Replacing the file: " + file + "...")

        try:
            if isThisStringUnicode(file):
                photo = ('photo', file.encode('utf-8'), open(file, 'rb').read())
            else:
                photo = ('photo', file, open(file, 'rb').read())

            res = None
            res_add_tag = None
            res_get_info = None

            for x in range(0, MAX_UPLOAD_ATTEMPTS):
                try:
                    replaceResp = nuflickr.replace(
                                    filename=file,
                                    fileobj=FileWithCallback(file, callback),
                                    photo_id=file_id
                                )
                    logging.info('replaceResp: ')
                    logging.info( xml.etree.ElementTree.tostring(
                                                    replaceResp,
                                                    encoding='utf-8',
                                                    method='xml'))

                    if (self.isGood(replaceResp)):
                        # Update checksum tag at this time.
                        res_add_tag = flick.photos_add_tags(
                                        file_id,
                                        ['checksum:{}'.format(fileMd5)]
                                      )
                        logging.info('res_add_tag: ')
                        logging.info( xml.etree.ElementTree.tostring(
                                                res_add_tag,
                                                encoding='utf-8',
                                                method='xml'))
                        if (self.isGood(res_add_tag)):
                            # Gets Flickr file info to obtain all tags
                            # in order to update checksum tag if exists
                            res_get_info = nuflickr.photos_get_info(
                                                photo_id=file_id
                                                )
                            logging.info('res_get_info: ')
                            logging.info( xml.etree.ElementTree.tostring(
                                                    res_get_info,
                                                    encoding='utf-8',
                                                    method='xml'))
                            # find tag checksum with oldFileMd5
                            # later use such tag_id to delete it
                            if (self.isGood(res_get_info)):
                                tag_id = None
                                for tag in res_get_info.\
                                                find('photo').\
                                                find('tags').\
                                                findall('tag'):
                                    if (tag.attrib['raw'] == \
                                           'checksum:{}'.format(oldFileMd5)):
                                        tag_id = tag.attrib['id']
                                        break
                                if not tag_id:
                                    niceprint('Can\'t find tag [{!s}]'
                                              'for file [{!s}]'.
                                              format(tag_id, file_id))
                                    # break from attempting to update tag_id
                                    break
                                else:
                                    # update tag_id with new Md5
                                    logging.info('Will remove tag_id:[{!s}]'.
                                                    format(tag_id))
                                    remtagResp = self.photos_remove_tag(tag_id)
                                    logging.info('remtagResp: ')
                                    logging.info(xml.etree.ElementTree.tostring(
                                                            remtagResp,
                                                            encoding='utf-8',
                                                            method='xml'))
                                    if (self.isGood(remtagResp)):
                                        niceprint('Tag removed.')
                                    else:
                                        niceprint('Tag Not removed.')

                    # if res.documentElement.attributes['stat'].value == "ok":
                    #     res_add_tag = self.photos_add_tags(file_id, ['checksum:{}'.format(fileMd5)])
                    #     if res_add_tag['stat'] == 'ok':
                    #         res_get_info = flick.photos_get_info(file_id)
                    #         if res_get_info['stat'] == 'ok':
                    #             tag_id = None
                    #             for tag in res_get_info['photo']['tags']['tag']:
                    #                 if tag['raw'] == 'checksum:{}'.format(oldFileMd5):
                    #                     tag_id = tag['id']
                    #                     break
                    #             if not tag_id:
                    #                 print("Can't find tag {} for file {}".format(tag_id, file_id))
                    #                 break
                    #             else:
                    #                 self.photos_remove_tag(tag_id)
                    break
                # Exceptions for flickr.upload function call...
                except (IOError, ValueError, httplib.HTTPException):
                    niceprint('+++ #03 Caught IOError, ValueError, HTTP expcetion')
                    niceprint('Sleep 10 and try to replace again.')
                    niceprint(str(sys.exc_info()))
                    nutime.sleep(10)
                # except (IOError, ValueError, httplib.HTTPException):
                #     print(str(sys.exc_info()))
                #     print("Replacing again")
                #     nutime.sleep(5)

                    if x == MAX_UPLOAD_ATTEMPTS - 1:
                        raise ValueError('Reached maximum number of attempts '
                                         'to replace, skipping')
                    continue

            if (not self.isGood(replaceResp)) or \
                   (not self.isGood(res_add_tag)) or \
                   (not self.isGood(res_get_info)):
                niceprint(u'A problem occurred while attempting to '
                          'replace the file: ' + file.encode('utf-8')) \
                          if isThisStringUnicode(file) \
                          else ('A problem occurred while attempting to '
                                'replace the file: ' + file)

            if (not self.isGood(replaceResp)):
                raise IOError(replaceResp)

            if (not(self.isGood(res_add_tag))):
                raise IOError(res_add_tag)

            if (not self.isGood(res_get_info)):
                raise IOError(res_get_info)

            # if res.documentElement.attributes['stat'].value != "ok":
            #     raise IOError(str(res.toxml()))
            #
            # if res_add_tag['stat'] != 'ok':
            #     raise IOError(res_add_tag)
            #
            # if res_get_info['stat'] != 'ok':
            #     raise IOError(res_get_info)

            # print(u'Successfully replaced the file: ' + file.encode('utf-8')) if isThisStringUnicode(file) else ("Successfully replaced the file: " + file)
            niceprint(u'Successfully replaced the file: ' +
                      file.encode('utf-8')) \
                      if isThisStringUnicode(file) \
                      else ("Successfully replaced the file: " + file)

            # Update the db the file uploaded
            # Control for when running multiprocessing set locking
            if (args.processes and args.processes > 0):
                logging.debug('===Multiprocessing=== in.lock.acquire')
                lock.acquire()
                logging.warning('===Multiprocessing=== '
                                'out.lock.acquire')

            cur.execute('UPDATE files SET md5 = ?,last_modified = ? '
                        'WHERE files_id = ?',
                        (fileMd5, last_modified, file_id))
            con.commit()

            # Control for when running multiprocessing release locking
            if (args.processes and args.processes > 0):
                logging.debug('===Multiprocessing=== in.lock.release')
                lock.release()
                logging.warning('===Multiprocessing=== '
                                'out.lock.release')

            # Update Date/Time on Flickr for Video files
            # MSP: mimetypes already imported is it required?
            # import mimetypes
            # import time
            filetype = mimetypes.guess_type(file)
            logging.info('filetype:[{!s}]:'.format(filetype[0])) \
                        if not (filetype[0] is None) \
                        else ('filetype is None!!!')

            if (not filetype[0] is None) and ('video' in filetype[0]):
                video_date = nutime.strftime('%Y-%m-%d %H:%M:%S',
                                             nutime.localtime(last_modified))
                logging.info('video_date:[{!s}]'.format(video_date))

                try:
                    res_set_date = flick.photos_set_dates(file_id, video_date)
                    if self.isGood(res_set_date):
                        niceprint("Set date ok")
                except (IOError, ValueError, httplib.HTTPException):
                    print(str(sys.exc_info()))
                    print("Error setting date")
                if not self.isGood(res_set_date):
                    raise IOError(res_set_date)
                # print("Successfully set date for pic number: " + str(file_id) + " File: " + file.encode('utf-8') + " date:" + video_date)
                # print(u'Successfully set date for pic number: ' + str(file_id) + u' File: ' + file.encode('utf-8') + u' date:' + video_date) if isThisStringUnicode(file) else ("Successfully set date for pic number: " + str(file_id) + ' File: ' + file + " date:" + video_date)
                niceprint(u'Successfully set date for pic number: ' +
                          file.encode('utf-8') + u' date:' + video_date) \
                          if isThisStringUnicode(file)\
                          else ('Successfully set date for pic '
                                'number: ' +
                                file +
                                ' date:' +
                                video_date)

            success = True
        # MSP: Do I need this generic except? Maybe after flickr and SQLite3?
        # except:
        #     print(str(sys.exc_info()))
        except flickrapi.exceptions.FlickrError as ex:
            niceprint('+++ #04 Caught flickrapi exception')
            niceprint('Error code: [{!s}]'.format(ex.code))
            niceprint('Error code: [{!s}]'.format(ex))
            niceprint(str(sys.exc_info()))
        except lite.Error as e:
            print "A DB error occurred:", e.args[0]
            if (args.processes and args.processes > 0):
                logging.debug('===Multiprocessing=== lock.release (in Error)')
                lock.release()
                logging.debug('===Multiprocessing=== lock.release (in Error)')
            success = False

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

        if args.dry_run:
            print(u'Deleting file: ' + file[1].encode('utf-8')) if isThisStringUnicode(file[1]) else ("Deleting file: " + file[1])
            return True

        success = False
        # print(u'Deleting file: ' + file[1].encode('utf-8')) if isThisStringUnicode(file[1]) else ("Deleting file: " + file[1])
        niceprint('Deleting file: ' + file[1].encode('utf-8')
                    if isThisStringUnicode(file[1])
                    else ('Deleting file: ' + file[1]))
        try:
            deleteResp = nuflickr.photos.delete(
                                        photo_id=str(file[0]))
            logging.info('Output for {!s}:'.format('deleteResp'))
            logging.info( xml.etree.ElementTree.tostring(
                                    deleteResp,
                                    encoding='utf-8',
                                    method='xml'))
            if (self.isGood(deleteResp)):
                # Find out if the file is the last item in a set, if so, remove the set from the local db
                cur.execute("SELECT set_id FROM files WHERE files_id = ?", (file[0],))
                row = cur.fetchone()
                cur.execute("SELECT set_id FROM files WHERE set_id = ?", (row[0],))
                rows = cur.fetchall()
                if (len(rows) == 1):
                    niceprint('File is the last of the set, '
                              'deleting the set ID: ' + str(row[0]))
                    cur.execute("DELETE FROM sets WHERE set_id = ?", (row[0],))

                # Delete file record from the local db
                cur.execute("DELETE FROM files WHERE files_id = ?", (file[0],))
                niceprint("Successful deletion.")
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

    #--------------------------------------------------------------------------
    # logSetCreation
    #
    #   Creates on flickrdb local database a SetName(Album)
    #
    def logSetCreation(self, setId, setName, primaryPhotoId, cur, con):
        """
        Creates on flickrdb local database a SetName(Album)
        """

        if LOGGING_LEVEL <= logging.INFO:
            logging.info('setName:[{!s}] setName.type:[{!s}]'.
                            format(setName,
                                    type(setName)))
            # niceprint u'setName.type=' + str(type(setName)).encode('utf-8')
            logging.warning('Adding set: [{!s}] to log.'.format(setName))

        success = False
        cur.execute("INSERT INTO sets (set_id, name, primary_photo_id) VALUES (?,?,?)",
                    (setId, setName, primaryPhotoId))
        cur.execute("UPDATE files SET set_id = ? WHERE files_id = ?", (setId, primaryPhotoId))
        con.commit()
        return True

    # MSP: May be removed after migration to flickrapi
    # def build_request(self, theurl, fields, files, txheaders=None):
    #     """
    #     build_request/encode_multipart_formdata code is from www.voidspace.org.uk/atlantibots/pythonutils.html
    #
    #     Given the fields to set and the files to encode it returns a fully formed urllib2.Request object.
    #     You can optionally pass in additional headers to encode into the opject. (Content-type and Content-length will be overridden if they are set).
    #     fields is a sequence of (name, value) elements for regular form fields - or a dictionary.
    #     files is a sequence of (name, filename, value) elements for data to be uploaded as files.
    #     """
    #
    #     content_type, body = self.encode_multipart_formdata(fields, files)
    #     if not txheaders: txheaders = {}
    #     txheaders['Content-type'] = content_type
    #     txheaders['Content-length'] = str(len(body))
    #
    #     return urllib2.Request(theurl, body, txheaders)

    # MSP: May be removed after migration to flickrapi
    # def encode_multipart_formdata(self, fields, files, BOUNDARY='-----' + mimetools.choose_boundary() + '-----'):
    #     """ Encodes fields and files for uploading.
    #     fields is a sequence of (name, value) elements for regular form fields - or a dictionary.
    #     files is a sequence of (name, filename, value) elements for data to be uploaded as files.
    #     Return (content_type, body) ready for urllib2.Request instance
    #     You can optionally pass in a boundary string to use or we'll let mimetools provide one.
    #     """
    #
    #     CRLF = '\r\n'
    #     L = []
    #     if isinstance(fields, dict):
    #         fields = fields.items()
    #     for (key, value) in fields:
    #         L.append('--' + BOUNDARY)
    #         L.append('Content-Disposition: form-data; name="%s"' % key)
    #         L.append('')
    #         L.append(value)
    #     for (key, filename, value) in files:
    #         filetype = mimetypes.guess_type(filename)[0] or 'application/octet-stream'
    #         L.append('--' + BOUNDARY)
    #         L.append('Content-Disposition: form-data; name="%s"; filename="%s"' % (key, filename))
    #         L.append('Content-Type: %s' % filetype)
    #         L.append('')
    #         L.append(value)
    #     L.append('--' + BOUNDARY + '--')
    #     L.append('')
    #     body = CRLF.join(L)
    #     content_type = 'multipart/form-data; boundary=%s' % BOUNDARY  # XXX what if no files are encoded
    #     return content_type, body

    #--------------------------------------------------------------------------
    # isGood
    #
    def isGood(self, res):
        """ isGood

            Returns true if attrib['stat'] == "ok" for a given XML object
        """
        if (res == None):
            return False
        elif (not res == "" and res.attrib['stat'] == "ok"):
            return True
        else:
            return False

    #--------------------------------------------------------------------------
    # reportError
    #
    # MSP: Check if required!!
    #
    def reportError(self, res):
        """ reportError
        """

        try:
            print("ReportError: " + str(res['code'] + " " + res['message']))
        except:
            print("ReportError: " + str(res))

    # MSP: Probably not required any more
    # def getResponse(self, url):
    #     """
    #     Send the url and get a response.  Let errors float up
    #     """
    #     res = None
    #     try:
    #         res = urllib2.urlopen(url, timeout=SOCKET_TIMEOUT).read()
    #     except urllib2.HTTPError, e:
    #         print(e.code)
    #     except urllib2.URLError, e:
    #         print(e.args)
    #     return json.loads(res, encoding='utf-8')

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
            niceprint("Last check: " + str(nutime.asctime(time.localtime())))
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
                    niceprint(u'Created the set: ' + setName.encode('utf-8')
                              if isThisStringUnicode(setName)
                              else ('Created the set: ' + setName))
                    newSetCreated = True
                else:
                    setId = set[0]

                if row[2] == None and newSetCreated == False:
                    niceprint(u'adding file to set ' + row[1].encode('utf-8') + u'...') if isThisStringUnicode(row[1]) else ("adding file to set " + row[1])

                    self.addFileToSet(setId, row, cur)

        # Closing DB connection
        if con != None:
            con.close()
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
            con = lite.connect(DB_PATH)
            con.text_factory = str

            addPhotoResp = nuflickr.photosets.addPhoto(
                                photoset_id = str(setId),
                                photo_id = str(file[0]))

            if LOGGING_LEVEL <= logging.INFO:
                logging.info('addPhotoResp: ')
                # try out to string...
                logging.info( xml.etree.ElementTree.tostring(
                                                    addPhotoResp,
                                                    encoding='utf-8',
                                                    method='xml'))
                # xml.etree.ElementTree.dump(addPhotoResp)

            if (self.isGood(addPhotoResp)):
                niceprint(u'Successfully added file ' +
                          file[1].encode('utf-8') +
                          u' to its set.')\
                          if isThisStringUnicode(file[1])\
                          else ("Successfully added file " +
                                file[1] +
                                " to its set.")

                cur.execute("UPDATE files SET set_id = ? WHERE files_id = ?",
                            (setId, file[0]))
            else:
                if (addPhotoResp['code'] == 1):
                    niceprint('Photoset not found, creating new set...')
                    if FULL_SET_NAME:
                        setName = os.path.relpath(os.path.dirname(file[1]),
                                                  unicode(FILES_DIR, 'utf-8'))
                    else:
                        head, setName = os.path.split(os.path.dirname(file[1]))

                    self.createSet(setName, file[0], cur, con)
                elif (addPhotoRest['code'] == 3):
                    niceprint('Photo already in set... updating DB')
                    niceprint(addPhotoRest['message'] + '... updating DB')
                    cur.execute('UPDATE files SET set_id = ? '
                                'WHERE files_id = ?', (setId, file[0]))
                else:
                    self.reportError(res)
            # Closing DB connection
            if con != None:
                con.close()
        except:
            print(str(sys.exc_info()))

    #--------------------------------------------------------------------------
    # createSet
    #
    def createSet(self, setName, primaryPhotoId, cur, con):

        global nuflickr

        niceprint(u'setName.type=' + str(type(setName)).encode('utf-8'))
        niceprint(u'Creating new set: '.encode('utf-8') + str(setName))
        #print("Creating new set: ", str(setName).encode('utf-8'))

        if args.dry_run:
            return True

        try:
            createResp = nuflickr.photosets.create(
                            title = setName,
                            primary_photo_id = str(primaryPhotoId))
            if LOGGING_LEVEL <= logging.WARNING:
                logging.warning('createResp: ')
                # xml.etree.ElementTree.dump(createResp)
                logging.warning( xml.etree.ElementTree.tostring(
                                                createResp,
                                                encoding='utf-8',
                                                method='xml'))

            if (self.isGood(createResp)):
                if LOGGING_LEVEL <= logging.WARNING:
                    logging.warning('createResp["photoset"]["id"]:[{!s}]'.
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
                    # xml.etree.ElementTree.dump(createResp)
                    logging.warning( xml.etree.ElementTree.tostring(
                                                        createResp,
                                                        encoding='utf-8',
                                                        method='xml'))
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
            # Closing DB connection
            if con != None:
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
        if args.dry_run:
                return True

        con = lite.connect(DB_PATH)
        con.text_factory = str
        with con:
            cur = con.cursor()
            cur.execute("SELECT set_id, name FROM sets WHERE set_id NOT IN\
                        (SELECT set_id FROM files)")
            unusedsets = cur.fetchall()

            for row in unusedsets:
                niceprint('Removing set [' +
                          str(row[0]) +
                          "] (" +
                          row[1].decode('utf-8') +
                          ').')

                cur.execute("DELETE FROM sets WHERE set_id = ?", (row[0],))
            con.commit()

        # Closing DB connection
        if con != None:
            con.close()
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
        # Closing DB connection
        if con != None:
            con.close()

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
        if args.dry_run:
                return True

        con = lite.connect(DB_PATH)
        con.text_factory = str
        try:
            sets = nuflickr.photosets_getList()

            logging.info('Output for {!s}'.format('photosets_getList:'))
            logging.info( xml.etree.ElementTree.tostring(
                                                sets,
                                                encoding='utf-8',
                                                method='xml'))

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

            if (self.isGood(sets)):
                cur = con.cursor()
                # print "Before Title"
                # title  = sets['photosets']['photoset'][0]['title']['_content']
                # print "After Title"

                # print('First set title: %s' % title)

                for row in sets.find('photosets').findall('photoset'):
                    logging.info('Output for {!s}:'.format('row'))
                    logging.info( xml.etree.ElementTree.tostring(
                                row,
                                encoding='utf-8',
                                method='xml'))

                    setId = row.attrib['id']
                    setName = row.find('title').text
                    primaryPhotoId = row.attrib['primary']
                    # print('no encode commas', setId, setName, primaryPhotoId)
                    # print('no encode plus' + setId + setName + primaryPhotoId)
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
                    niceprint(u'id=['.encode('utf-8') +
                              setId.encode('utf-8') + u'] '.encode('utf-8') +
                              u'setName=['.encode('utf-8') +
                              setName +
                              u'] '.encode('utf-8') +
                              u'primaryPhotoId=['.encode('utf-8') +
                              primaryPhotoId.encode('utf-8') +
                              u']'.encode('utf-8'))
                    if LOGGING_LEVEL <= logging.INFO:
                        logging.info('setId:[{!s}] '
                                     'setName:[{!s}] '
                                     'primaryPhotoId:[{!s}]'.
                                     format(setId,
                                            setName.encode('utf-8'),
                                            primaryPhotoId))

                    cur.execute("SELECT set_id FROM sets WHERE set_id = '"
                                + setId + "'")
                    foundSets = cur.fetchone()
                    if LOGGING_LEVEL <= logging.INFO:
                        logging.info('Output for {!s}:'.format('foundSets'))
                        logging.info(foundSets)

                    if foundSets == None:
                        niceprint(u'Adding set ['.encode('utf-8') +
                                  setId.encode('utf-8') +
                                  u'] ('.encode('utf-8') +
                                  setName +
                                  u') '.encode('utf-8') +
                                  u'with primary photo '.encode('utf-8') +
                                  primaryPhotoId.encode('utf-8') +
                                   u'.'.encode('utf-8'))
                        # print(u"Adding set #{0} ({1}) with primary photo #{2}".
                        #       format(setId, setName, primaryPhotoId))
                        cur.execute('INSERT INTO sets (set_id, name, '
                                    'primary_photo_id) VALUES (?,?,?)',
                                    (setId, setName, primaryPhotoId))
                    else:
                        niceprint('Flickr Set/Album already on local database.')

                con.commit()
                # niceprint('Sleep...3...to allow Commit... TO BE REMOVED?')
                # nutime.sleep(3)
                # niceprint('After Sleep...3...to allow Commit')
                # Closing DB connection
                if con != None:
                    con.close()
            else:
                logging.warning( xml.etree.ElementTree.tostring(
                                    sets,
                                    encoding='utf-8',
                                    method='xml'))
                # xml.etree.ElementTree.dump(sets)
                self.reportError(sets)

        except flickrapi.exceptions.FlickrError as ex:
            print("Error code: %s" % ex.code)
            print("Error code:", ex)
            print(str(sys.exc_info()))

        # except:
        #     print "EXCEPTION"
        #     FlickrError
        #     print(str(sys.exc_info()))

        # Closing DB connection
        if con != None:
            con.close()
        niceprint('*****Completed adding Flickr Sets to DB*****')

    #--------------------------------------------------------------------------
    # photos_search
    #
    # Searchs for image with on tag:checksum (calls Flickr photos.search)
    #
    def photos_search(self, checksum):
        """
            photos_search
            Searchs for image with on tag:checksum
        """

        global nuflickr

        logging.info('FORMAT checksum:{!s}:'.format(checksum))

        searchResp = nuflickr.photos.search(tags='checksum:{}'.format(checksum))
        # Debug
        logging.debug('Search Results SearchResp:')
        logging.debug( xml.etree.ElementTree.tostring(
                                            searchResp,
                                            encoding='utf-8',
                                            method='xml'))

        return searchResp

    #--------------------------------------------------------------------------
    # people_get_photos
    #
    #   Local Wrapper for Flickr people.getPhotos
    #
    def people_get_photos(self):
        """
        """

        global nuflickr

        getPhotosResp = nuflickr.people.getPhotos(user_id="me",
                                                  per_page=1)
        return getPhotosResp

    #--------------------------------------------------------------------------
    # photos_get_not_in_set
    #
    #   Local Wrapper for Flickr photos.getNotInSet
    #
    def photos_get_not_in_set(self):
        """
        Local Wrapper for Flickr photos.getNotInSet
        """

        global nuflickr

        notinsetResp = nuflickr.photos.getNotInSet(per_page=1)
        return notinsetResp

    #--------------------------------------------------------------------------
    # photos_add_tags
    #
    #   Local Wrapper for Flickr photos.addTags
    #
    def photos_add_tags(self, photo_id, tags):
        """
        Local Wrapper for Flickr photos.addTags
        """

        global nuflickr

        photos_add_tagsResp = nuflickr.photos.addTags(photo_id=photo_id,
                                                      tags=tags)
        return photos_add_tagsResp

    #--------------------------------------------------------------------------
    # photos_get_info
    #
    #   Local Wrapper for Flickr photos.getInfo
    #
    def photos_get_info(self, photo_id):
        """
        Local Wrapper for Flickr photos.getInfo
        """

        global nuflickr

        photos_get_infoResp = nuflickr.photos.getInfo(photo_id=photo_id)

        return photos_get_infoResp

    #--------------------------------------------------------------------------
    # photos_remove_tag
    #
    #   Local Wrapper for Flickr photos.removeTag
    #   The tag to remove from the photo. This parameter should contain
    #   a tag id, as returned by flickr.photos.getInfo.
    #
    def photos_remove_tag(self, tag_id):
        """
        Local Wrapper for Flickr photos.removeTag

        The tag to remove from the photo. This parameter should contain
        a tag id, as returned by flickr.photos.getInfo.
        """

        global nuflickr

        removeTagResp = nuflickr.photos.removeTag(tag_id=tag_id)

        return removeTagResp

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

        respDate = nuflickr.photos.setdates(photo_id=photo_id,
                                            date_taken=datetxt)
        logging.info('Output for {!s}:'.format('respDate'))
        # xml.etree.ElementTree.dump(respDate)
        logging.info( xml.etree.ElementTree.tostring(
                                respDate,
                                encoding='utf-8',
                                method='xml'))

        return respDate

    #--------------------------------------------------------------------------
    # print_stat
    #
    # List Local pics, loaded pics into Flickr, pics not in sets on Flickr
    #
    def print_stat(self):
        """ print_stat
        Shows Total photos and Photos Not in Sets on Flickr
        """
        # Total Local photos count
        con = lite.connect(DB_PATH)
        con.text_factory = str
        countlocal = 0
        with con:
            cur = con.cursor()
            cur.execute("SELECT Count(*) FROM files")

            countlocal = cur.fetchone()[0]
            if LOGGING_LEVEL <= logging.DEBUG:
                print('Total photos on local: {}'.format(countlocal))

        # Total FLickr photos count
        countflickr = 0
        res = self.people_get_photos()
        if not self.isGood(res):
            raise IOError(res)
        logging.debug('print people_get_photos')
        logging.debug( xml.etree.ElementTree.tostring(
                                res,
                                encoding='utf-8',
                                method='xml'))

        countflickr = format(res.find('photos').attrib['total'])
        if LOGGING_LEVEL <= logging.DEBUG:
            logging.debug('Total photos on flickr: {!s}'.format(countflickr))

        # Total photos not on Sets/Albums on FLickr
        countnotinsets = 0
        res = self.photos_get_not_in_set()
        if not self.isGood(res):
            raise IOError(res)
        logging.debug('print get_not_in_set')
        logging.debug( xml.etree.ElementTree.tostring(
                                res,
                                encoding='utf-8',
                                method='xml'))

        countnotinsets = format(res.find('photos').attrib['total'])
        if LOGGING_LEVEL <= logging.DEBUG:
            logging.debug(
                'Photos not in sets on flickr: {!s}'.format(countnotinsets))

        # Print total stats counters
        niceprint('Photos count: Local:[' + str(countlocal) + '] ' +
                  'Flickr:[' + str(countflickr) + '] ' +
                  'Not in sets on Flickr:[' + str(countnotinsets) + '] ')

        # List pics not in sets (if within a parameter, default 10)
        if (args.list_photos_not_in_set and
                args.list_photos_not_in_set > 0 and
                countnotinsets > 0):
            niceprint('*****Listing Photos not in a set in Flickr******')
            itr = 0
            for row in res.find('photos').findall('photo'):
                if LOGGING_LEVEL <= logging.DEBUG:
                    logging.debug(
                        'Photo get_not_in_set '
                        'id:[{!s}] '
                        'title:[{!s}]'.format(row.attrib['id'],
                                              row.attrib['title']))
                    # xml.etree.ElementTree.dump(row)
                    logging.debug( xml.etree.ElementTree.tostring(
                                    row,
                                    encoding='utf-8',
                                    method='xml'))
                niceprint('Photo get_not_in_set: id:[' +
                          row.attrib['id'] + ']' +
                          'title:[' +
                          row.attrib['title'] + ']')
                itr = itr + 1
                if itr > args.list_photos_not_in_set:
                    break
            niceprint('*****Completed Listing Photos not in a set '
                      'in Flickr******')

#------------------------------------------------------------------------------
# Main code
#
nutime = time

niceprint('--------- Start time: ' +
          nutime.strftime(UPLDRConstants.TimeFormat) +
          ' ---------')
if __name__ == "__main__":
    # Ensure that only once instance of this script is running
    f = open(LOCK_PATH, 'w')
    try:
        fcntl.lockf(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except IOError, e:
        if e.errno == errno.EAGAIN:
            sys.stderr.write('[{!s}] Script already running.\n'.
                             format(nutime.strftime(
                                                UPLDRConstants.TimeFormat)))
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
                        metavar='P', type=int,
                        help='Number of photos to upload simultaneously')
    parser.add_argument('-n', '--dry-run', action='store_true',
                        help='Dry run')
    # when you change EXCLUDE_FOLDERS setting
    parser.add_argument('-g', '--remove-ignored', action='store_true',
                        help='Remove previously uploaded files, '
                             'now ignored due to change of EXCLUDED_FOLDERS')
    # used in print_stat function
    parser.add_argument('-l', '--list-photos-not-in-set',
                        metavar='N', type=int,
                        help='List N photos not in set.')

    args = parser.parse_args()

    # Debug to show arguments
    if LOGGING_LEVEL <= logging.INFO:
        logging.info('Pretty Print Output for {!s}'.format('args:'))
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
        print('Please enter an API key and secret in the configuration '
              'script file, normaly uploadr.ini (see README).')
        sys.exit()

    flick.setupDB()

    if args.daemon:
        # Will run in daemon mode every SLEEP_TIME seconds
        if LOGGING_LEVEL <= logging.WARNING:
            logging.warning('Will run in daemon mode every {!s} seconds'.
                            format(SLEEP_TIME))
        flick.run()
    else:
        niceprint("Checking if token is available... if not will authenticate")
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

niceprint("--------- End time: " +
          time.strftime(UPLDRConstants.TimeFormat) +
          " ---------")
