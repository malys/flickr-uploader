# flickr-uploader
----------------
by oPromessa, 2017, V2.6.4

## IMPORTANT NOTE: (MOST OF THE WORK DONE). MORE IN PROGRESS...
* Updated to use sybrenstuvel's flickrapi and OAuth...
* V2.6.3 would be good for use and testing.

## Description
--------------
* flickr-uploader designed for Synology Devices.
* Upload a directory of media to Flickr to use as a backup to your
local storage.
* Check Features, Requirements and Setup remarks.

## Features
-----------
* Uploads both images and movies (JPG, PNG, GIF, AVI, MOV, 3GP files)
   * Personnaly I avoid PNG files which do not support EXIF info
* Multiple loadings in parallel is available (check -p option)
* Stores image information locally using a simple SQLite database
* Creates "Sets" based on the folder name the media is in
  (getting existing sets from Flickr is managed also)
* Ignores unwanted directories (like ".picasabackup" for Picasa users or
  "@eaDir" for Synology NAS users) and you can easily add/configure more
  yourself. Check uploadr.ini config file.
* Allows specific files to be ignored (via regular expressions)
* Skips files that are over a configurable size (max flickr size is about 900MB)
* Reuploads modified images
* Automatically removes images from Flickr when they are removed from your
  local hard drive
* Convert RAW files (with an external tool). Check Known issues section.

THIS SCRIPT IS PROVIDED WITH NO WARRANTY WHATSOEVER.
PLEASE REVIEW THE SOURCE CODE TO MAKE SURE IT WILL WORK FOR YOUR NEEDS.
IF YOU FIND A BUG, PLEASE REPORT IT.

### Sample file structure
Consider this example to explain how files are uploaded into Albums/Sets on Flickr.

If you have the following folders and pics  (the name of the flickr setnames/Albums depends on the uploadr.ini file setting FULL_SET_NAME, but I normally use it as False):
```
/home/user/media/pic00.jpg
/home/user/media/Album1/pic01.jpg
/home/user/media/Album2/pic02.jpg
/home/user/media/Album3/pic03.jpg
/home/user/media/folder/Album4/pic04.jpg
/home/user/media/folder/Album4/Sub/pic041.jpg
/home/user/media/newfolder/Album4/pic042.jpg
/home/user/media/folderAlbum5/pic01.jpg

```

And you setup FILES_DIR
```
FILES_DIR=/home/user/media
```
You should get the following:

| FilePathName | SetName/Album Name (with FULL_SET_NAME=False) | SetName/Album Name (with FULL_SET_NAME=True) | Pic | Remarks | 
| ------------- | ------------- | ------------- | ------------- | ------------- |
| /home/user/media/pic00.jpg | media | . | pic00 | |
| /home/user/media/Album1/pic01.jpg | Album1 |  Album1 | pic01 | |
| /home/user/media/Album2/pic02.jpg | Album2 |  Album2 | pic02 | |
| /home/user/media/Album3/pic03.jpg | Album3 |  Album3 | pic03 | |
| /home/user/media/folder/Album4/pic04.jpg | Album4 | folder/Album4 | pic04 | |
| /home/user/media/folder/Album4/Sub/pic041.jpg | Sub  | folder/Album4/Sub  | pic041 | |
| /home/user/media/newfolder/Album4/pic042.jpg | Album4 | newfolder/Album4 | pic042 | |
| /home/user/media/Album5/pic01.jpg | Album5 |  Album5 | pic01 | It's the same pic as in Album01 but it will be loaded twice as it belongs to a different Album |

## Requirements
---------------
* Python 2.7+ (should work on DSM from Synology (v6.1), Windows and MAC)
* flicrkapi module. May need to install get-pip.py. (Instructions for
  Synology DSM below.)
* File write access (for the token and local database)
* Flickr API key (free)

## Setup on Synology
--------------------
Might work on other platforms like Windows also.
*Side note:* don't be overwhelmed with this setup. They are quite
straitghtforward.

Enable and access your Synology DSM via SSH with an admin user.
Avoid the use of root for security reasons

To create a local install define and export PYTHONPATH variable:
```bash
$ cd
$ mkdir apps
$ mkdir apps/Python
$ export PYTHONPATH=~/apps/Python/lib/python2.7/site-packages
```
Download get-pip.py and install
```bash        
$ cd
$ mkdir dev
$ cd dev
```
Download get-pip.py and extract to ~/dev to run setup
*Make sure to use the --prefix parameter*
```bash
$ python get-pip.py --prefix=~/apps/Python
Collecting pip
    Downloading pip-9.0.1-py2.py3-none-any.whl (1.3MB)
        100%  1.3MB 495kB/s
Collecting setuptools
    Downloading setuptools-36.6.0-py2.py3-none-any.whl (481kB)
        100%  481kB 1.3MB/s
Collecting wheel
    Downloading wheel-0.30.0-py2.py3-none-any.whl (49kB)
        100%  51kB 4.1MB/s
Installing collected packages: pip, setuptools, wheel
    Successfully installed pip setuptools wheel
```
Download flickrapi-2.3.tar.gz and extract to ~/dev to run setup
*Make sure to use the --prefix parameter*
```bash
$ python setup.py install --prefix=~/apps/Python
python setup.py install --prefix=~/apps/Python
running install
running bdist_egg
running egg_info
writing requirements to flickrapi.egg-info/requires.txt
writing flickrapi.egg-info/PKG-INFO
(...)
zip_safe flag not set; analyzing archive contents...
Moving chardet-3.0.4-py2.7.egg to /xxx/xxx/xxx/apps/Python/lib/python2.7/site-packages
Adding chardet 3.0.4 to easy-install.pth file
Installing chardetect script to /xxx/xxx/xxx/apps/Python/bin

Installed /xxx/xxx/xxx/apps/Python/lib/python2.7/site-packages/chardet-3.0.4-py2.7.egg
Finished processing dependencies for flickrapi==2.3
```
## Configuration
----------------
Go to http://www.flickr.com/services/apps/create/apply and apply for an API
key Edit the following variables in the uploadr.ini

* FILES_DIR = "YourDir"
* FLICKR = {
        "title"                 : "",
        "description"           : "",
        "tags"                  : "auto-upload",
        "is_public"             : "0",
        "is_friend"             : "0",
        "is_family"             : "0",
        "api_key"               : "Yourkey",
        "secret"                : "YourSecret"
        }
* FLICKR["api_key"] = ""
* FLICKR["secret"] = ""
* EXCLUDED_FOLDERS = ["@eaDir","#recycle"]
* IGNORED_REGEX = ['*[Ii][Gg][Nn][Oo][Rr][Ee]*', 'Private*']
* ALLOWED_EXT = ["jpg","png","avi","mov","mpg","mp4","3gp"]
* MANAGE_CHANGES = True
* FULL_SET_NAME = False

Refer to https://www.flickr.com/services/api/upload.api.html for what each
of the upload arguments above correspond to for Flickr's API.

- Before running uploadr.py make sure you run the command below:
  - To avoid running this command exerytime you log-in into your system, follow the [notes on this link](https://scipher.wordpress.com/2010/05/10/setting-your-pythonpath-environment-variable-linuxunixosx/) to edit file ~/.bashrc and place this command there.
```bash
 $  export PYTHONPATH=~/apps/Python/lib/python2.7/site-packages
 $ ./uploadr.py -v
```
 
## Usage/Arguments/Options
--------------------------
Place the file uploadr.py in any directory and run via ssh
(execution privs required).
It will crawl through all the files from the FILES_DIR directory and begin
the upload process.
```bash
$ ./uploadr.py
```
To check what files uploadr.py would upload and delete you can run the
script withe option --dry-run:
```bash
$ ./uploadr.py --dry-run
```
Run ./uploadrd.py --help for up to the minute information or arguments:
```bash
$ ./uploadr.py --help

usage: uploadr.py [-h] [-v] [-n] [-i TITLE] [-e DESCRIPTION] [-t TAGS] [-r]
                  [-p P] [-g] [-l N] [-d] [-b]

Upload files to Flickr. Uses uploadr.ini as config file.

optional arguments:
  -h, --help            show this help message and exit
  -v, --verbose         Provides some more verbose output. Will provide
                        progress information on upload. See also LOGGING_LEVEL
                        value in INI file.
  -n, --dry-run         Dry run
  -i TITLE, --title TITLE
                        Title for uploaded files. Overwrites title from INI
                        config file. If not indicated and not defined in INI
                        file, it uses filename as title.
  -e DESCRIPTION, --description DESCRIPTION
                        Description for uploaded filesOverwrites description
                        from INI config file.
  -t TAGS, --tags TAGS  Space-separated tags for uploaded files.It appends to
                        the tags defined in INI file.
  -r, --drip-feed       Wait a bit between uploading individual files
  -p P, --processes P   Number of photos to upload simultaneously.
  -g, --remove-ignored  Remove previously uploaded files, that are now being
                        ignored due to change of the INI file configuration
                        EXCLUDED_FOLDERS
  -l N, --list-photos-not-in-set N
                        List as many as N photos not in set. Maximum listed
                        photos is 500.
  -d, --daemon          Run forever as a daemon.Uploading every SLEEP_TIME
                        secondsPlease note it only performs upload/replace
  -b, --bad-files       Save on database bad files to prevent continuous
                        uploading attempts. Bad files are files in your
                        Library that flickr does not recognize (Error 5).
  -w, --walk-files-only Scan files to populate database
  -f  --fast-upload     Disable walk files to upload directly
```

## Task Scheduler (cron)
------------------------
### On Synology systems, run with Task Scheduler (Synology/Control Panel)
- Log into your Synology system via Web interface.
   - Go to Control Panel-> Task Scheduler
   - Create a new "User Defined Script"
   - Adjust the run schedule settings, the email notifications
   - Under "Run Command" include a reference to the uploadr.cron file
`/full/path/to/uploadr.cron`
- Use sample file uploadr.cron added to the distribution and adapt to your needs.
- Do not use crontab directly. Having Task Scheduler replaces crontab.

### On Linux/Unix/Mac based systems, run via crontab
- Use  upload.cron added to the distribution and adapt to your needs.
- Use wither "crontab -e" or vi /etc/crontab according to your system.
```bash
# cron entry (runs at the top of every hour)
0  *  *  *  * /full/path/to/uploadr.cron > /dev/null 2>&1
```

### Launch from the command line in Daemon mode (-d option).
- Recommendation is to use Task Scheduler or cron.
- With -d option it runs in daemon mode and checks for files every SLEEP_TIME seconds (as configured on uploadr.ini)
- It simply loads the files. It does not create Albums/Sets.
- SLEEP_TIME is only used in this case.
```bash
$ ./uploadr.py -v -d
```

## Recognition
--------------
Inspired by:
* https://github.com/sybrenstuvel/flickrapi
* http://micampe.it/things/flickruploadr
* https://github.com/joelmx/flickrUploadr/blob/master/python3/uploadr.py

## Final remarks
---------------
You may use this code however you see fit in any form whatsoever.
And enjoy!!!

## Questions & Answers
----------------------
* Q: Who is this script designed for?
   - Those people comfortable with the command line that want to backup their media on Flickr in full resolution.

* Q: Why don't you use OAuth?
   - I do! As of November 2017

* Q: Are you a python ninja?
   - No, sorry. I just picked up the language to write this script because python can easily be installed on a Synology Diskstation.

* Q: Is this script feature complete and fully tested?
   - Nope. It's a work in progress. I've tested it as needed for my needs, but it's possible to build additional features by contributing to the script.

* Q: How to automate it with a Synology NAS ?
   - First you will need to run script at least one time in a ssh client to get the token file.
     Refer to the "Task Scheduler (cron)" section above.
     Then with DSM 6.1, create an automate task, make it run once a day for example, and put this in the textbox without quotes "path_to_your_python_program path_to_your_script". For example, assuming you installed Python package from Synocommunity, command should look like "/usr/local/python/bin/python /volume1/script/flickr-uploader/uploadr.py".

* Q: What if I have different folders to sync?
   - the standard mode of operation should be to sync always the same main folder structure with all your subfolder/pics.
   - syncing different folders on each run *does work* and uploads new pics; but uploadr was not originally designed for that. 
      - What happens to previously loaded pics depends if they still exist and Uploadr can still find them (depending if FILES_DIR was set as an absolute folder or relative folder path)
         - File to upload: /home/user/media/2014/05/05/photo.jpg
         - FULL_SET_NAME:
            - False: 05
            - True: 2014/05/05
   - Uploadr saves the (full or relative depending on FILES_DIR) path name for the pics loaded. So, event though you provide a new origin folder, if the previously loaded pics still exist on their original locations, they are not deleted. If they are deleted from such original location or uploadr has no access to them, then they will be deleted from flickr.
   - If using relative FILES_DIR and two files exist on the same subfolder, it will not be re-uploaded.
   - So, in a nutshell, too many issues if you play around changing the FILES_DIR location.


* Q: "my understanding is that this is a sync script, which means when I later delete a pic from a synced folder, it will get deleted from Flickr"
   - Yes a file removed locally will be deleted from Flickr.
   - *Remark*: I'm assuming in between each run you keep the contents of the flickrdb control database and do not remove it.

* Q: "What about previously existing folders (they didn't seem to get deleted)"
   - If all files from a folder (and corresponding Album on flickr) are deleted, then the actual Album will be also eliminated. Again, if you do not chnage the FILES_DIR in between runs.

* Q: What about when I sync a folder with the same name of a previously existing folder? (you mention
getting existing sets from Flickr is managed also
   - hmmm... if you mean "sync a folder" via setting FILES_DIR... it would depend if you use full or relative pathname on FILES_DIR. Check the section "Clarification" above. It will delete the files he cannot find locally.
   - hmmm... if you mean two subfolders with the same name, to which Set/Album will be added depends on the setting FULL_SET_NAME. Check the section "Clarification" above for example pic042.

* Q: What about when I run the script on ~/pictures/parent_folder/folder_A and then later on ~/pictures/parentfolder will the script recongize the folder_A within parentfolder as being the one it uploaded before becaues its content will have matching checksums?
   - Again it depends on FULL_SET_NAME setting and FILE_DIR being an absolute or relative path and the match is initially done by full pathname + filename. So, in your example ~/pictures will expand to a full path so it would recognize the same files and not upload them again.

* Q: I thought I read a mention of checksum as a way to detect file modification: what about the same file in 2 different folders, is it then upoad each time (in a set with the folder name) or only once?
   - same file on two folders loads up twice. Check example above with Album5/pic02.jpg
