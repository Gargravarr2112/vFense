"CVE DOWNLOADER FOR TOPPATCH, NVD/CVE XML VERSION 1.2"
import os
import re
from time import sleep
import requests
from bs4 import BeautifulSoup
import demjson
import logging
import logging.config
from vFense import VFENSE_LOGGING_CONFIG

from time import sleep
from vFense.plugins.vuln.windows._constants import WindowsDataDir, \
    WindowsBulletinStrings

logging.config.fileConfig(VFENSE_LOGGING_CONFIG)
logger = logging.getLogger('cve')

def get_msft_bulletin_xlsx(xls_url, count=0):
    """Retrieve the Microsoft XLSX file.
    """

    downloaded = False
    data = None

    try:
        data = requests.get(xls_url, timeout=2)

        if data:
            if data.status_code == 200:
                downloaded = True

        return(downloaded, data)

    except Exception as e:
        sleep(5)
        if count <= 20:
            count += 1
            logger.exception(
                'failed to retrieve XLSX file from %s: count = %s'
                % (xls_url, str(count))
            )

            return(get_msft_bulletin_xlsx(xls_url, count))

        else:
            logger.exception(
                'Microsoft is not letting us get the XLSX file from %s'
                % WindowsBulletinStrings.XLS_DOWNLOAD_URL
            )

            return(downloaded, data)


def get_msft_bulletin_url(count=0):
    """Hack to retrieve the Microsoft XLSX url and name of the file.
      Because the download page is such a train wreck, rewritten to do the following:
      1. store the HTML as a string
      2. parse the HTML with Beautiful Soup
      3. use Beautiful Soup to find the <script> tag where the URL is defined (downloadData=)
      4. use regex to parse out the JS object defining the URLs
      5. use demjson to parse the JS object into a Python dict
      6. THEN get the damned URL!
    """

    xls_url = None
    xls_file_name = None

    
    main_url = requests.get(
        WindowsBulletinStrings.XLS_DOWNLOAD_URL, timeout=30
    )

    if main_url.status_code == 200:
        htmlSoup = BeautifulSoup(main_url.content, 'html.parser')
        scriptBlocks = htmlSoup.find_all('script', string=re.compile('downloadData='))
        if len(scriptBlocks) > 1:
            logger.warn(
                'Microsoft Bulletin page download search returned more than one result, selecting first and crossing fingers...'
            )
        elif len(scriptBlocks) == 0:
            logger.error(
                "Couldn't find any script tags containing 'downloadData='!"
            )
            return (False, False)
        
        block = scriptBlocks[0];
        urlObject = re.search('(\{.*\})', block.text) #JS object is everything between {}
        
        if urlObject:
            objectText = urlObject.groups()[0];
            urls = demjson.decode(objectText)
            
            xls_url = urls['base_0']['url'] #Please oh please still be the first result or we're going to have a problem

            if xls_url:
                xls_file_name = xls_url.split('/')[-1]
                
                if xls_file_name[-5:] == '.xlsx':
                    if xls_file_name != 'BulletinSearch.xlsx':
                        logger.warning(
                            "Filename retrieved appears to be %s" % xls_file_name
                        )
                    return(xls_url, xls_file_name)
                else:
                    logger.error("Didn't find an XLSX file!")
    
    else:
        logger.exception(
            "Downloading the bulletin from Microsoft returned %d, skipping" % main_url.status_code
        )
        
    return (False, False)


def download_latest_xls_from_msft():
    """Download the lates Microsoft Security Bulletin excel spreadsheet
        and than store it on disk
    Returns:
        Tuple (Boolen, file_location)
    """

    downloaded = False
    xls_file_location = None

    if not os.path.exists(WindowsDataDir.XLS_DIR):
        print('Creating data directory %s' % WindowsDataDir.XLS_DIR)
        os.makedirs(WindowsDataDir.XLS_DIR)

    xls_url, xls_file_name = get_msft_bulletin_url()
    print('Resolved URL as %s' % xls_url)
    print('Resolved filename as %s' % xls_file_name)

    if xls_url:
        xls_file_location = os.path.join(WindowsDataDir.XLS_DIR, xls_file_name)
        print('Resolved full filename as %s' % xls_file_location)
        file_downloaded, xls_data = get_msft_bulletin_xlsx(xls_url)

        if file_downloaded:
            xml_file = open(xls_file_location, 'wb')
            xml_file.write(xls_data.content)
            xml_file.close()

            if (xls_data.headers['content-length'] ==
                    str(os.stat(xls_file_location).st_size)):
                downloaded = True
                logger.info(
                    '%s downloaded to %s: file_size: %s matches content-length' %
                    (
                        xls_url,xls_file_location,
                        os.stat(xls_file_location).st_size
                    )
                )

            else:
                logger.warn(
                    '%s downloaded to %s: file_size: %s does not match the content-length' %
                    (
                        xls_url,xls_file_location,
                        os.stat(xls_file_location).st_size
                    )
                )
    else:
        print('Download failed!')

    return(downloaded, xls_file_location)

#download_latest_xls_from_msft()
