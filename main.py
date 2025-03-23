import os

from mac_gurl.gurl import Gurl

from Foundation import NSHTTPURLResponse

def get_url(url, destinationpath,
            custom_headers=None, message=None, onlyifnewer=False,
            resume=False, follow_redirects=False, pkginfo=None):
    """Gets an HTTP or HTTPS URL and stores it in
    destination path. Returns a dictionary of headers, which includes
    http_result_code and http_result_description.
    Will raise ConnectionError if Gurl has a connection error.
    Will raise HTTPError if HTTP Result code is not 2xx or 304.
    Will raise GurlError if Gurl has some other error.
    If destinationpath already exists, you can set 'onlyifnewer' to true to
    indicate you only want to download the file only if it's newer on the
    server.
    If you set resume to True, Gurl will attempt to resume an
    interrupted download."""

    tempdownloadpath = destinationpath + '.download'
    if os.path.exists(tempdownloadpath) and not resume:
        os.remove(tempdownloadpath)

    cache_data = None
    if onlyifnewer and os.path.exists(destinationpath):
        # create a temporary Gurl object so we can extract the
        # stored caching data so we can download only if the
        # file has changed on the server
        gurl_obj = Gurl.alloc().initWithOptions_({'file': destinationpath})
        cache_data = gurl_obj.getStoredHeaders()
        del gurl_obj

    # only works with NSURLSession (10.9 and newer)
    # ignore_system_proxy = prefs.pref('IgnoreSystemProxies') # default in https://github.com/munki/munki/blob/46b81f061ce4b3888ca87eae7daf3d8bc49d0742/code/client/munkilib/prefs.py
    ignore_system_proxy = False

    options = {'url': url,
               'file': tempdownloadpath,
               'follow_redirects': follow_redirects,
               'ignore_system_proxy': ignore_system_proxy,
               'can_resume': resume,
               'additional_headers': {},
               'download_only_if_changed': onlyifnewer,
               'cache_data': cache_data,
               'logging_function': print,
               'pkginfo': pkginfo}
    print('Options: %s' % options)

    connection = Gurl.alloc().initWithOptions_(options)
    stored_percent_complete = -1
    stored_bytes_received = 0
    connection.start()
    try:
        while True:
            # if we did `while not connection.isDone()` we'd miss printing
            # messages and displaying percentages if we exit the loop first
            connection_done = connection.isDone()
            if message and connection.status and connection.status != 304:
                # log always, display if verbose is 1 or more
                # also display in MunkiStatus detail field
                print(message)
                # now clear message so we don't display it again
                message = None
            if (str(connection.status).startswith('2')
                    and connection.percentComplete != -1):
                if connection.percentComplete != stored_percent_complete:
                    # display percent done if it has changed
                    stored_percent_complete = connection.percentComplete
                    print(stored_percent_complete, 100)
            elif connection.bytesReceived != stored_bytes_received:
                # if we don't have percent done info, log bytes received
                stored_bytes_received = connection.bytesReceived
                print('Bytes received: %s', stored_bytes_received)
            if connection_done:
                break

    except (KeyboardInterrupt, SystemExit):
        # safely kill the connection then re-raise
        connection.cancel()
        raise
    except Exception as err:  # too general, I know
        # Let us out! ... Safely! Unexpectedly quit dialogs are annoying...
        connection.cancel()
        # Re-raise the error as a GurlError
        print(err)
        raise

    if connection.error is not None:
        # gurl returned an error
        print('Download error %s: %s', connection.error.code(),
            connection.error.localizedDescription())
        if connection.SSLerror:
            print('SSL error detail: %s', str(connection.SSLerror))
            #keychain.debug_output()
        print('Headers: %s', connection.headers)
        if os.path.exists(tempdownloadpath) and not resume:
            os.remove(tempdownloadpath)
        raise ConnectionError(connection.error.code(),
                              connection.error.localizedDescription())

    if connection.response is not None:
        print('Status: %s', connection.status)
        print('Headers: %s', connection.headers)
    if connection.redirection != []:
        print('Redirection: %s', connection.redirection)

    temp_download_exists = os.path.isfile(tempdownloadpath)
    connection.headers['http_result_code'] = str(connection.status)
    description = NSHTTPURLResponse.localizedStringForStatusCode_(
        connection.status)
    connection.headers['http_result_description'] = description

    if str(connection.status).startswith('2') and temp_download_exists:
        try:
            os.rename(tempdownloadpath, destinationpath)
        except OSError as err:
            # Re-raise the error as a GurlError
            print(err)
            raise
        return connection.headers
    elif connection.status == 304:
        # unchanged on server
        print('Item is unchanged on the server.')
        return connection.headers
    else:
        # there was an HTTP error of some sort; remove our temp download.
        if os.path.exists(tempdownloadpath):
            try:
                os.unlink(tempdownloadpath)
            except OSError:
                pass
        print(connection.status)
        print(connection.headers.get('http_result_description', ''))
        return


if __name__ == "__main__":
    get_url(url="https://spc.ondemand.com/cam/api/v1/profile_requests?user=I554517", destinationpath="./download")
