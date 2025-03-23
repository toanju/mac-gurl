from io import BytesIO

from Foundation import NSHTTPURLResponse
from requests import Response
from requests.adapters import HTTPAdapter
from requests.structures import CaseInsensitiveDict
from requests.utils import get_encoding_from_headers

from pprint import pprint

from mac_gurl.gurl import Gurl


class MacHTTPAdapter(HTTPAdapter):
    def __init__(self, *args, **kwargs):
        super(MacHTTPAdapter, self).__init__(*args, **kwargs)

    def send(
        self, request, stream=False, timeout=None, verify=True, cert=None, proxies=None
    ):
        # def _get_url(
        #    self,
        #    url,
        #    custom_headers=None,
        #    message=None,
        #    onlyifnewer=False,
        #    resume=False,
        #    follow_redirects=False,
        #    pkginfo=None,
        # ):
        """Gets an HTTP or HTTPS URL and stores it in
        destination path. Returns a dictionary of headers, which includes
        http_result_code and http_result_description.
        Will raise ConnectionError if Gurl has a connection error.
        Will raise HTTPError if HTTP Result code is not 2xx or 304.
        Will raise GurlError if Gurl has some other error.
        If you set resume to True, Gurl will attempt to resume an
        interrupted download."""

        message = None
        # only works with NSURLSession (10.9 and newer)
        # ignore_system_proxy = prefs.pref('IgnoreSystemProxies') # default in https://github.com/munki/munki/blob/46b81f061ce4b3888ca87eae7daf3d8bc49d0742/code/client/munkilib/prefs.py
        ignore_system_proxy = False

        options = {
            "url": request.url,
            "follow_redirects": False,
            "ignore_system_proxy": ignore_system_proxy,
            "can_resume": False,
            "additional_headers": request.headers,
            "download_only_if_changed": False,
            "logging_function": print,
        }
        print("Options: %s" % options)

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
                if (
                    str(connection.status).startswith("2")
                    and connection.percentComplete != -1
                ):
                    if connection.percentComplete != stored_percent_complete:
                        # display percent done if it has changed
                        stored_percent_complete = connection.percentComplete
                        print(stored_percent_complete, 100)
                elif connection.bytesReceived != stored_bytes_received:
                    # if we don't have percent done info, log bytes received
                    stored_bytes_received = connection.bytesReceived
                    print("Bytes received: %s" % stored_bytes_received)
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
            print(
                "Download error %s: %s" % connection.error.code(),
                connection.error.localizedDescription(),
            )
            if connection.SSLerror:
                print("SSL error detail: %s" % str(connection.SSLerror))
                # keychain.debug_output()
            print("Headers: %s", connection.headers)
            raise ConnectionError(
                connection.error.code(), connection.error.localizedDescription()
            )

        if connection.response is not None:
            print("Status: %s" % connection.status)
            print("Headers: %s" % connection.headers)
        if connection.redirection != []:
            print("Redirection: %s", connection.redirection)

        description = NSHTTPURLResponse.localizedStringForStatusCode_(connection.status)

        response = Response()

        # Fallback to None if there's no status_code, for whatever reason.
        response.status_code = connection.status

        # Make headers case-insensitive.
        response.headers = CaseInsensitiveDict(connection.headers)

        # Set encoding.
        response.encoding = get_encoding_from_headers(connection.headers)
        response.raw = BytesIO(connection.received_data)
        self.reason = description

        if isinstance(request.url, bytes):
            response.url = request.url.decode("utf-8")
        else:
            response.url = request.url

        # Add new cookies from the server.
        # extract_cookies_to_jar(response.cookies, request, resp)

        # Give the Response some context.
        response.request = request
        response.connection = self

        return response


if __name__ == "__main__":
    import requests

    s = requests.Session()
    s.mount("https://", MacHTTPAdapter())

    resp = s.get("https://spc.ondemand.com/cam/api/v1/profile_requests?user=I554517")
    pprint(resp.json())
