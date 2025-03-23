import logging
from io import BytesIO

from requests import Response
from requests.adapters import HTTPAdapter
from requests.structures import CaseInsensitiveDict
from requests.utils import get_encoding_from_headers

from .gurl import Gurl


class MacHTTPAdapter(HTTPAdapter):
    def __init__(self, *args, **kwargs):
        super(MacHTTPAdapter, self).__init__(*args, **kwargs)
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.INFO)

    def send(
        self, request, stream=False, timeout=None, verify=True, cert=None, proxies=None
    ):
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
            "logging_function": self.logger.debug,
        }
        self.logger.debug("Options: %s" % options)

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
                    self.logger.debug(message)
                    # now clear message so we don't display it again
                    message = None
                if (
                    str(connection.status).startswith("2")
                    and connection.percentComplete != -1
                ):
                    if connection.percentComplete != stored_percent_complete:
                        # display percent done if it has changed
                        stored_percent_complete = connection.percentComplete
                        self.logger.debug(stored_percent_complete, 100)
                elif connection.bytesReceived != stored_bytes_received:
                    # if we don't have percent done info, log bytes received
                    stored_bytes_received = connection.bytesReceived
                    self.logger.debug("Bytes received: %s" % stored_bytes_received)
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
            self.logger.error(err)
            raise

        if connection.error is not None:
            # gurl returned an error
            self.logger.debug(
                "Download error %s: %s" % connection.error.code(),
                connection.error.localizedDescription(),
            )
            if connection.SSLerror:
                self.logger.error("SSL error detail: %s" % str(connection.SSLerror))
                # keychain.debug_output()
            self.logger.debug("Headers: %s", connection.headers)
            raise ConnectionError(
                connection.error.code(), connection.error.localizedDescription()
            )

        if connection.response is not None:
            self.logger.debug("Status: %s" % connection.status)
            self.logger.debug("Headers: %s" % connection.headers)
        if connection.redirection != []:
            self.logger.debug("Redirection: %s", connection.redirection)

        description = connection.description

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
            assert response.url is None
            response.url = request.url

        # Add new cookies from the server.
        # extract_cookies_to_jar(response.cookies, request, resp)

        # Give the Response some context.
        response.request = request
        response.connection = self

        return response
