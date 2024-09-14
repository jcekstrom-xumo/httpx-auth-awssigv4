"""Utility to help with SigV4 authentication for httpx python library.

Reference:
https://docs.aws.amazon.com/general/latest/gr/sigv4-signed-request-examples.html
"""

import hashlib
import hmac
from datetime import datetime
from typing import Optional

from httpx import Request


class SigV4Auth:
    """Auth class to provide AWS Sigv4 authentication support to httpx library.

    When we send API requests to AWS, we need to sign the requests so that AWS can identify who sent them. To sign the
    requests we use Signature V4 process to sign API requests. Instantiation of this class creates an auth object that
    python httpx library can use to sign the API requests before sending them to AWS.

    Note:
        This class only supports adding authorization header as part of the request and doesn't support adding
        authorization header in query string

    Usage:


        import httpx
        from httpx_auth_awssigv4 import Sigv4Auth

        auth = Sigv4Auth(
            access_key: "AWS_ACCESS_KEY_ID",
            secret_key: "AWS_SECRET_ACCESS_KEY",
            service: "execute-api",
            region: "us-east-1"
        )

        response = httpx.get(
            url="https://<API ID>.execute-api.<Region>.amazonaws.com/prod/detials",
            params={"username": "tstark"},
            auth=auth
        )

    Args:
        access_key (str): AWS access key
        secret_key (str): AWS secret access key
        service (str): Name of the service request is being made to
        region (str): AWS region to which the API request is being sent to
        token (Optional[str], optional): AWS Session token in case of temporary crendentials. Defaults to None.

    """

    def __init__(self, access_key: str, secret_key: str, service: str, region: str, token: Optional[str] = None):
        """Auth class to provide AWS Sigv4 authentication support to httpx library.

        Args:
            access_key (str): AWS access key
            secret_key (str): AWS secret access key
            service (str): Name of the service request is being made to
            region (str): AWS region to which the API request is being sent to
            token (Optional[str], optional): AWS Session token in case of temporary crendentials. Defaults to None.
        """
        self._access_key = access_key
        self._secret_key = secret_key
        self._token = token
        self._service = service
        self._region = region

        self._signed_headers = "host;x-amz-date"

        # the hashing algorithm that you use to calculate the digests in the canonical request
        self._algorithm = "AWS4-HMAC-SHA256"

    def get_signature_key(self, date_stamp: str) -> bytes:
        """Creates a signing key derived from secret key.

        Read more about creating a signing key in the following page
        Ref: https://docs.aws.amazon.com/general/latest/gr/sigv4-calculate-signature.html

        Args:
            date_stamp (str): date used in credential scope, should be in '%Y%m%d' format

        Returns:
            str: Signing key derived from secret key

        """

        def sign(key, msg):
            return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()

        date = sign(("AWS4" + self._secret_key).encode("utf-8"), date_stamp)
        region = sign(date, self._region)
        service = sign(region, self._service)
        signing = sign(service, "aws4_request")
        return signing

    def get_signed_headers(self, request: Request):
        """ Find the headers to sign

        Args:
            request (Request): https Request Object

        Returns:
            list: headers to sign
            str: headers to sign joined but ";"
        """
        # Add the Host header and all the "x-amz-" headers
        signed_headers = sorted(
            filter(
                lambda h: h.startswith('x-amz-') or h == 'host',
                map(lambda h_key: h_key.lower(), request.headers.keys()),
            )
        )
        return (signed_headers, ';'.join(signed_headers))

    def get_canonical_request(self, request: Request, timestamp: str, payload_hash: str) -> str:
        """Creates a canonical request.

        This function returns information from your request in a standardized (canonical) format. Read more about
        Cananolical requests below
        https://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html

        Args:
            request (Request): httpx Request object
            timestamp (str): The date is specified with ISO8601 basic format in the x-amz-date header in the format
                YYYYMMDD'T'HHMMSS'Z'

        Returns:
            str: request infromation in a canonical format
        """
        canonical_querystring = request.url.query.decode("utf-8")
        canonical_uri = request.url.path
        headers_to_sign, signed_headers = self.get_signed_headers(request)

        # Create the canonical headers and signed headers. Header names
        # must be trimmed and lowercase, and sorted in code point order from
        # low to high. Note that there is a trailing \n.
        canonical_headers = ''.join(map(lambda h: ":".join((h, request.headers[h])) + '\n', headers_to_sign))
                
        # Combine elements to create canonical request
        canonical_request = '\n'.join(
            [
                request.method,
                canonical_uri,
                canonical_querystring,
                canonical_headers,
                signed_headers,
                payload_hash,
            ]
        )


        return canonical_request

    def get_authorization_header(self, request: Request, credential_scope: str, signature: str) -> str:
        """Constructs "Authorization" header to include in the request.

        Args:
            request (Request): httpx Request object
            credential_scope (str): String that includes the date, the Region you are targeting, the service you are
                requesting, and a termination string
            signature (str): calculated signature to include in Authorization header

        Returns:
            str: String to send under "Authorization" header
        """
        _, signed_headers = self.get_signed_headers(request)
        return (
            f"{self._algorithm} Credential={self._access_key}/{credential_scope},"
            f" SignedHeaders={signed_headers}, Signature={signature}"
        )

    def __call__(self, request: Request) -> Request:
        """The httpx library calls this method before sending the API request.

        Args:
            request (Request): API request information as a httpx Request

        Returns:
            Request : Modified request signed with AWS crdentials using Signature v4 process
        """
        # Create a date for headers and the credential string
        current_time = datetime.utcnow()
        timestamp = current_time.strftime("%Y%m%dT%H%M%SZ")
        datestamp = current_time.strftime("%Y%m%d")  # Date w/o time, used in credential scope

        # Add Headers to Request
        if request.content:
            payload_hash = hashlib.sha256(request.content).hexdigest()
        else:
            payload_hash = hashlib.sha256(("").encode("utf-8")).hexdigest()

        headers = {
            "X-Amz-Content-SHA256": payload_hash,
            "X-Amz-Date": timestamp,
        }

        if self._token:
            headers["X-Amz-Security-Token"] = self._token

        request.headers.update(headers)

        # CREATE A CANONICAL REQUEST
        canonical_request = self.get_canonical_request(request=request, timestamp=timestamp, payload_hash=payload_hash)

        # CREATE THE STRING TO SIGN

        credential_scope = f"{datestamp}/{self._region}/{self._service}/aws4_request"
        string_to_sign = (
            f"{self._algorithm}\n{timestamp}\n{credential_scope}\n"
            f'{hashlib.sha256(canonical_request.encode("utf-8")).hexdigest()}'
        )

        # CALCULATE THE SIGNATURE
        signing_key = self.get_signature_key(datestamp)
        signature = hmac.new(signing_key, (string_to_sign).encode("utf-8"), hashlib.sha256).hexdigest()

        # ADD SIGNING INFORMATION TO THE REQUEST

        authorization_header = self.get_authorization_header(request=request, credential_scope=credential_scope, signature=signature)

        headers = {
            "Authorization": authorization_header,
        }

        request.headers.update(headers)

        return request
