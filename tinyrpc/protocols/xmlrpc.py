#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""XML RPC 1.0 Protocol implementation.

"""

import xmlrpc.client
import sys
from tinyrpc.exc import UnexpectedIDError
from typing import Dict, Any, Union, Optional, List, Tuple, Callable, Generator

from . import default_id_generator
from .. import (
    RPCBatchProtocol, RPCRequest, RPCResponse, RPCErrorResponse,
    InvalidRequestError, MethodNotFoundError, InvalidReplyError, RPCError,
    RPCBatchRequest, RPCBatchResponse, InvalidParamsError,
)

multicall_return_token = '###multicall.return###'


class FixedErrorMessageMixin(object):
    """Combines XML RPC exceptions with the generic RPC exceptions.

    Constructs the exception using the provided parameters as well as
    properties of the XML RPC Exception.

    XML RPC exceptions declare two attributes:

    .. py:attribute:: xmlrpc_error_code

        This is an error code conforming to the XML RPC `error codes`_ convention.

        :type: :py:class:`int`

    .. py:attribute:: message

        This is a textual representation of the error code.

        :type: :py:class:`str`

    :param list args: Positional arguments for the constructor.
        When present it overrules the :py:attr:`message` attribute.
    :param dict kwargs: Keyword arguments for the constructor.
        If the ``data`` parameter is found in ``kwargs`` its contents are
        used as the *data* property of the XML RPC Error object.

    :py:class:`FixedErrorMessageMixin` is the basis for adding your own
    exceptions to the predefined ones.
    Here is a version of the reverse string example that dislikes palindromes:

    .. code-block:: python

        class PalindromeError(FixedErrorMessageMixin, Exception)
            xmlrpc_error_code = 99
            message = "Ah, that's cheating"

        @public
        def reverse_string(s):
            r = s[::-1]
            if r == s:
                raise PalindromeError(data=s)
            return r

    >>> client.reverse('rotator')

    Will return an error object to the client looking like:

    .. code-block:: xml

        {
            "xmlrpc": "2.0",
            "id": 1,
            "error": {
                "code": 99,
                "message": "Ah, that's cheating",
                "data": "rotator"
            }
        }

    .. _error codes: https://www.xmlrpc.org/specification#error_object
    """
    def __init__(self, *args, **kwargs) -> None:
        if not args:
            args = [self.message]
        self.request_id = kwargs.pop('request_id', None)
        if 'data' in kwargs:
            self.data = kwargs.pop('data')
        super().__init__(*args, **kwargs)

    def error_respond(self) -> 'XMLRPCErrorResponse':
        """Converts the error to an error response object.

        :return: An error response object ready to be serialized and sent to the client.
        :rtype: :py:class:`XMLRPCErrorResponse`
        """
        response = XMLRPCErrorResponse()

        response.error = self.message
        response.unique_id = self.request_id
        response._xmlrpc_error_code = self.xmlrpc_error_code
        if hasattr(self, 'data'):
            response.data = self.data
        return response


class XMLRPCParseError(FixedErrorMessageMixin, InvalidRequestError):
    """The request cannot be decoded or is malformed."""
    xmlrpc_error_code = -32700
    message = 'Parse error'


class XMLRPCInvalidRequestError(FixedErrorMessageMixin, InvalidRequestError):
    """The request contents are not valid for XML RPC 2.0"""
    xmlrpc_error_code = -32600
    message = 'Invalid Request'


class XMLRPCMethodNotFoundError(FixedErrorMessageMixin, MethodNotFoundError):
    """The requested method name is not found in the registry."""
    xmlrpc_error_code = 1
    message = "Method is not supported"


class XMLRPCInvalidParamsError(FixedErrorMessageMixin, InvalidRequestError):
    """The provided parameters are not appropriate for the function called."""
    xmlrpc_error_code = -32602
    message = 'Invalid parameters'


class XMLRPCInternalError(FixedErrorMessageMixin, InvalidRequestError):
    """Unspecified error, not in the called function."""
    xmlrpc_error_code = -32603
    message = 'Internal error'


class XMLRPCServerError(FixedErrorMessageMixin, InvalidRequestError):
    """Unspecified error, this message originates from the called function."""
    xmlrpc_error_code = -32000
    message = ''


class XMLRPCError(FixedErrorMessageMixin, RPCError):
    """Reconstructs (to some extend) the server-side exception.

    The client creates this exception by providing it with the ``error``
    attribute of the XML error response object returned by the server.

    :param dict error: This dict contains the error specification:

        * code (int): the numeric error code.
        * message (str): the error description.
        * data (any): if present, the data attribute of the error
    """
    def __init__(self, error: Union['XMLRPCErrorResponse', Dict[str, Any]]) -> None:
        if isinstance(error, XMLRPCErrorResponse):
            super().__init__(error.error)
            self.message = error.error
            self._xmlrpc_error_code = error._xmlrpc_error_code
            if hasattr(error, 'data'):
                self.data = error.data
        else:
            super().__init__(error.message)
            self.message = error['message']
            self._xmlrpc_error_code = error['code']
            if 'data' in error:
                self.data = error['data']


class XMLRPCSuccessResponse(RPCResponse):
    """Collects the attributes of a successful response message.

    Contains the fields of a normal (i.e. a non-error) response message.

    .. py:attribute:: unique_id

        Correlation ID to match request and response.
        A XML RPC response *must* have a defined matching id attribute.
        ``None`` is not a valid value for a successful response.

        :type: str or int

    .. py:attribute:: result

        Contains the result of the RPC call.

        :type: Any type that can be serialized by the protocol.
    """
    def __init__(self) -> None:
        super().__init__()

        self.allow_none = False

    def serialize(self) -> bytes:
        """Returns a serialization of the response.

        Converts the response into a bytes object that can be passed to and by the transport layer.

        :return: The serialized encoded response object.
        :rtype: bytes
        """
        # result should be a 1-tuple
        result = (self.result,)
        try:
            res = xmlrpc.client.dumps(result, methodresponse=True,
                                      allow_none=self.allow_none).encode()
            return res

        except xmlrpc.client.Fault as e:
            return xmlrpc.client.dumps(e, methodresponse=True,
                                       allow_none=self.allow_none).encode()

        except Exception as e:
            fault = xmlrpc.client.Fault(1, str(e))
            return xmlrpc.client.dumps(fault, methodresponse=True,
                                       allow_none=self.allow_none).encode()


class XMLRPCErrorResponse(RPCErrorResponse):
    """Collects the attributes of an error response message.

    Contains the fields of an error response message.

    .. py:attribute:: unique_id

        Correlation ID to match request and response.
        ``None`` is a valid ID when the error cannot be matched to a particular request.

        :type: str or int or None

    .. py:attribute:: error

        The error message. A string describing the error condition.

        :type: str

    .. py:attribute:: data

        This field may contain any XML encodable datum that the server may want
        to return the client.

        It may contain additional information about the error condition, a partial result
        or whatever. Its presence and value are entirely optional.

        :type: Any type that can be serialized by the protocol.

    .. py:attribute:: _xmlrpc_error_code

        The numeric error code.

        The value is usually predefined by one of the XML protocol exceptions.
        It can be set by the developer when defining application specific exceptions.
        See :py:class:`FixedErrorMessageMixin` for an example on how to do this.

        Note that the value of this field *must* comply with the defined values in
        the standard_.

    .. _standard: http://xmlrpc.com/spec.md
    """
    def __init__(self) -> None:
        super().__init__()

        self.allow_none = False

    def serialize(self) -> bytes:
        """Returns a serialization of the error.

        Converts the response into a bytes object that can be passed to and by the transport layer.

        :return: The serialized encoded error object.
        :rtype: bytes
        """
        fault = xmlrpc.client.Fault(self._xmlrpc_error_code,
                                    str(self.error))
        return xmlrpc.client.dumps(fault, methodresponse=True,
                                   allow_none=self.allow_none).encode()


def _get_code_message_and_data(error: Union[Exception, str]
                               ) -> Tuple[int, str, Any]:
    assert isinstance(error, (Exception, str))
    data = None
    if isinstance(error, Exception):
        if hasattr(error, 'xmlrpc_error_code'):
            code = error.xmlrpc_error_code
            msg = str(error)
            try:
                data = error.data
            except AttributeError:
                pass
        elif isinstance(error, InvalidRequestError):
            code = XMLRPCInvalidRequestError.xmlrpc_error_code
            msg = XMLRPCInvalidRequestError.message
        elif isinstance(error, MethodNotFoundError):
            code = XMLRPCMethodNotFoundError.xmlrpc_error_code
            msg = XMLRPCMethodNotFoundError.message
        elif isinstance(error, InvalidParamsError):
            code = XMLRPCInvalidParamsError.xmlrpc_error_code
            msg = XMLRPCInvalidParamsError.message
        else:
            # allow exception message to propagate
            code = XMLRPCServerError.xmlrpc_error_code
            if len(error.args) == 2:
                msg = str(error.args[0])
                data = error.args[1]
            else:
                msg = str(error)
    else:
        code = 1
        msg = error

    return code, msg, data


class XMLRPCRequest(RPCRequest):
    """Defines a XML RPC request."""
    def __init__(self):
        super().__init__()
        self.one_way = False
        """Request or Notification.

        :type: bool

        This flag indicates if the client expects to receive a reply (request: ``one_way = False``)
        or not (notification: ``one_way = True``).

        Note that according to the specification it is possible for the server to return an error response.
        For example if the request becomes unreadable and the server is not able to determine that it is
        in fact a notification an error should be returned. However, once the server had verified that the
        request is a notification no reply (not even an error) should be returned.
        """

        self.unique_id = None
        """Correlation ID used to match request and response.

        :type: int or str

        Generated by the client, the server copies it from request to corresponding response.
        """

        self.method = None
        """The name of the RPC function to be called.

        :type: str

        The :py:attr:`method` attribute uses the name of the function as it is known by the public.
        The :py:class:`~tinyrpc.dispatch.RPCDispatcher` allows the use of public aliases in the
        ``@public`` decorators.
        These are the names used in the :py:attr:`method` attribute.
        """

        self.args = []
        """The positional arguments of the method call.

        :type: list

        The contents of this list are the positional parameters for the :py:attr:`method` called.
        It is eventually called as ``method(*args)``.
        """

        self.kwargs = {}
        """The keyword arguments of the method call.

        :type: dict

        The contents of this dict are the keyword parameters for the :py:attr:`method` called.
        It is eventually called as ``method(**kwargs)``.
        """

        self.allow_none = False
        """Flag used to indicate whether the null value (None) can be returned as a value.

        :type: bool

        Set in the protocol, it is copied to requests and responses.
        """

    def error_respond(self, error: Union[Exception, str]
                      ) -> Optional['XMLRPCErrorResponse']:
        """Create an error response to this request.

        When processing the request produces an error condition this method can be used to
        create the error response object.

        :param error: Specifies what error occurred.
        :type error: Exception or str
        :returns: An error response object that can be serialized and sent to the client.
        :rtype: ;py:class:`XMLRPCErrorResponse`
        """
        if self.unique_id is None:
            return None

        response = XMLRPCErrorResponse()
        response.unique_id = None if self.one_way else self.unique_id
        response.allow_none = self.allow_none

        code, msg, data = _get_code_message_and_data(error)

        response.error = msg
        response._xmlrpc_error_code = code
        if data:
            response.data = data
        return response

    def respond(self, result: Any) -> Optional['XMLRPCSuccessResponse']:
        """Create a response to this request.

        When processing the request completed successfully this method can be used to
        create a response object.

        :param result: The result of the invoked method.
        :type result: Anything that can be encoded by XML.
        :returns: A response object that can be serialized and sent to the client.
        :rtype: :py:class:`XMLRPCSuccessResponse`
        """
        if self.one_way or self.unique_id is None:
            return None

        response = XMLRPCSuccessResponse()

        response.result = result
        response.unique_id = self.unique_id
        response.allow_none = self.allow_none

        return response

    def serialize(self) -> bytes:
        """Returns a serialization of the request.

        Converts the request into a bytes object that can be sent to the server.

        :return: The serialized encoded request object.
        :rtype: bytes
        """
        return xmlrpc.client.dumps(self.args, methodname=self.method,
                                   allow_none=self.allow_none).encode()


class XMLRPCBatchRequest(RPCBatchRequest):
    """Defines a XML RPC batch request."""
    def create_batch_response(self) -> Optional['XMLRPCBatchResponse']:
        """Produces a batch response object if a response is expected.

        :return: A batch response if needed
        :rtype: :py:class:`XMLRPCBatchResponse`
        """
        if self._expects_response():
            return XMLRPCBatchResponse()

    def _expects_response(self):
        for request in self:
            if isinstance(request, Exception):
                return True
            if not request.one_way and request.unique_id is not None:
                return True

        return False

    def serialize(self) -> bytes:
        """Returns a serialization of the request.

        Converts the request into a bytes object that can be passed to and by the transport layer.

        :return: A bytes object to be passed on to a transport.
        :rtype: bytes
        """
        return xmlrpc.client.dumps(([req.args for req in self],),
                                   methodname='system.multicall',
                                   allow_none=True).encode()


class XMLRPCBatchResponse(RPCBatchResponse):
    """Multiple responses from a batch request. See
    :py:class:`XMLRPCBatchRequest` on how to handle.

    Items in a batch response need to be
    :py:class:`XMLRPCResponse` instances or None, meaning no reply should be
    generated for the request.
    """
    def serialize(self) -> bytes:
        """Returns a serialization of the batch response.

        Converts the response into a bytes object that can be passed to and by the transport layer.

        :return: A bytes object to be passed on to a transport.
        :rtype: bytes
        """
        result = ( #([multicall_return_token],) +
                  tuple([self._prep_for_multicall(resp)
                         for resp in self
                         if resp is not None]), )
        return xmlrpc.client.dumps(result,
                                   methodname='system.multicall',
                                   methodresponse=True,
                                   allow_none=True).encode()

    def _prep_for_multicall(self, resp):
        # see MultiCallIterator in Python stdlib xmlrpc.client
        if isinstance(resp, XMLRPCSuccessResponse):
            return [resp.result]
        elif isinstance(resp, XMLRPCErrorResponse):
            return dict(faultCode=resp._xmlrpc_error_code,
                        faultString=resp.error)
        else:
            return dict(faultCode=1,
                        faultString="unexpected type '{}' in place of response".format(type(resp)))


class XMLRPCProtocol(RPCBatchProtocol):
    """XMLRPC protocol implementation."""

    XML_RPC_VERSION = "1.0"

    def __init__(
            self,
            id_generator: Optional[Generator[object, None, None]] = None,
            *args,
            allow_none: bool = False,
            use_builtin_types: bool = False,
            **kwargs
    ) -> None:

        super().__init__(*args, **kwargs)

        self.allow_none = allow_none
        self.use_builtin_types = use_builtin_types

        self._id_generator = id_generator or default_id_generator()

    def _get_unique_id(self) -> object:
        return next(self._id_generator)

    def request_factory(self) -> 'XMLRPCRequest':
        """Factory for request objects.

        Allows derived classes to use requests derived from :py:class:`XMLRPCRequest`.

        :rtype: :py:class:`XMLRPCRequest`
        """
        req = XMLRPCRequest()
        req.allow_none = self.allow_none
        return req

    def create_batch_request(
            self,
            requests: Union['XMLRPCRequest', List['XMLRPCRequest']] = None
    ) -> 'XMLRPCBatchRequest':
        """Create a new :py:class:`XMLRPCBatchRequest` object.

        Called by the client when constructing a request.

        :param requests: A list of requests.
        :type requests: :py:class:`list` or :py:class:`XMLRPCRequest`
        :return: A new request instance.
        :rtype: :py:class:`XMLRPCBatchRequest`
        """
        return XMLRPCBatchRequest(requests or [])

    def create_request(
            self,
            method: str,
            args: List[Any] = None,
            kwargs: Dict[str, Any] = None,
            one_way: bool = False
    ) -> 'XMLRPCRequest':
        """Creates a new :py:class:`XMLRPCRequest` object.

        Called by the client when constructing a request.
        XML RPC allows either the ``args`` or ``kwargs`` argument to be set.

        :param str method: The method name to invoke.
        :param list args: The positional arguments to call the method with.
        :param dict kwargs: The keyword arguments to call the method with.
        :param bool one_way: The request is an update, i.e. it does not expect a reply.
        :return: A new request instance
        :rtype: :py:class:`XMLRPCRequest`
        :raises InvalidRequestError: when ``args`` and ``kwargs`` are both defined.
        """
        if args and kwargs:
            raise InvalidRequestError(
                'Does not support args and kwargs at '
                'the same time'
            )

        request = self.request_factory()
        request.one_way = one_way
        request.allow_none = self.allow_none

        if not one_way:
            request.unique_id = self._get_unique_id()

        request.method = method
        if args is not None:
            request.args = args
        if kwargs is not None:
            request.kwargs = kwargs

        return request

    def parse_reply(
            self, data: bytes
    ) -> Union['XMLRPCSuccessResponse', 'XMLRPCErrorResponse', 'XMLRPCBatchResponse']:
        """De-serializes and validates a response.

        Called by the client to reconstruct the serialized :py:class:`XMLRPCResponse`.

        :param bytes data: The data stream received by the transport layer containing the
            serialized request.
        :return: A reconstructed response.
        :rtype: :py:class:`XMLRPCSuccessResponse` or :py:class:`XMLRPCErrorResponse`
        :raises InvalidReplyError: if the response is not valid XML or does not conform
            to the standard.
        """
        if isinstance(data, bytes):
            data = data.decode()

        try:
            reply = xmlrpc.client.loads(data, use_builtin_types=self.use_builtin_types)

        except xmlrpc.client.Fault as e:
            # NOTE: xmlrpc.client.loads() raises an exception here if the
            # result of the call was an exception
            #raise e
            resp = XMLRPCErrorResponse()
            resp.error = e.faultString
            resp._xmlrpc_error_code = e.faultCode
            return resp

        except Exception as e:
            raise InvalidReplyError(e)

        #print("reply:", reply)
        if not isinstance(reply, tuple) or len(reply) != 2:
            raise InvalidReplyError("Reply does not have the expected format.")

        result, method_name = reply

        if not isinstance(result, tuple) or len(result) != 1:
            raise InvalidReplyError("Reply does not have the expected format.")

        # TODO:
        # The Python xmlrpc.server implementation of XMLRPC returns `None` for
        # the method_name, so that we cannot tell whether the return is the
        # result of a multicall (batch call)
        batch_request = False
        if not batch_request:
            return self._make_response(result[0])

        # <-- batch request
        replies = XMLRPCBatchResponse()
        for subresult in result[0]:
            try:
                replies.append(self._make_response(subresult[0]))
            except RPCError as e:
                replies.append(e)
            except Exception as e:
                replies.append(InvalidReplyError(e))

        if not replies:
            raise InvalidReplyError("Empty batch response received.")
        return replies

    def _make_response(self, result):
        response = XMLRPCSuccessResponse()
        response.result = result
        return response

    def parse_request(self, data: bytes
                      ) -> Union['XMLRPCRequest', 'XMLRPCBatchRequest']:
        """De-serializes and validates a request.

        Called by the server to reconstruct the serialized :py:class:`XMLRPCRequest`.

        :param bytes data: The data stream received by the transport layer containing the
            serialized request.
        :return: A reconstructed request.
        :rtype: :py:class:`XMLRPCRequest`
        :raises XMLRPCParseError: if the ``data`` cannot be parsed as valid XML.
        :raises XMLRPCInvalidRequestError: if the request does not comply with the standard.
        """
        if isinstance(data, bytes):
            data = data.decode()

        try:
            req = xmlrpc.client.loads(data, use_builtin_types=self.use_builtin_types)

        except Exception as e:
            raise XMLRPCParseError()

        if not isinstance(req, tuple) or len(req) != 2:
            raise XMLRPCInvalidRequestError()

        # req looks like:
        # (args, method_name)
        args, method_name = req
        if not isinstance(args, tuple) or not isinstance(method_name, str):
            raise XMLRPCInvalidRequestError()

        if method_name != 'system.multicall':
            kwargs = {}
            return self._make_request(method_name, args, kwargs)

        # <-- batch call (XMLRPC multicall)
        # req looks like:
        # (([{'methodName': 'add', 'params': [7, 3]},
        #    {'methodName': 'subtract', 'params': [7, 3]},
        #    {'methodName': 'multiply', 'params': [7, 3]},
        #    {'methodName': 'divide', 'params': [7, 3]}],), 'system.multicall')

        if len(args) != 1:
            raise XMLRPCInvalidRequestError()

        batch_list = args[0]
        if not isinstance(batch_list, list):
            raise XMLRPCInvalidRequestError()

        requests = XMLRPCBatchRequest()
        for subreq in batch_list:

            if not isinstance(subreq, dict):
                raise XMLRPCInvalidRequestError()

            if 'params' not in subreq or 'methodName' not in subreq:
                raise XMLRPCInvalidRequestError()

            args, method_name = subreq['params'], subreq['methodName']
            kwargs = {}
            try:
                req = self._make_request(method_name, args, kwargs)
                requests.append(req)
            except RPCError as e:
                requests.append(e)
            except Exception as e:
                requests.append(XMLRPCInvalidRequestError())

        if not requests:
            raise XMLRPCInvalidRequestError()
        return requests

    def _make_request(self, method_name: str, args: Tuple, kwargs: Dict):
        request = self.request_factory()

        request.method = method_name
        unique_id = self._get_unique_id()
        # TODO
        #request.one_way = 'id' not in req
        request.one_way = False
        if not request.one_way:
            #request.unique_id = req['id']
            request.unique_id = unique_id

        if args is not None:
            request.args = args
        if kwargs is not None:
            request.kwargs = kwargs

        return request

    def raise_error(
            self, error: Union['XMLRPCErrorResponse', Dict[str, Any]]
    ) -> 'XMLRPCError':
        """Recreates the exception.

        Creates a :py:class:`~tinyrpc.protocols.xmlrpc.XMLRPCError` instance
        and raises it.
        This allows the error, message and data attributes of the original
        exception to propagate into the client code.

        The :py:attr:`~tinyrpc.protocols.RPCProtocol.raises_error` flag controls if the exception object is
        raised or returned.

        :returns: the exception object if it is not allowed to raise it.
        :raises XMLRPCError: when the exception can be raised.
            The exception object will contain ``message``, ``code`` and optionally a
            ``data`` property.
        """
        #exc = XMLRPCError(error)
        exc = xmlrpc.client.Fault(error.error, error._xmlrpc_error_code)
        if self.raises_errors:
            raise exc
        return exc

    def _caller(
            self, method: Callable, args: List[Any], kwargs: Dict[str, Any]
    ) -> Any:
        # Custom dispatcher called by RPCDispatcher._dispatch().
        # Override this when you need to call the method with additional parameters for example.
        return method(*args, **kwargs)
