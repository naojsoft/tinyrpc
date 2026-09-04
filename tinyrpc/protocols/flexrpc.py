#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""An RPC protocol whose encoding and protection are choices, not givens.

XML-RPC, JSON-RPC and msgpack-RPC each fix their encoding, and none of them
says anything about who is calling: the specification *is* the encoding, and
authentication is left to whatever the transport happens to offer -- which
for HTTP means a password in a header, and for a raw socket means nothing at
all.

FlexRPC separates the three decisions that are usually welded together:

* **how the body is encoded** is a :py:mod:`~tinyrpc.serializers` choice --
  msgpack where it is machine to machine, json where a person may have to
  read it -- recorded in the envelope, so a server answers in the encoding
  it was addressed in without being configured to;
* **what protects the message** is a :py:mod:`~tinyrpc.framing` choice --
  signing, encryption, compression, credentials, in whatever combination --
  and a receiver states what it *requires*, so a peer cannot opt out of it;
* **how the bytes get there** is the transport, unchanged and unaware of
  either.

There is one envelope, not two.  The framing header already carries a
version, the serializer and the security sections, so the body carries none
of that: it holds the call and nothing else.  The header's protocol byte
versions the body's own shape, which is what a nested envelope would have
been for.

Deliberate properties, since this is ours to define rather than inherited:

* every request carries a correlation id and every reply echoes it, so
  several calls can be in flight on one connection and
  :py:class:`~tinyrpc.client_multiplexing.MultiplexingRPCClient` works over
  it -- which is most of the reason to want a persistent transport at all;
* keyword arguments are carried natively, which XML-RPC cannot do;
* errors are a distinct message type rather than a value that might be
  mistaken for a result, and carry the numeric codes from the XML-RPC fault
  code interoperability table that JSON-RPC 2.0 also adopted, so one table
  explains every protocol here;
* a verified signature reaches the server's authenticator as a *principal*,
  kept apart from any password the sender merely claimed.

This is not a standard, and no third party speaks it.  It is for traffic
between components that can both be upgraded; XML-RPC remains what keeps
un-upgraded peers working.
"""

from typing import Any, Callable, Dict, List, Optional, Tuple

from ..exc import (InvalidParamsError, InvalidReplyError,
                   InvalidRequestError, MethodNotFoundError, RPCError,
                   ServerError)
from ..framing import Framing, FramingError, PolicyError
from ..layers import Credentials
from ..protocols import (RPCErrorResponse, RPCProtocol, RPCRequest,
                         RPCResponse, default_id_generator)
from ..serializers import get_serializer, serializer_by_id

#: The shape of the body.  Carried in the framing header's protocol byte, so
#: a peer refuses a shape it does not know rather than guessing at it.  The
#: envelope around it has its own version, and they move independently.
BODY_VERSION = 1

#: The default encoding, when a caller expresses no preference.
DEFAULT_SERIALIZER = 'msgpack'

# Message types.
REQUEST = 'request'
RESPONSE = 'response'
ERROR = 'error'

#: Error codes, from the XML-RPC fault code interoperability table that
#: JSON-RPC 2.0 later adopted.
ERROR_PARSE = -32700
ERROR_INVALID_REQUEST = -32600
ERROR_METHOD_NOT_FOUND = -32601
ERROR_INVALID_PARAMS = -32602
ERROR_INTERNAL = -32603
ERROR_APPLICATION = -32500

#: A message that did not survive the envelope: a signature that did not
#: verify, a peer that omitted protection this end requires, credentials
#: this end would not accept.  In the implementation-defined range, since
#: neither table has a code for "I will not talk to you".
ERROR_REFUSED = -32001


class FlexRPCError(RPCError):
    """An error reported by the far end of a FlexRPC call."""

    def __init__(self, message: str, code: int = ERROR_APPLICATION,
                 data: Any = None) -> None:
        super().__init__(message)
        self.message = message
        self.code = code
        self.data = data


def _code_and_message(error: Any) -> Tuple[int, str, Any]:
    """Classify an exception for the wire.

    The distinction that matters to a caller is whether the service refused
    the request or the method itself failed, so it is kept: everything the
    RPC machinery raises gets its own code, and anything else is an
    application error carrying the exception's own text.
    """
    if isinstance(error, str):
        return ERROR_APPLICATION, error, None
    if isinstance(error, FlexRPCError):
        return error.code, error.message, error.data
    if isinstance(error, MethodNotFoundError):
        return ERROR_METHOD_NOT_FOUND, 'Method not found', None
    if isinstance(error, InvalidParamsError):
        return ERROR_INVALID_PARAMS, 'Invalid parameters', None
    if isinstance(error, InvalidRequestError):
        return ERROR_INVALID_REQUEST, 'Invalid request', None
    if isinstance(error, ServerError):
        return ERROR_INTERNAL, 'Internal error', None
    if isinstance(error, (PermissionError, FramingError)):
        return ERROR_REFUSED, str(error) or type(error).__name__, None
    # An exception out of the called method.  Name the type as well as the
    # message: without a traceback it is often the only clue as to what went
    # wrong on the far side.
    return ERROR_APPLICATION, '%s: %s' % (type(error).__name__, error), None


class _Message:
    """What every FlexRPC message needs to put itself on the wire.

    The serializer travels with the message rather than being fixed on the
    protocol, so a reply goes back in the encoding its request arrived in.
    """

    def _framed(self, body: Dict[str, Any]) -> bytes:
        serializer = serializer_by_id(self.serializer_id)
        return self._protocol.framing.wrap(
            serializer.dumps(body),
            credentials=self._credentials,
            serializer_id=self.serializer_id,
            sign_as=self.sign_as)


class FlexRPCRequest(_Message, RPCRequest):
    """One call, on its way out or just arrived.

    .. py:attribute:: principal

        Who the sender is *proven* to be, or ``None`` -- set by the framing
        when a signature verified, and by nothing else.

    .. py:attribute:: credentials

        What the sender *claimed* to be, unverified, or ``None``.  A server
        that trusts this without checking it has authenticated nobody.

    .. py:attribute:: signed_as

        The id of the key that verified this request, or ``None``.  Where
        several keys map to one principal -- a rotation, an alias -- this
        says which was actually used.

    .. py:attribute:: sign_as

        Which key to sign the reply with, or ``None`` for this end's own.

        Left alone, a reply is signed by the service, which is what makes
        ``reply.principal`` mean "this came from the service" -- and with
        public keys, where only the service can produce that signature, it
        genuinely does.

        Setting it to ``signed_as`` answers under the caller's key instead.
        That is right only where the key is a secret both ends already
        share, because there it names the secret rather than the sender; it
        lets a caller holding just its own key check the reply.  With keys
        that identify senders it is either impossible -- the service does
        not hold the caller's private key -- or a lie about who answered,
        so it is never done automatically.
    """

    def __init__(self, protocol: 'FlexRPCProtocol',
                 serializer_id: Optional[int] = None) -> None:
        RPCRequest.__init__(self)
        self.one_way = False
        self._protocol = protocol
        self.serializer_id = (protocol.serializer.id if serializer_id is None
                              else serializer_id)
        self._credentials = protocol._credentials
        self.principal: Optional[str] = None
        self.credentials: Optional[Credentials] = None
        self.signed_as: Optional[str] = None
        self.sign_as: Optional[str] = None

    def serialize(self) -> bytes:
        return self._framed({
            'type': REQUEST,
            'id': self.unique_id,
            'method': self.method,
            'args': list(self.args or ()),
            'kwargs': dict(self.kwargs or {}),
        })

    def respond(self, result: Any) -> Optional['FlexRPCResponse']:
        """Build the reply to this request, or ``None`` if none is wanted."""
        if self.one_way or self.unique_id is None:
            return None

        response = FlexRPCResponse(self._protocol, self.serializer_id)
        response.unique_id = self.unique_id
        response.result = result
        response.sign_as = self.sign_as
        return response

    def error_respond(self, error: Any) -> Optional['FlexRPCErrorResponse']:
        """Build an error reply to this request."""
        if self.one_way or self.unique_id is None:
            return None

        response = FlexRPCErrorResponse(self._protocol, self.serializer_id)
        response.unique_id = self.unique_id
        response.code, response.error, response.data = _code_and_message(error)
        response.sign_as = self.sign_as
        return response


class FlexRPCResponse(_Message, RPCResponse):
    """A successful reply."""

    def __init__(self, protocol: 'FlexRPCProtocol',
                 serializer_id: Optional[int] = None) -> None:
        RPCResponse.__init__(self)
        self.result = None
        self._protocol = protocol
        self.serializer_id = (protocol.serializer.id if serializer_id is None
                              else serializer_id)
        # A reply identifies itself by its signature, if the framing signs;
        # a password would be the caller's, and has no business coming back.
        self._credentials = None
        self.principal: Optional[str] = None
        self.sign_as: Optional[str] = None

    def serialize(self) -> bytes:
        return self._framed({
            'type': RESPONSE,
            'id': self.unique_id,
            'result': self.result,
        })


class FlexRPCErrorResponse(_Message, RPCErrorResponse):
    """A reply reporting that the call failed."""

    def __init__(self, protocol: 'FlexRPCProtocol',
                 serializer_id: Optional[int] = None) -> None:
        RPCErrorResponse.__init__(self)
        self.error = None
        self.code = ERROR_APPLICATION
        self.data = None
        self._protocol = protocol
        self.serializer_id = (protocol.serializer.id if serializer_id is None
                              else serializer_id)
        self._credentials = None
        self.principal: Optional[str] = None
        self.sign_as: Optional[str] = None

    def serialize(self) -> bytes:
        error: Dict[str, Any] = {'code': self.code, 'message': self.error}
        if self.data is not None:
            error['data'] = self.data
        return self._framed({
            'type': ERROR,
            'id': self.unique_id,
            'error': error,
        })


class FlexRPCProtocol(RPCProtocol):
    """FlexRPC, encoded and protected however you ask.

    :param serializer: A name from :py:data:`~tinyrpc.serializers.SERIALIZERS`.
        It decides only how the body is encoded; what a peer must understand
        is the same either way, and a peer may answer in another.
    :param framing: What protects the message.  The default protects nothing
        and costs two ``struct`` calls, which is the right choice on a
        trusted socket and the wrong one anywhere else.  A server that means
        to require protection must say so on its own
        :py:class:`~tinyrpc.framing.Framing`, since a sender can always
        choose to apply none.
    :param credentials: A :py:class:`~tinyrpc.layers.Credentials` to attach
        to every outgoing request.  A claim, not a proof: it arrives as
        ``request.credentials`` for something to check, and never as
        ``request.principal``.
    :param id_generator: Where correlation ids come from.
    """

    #: Replies carry the id of the request they answer, so calls can be
    #: multiplexed over one connection.
    supports_reply_correlation = True
    supports_out_of_order = True

    def __init__(self, serializer: str = DEFAULT_SERIALIZER,
                 framing: Optional[Framing] = None,
                 credentials: Optional[Credentials] = None,
                 id_generator: Any = None) -> None:
        self.serializer = get_serializer(serializer)
        self.framing = framing if framing is not None else Framing()
        # The framing's own defaults are what an unadorned wrap() would
        # stamp; ours are what this protocol means by those bytes.
        self.framing.serializer_id = self.serializer.id
        self.framing.protocol_id = BODY_VERSION
        self._credentials = (credentials.encode()
                             if credentials is not None else None)
        self._id_generator = id_generator or default_id_generator()

    def _get_unique_id(self) -> Any:
        return next(self._id_generator)

    def request_factory(self) -> FlexRPCRequest:
        return FlexRPCRequest(self)

    def create_request(self, method: str, args: List[Any] = None,
                       kwargs: Dict[str, Any] = None,
                       one_way: bool = False) -> FlexRPCRequest:
        """Build a request.

        Unlike XML-RPC, positional and keyword arguments may both be given.
        """
        request = self.request_factory()
        request.method = method
        request.args = list(args or ())
        request.kwargs = dict(kwargs or {})
        request.one_way = one_way
        if not one_way:
            request.unique_id = self._get_unique_id()
        return request

    # ------------------------------------------------------------ incoming --

    def _unwrap(self, data: bytes) -> Tuple[Any, Dict[str, Any]]:
        """Undo the envelope and decode the body, or say why not."""
        try:
            got = self.framing.unwrap(data)
        except PolicyError as e:
            raise FlexRPCError(str(e), code=ERROR_REFUSED) from None
        except FramingError as e:
            # Includes a signature that did not verify.  The text says which
            # check failed, which is what makes a misconfigured deployment
            # diagnosable; it names key ids and services, both of which the
            # name service publishes anyway.
            raise FlexRPCError(str(e), code=ERROR_REFUSED) from None

        if got.protocol_id != BODY_VERSION:
            raise FlexRPCError(
                'unsupported body version %r (this speaks %d)'
                % (got.protocol_id, BODY_VERSION),
                code=ERROR_INVALID_REQUEST)

        try:
            serializer = serializer_by_id(got.serializer_id)
        except ValueError as e:
            raise FlexRPCError(str(e), code=ERROR_PARSE) from None

        try:
            body = serializer.loads(got.payload)
        except Exception as e:
            raise FlexRPCError('could not decode the body: %s' % (e,),
                               code=ERROR_PARSE) from None

        if not isinstance(body, dict):
            raise FlexRPCError('message body is not a mapping',
                               code=ERROR_INVALID_REQUEST)
        return got, body

    def parse_request(self, data: bytes) -> FlexRPCRequest:
        """Reconstruct a request from the wire."""
        try:
            got, body = self._unwrap(data)
        except FlexRPCError as e:
            raise _as_request_error(self, e) from None

        if body.get('type') != REQUEST:
            raise _as_request_error(self, FlexRPCError(
                'expected a request, got %r' % (body.get('type'),),
                code=ERROR_INVALID_REQUEST))

        method = body.get('method')
        if not isinstance(method, str):
            raise _as_request_error(self, FlexRPCError(
                'request names no method', code=ERROR_INVALID_REQUEST))

        # Answer in the encoding we were addressed in.  The header says what
        # that was, so neither end has to be configured with the other's
        # preference, and imposing ours would only make a caller decode
        # something it did not ask for.
        request = FlexRPCRequest(self, serializer_id=got.serializer_id)
        request.method = method
        request.args = list(body.get('args') or ())
        request.kwargs = dict(body.get('kwargs') or {})
        request.unique_id = body.get('id')
        request.one_way = request.unique_id is None

        # Proven and claimed, kept apart all the way to the authenticator.
        request.principal = got.principal
        request.credentials = got.credentials()
        request.signed_as = got.signed_as
        # A request built here inherits this protocol's outgoing
        # credentials, which is right for a call we are making and wrong for
        # one we merely received.  A service that re-serializes an arrived
        # request -- a relay, a proxy -- would otherwise sign it with its
        # own password without anyone asking it to.  A relay that means to
        # vouch for the message can say so explicitly.
        request._credentials = None
        return request

    def parse_reply(self, data: bytes) -> RPCResponse:
        """Reconstruct a reply from the wire.

        The reply carries the id of the request it answers, which is what
        lets a client keep several calls in flight at once.
        """
        try:
            got, body = self._unwrap(data)
        except FlexRPCError as e:
            raise InvalidReplyError(str(e)) from None

        kind = body.get('type')

        if kind == RESPONSE:
            response = FlexRPCResponse(self, got.serializer_id)
            response.unique_id = body.get('id')
            response.result = body.get('result')
            response.principal = got.principal
            return response

        if kind == ERROR:
            error = body.get('error') or {}
            failed = FlexRPCErrorResponse(self, got.serializer_id)
            failed.unique_id = body.get('id')
            failed.error = error.get('message', 'unspecified error')
            failed.code = error.get('code', ERROR_APPLICATION)
            failed.data = error.get('data')
            failed.principal = got.principal
            return failed

        raise InvalidReplyError('expected a reply, got %r' % (kind,))

    def raise_error(self, error: FlexRPCErrorResponse) -> RPCError:
        """Turn an error reply back into an exception for the caller."""
        exception = FlexRPCError(
            error.error,
            code=getattr(error, 'code', ERROR_APPLICATION),
            data=getattr(error, 'data', None))
        if self.raises_errors:
            raise exception
        return exception


def _as_request_error(protocol: FlexRPCProtocol,
                      error: FlexRPCError) -> InvalidRequestError:
    """Wrap a parse failure as the exception a server expects.

    A server catches :py:class:`~tinyrpc.exc.RPCError` around
    ``parse_request`` and calls ``error_respond()`` on it, so a failure there
    has to arrive as one of those rather than as a bare exception.

    The reply cannot echo a correlation id: whatever the message claimed, it
    did not survive the envelope, so there is nothing here to trust.  A
    client waiting on a specific id will time out; one that reads what came
    back learns why it was refused.
    """
    class _ParseFailure(InvalidRequestError):
        def error_respond(self) -> FlexRPCErrorResponse:
            response = FlexRPCErrorResponse(protocol)
            response.unique_id = None
            response.error = str(error)
            response.code = error.code
            return response

    return _ParseFailure(str(error))


def require_principal(*allowed: str) -> Callable[[Any, Any], None]:
    """An authenticator that accepts only these proven identities.

    For :py:attr:`tinyrpc.server.RPCServer.authenticator`.  It looks at the
    principal and never at the credentials, which is the whole point: a
    caller can put any name it likes in the second.

    .. code-block:: python

        server.authenticator = require_principal('status', 'taskmgr')
    """
    permitted = frozenset(allowed)

    def authenticator(context: Any, request: Any) -> None:
        principal = getattr(request, 'principal', None)
        if principal is None:
            raise PermissionError('this service requires a signed request')
        if principal not in permitted:
            raise PermissionError('%s may not call this service'
                                  % (principal,))

    return authenticator
