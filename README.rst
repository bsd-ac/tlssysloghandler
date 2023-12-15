======================
SysLogHandler with TLS
======================

Python logging.handler as a drop-in replacement for logging.SysLogHandler with support for sending syslog messages over TCP with TLS.

Installation
------------

.. code:: bash

    pip install tlssysloghandler


Usage
-----

.. code:: python

    import logging
    from tlssysloghandler import TLSSysLogHandler

    logger = logging.getLogger()
    logger.setLevel(logging.INFO)

    # with default system certificate store
    handler1 = TLSSysLogHandler(address=('secure-logging.example.com', 6514),
                                socktype=socket.SOCK_STREAM,
                                secure=True)
    logger.addHandler(handler1)

    # with custom certificates, via cafile/capath/cadata
    # refer to https://docs.python.org/3/library/ssl.html#ssl.create_default_context
    handler2 = TLSSysLogHandler(address=('secure-logging.example.com', 6514), 
                                socktype=socket.SOCK_STREAM,
                                secure={cafile='/path/to/ca/file'})
    logger.addHandler(handler2)

    # with custom SSLContext (e.g. for mutual TLS authentication)
    context = ssl.create_default_context(
        purpose=ssl.Purpose.SERVER_AUTH, cafile="/path/to/ca/file"
    )
    context.load_cert_chain(
        certfile="/path/to/client/cert.pem",
        keyfile="/path/to/client/priv.key",
    )
    handler3 = TLSSysLogHandler(address=('secure-logging.example.com', 6514), 
                                socktype=socket.SOCK_STREAM,
                                secure=context)
    logger.addHandler(handler3)

    # or allow TLS without verification (not recommended)
    handler4 = TLSSysLogHandler(address=('secure-logging.example.com', 6514), 
                                socktype=socket.SOCK_STREAM,
                                secure="noverify")
    logger.addHandler(handler4)

    logger.info('Hello, World!')
