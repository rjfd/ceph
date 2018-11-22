#include "Protocol.h"

#include "AsyncConnection.h"
#include "AsyncMessenger.h"

Protocol::Protocol(AsyncConnection *connection)
    : connection(connection),
      messenger(connection->async_msgr),
      cct(connection->async_msgr->cct) {}

Protocol::~Protocol() {}
