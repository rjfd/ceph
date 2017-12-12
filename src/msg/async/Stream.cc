#include "Stream.h"
#include "AsyncConnection.h"

Stream::Stream(CephContext *cct, Messenger *m) :
  Connection(cct, m), conn(nullptr) {
}

Stream::~Stream() {
}

int Stream::send_message(Message *m) {
  if (!conn)
    return 0;
  return conn->send_message(m);
}

void Stream::send_keepalive() {
  if (!conn)
    return;
  conn->send_keepalive();
}

void Stream::mark_down() {
  if (!conn)
    return;
  conn->mark_down();
}

void Stream::mark_disposable() {
  if (!conn)
    return;
  return conn->mark_disposable();
}

bool Stream::is_connected() {
  if (!conn)
    return true;
  return conn->is_connected();
}

