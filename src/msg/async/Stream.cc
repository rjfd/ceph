#include "Stream.h"
#include "AsyncConnection.h"

#define dout_subsys ceph_subsys_ms
#undef dout_prefix
#define dout_prefix _conn_prefix(_dout)
ostream& Stream::_conn_prefix(std::ostream *_dout) {
  return *_dout << "-- " << msgr->get_myinst().addr << " >> " << peer_addr << " conn(" << this
                << ").";
}

Stream::Stream(AsyncConnection *conn,  uint32_t stream_id) :
  Connection(conn->get_messenger()->cct, conn->get_messenger()),
  conn(conn), stream_id(stream_id) {
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

int Stream::process_frame(char *paylod, uint32_t len) {
  ldout(msgr->cct, 10) << __func__ << " processing frame for stream id="
                       << stream_id << dendl;
  return 0;
}

