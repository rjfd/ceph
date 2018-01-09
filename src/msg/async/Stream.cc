#include "Stream.h"
#include "AsyncConnection.h"

#define dout_subsys ceph_subsys_ms
#undef dout_prefix
#define dout_prefix _conn_prefix(_dout)
ostream& Stream::_conn_prefix(std::ostream *_dout) {
  return *_dout << "-- " << msgr->get_myinst().addr << " >> " << peer_addr
                << " conn(" << this << ").stream(" << stream_id << ").";
}

Stream::Stream(AsyncConnection *conn,  uint32_t stream_id) :
  Connection(conn->get_messenger()->cct, conn->get_messenger()),
  conn(conn), stream_id(stream_id),
  state(State::STATE_WAITING_AUTH_SETUP) {
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

int Stream::process_frame(char *payload, uint32_t len) {
  ldout(msgr->cct, 1) << __func__ << " payload_len=" << len << dendl;

  char tag;
  memcpy(&tag, payload, sizeof(tag));
  TagMsg msg({(Tag)tag, payload+sizeof(tag), len-(uint32_t)sizeof(tag)});
  process_message(msg);
  return 0;
}

int Stream::send_message(Tag tag, char *payload, uint32_t len) {
  __le32 frame_len = sizeof(char) + len;
  ldout(msgr->cct, 1) << __func__ << " frame_len=" << frame_len << " tag="
                      << (int)tag << " payload_len=" << len << dendl;

  char data[sizeof(__le32)*2+frame_len];
  memcpy(data, &stream_id, sizeof(__le32));
  memcpy(data+sizeof(__le32), &frame_len, sizeof(__le32));
  memcpy(data+sizeof(__le32)*2, &tag, sizeof(char));
  memcpy(data+sizeof(__le32)*2+sizeof(char), payload, len);

  bufferlist bl;
  bl.append(data, sizeof(__le32)*2+frame_len);
  return conn->try_send(bl);
}

void Stream::connection_ready() {
}

