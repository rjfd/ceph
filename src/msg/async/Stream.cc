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
  conn(conn), stream_id(stream_id), state(State::STATE_WAITING_AUTH_SETUP) {
}

Stream::~Stream() {
}

void Stream::execute_state() {
  std::lock_guard<std::mutex> l(lock);
  int r;

  ldout(msgr->cct, 1) << __func__ << " state=" << (int)state << dendl;

  switch(state) {
    case State::STATE_WAITING_AUTH_SETUP:
      break;
    case State::STATE_SET_AUTH_METHOD:
      break;
    case State::STATE_NEW_STREAM:
    {
      r = send_message(Tag::TAG_NEW_STREAM, nullptr, 0);
      if (r < 0) {
        lderr(msgr->cct) << __func__ << " error sending new stream message id="
                         << stream_id << dendl;
        state = State::STATE_NEW_STREAM;
      } else {
        state = State::STATE_WAITING_AUTH_SETUP;
      }
      break;
    }
  }
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

void Stream::send_auth_methods() {
  __le32 methods[2];
  methods[0] = CEPH_AUTH_NONE; 
  methods[1] = CEPH_AUTH_CEPHX;
  int r = send_message(Tag::TAG_AUTH_METHODS, (char *)methods,
                       sizeof(__le32)*2);
  if (r < 0) {
    lderr(msgr->cct) << __func__ << " failed to send auth methods: r=" << r
                     << dendl;
  }
}

void Stream::send_set_auth_method(__le32 *allowed_methods, uint32_t len) {
  for (int i=0; i < len; i++) {
     ldout(msgr->cct, 1) << __func__ << " supported auth method: "
                         << allowed_methods[i] << dendl;
   }
  // choose one auth method
  int r = send_message(Tag::TAG_AUTH_SET_METHOD, (char *)&allowed_methods[1],
                       sizeof(__le32));
  if (r < 0) {
    lderr(msgr->cct) << __func__ << " failed to send set auth method: r=" << r
                     << dendl;
  }
}

void Stream::handle_auth_set_method(__le32 method) {
  ldout(msgr->cct, 1) << __func__ << " method=" << method << dendl;
  if (method != CEPH_AUTH_CEPHX) {
    int r = send_message(Tag::TAG_AUTH_BAD_METHOD, (char *)&method,
                         sizeof(__le32));
    if (r < 0) {
      lderr(msgr->cct) << __func__ << " failed to send bad auth method: r="
                       << r << dendl;
    }
  }

  ldout(msgr->cct, 1) << __func__ << " accepted auth method=" << method
                      << dendl;
  std::lock_guard<std::mutex> l(lock);
  auth_method = method;
}

void Stream::process_message(Tag tag, char *payload, uint32_t len) {
  ldout(msgr->cct, 1) << __func__ << " tag=" << (int)tag << " payload_len="
                      << len << dendl;

  // TODO: validate payload format for each Tag

  switch(tag) {
    case Tag::TAG_AUTH_METHODS:
      send_set_auth_method((__le32 *)payload, len/sizeof(__le32));      
      break;
    case Tag::TAG_NEW_STREAM:
      send_auth_methods();
      break;
    case Tag::TAG_AUTH_SET_METHOD:
      handle_auth_set_method(*(__le32 *)payload);
      break;
  }
}

int Stream::process_frame(char *payload, uint32_t len) {
  ldout(msgr->cct, 1) << __func__ << " payload_len=" << len << dendl;

  char tag;
  memcpy(&tag, payload, sizeof(tag));
  process_message((Tag)tag, payload+sizeof(tag), len-sizeof(tag));
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
  ldout(msgr->cct, 1) << __func__ << dendl;
  {
    std::lock_guard<std::mutex> l(lock);
    state = State::STATE_NEW_STREAM;
  }

  execute_state();
}

