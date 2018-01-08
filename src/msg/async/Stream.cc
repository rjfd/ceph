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
  state(State::STATE_SERVER_WAITING_AUTH_SETUP) {
}

Stream::~Stream() {
}

void Stream::send_new_stream() {
  int r = send_message(Tag::TAG_NEW_STREAM, nullptr, 0);
  if (r < 0) {
    lderr(msgr->cct) << __func__ << " error sending new stream message id="
                     << stream_id << dendl;
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

void Stream::send_set_auth_method(__le32 *allowed_methods,
                                  uint32_t num_methods) {

  // TODO: choose the prefered auth method from daemon/client config
  int r;
  __le32 method = CEPH_AUTH_NONE;

  if (allowed_methods) {
    method = allowed_methods[1];
  }

  ldout(msgr->cct, 1) << __func__ << " sending method=" << method << dendl;
  r = send_message(Tag::TAG_AUTH_SET_METHOD, (char *)&method, sizeof(__le32));
  if (r < 0) {
    lderr(msgr->cct) << __func__ << " failed to send set auth method: r=" << r
                     << dendl;
  }
}

void Stream::handle_auth_methods(__le32 *allowed_methods,
                                 uint32_t num_methods) {
  for (uint32_t i=0; i < num_methods; i++) {
     ldout(msgr->cct, 1) << __func__ << " supported auth method: "
                         << allowed_methods[i] << dendl;
  }

}

void Stream::handle_auth_set_method(__le32 method) {
  ldout(msgr->cct, 1) << __func__ << " method=" << method << dendl;
  if (method != CEPH_AUTH_CEPHX) {
    __le32 payload[4];
    payload[0] = method;
    payload[1] = 2;
    payload[2] = CEPH_AUTH_NONE;
    payload[3] = CEPH_AUTH_CEPHX;

    int r = send_message(Tag::TAG_AUTH_BAD_METHOD, (char *)&payload,
                         sizeof(__le32)*4);
    if (r < 0) {
      lderr(msgr->cct) << __func__ << " failed to send bad auth method: r="
                       << r << dendl;
    }
    return;
  }

  ldout(msgr->cct, 1) << __func__ << " accepted auth method=" << method
                      << dendl;
  std::lock_guard<std::mutex> l(lock);
  auth_method = method;
}

void Stream::handle_auth_bad_method(__le32 method, __le32 num_methods,
                                    __le32 *allowed_methods) {
  ldout(msgr->cct, 1) << __func__ << " method=" << method << dendl;

  for (uint32_t i=0; i < num_methods; i++) {
     ldout(msgr->cct, 1) << __func__ << " allowed auth method: "
                         << allowed_methods[i] << dendl;
  }
  send_set_auth_method(allowed_methods, num_methods);
}

void Stream::execute_server_waiting_auth_setup_state(TagMsg &msg) {
  ldout(msgr->cct, 1) << __func__ << " tag=" << (int)msg.tag << " payload_len="
                      << msg.len << dendl;
  switch(msg.tag) {
    case Tag::TAG_NEW_STREAM:
      send_auth_methods();
      break;
    case Tag::TAG_AUTH_SET_METHOD:
      handle_auth_set_method(*(__le32 *)msg.payload);
      break;
    default:
      break;
  }
}

void Stream::execute_client_waiting_auth_setup_state(TagMsg &msg) {
  ldout(msgr->cct, 1) << __func__ << " tag=" << (int)msg.tag << " payload_len="
                      << msg.len << dendl;
  switch(msg.tag) {
    case Tag::TAG_AUTH_METHODS:
      send_set_auth_method((__le32 *)msg.payload, msg.len/sizeof(__le32));
      break;
    case Tag::TAG_AUTH_BAD_METHOD:
    {
      __le32 *cont = (__le32 *)msg.payload;
      handle_auth_bad_method(cont[0], cont[1], cont+2);
    }
    default:
      break;
  }
}

void Stream::process_message(TagMsg &msg) {
  ldout(msgr->cct, 1) << __func__ << " tag=" << (int)msg.tag << " payload_len="
                      << msg.len << dendl;

  // TODO: validate payload format for each Tag

  switch(state) {
    case State::STATE_SERVER_WAITING_AUTH_SETUP:
      execute_server_waiting_auth_setup_state(msg);
      break;
    case State::STATE_CLIENT_WAITING_AUTH_SETUP:
      execute_client_waiting_auth_setup_state(msg);
    case State::STATE_SET_AUTH_METHOD:
      break;
  }
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
  ldout(msgr->cct, 1) << __func__ << dendl;
  {
    std::lock_guard<std::mutex> l(lock);
    state = State::STATE_CLIENT_WAITING_AUTH_SETUP;
  }

  send_set_auth_method(nullptr, 0);
}

