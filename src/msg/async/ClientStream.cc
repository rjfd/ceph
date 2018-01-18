#include "ClientStream.h"
#include "AsyncConnection.h"

#include "common/errno.h"

#define dout_subsys ceph_subsys_ms
#undef dout_prefix
#define dout_prefix _conn_prefix(_dout)

ClientStream::ClientStream(AsyncConnection *conn, uint32_t stream_id) :
  Stream(conn, stream_id) {
}

void ClientStream::connection_ready() {
  ldout(msgr->cct, 1) << __func__ << dendl;
  send_new_stream();
  send_set_auth_method(nullptr, 0);
}

void ClientStream::process_message(TagMsg &msg) {
  ldout(msgr->cct, 1) << __func__ << " tag=" << (int)msg.tag << " payload_len="
                      << msg.len << dendl;

  // TODO: validate payload format for each Tag

  switch(state) {
    case State::STATE_WAITING_AUTH_SETUP:
      execute_waiting_auth_setup_state(msg);
    default:
      break;
  }
}

void ClientStream::execute_waiting_auth_setup_state(TagMsg &msg) {
  ldout(msgr->cct, 1) << __func__ << " tag=" << (int)msg.tag << " payload_len="
                      << msg.len << dendl;
  switch(msg.tag) {
    case Tag::TAG_AUTH_BAD_METHOD:
    {
      __le32 *cont = (__le32 *)msg.payload;
      handle_auth_bad_method(cont[0], cont[1], cont+2);
    }
    default:
      break;
  }
}

void ClientStream::send_new_stream() {
  int r;

  __le32 peer_type = msgr->get_myinst().name.type();
  ldout(msgr->cct, 1) << __func__ << " sending new stream: peer_type="
                      << peer_type << dendl;
  r = send_message(Tag::TAG_NEW_STREAM, (char *)&peer_type, sizeof(__le32));
  if (r < 0) {
    lderr(msgr->cct) << __func__ << " failed to send new stream: r="
                     << r << " " << cpp_strerror(r) << dendl;
  }
}

void ClientStream::send_set_auth_method(__le32 *allowed_methods,
                                        uint32_t num_methods) {

  int r;
  __le32 method = CEPH_AUTH_CEPHX;//CEPH_AUTH_NONE;

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

void ClientStream::handle_auth_bad_method(__le32 method, __le32 num_methods,
                                          __le32 *allowed_methods) {
  ldout(msgr->cct, 1) << __func__ << " method=" << method << dendl;

  for (uint32_t i=0; i < num_methods; i++) {
     ldout(msgr->cct, 1) << __func__ << " allowed auth method: "
                         << allowed_methods[i] << dendl;
  }
  send_set_auth_method(allowed_methods, num_methods);
}

