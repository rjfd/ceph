#include "ServerStream.h"
#include "AsyncConnection.h"

#define dout_subsys ceph_subsys_ms
#undef dout_prefix
#define dout_prefix _conn_prefix(_dout)

ServerStream::ServerStream(AsyncConnection *conn, uint32_t stream_id) :
  Stream(conn, stream_id) {
}

void ServerStream::process_message(TagMsg &msg) {
  ldout(msgr->cct, 1) << __func__ << " tag=" << (int)msg.tag << " payload_len="
                      << msg.len << dendl;

  // TODO: validate payload format for each Tag

  switch(state) {
    case State::STATE_SERVER_NEW_STREAM:
      execute_new_stream(msg);
      break;
    case State::STATE_WAITING_AUTH_SETUP:
      execute_waiting_auth_setup_state(msg);
      break;
    case State::STATE_AUTH_SETUP:
      execute_auth_setup_state(msg);
      break;
    default:
      break;
  }
}

void ServerStream::execute_new_stream(TagMsg &msg) {
  ldout(msgr->cct, 1) << __func__ << " tag=" << (int)msg.tag << " payload_len="
                      << msg.len << dendl;
  switch(msg.tag) {
    case Tag::TAG_NEW_STREAM:
      handle_new_stream(*(__le32 *)msg.payload);
      break;
    default:
      ldout(msgr->cct, 1) << __func__ << " dropping message tag="
                          << (int)msg.tag << " payload_len=" << msg.len
                          << dendl;
      break;
  }
}

void ServerStream::execute_waiting_auth_setup_state(TagMsg &msg) {
  ldout(msgr->cct, 1) << __func__ << " tag=" << (int)msg.tag << " payload_len="
                      << msg.len << dendl;
  switch(msg.tag) {
    case Tag::TAG_AUTH_SET_METHOD:
      handle_auth_set_method(*(__le32 *)msg.payload);
      break;
    default:
      ldout(msgr->cct, 1) << __func__ << " dropping message tag="
                          << (int)msg.tag << " payload_len=" << msg.len
                          << dendl;
      break;
  }
}

void ServerStream::execute_auth_setup_state(TagMsg &msg) {
  ldout(msgr->cct, 1) << __func__ << " tag=" << (int)msg.tag << " payload_len="
                      << msg.len << dendl;

  switch(msg.tag) {
    case Tag::TAG_AUTH_REQUEST:
      break;
    default:
      ldout(msgr->cct, 1) << __func__ << " dropping message tag="
                          << (int)msg.tag << " payload_len=" << msg.len
                          << dendl;
      break;
  }
}

void ServerStream::handle_new_stream(__le32 peer_type) {
  ldout(msgr->cct, 1) << __func__ << " peer_type=" << peer_type << dendl;

  std::lock_guard<std::mutex> l(lock);
  this->peer_type = peer_type;
  state = State::STATE_WAITING_AUTH_SETUP;
}

void ServerStream::handle_auth_set_method(__le32 method) {
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
  state = State::STATE_AUTH_SETUP;
}

