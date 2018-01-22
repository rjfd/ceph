#include "ServerStream.h"
#include "AsyncConnection.h"

#include "common/errno.h"

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
      execute_new_stream_state(msg);
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

void ServerStream::execute_new_stream_state(TagMsg &msg) {
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
      handle_auth_request(*(__le32 *)msg.payload,
                          (char *)(msg.payload+sizeof(__le32)));
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

int ServerStream::handle_auth_set_method(__le32 method) {
  ldout(msgr->cct, 1) << __func__ << " method=" << method << dendl;
  std::vector<uint32_t> allowed_methods;
  msgr->ms_deliver_get_allowed_auth_methods(peer_type, allowed_methods);

  bool found = false;
  for (const auto& a_method : allowed_methods) {
    if (a_method == method) {
      found = true;
      break;
    }
  }

  int r = 0;
  if (!found) {
    // send TAG_BAD_AUTH_METHOD
    __le32 payload[2+allowed_methods.size()];
    payload[0] = method;
    payload[1] = allowed_methods.size();
    int i=2;
    for (const auto& a_method : allowed_methods) {
      payload[i++] = a_method;
    }
    r = send_message(Tag::TAG_AUTH_BAD_METHOD, (char *)&payload,
                     sizeof(__le32)*(2+allowed_methods.size()));
    if (r < 0) {
      lderr(msgr->cct) << __func__ << " failed to send bad auth method: r="
                       << r << " " << cpp_strerror(r) << dendl;
    }
    return r;
  }

  std::lock_guard<std::mutex> l(lock);
  auth_method = method;
  state = State::STATE_AUTH_SETUP;

  return r;
}

int ServerStream::handle_auth_request(__le32 len, char *auth_payload) {
  ldout(msgr->cct, 1) << __func__ << " received auth block len=" << len
                      << dendl;
  bufferlist auth_block;
  auth_block.append(auth_payload, len);
  bufferlist auth_reply;
  bool authorizer_valid;
  CryptoKey session_key;

  int r;
  if (!msgr->ms_deliver_verify_authorizer(this, peer_type, auth_method,
                                          auth_block, auth_reply,
                                          authorizer_valid, session_key) ||
      !authorizer_valid) {
    ldout(msgr->cct, 1) << __func__ << " authentication verification failed:"
                        << " isvalid=" << authorizer_valid << dendl;
    r = send_message(Tag::TAG_AUTH_BAD_AUTH, nullptr, 0);
    if (r < 0) {
      lderr(msgr->cct) << __func__ << " failed to send bad authorizer message:"
                       << " r=" << r << " " << cpp_strerror(r) << dendl;
    }
  } else {
    __le32 reply_len = auth_reply.length();
    char payload[reply_len+sizeof(__le32)];
    memcpy(payload, &reply_len, sizeof(__le32));
    memcpy(payload+sizeof(__le32), auth_reply.c_str(), reply_len);

    r = send_message(Tag::TAG_AUTH_REPLY, (char *)&payload,
                     reply_len+sizeof(__le32));
    if (r < 0) {
      lderr(msgr->cct) << __func__ << " failed to send auth reply message: r="
                       << r << " " << cpp_strerror(r) << dendl;
    }
  }

  return r;
}









