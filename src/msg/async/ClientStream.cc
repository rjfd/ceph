#include "ClientStream.h"
#include "AsyncConnection.h"

#include "auth/Auth.h"
#include "common/errno.h"

#define dout_subsys ceph_subsys_ms
#undef dout_prefix
#define dout_prefix _conn_prefix(_dout)

ClientStream::ClientStream(AsyncConnection *conn, uint32_t stream_id) :
  Stream(conn, stream_id), authorizer(nullptr) {
}

void ClientStream::connection_ready() {
  ldout(msgr->cct, 1) << __func__ << dendl;
  {
    std::lock_guard<std::mutex> l(lock);
    state = State::STATE_WAITING_AUTH_SETUP;
  }
  send_new_stream();
  send_set_auth_method(nullptr, 0);
  send_auth_request();
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
    case Tag::TAG_AUTH_BAD_AUTH:
      handle_bad_auth();
      break;
    case Tag::TAG_AUTH_REPLY:
      handle_auth_reply(*(__le32 *)msg.payload,
                        (char *)(msg.payload+sizeof(__le32)));
      break;
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

int ClientStream::send_set_auth_method(__le32 *allowed_methods,
                                       uint32_t num_methods) {
  int r;
  __le32 method = CEPH_AUTH_NONE;

  {
    std::lock_guard<std::mutex> l(lock);
    delete authorizer;
    authorizer = msgr->ms_deliver_get_authorizer(conn->peer_type, false);
    method = authorizer->protocol;
  }

  if (allowed_methods) {
    bool found = false;
    for (uint32_t i=0; i < num_methods; ++i) {
      if (allowed_methods[i] == method) {
        found = true;
        break;
      }
    }
    if (!found) {
      lderr(msgr->cct) << __func__ << " client does not support any of the"
                       << " allowed methods" << dendl;
      return -EPROTONOSUPPORT;
    }
  }

  ldout(msgr->cct, 1) << __func__ << " sending method=" << method << dendl;
  r = send_message(Tag::TAG_AUTH_SET_METHOD, (char *)&method, sizeof(__le32));
  if (r < 0) {
    lderr(msgr->cct) << __func__ << " failed to send set auth method: r=" << r
                     << " " << cpp_strerror(r) << dendl;
    return r;
  }

  return 0;
}

int ClientStream::send_auth_request() {
  ldout(msgr->cct, 1) << __func__ << " sending auth block len="
                      << authorizer->bl.length() << dendl;
  char *auth_block = authorizer->bl.c_str();
  __le32 len = authorizer->bl.length();

  char payload[len+sizeof(__le32)];
  memcpy(payload, &len, sizeof(__le32));
  memcpy(payload+sizeof(__le32), auth_block, len);

  int r;
  r = send_message(Tag::TAG_AUTH_REQUEST, (char *)&payload,
                   len+sizeof(__le32));
  if (r < 0) {
    lderr(msgr->cct) << __func__ << " failed to send auth request: r=" << r
                     << " " << cpp_strerror(r) << dendl;
  }

  return r;
}

int ClientStream::handle_auth_bad_method(__le32 method, __le32 num_methods,
                                          __le32 *allowed_methods) {
  ldout(msgr->cct, 1) << __func__ << " method=" << method << dendl;

  for (uint32_t i=0; i < num_methods; i++) {
     ldout(msgr->cct, 1) << __func__ << " allowed auth method: "
                         << allowed_methods[i] << dendl;
  }
  int r;
  r = send_set_auth_method(allowed_methods, num_methods);
  if (r == 0) {
    return send_auth_request();
  }
  return r;
}

int ClientStream::handle_bad_auth() {
  ldout(msgr->cct, 1) << __func__ << dendl;
  return 0;
}

int ClientStream::handle_auth_reply(__le32 len, char *auth_payload) {
  ldout(msgr->cct, 1) << __func__ << " payload_len=" << len << dendl;
  bufferlist auth_block;
  auth_block.append(auth_payload, len);
  bufferlist::iterator iter = auth_block.begin();
  if (!authorizer->verify_reply(iter)) {
    ldout(msgr->cct, 1) << __func__ << " failed verifying authorizer reply"
                        << dendl;
    return -1;
  }

  ldout(msgr->cct, 1) << __func__ << " authorizer verified successfully"
                      << dendl;
  return 0;
}

