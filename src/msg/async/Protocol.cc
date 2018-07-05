#include "Protocol.h"

#include "AsyncConnection.h"
#include "AsyncMessenger.h"

#define dout_subsys ceph_subsys_ms
//#undef dout_prefix
//#define dout_prefix connection->_conn_prefix(_dout)

Protocol::Protocol(AsyncConnection *connection)
    : connection(connection), messenger(connection->async_msgr) {}

Protocol::~Protocol() {}

/**
 * Protocol V1
 **/

ProtocolV1::ProtocolV1(AsyncConnection *connection)
    : Protocol(connection), _abort(false) {}

void ProtocolV1::handle_failure(int r) { connection->fault(); }

void ProtocolV1::abort() {
  std::lock_guard<std::mutex> l(connection->lock);
  _abort = true;
}

/**
 * Client Protocol V1
 **/

ClientProtocolV1::ClientProtocolV1(AsyncConnection *connection)
    : ProtocolV1(connection) {}

void ClientProtocolV1::init() { send_banner(); }

void ClientProtocolV1::send_banner() {
  ldout(messenger->cct, 20) << __func__ << " BEGIN" << dendl;
  bufferlist bl;
  bl.append(CEPH_BANNER, strlen(CEPH_BANNER));

  connection->write(bl, std::bind(&ClientProtocolV1::handle_banner_write, this,
                                  std::placeholders::_1));
  ldout(messenger->cct, 20) << __func__ << " END" << dendl;
}

void ClientProtocolV1::handle_banner_write(int r) {
  ldout(messenger->cct, 20) << __func__ << " BEGIN" << dendl;
  std::lock_guard<std::mutex> l(connection->lock);
  if (r < 0) {
    handle_failure(r);
    return;
  }
  ldout(messenger->cct, 10)
      << __func__
      << " connect write banner done: " << connection->get_peer_addr() << dendl;

  ldout(messenger->cct, 20) << __func__ << " END" << dendl;

  wait_server_banner();
}

void ClientProtocolV1::wait_server_banner() {
  ldout(messenger->cct, 20) << __func__ << " BEGIN" << dendl;
  bufferlist myaddrbl;
  unsigned banner_len = strlen(CEPH_BANNER);
  unsigned need_len = banner_len + sizeof(ceph_entity_addr) * 2;
  connection->read(need_len,
                   std::bind(&ClientProtocolV1::handle_server_banner, this,
                             std::placeholders::_1, std::placeholders::_2));
  ldout(messenger->cct, 20) << __func__ << " END" << dendl;
}

void ClientProtocolV1::handle_server_banner(char *buffer, int r) {
  ldout(messenger->cct, 20) << __func__ << " BEGIN" << dendl;
  std::lock_guard<std::mutex> l(connection->lock);

  if (r < 0) {
    ldout(messenger->cct, 1)
        << __func__ << " read banner and identify addresses failed" << dendl;
    handle_failure(r);
    ldout(messenger->cct, 20) << __func__ << " END" << dendl;
    return;
  }

  unsigned banner_len = strlen(CEPH_BANNER);
  if (memcmp(buffer, CEPH_BANNER, banner_len)) {
    ldout(messenger->cct, 0)
        << __func__ << " connect protocol error (bad banner) on peer "
        << connection->get_peer_addr() << dendl;
    handle_failure();
    ldout(messenger->cct, 20) << __func__ << " END" << dendl;
    return;
  }

  bufferlist bl;
  entity_addr_t paddr, peer_addr_for_me;

  bl.append(buffer + banner_len, sizeof(ceph_entity_addr) * 2);
  auto p = bl.cbegin();
  try {
    decode(paddr, p);
    decode(peer_addr_for_me, p);
  } catch (const buffer::error &e) {
    lderr(messenger->cct) << __func__ << " decode peer addr failed " << dendl;
    handle_failure();
    ldout(messenger->cct, 20) << __func__ << " END" << dendl;
    return;
  }
  ldout(messenger->cct, 20) << __func__ << " connect read peer addr " << paddr
                            << " on socket " << connection->cs.fd() << dendl;

  entity_addr_t peer_addr = connection->peer_addr;
  if (peer_addr != paddr) {
    if (paddr.is_blank_ip() && peer_addr.get_port() == paddr.get_port() &&
        peer_addr.get_nonce() == paddr.get_nonce()) {
      ldout(messenger->cct, 0)
          << __func__ << " connect claims to be " << paddr << " not "
          << peer_addr << " - presumably this is the same node!" << dendl;
    } else {
      ldout(messenger->cct, 10) << __func__ << " connect claims to be " << paddr
                                << " not " << peer_addr << dendl;
      handle_failure();
      ldout(messenger->cct, 20) << __func__ << " END" << dendl;
      return;
    }
  }

  ldout(messenger->cct, 20) << __func__ << " connect peer addr for me is "
                            << peer_addr_for_me << dendl;
  connection->lock.unlock();
  messenger->learned_addr(peer_addr_for_me);
  if (messenger->cct->_conf->ms_inject_internal_delays &&
      messenger->cct->_conf->ms_inject_socket_failures) {
    if (rand() % messenger->cct->_conf->ms_inject_socket_failures == 0) {
      ldout(messenger->cct, 10)
          << __func__ << " sleep for "
          << messenger->cct->_conf->ms_inject_internal_delays << dendl;
      utime_t t;
      t.set_from_double(messenger->cct->_conf->ms_inject_internal_delays);
      t.sleep();
    }
  }

  connection->lock.lock();
  if (_abort) {
    ldout(messenger->cct, 1)
        << __func__ << " state changed while learned_addr, mark_down or "
        << " replacing must be happened just now" << dendl;
    ldout(messenger->cct, 20) << __func__ << " END" << dendl;
    return;
  }

  bufferlist myaddrbl;
  encode(messenger->get_myaddr(), myaddrbl, 0);  // legacy
  connection->write(myaddrbl, std::bind(&ClientProtocolV1::handle_my_addr_write,
                                        this, std::placeholders::_1));
  ldout(messenger->cct, 20) << __func__ << " END" << dendl;
}

void ClientProtocolV1::handle_my_addr_write(int r) {
  ldout(messenger->cct, 20) << __func__ << " BEGIN" << dendl;
  std::lock_guard<std::mutex> l(connection->lock);
  if (r < 0) {
    ldout(messenger->cct, 2) << __func__ << " connect couldn't write my addr, "
                             << cpp_strerror(r) << dendl;
    handle_failure(r);
    ldout(messenger->cct, 20) << __func__ << " END" << dendl;
    return;
  }
  ldout(messenger->cct, 10) << __func__ << " connect sent my addr "
                            << messenger->get_myaddr() << dendl;

  ldout(messenger->cct, 20) << __func__ << " END" << dendl;

  send_connect_message();
}

void ClientProtocolV1::send_connect_message() {
  ldout(messenger->cct, 20) << __func__ << " BEGIN" << dendl;

  if (!connection->got_bad_auth) {
    delete connection->authorizer;
    connection->authorizer =
        messenger->get_authorizer(connection->peer_type, false);
  }
  bufferlist bl;

  connection->connect_msg.features = connection->policy.features_supported;
  connection->connect_msg.host_type = messenger->get_myname().type();
  connection->connect_msg.global_seq = connection->global_seq;
  connection->connect_msg.connect_seq = connection->connect_seq;
  connection->connect_msg.protocol_version =
      messenger->get_proto_version(connection->peer_type, true);
  connection->connect_msg.authorizer_protocol =
      connection->authorizer ? connection->authorizer->protocol : 0;
  connection->connect_msg.authorizer_len =
      connection->authorizer ? connection->authorizer->bl.length() : 0;

  if (connection->authorizer) {
    ldout(messenger->cct, 10)
        << __func__ << " connect_msg.authorizer_len="
        << connection->connect_msg.authorizer_len
        << " protocol=" << connection->connect_msg.authorizer_protocol << dendl;
  }

  connection->connect_msg.flags = 0;
  if (connection->policy.lossy)
    connection->connect_msg.flags |=
        CEPH_MSG_CONNECT_LOSSY;  // this is fyi, actually, server decides!
  bl.append((char *)&connection->connect_msg, sizeof(connection->connect_msg));
  if (connection->authorizer) {
    bl.append(connection->authorizer->bl.c_str(),
              connection->authorizer->bl.length());
  }
  ldout(messenger->cct, 10)
      << __func__ << " connect sending gseq=" << connection->global_seq
      << " cseq=" << connection->connect_seq
      << " proto=" << connection->connect_msg.protocol_version << dendl;

  connection->write(
      bl, std::bind(&ClientProtocolV1::handle_connect_message_write, this,
                    std::placeholders::_1));
}

void ClientProtocolV1::handle_connect_message_write(int r) {
  ldout(messenger->cct, 20) << __func__ << " BEGIN" << dendl;

  if (r < 0) {
    ldout(messenger->cct, 2) << __func__ << " connect couldn't send reply "
                             << cpp_strerror(r) << dendl;
    handle_failure(r);
    ldout(messenger->cct, 20) << __func__ << " END" << dendl;
    return;
  }

  ldout(messenger->cct, 20)
      << __func__ << " connect wrote (self +) cseq, waiting for reply" << dendl;

  ldout(messenger->cct, 20) << __func__ << " END" << dendl;

  wait_connect_reply();
}

void ClientProtocolV1::wait_connect_reply() {
  ldout(messenger->cct, 20) << __func__ << " BEGIN" << dendl;
  connection->read(sizeof(connection->connect_reply),
                   std::bind(&ClientProtocolV1::handle_connect_reply_1, this,
                             std::placeholders::_1, std::placeholders::_2));
  ldout(messenger->cct, 20) << __func__ << " END" << dendl;
}

void ClientProtocolV1::handle_connect_reply_1(char *buffer, int r) {
  ldout(messenger->cct, 20) << __func__ << " BEGIN" << dendl;
  if (r < 0) {
    ldout(messenger->cct, 1)
        << __func__ << " read connect reply failed" << dendl;
    handle_failure(r);
    ldout(messenger->cct, 20) << __func__ << " END" << dendl;
    return;
  }

  connection->connect_reply = *((ceph_msg_connect_reply *)buffer);

  ldout(messenger->cct, 20)
      << __func__ << " connect got reply tag "
      << (int)connection->connect_reply.tag << " connect_seq "
      << connection->connect_reply.connect_seq << " global_seq "
      << connection->connect_reply.global_seq << " proto "
      << connection->connect_reply.protocol_version << " flags "
      << (int)connection->connect_reply.flags << " features "
      << connection->connect_reply.features << dendl;

  if (connection->connect_reply.authorizer_len) {
    ldout(messenger->cct, 20) << __func__ << " END" << dendl;
    wait_connect_reply_auth();
    return;
  }

  ldout(messenger->cct, 20) << __func__ << " END" << dendl;
  handle_connect_reply_2();
}

void ClientProtocolV1::wait_connect_reply_auth() {
  ldout(messenger->cct, 20) << __func__ << " BEGIN" << dendl;

  ldout(messenger->cct, 10)
      << __func__
      << " reply.authorizer_len=" << connection->connect_reply.authorizer_len
      << dendl;

  assert(connection->connect_reply.authorizer_len < 4096);

  connection->read(connection->connect_reply.authorizer_len,
                   std::bind(&ClientProtocolV1::handle_connect_reply_auth, this,
                             std::placeholders::_1, std::placeholders::_2));

  ldout(messenger->cct, 20) << __func__ << " END" << dendl;
}

void ClientProtocolV1::handle_connect_reply_auth(char *buffer, int r) {
  ldout(messenger->cct, 20) << __func__ << " BEGIN" << dendl;

  if (r < 0) {
    ldout(messenger->cct, 1)
        << __func__ << " read connect reply authorizer failed" << dendl;
    handle_failure(r);
    ldout(messenger->cct, 20) << __func__ << " END" << dendl;
    return;
  }

  bufferlist authorizer_reply;
  authorizer_reply.append(buffer, connection->connect_reply.authorizer_len);
  auto iter = authorizer_reply.cbegin();
  if (connection->authorizer && !connection->authorizer->verify_reply(iter)) {
    ldout(messenger->cct, 0)
        << __func__ << " failed verifying authorize reply" << dendl;
    handle_failure(-1);
    ldout(messenger->cct, 20) << __func__ << " END" << dendl;
    return;
  }

  ldout(messenger->cct, 20) << __func__ << " END" << dendl;
  handle_connect_reply_2();
}

void ClientProtocolV1::handle_connect_reply_2() {
  ldout(messenger->cct, 20) << __func__ << " BEGIN" << dendl;

  if (connection->connect_reply.tag == CEPH_MSGR_TAG_FEATURES) {
    ldout(messenger->cct, 0)
        << __func__ << " connect protocol feature mismatch, my " << std::hex
        << connection->connect_msg.features << " < peer "
        << connection->connect_reply.features << " missing "
        << (connection->connect_reply.features &
            ~connection->policy.features_supported)
        << std::dec << dendl;
    handle_failure(-1);
    ldout(messenger->cct, 20) << __func__ << " END" << dendl;
    return;
  }

  if (connection->connect_reply.tag == CEPH_MSGR_TAG_BADPROTOVER) {
    ldout(messenger->cct, 0)
        << __func__ << " connect protocol version mismatch, my "
        << connection->connect_msg.protocol_version
        << " != " << connection->connect_reply.protocol_version << dendl;
    handle_failure(-1);
    ldout(messenger->cct, 20) << __func__ << " END" << dendl;
    return;
  }

  if (connection->connect_reply.tag == CEPH_MSGR_TAG_BADAUTHORIZER) {
    ldout(messenger->cct, 0)
        << __func__ << " connect got BADAUTHORIZER" << dendl;
    if (connection->got_bad_auth) {
      handle_failure(-1);
      ldout(messenger->cct, 20) << __func__ << " END" << dendl;
      return;
    }
    connection->got_bad_auth = true;
    delete connection->authorizer;
    connection->authorizer =
        messenger->get_authorizer(connection->peer_type, true);  // try harder
    ldout(messenger->cct, 20) << __func__ << " END" << dendl;
    send_connect_message();
    return;
  }

  if (connection->connect_reply.tag == CEPH_MSGR_TAG_RESETSESSION) {
    ldout(messenger->cct, 0)
        << __func__ << " connect got RESETSESSION" << dendl;
    connection->was_session_reset();
    // see was_session_reset
    connection->outcoming_bl.clear();
    ldout(messenger->cct, 20) << __func__ << " END" << dendl;
    send_connect_message();
    return;
  }

  if (connection->connect_reply.tag == CEPH_MSGR_TAG_RETRY_GLOBAL) {
    connection->global_seq =
        messenger->get_global_seq(connection->connect_reply.global_seq);
    ldout(messenger->cct, 5)
        << __func__ << " connect got RETRY_GLOBAL "
        << connection->connect_reply.global_seq << " chose new "
        << connection->global_seq << dendl;
    ldout(messenger->cct, 20) << __func__ << " END" << dendl;
    send_connect_message();
    return;
  }

  if (connection->connect_reply.tag == CEPH_MSGR_TAG_RETRY_SESSION) {
    assert(connection->connect_reply.connect_seq > connection->connect_seq);
    ldout(messenger->cct, 5)
        << __func__ << " connect got RETRY_SESSION " << connection->connect_seq
        << " -> " << connection->connect_reply.connect_seq << dendl;
    connection->connect_seq = connection->connect_reply.connect_seq;
    ldout(messenger->cct, 20) << __func__ << " END" << dendl;
    send_connect_message();
    return;
  }

  if (connection->connect_reply.tag == CEPH_MSGR_TAG_WAIT) {
    ldout(messenger->cct, 1)
        << __func__ << " connect got WAIT (connection race)" << dendl;
    connection->state = AsyncConnection::STATE_WAIT;
    handle_failure(-1);
    ldout(messenger->cct, 20) << __func__ << " END" << dendl;
    return;
  }

  uint64_t feat_missing;
  feat_missing = connection->policy.features_required &
                 ~(uint64_t)connection->connect_reply.features;
  if (feat_missing) {
    ldout(messenger->cct, 1) << __func__ << " missing required features "
                             << std::hex << feat_missing << std::dec << dendl;
    handle_failure(-1);
    ldout(messenger->cct, 20) << __func__ << " END" << dendl;
    return;
  }

  if (connection->connect_reply.tag == CEPH_MSGR_TAG_SEQ) {
    ldout(messenger->cct, 10)
        << __func__
        << " got CEPH_MSGR_TAG_SEQ, reading acked_seq and writing in_seq"
        << dendl;

    ldout(messenger->cct, 20) << __func__ << " END" << dendl;
    wait_ack_seq();
    return;
  }
  if (connection->connect_reply.tag == CEPH_MSGR_TAG_READY) {
    ldout(messenger->cct, 10)
        << __func__ << " got CEPH_MSGR_TAG_READY " << dendl;
  }

  ldout(messenger->cct, 20) << __func__ << " END" << dendl;
  ready();
}

void ClientProtocolV1::wait_ack_seq() {
  ldout(messenger->cct, 20) << __func__ << " BEGIN" << dendl;
  connection->read(sizeof(uint64_t),
                   std::bind(&ClientProtocolV1::handle_ack_seq, this,
                             std::placeholders::_1, std::placeholders::_2));
  ldout(messenger->cct, 20) << __func__ << " END" << dendl;
}

void ClientProtocolV1::handle_ack_seq(char *buffer, int r) {
  ldout(messenger->cct, 20) << __func__ << " BEGIN" << dendl;

  if (r < 0) {
    ldout(messenger->cct, 1)
        << __func__ << " read connect ack seq failed" << dendl;
    handle_failure(r);
    ldout(messenger->cct, 20) << __func__ << " END" << dendl;
    return;
  }

  uint64_t newly_acked_seq = 0;

  newly_acked_seq = *((uint64_t *)buffer);
  ldout(messenger->cct, 2) << __func__ << " got newly_acked_seq "
                           << newly_acked_seq << " vs out_seq "
                           << connection->out_seq << dendl;
  connection->discard_requeued_up_to(newly_acked_seq);

  bufferlist bl;
  uint64_t s = connection->in_seq;
  bl.append((char *)&s, sizeof(s));
  connection->write(bl, std::bind(&ClientProtocolV1::handle_in_seq_write, this,
                                  std::placeholders::_1));

  ldout(messenger->cct, 20) << __func__ << " END" << dendl;
}

void ClientProtocolV1::handle_in_seq_write(int r) {
  ldout(messenger->cct, 20) << __func__ << " BEGIN" << dendl;

  if (r < 0) {
    ldout(messenger->cct, 10) << __func__ << " failed to send in_seq " << dendl;
    handle_failure(r);
    ldout(messenger->cct, 20) << __func__ << " END" << dendl;
    return;
  }

  ldout(messenger->cct, 10) << __func__ << " send in_seq done " << dendl;

  ldout(messenger->cct, 20) << __func__ << " END" << dendl;
  ready();
}

void ClientProtocolV1::ready() {
  ldout(messenger->cct, 20) << __func__ << " BEGIN" << dendl;

  // hooray!
  connection->peer_global_seq = connection->connect_reply.global_seq;
  connection->policy.lossy =
      connection->connect_reply.flags & CEPH_MSG_CONNECT_LOSSY;
  connection->state = AsyncConnection::STATE_OPEN;
  connection->once_ready = true;
  connection->connect_seq += 1;
  assert(connection->connect_seq == connection->connect_reply.connect_seq);
  connection->backoff = utime_t();
  connection->set_features((uint64_t)connection->connect_reply.features &
                           (uint64_t)connection->connect_msg.features);
  ldout(messenger->cct, 10)
      << __func__ << " connect success " << connection->connect_seq
      << ", lossy = " << connection->policy.lossy << ", features "
      << connection->get_features() << dendl;

  // If we have an authorizer, get a new AuthSessionHandler to deal with ongoing
  // security of the connection.  PLR
  if (connection->authorizer != NULL) {
    connection->session_security.reset(get_auth_session_handler(
        messenger->cct, connection->authorizer->protocol,
        connection->authorizer->session_key, connection->get_features()));
  } else {
    // We have no authorizer, so we shouldn't be applying security to messages
    // in this AsyncConnection.  PLR
    connection->session_security.reset();
  }

  if (connection->delay_state) assert(connection->delay_state->ready());
  connection->dispatch_queue->queue_connect(connection);
  messenger->ms_deliver_handle_fast_connect(connection);

  // make sure no pending tick timer
  if (connection->last_tick_id)
    connection->center->delete_time_event(connection->last_tick_id);
  connection->last_tick_id = connection->center->create_time_event(
      connection->inactive_timeout_us, connection->tick_handler);

  // message may in queue between last _try_send and connection ready
  // write event may already notify and we need to force scheduler again
  connection->write_lock.lock();
  connection->can_write = AsyncConnection::WriteStatus::CANWRITE;
  if (connection->is_queued())
    connection->center->dispatch_event_external(connection->write_handler);
  connection->write_lock.unlock();
  connection->maybe_start_delay_thread();

  ldout(messenger->cct, 20) << __func__ << " END" << dendl;
}

/**
 * Server Protocol V1
 **/
ServerProtocolV1::ServerProtocolV1(AsyncConnection *connection)
    : ProtocolV1(connection) {}

void ServerProtocolV1::init() { accept(); }

void ServerProtocolV1::accept() {
  ldout(messenger->cct, 20) << __func__ << " BEGIN" << dendl;
  bufferlist bl;

  bl.append(CEPH_BANNER, strlen(CEPH_BANNER));

  encode(messenger->get_myaddr(), bl, 0);  // legacy
  connection->port = messenger->get_myaddr().get_port();
  encode(connection->socket_addr, bl, 0);  // legacy

  ldout(messenger->cct, 1) << __func__ << " sd=" << connection->cs.fd() << " "
                           << connection->socket_addr << dendl;

  connection->write(bl, std::bind(&ServerProtocolV1::handle_banner_write, this,
                                  std::placeholders::_1));
  ldout(messenger->cct, 20) << __func__ << " END" << dendl;
}

void ServerProtocolV1::handle_banner_write(int r) {
  ldout(messenger->cct, 20) << __func__ << " BEGIN" << dendl;
  std::lock_guard<std::mutex> l(connection->lock);
  if (r < 0) {
    handle_failure(r);
    return;
  }
  ldout(messenger->cct, 10) << __func__ << " write banner and addr done: "
                            << connection->get_peer_addr() << dendl;

  ldout(messenger->cct, 20) << __func__ << " END" << dendl;

  wait_client_banner();
}

void ServerProtocolV1::wait_client_banner() {
  ldout(messenger->cct, 20) << __func__ << " BEGIN" << dendl;
  connection->read(strlen(CEPH_BANNER) + sizeof(ceph_entity_addr),
                   std::bind(&ServerProtocolV1::handle_client_banner, this,
                             std::placeholders::_1, std::placeholders::_2));
  ldout(messenger->cct, 20) << __func__ << " END" << dendl;
}

void ServerProtocolV1::handle_client_banner(char *buffer, int r) {
  ldout(messenger->cct, 20) << __func__ << " BEGIN" << dendl;
  std::lock_guard<std::mutex> l(connection->lock);
  if (r < 0) {
    ldout(messenger->cct, 1)
        << __func__ << " read peer banner and addr failed" << dendl;
    handle_failure(r);
    ldout(messenger->cct, 20) << __func__ << " END" << dendl;
    return;
  }

  if (memcmp(buffer, CEPH_BANNER, strlen(CEPH_BANNER))) {
    ldout(messenger->cct, 1)
        << __func__ << " accept peer sent bad banner '" << buffer
        << "' (should be '" << CEPH_BANNER << "')" << dendl;
    connection->fault();
    ldout(messenger->cct, 20) << __func__ << " END" << dendl;
    return;
  }

  bufferlist addr_bl;
  entity_addr_t peer_addr;

  addr_bl.append(buffer + strlen(CEPH_BANNER), sizeof(ceph_entity_addr));
  try {
    auto ti = addr_bl.cbegin();
    decode(peer_addr, ti);
  } catch (const buffer::error &e) {
    lderr(messenger->cct) << __func__ << " decode peer_addr failed " << dendl;
    connection->fault();
    ldout(messenger->cct, 20) << __func__ << " END" << dendl;
    return;
  }

  ldout(messenger->cct, 10)
      << __func__ << " accept peer addr is " << peer_addr << dendl;
  if (peer_addr.is_blank_ip()) {
    // peer apparently doesn't know what ip they have; figure it out for them.
    int port = peer_addr.get_port();
    peer_addr.u = connection->socket_addr.u;
    peer_addr.set_port(port);
    ldout(messenger->cct, 0)
        << __func__ << " accept peer addr is really " << peer_addr
        << " (socket is " << connection->socket_addr << ")" << dendl;
  }
  connection->set_peer_addr(peer_addr);  // so that connection_state gets set up

  ldout(messenger->cct, 20) << __func__ << " END" << dendl;

  wait_connect_message();
}

void ServerProtocolV1::wait_connect_message() {
  ldout(messenger->cct, 20) << __func__ << " BEGIN" << dendl;

  connection->read(sizeof(connection->connect_msg),
                   std::bind(&ServerProtocolV1::handle_connect_message_1, this,
                             std::placeholders::_1, std::placeholders::_2));
  ldout(messenger->cct, 20) << __func__ << " END" << dendl;
}

void ServerProtocolV1::handle_connect_message_1(char *buffer, int r) {
  ldout(messenger->cct, 20) << __func__ << " BEGIN" << dendl;

  if (r < 0) {
    ldout(messenger->cct, 1) << __func__ << " read connect msg failed" << dendl;
    handle_failure(r);
    ldout(messenger->cct, 20) << __func__ << " END" << dendl;
    return;
  }

  connection->connect_msg = *((ceph_msg_connect *)buffer);

  if (connection->connect_msg.authorizer_len) {
    ldout(messenger->cct, 20) << __func__ << " END" << dendl;
    wait_connect_message_auth();
    return;
  }

  ldout(messenger->cct, 20) << __func__ << " END" << dendl;

  handle_connect_message_2();
}

void ServerProtocolV1::wait_connect_message_auth() {
  ldout(messenger->cct, 20) << __func__ << " BEGIN" << dendl;

  connection->read(
      connection->connect_msg.authorizer_len,
      std::bind(&ServerProtocolV1::handle_connect_message_auth, this,
                std::placeholders::_1, std::placeholders::_2));

  ldout(messenger->cct, 20) << __func__ << " END" << dendl;
}

void ServerProtocolV1::handle_connect_message_auth(char *buffer, int r) {
  ldout(messenger->cct, 20) << __func__ << " BEGIN" << dendl;

  if (r < 0) {
    ldout(messenger->cct, 1)
        << __func__ << " read connect authorizer failed" << dendl;
    handle_failure(r);
    ldout(messenger->cct, 20) << __func__ << " END" << dendl;
    return;
  }

  connection->authorizer_buf.push_back(
      buffer::copy(buffer, connection->connect_msg.authorizer_len));

  ldout(messenger->cct, 20) << __func__ << " END" << dendl;

  handle_connect_message_2();
}

void ServerProtocolV1::handle_connect_message_2() {
  ldout(messenger->cct, 20) << __func__ << " BEGIN" << dendl;

  ldout(messenger->cct, 20)
      << __func__ << " accept got peer connect_seq "
      << connection->connect_msg.connect_seq << " global_seq "
      << connection->connect_msg.global_seq << dendl;

  connection->set_peer_type(connection->connect_msg.host_type);
  connection->policy = messenger->get_policy(connection->connect_msg.host_type);

  ldout(messenger->cct, 10)
      << __func__ << " accept of host_type "
      << connection->connect_msg.host_type
      << ", policy.lossy=" << connection->policy.lossy
      << " policy.server=" << connection->policy.server
      << " policy.standby=" << connection->policy.standby
      << " policy.resetcheck=" << connection->policy.resetcheck << dendl;

  ssize_t r = 0;
  bufferlist reply_bl;

  memset(&reply, 0, sizeof(reply));
  reply.protocol_version =
      messenger->get_proto_version(connection->peer_type, false);

  // mismatch?
  ldout(messenger->cct, 10)
      << __func__ << " accept my proto " << reply.protocol_version
      << ", their proto " << connection->connect_msg.protocol_version << dendl;

  if (connection->connect_msg.protocol_version != reply.protocol_version) {
    send_connect_message_reply(CEPH_MSGR_TAG_BADPROTOVER);
    ldout(messenger->cct, 20) << __func__ << " END" << dendl;
    return;
  }

  // require signatures for cephx?
  if (connection->connect_msg.authorizer_protocol == CEPH_AUTH_CEPHX) {
    if (connection->peer_type == CEPH_ENTITY_TYPE_OSD ||
        connection->peer_type == CEPH_ENTITY_TYPE_MDS) {
      if (messenger->cct->_conf->cephx_require_signatures ||
          messenger->cct->_conf->cephx_cluster_require_signatures) {
        ldout(messenger->cct, 10)
            << __func__
            << " using cephx, requiring MSG_AUTH feature bit for cluster"
            << dendl;
        connection->policy.features_required |= CEPH_FEATURE_MSG_AUTH;
      }
    } else {
      if (messenger->cct->_conf->cephx_require_signatures ||
          messenger->cct->_conf->cephx_service_require_signatures) {
        ldout(messenger->cct, 10)
            << __func__
            << " using cephx, requiring MSG_AUTH feature bit for service"
            << dendl;
        connection->policy.features_required |= CEPH_FEATURE_MSG_AUTH;
      }
    }
  }

  uint64_t feat_missing = connection->policy.features_required &
                          ~(uint64_t)connection->connect_msg.features;
  if (feat_missing) {
    ldout(messenger->cct, 1) << __func__ << " peer missing required features "
                             << std::hex << feat_missing << std::dec << dendl;
    send_connect_message_reply(CEPH_MSGR_TAG_FEATURES);
    ldout(messenger->cct, 20) << __func__ << " END" << dendl;
    return;
  }

  connection->lock.unlock();

  bool authorizer_valid;
  if (!messenger->verify_authorizer(connection, connection->peer_type,
                                    connection->connect_msg.authorizer_protocol,
                                    connection->authorizer_buf,
                                    authorizer_reply, authorizer_valid,
                                    connection->session_key) ||
      !authorizer_valid) {
    connection->lock.lock();
    ldout(messenger->cct, 0) << __func__ << ": got bad authorizer" << dendl;
    connection->session_security.reset();
    send_connect_message_reply(CEPH_MSGR_TAG_BADAUTHORIZER);
    ldout(messenger->cct, 20) << __func__ << " END" << dendl;
    return;
  }

    // We've verified the authorizer for this AsyncConnection, so set up the
    // session security structure.  PLR
    ldout(messenger->cct, 10)
        << __func__ << " accept setting up session_security." << dendl;

    // existing?
    AsyncConnectionRef existing = messenger->lookup_conn(connection->peer_addr);

    connection->inject_delay();

    connection->lock.lock();
    if (_abort) {
      ldout(messenger->cct, 1)
          << __func__ << " state changed while accept, it must be mark_down"
          << dendl;
      assert(connection->state == AsyncConnection::STATE_CLOSED);
      handle_failure(-1);
      ldout(messenger->cct, 20) << __func__ << " END" << dendl;
      return;
    }

    if (existing == connection) {
      existing = NULL;
    }

    if (existing) {
      // There is no possible that existing connection will acquire this
      // connection's lock
      existing->lock.lock();  // skip lockdep check (we are locking a second
                              // AsyncConnection here)

      if (existing->state == AsyncConnection::STATE_CLOSED) {
        ldout(messenger->cct, 1)
            << __func__ << " existing already closed." << dendl;
        existing->lock.unlock();
        existing = NULL;

        ldout(messenger->cct, 20) << __func__ << " END" << dendl;
        open();
        return;
      }

      // if (existing->replacing) {
      //   ldout(async_msgr->cct, 1)
      //       << __func__ << " existing racing replace happened while
      //       replacing."
      //       << " existing_state=" << get_state_name(existing->state) <<
      //       dendl;
      //   reply.global_seq = existing->peer_global_seq;
      //   r = _reply_accept(CEPH_MSGR_TAG_RETRY_GLOBAL, connect, reply,
      //                     authorizer_reply);
      //   existing->lock.unlock();
      //   if (r < 0) goto fail;
      //   return 0;
      // }

      // if (connect.global_seq < existing->peer_global_seq) {
      //   ldout(async_msgr->cct, 10)
      //       << __func__ << " accept existing " << existing << ".gseq "
      //       << existing->peer_global_seq << " > " << connect.global_seq
      //       << ", RETRY_GLOBAL" << dendl;
      //   reply.global_seq =
      //       existing->peer_global_seq;  // so we can send it below..
      //   existing->lock.unlock();
      //   return _reply_accept(CEPH_MSGR_TAG_RETRY_GLOBAL, connect, reply,
      //                        authorizer_reply);
      // } else {
      //   ldout(async_msgr->cct, 10)
      //       << __func__ << " accept existing " << existing << ".gseq "
      //       << existing->peer_global_seq << " <= " << connect.global_seq
      //       << ", looks ok" << dendl;
      // }

      // if (existing->policy.lossy) {
      //   ldout(async_msgr->cct, 0)
      //       << __func__
      //       << " accept replacing existing (lossy) channel (new one lossy="
      //       << policy.lossy << ")" << dendl;
      //   existing->was_session_reset();
      //   goto replace;
      // }

      // ldout(async_msgr->cct, 1)
      //     << __func__ << " accept connect_seq " << connect.connect_seq
      //     << " vs existing csq=" << existing->connect_seq
      //     << " existing_state=" << get_state_name(existing->state) << dendl;

      // if (connect.connect_seq == 0 && existing->connect_seq > 0) {
      //   ldout(async_msgr->cct, 0)
      //       << __func__
      //       << " accept peer reset, then tried to connect to us, replacing"
      //       << dendl;
      //   // this is a hard reset from peer
      //   is_reset_from_peer = true;
      //   if (policy.resetcheck)
      //     existing->was_session_reset();  // this resets out_queue, msg_ and
      //                                     // connect_seq #'s
      //   goto replace;
      // }

      // if (connect.connect_seq < existing->connect_seq) {
      //   // old attempt, or we sent READY but they didn't get it.
      //   ldout(async_msgr->cct, 10)
      //       << __func__ << " accept existing " << existing << ".cseq "
      //       << existing->connect_seq << " > " << connect.connect_seq
      //       << ", RETRY_SESSION" << dendl;
      //   reply.connect_seq = existing->connect_seq + 1;
      //   existing->lock.unlock();
      //   return _reply_accept(CEPH_MSGR_TAG_RETRY_SESSION, connect, reply,
      //                        authorizer_reply);
      // }

      // if (connect.connect_seq == existing->connect_seq) {
      //   // if the existing connection successfully opened, and/or
      //   // subsequently went to standby, then the peer should bump
      //   // their connect_seq and retry: this is not a connection race
      //   // we need to resolve here.
      //   if (existing->state == STATE_OPEN || existing->state ==
      //   STATE_STANDBY) {
      //     ldout(async_msgr->cct, 10)
      //         << __func__ << " accept connection race, existing " << existing
      //         << ".cseq " << existing->connect_seq
      //         << " == " << connect.connect_seq << ", OPEN|STANDBY,
      //         RETRY_SESSION"
      //         << dendl;
      //     // if connect_seq both zero, dont stuck into dead lock. it's ok to
      //     // replace
      //     if (policy.resetcheck && existing->connect_seq == 0) {
      //       goto replace;
      //     }

      //     reply.connect_seq = existing->connect_seq + 1;
      //     existing->lock.unlock();
      //     return _reply_accept(CEPH_MSGR_TAG_RETRY_SESSION, connect, reply,
      //                          authorizer_reply);
      //   }

      //   // connection race?
      //   if (peer_addr < async_msgr->get_myaddr() || existing->policy.server)
      //   {
      //     // incoming wins
      //     ldout(async_msgr->cct, 10)
      //         << __func__ << " accept connection race, existing " << existing
      //         << ".cseq " << existing->connect_seq
      //         << " == " << connect.connect_seq
      //         << ", or we are server, replacing my attempt" << dendl;
      //     goto replace;
      //   } else {
      //     // our existing outgoing wins
      //     ldout(async_msgr->cct, 10)
      //         << __func__ << " accept connection race, existing " << existing
      //         << ".cseq " << existing->connect_seq
      //         << " == " << connect.connect_seq << ", sending WAIT" << dendl;
      //     assert(peer_addr > async_msgr->get_myaddr());
      //     existing->lock.unlock();
      //     return _reply_accept(CEPH_MSGR_TAG_WAIT, connect, reply,
      //                          authorizer_reply);
      //   }
      }

  //     assert(connect.connect_seq > existing->connect_seq);
  //     assert(connect.global_seq >= existing->peer_global_seq);
  //     if (policy.resetcheck &&  // RESETSESSION only used by servers; peers
  //     do not
  //                               // reset each other
  //         existing->connect_seq == 0) {
  //       ldout(async_msgr->cct, 0)
  //           << __func__ << " accept we reset (peer sent cseq "
  //           << connect.connect_seq << ", " << existing
  //           << ".cseq = " << existing->connect_seq << "), sending
  //           RESETSESSION"
  //           << dendl;
  //       existing->lock.unlock();
  //       return _reply_accept(CEPH_MSGR_TAG_RESETSESSION, connect, reply,
  //                            authorizer_reply);
  //     }

  //     // reconnect
  //     ldout(async_msgr->cct, 10)
  //         << __func__ << " accept peer sent cseq " << connect.connect_seq <<
  //         " > "
  //         << existing->connect_seq << dendl;
  //     goto replace;
  //   }  // existing
  //   else if (!replacing && connect.connect_seq > 0) {
  //     // we reset, and they are opening a new session
  //     ldout(async_msgr->cct, 0)
  //         << __func__ << " accept we reset (peer sent cseq "
  //         << connect.connect_seq << "), sending RESETSESSION" << dendl;
  //     return _reply_accept(CEPH_MSGR_TAG_RESETSESSION, connect, reply,
  //                          authorizer_reply);
  //   } else {
  //     // new session
  //     ldout(async_msgr->cct, 10) << __func__ << " accept new session" <<
  //     dendl; existing = NULL; goto open;
  //   }

  // replace:
  //   ldout(async_msgr->cct, 10)
  //       << __func__ << " accept replacing " << existing << dendl;

  //   inject_delay();
  //   if (existing->policy.lossy) {
  //     // disconnect from the Connection
  //     ldout(async_msgr->cct, 1)
  //         << __func__ << " replacing on lossy channel, failing existing" <<
  //         dendl;
  //     existing->_stop();
  //     existing->dispatch_queue->queue_reset(existing.get());
  //   } else {
  //     assert(can_write == WriteStatus::NOWRITE);
  //     existing->write_lock.lock();

  //     // reset the in_seq if this is a hard reset from peer,
  //     // otherwise we respect our original connection's value
  //     if (is_reset_from_peer) {
  //       existing->is_reset_from_peer = true;
  //     }

  //     center->delete_file_event(cs.fd(), EVENT_READABLE | EVENT_WRITABLE);

  //     if (existing->delay_state) {
  //       existing->delay_state->flush();
  //       assert(!delay_state);
  //     }
  //     existing->reset_recv_state();

  //     auto temp_cs = std::move(cs);
  //     EventCenter *new_center = center;
  //     Worker *new_worker = worker;
  //     // avoid _stop shutdown replacing socket
  //     // queue a reset on the new connection, which we're dumping for the old
  //     _stop();

  //     dispatch_queue->queue_reset(this);
  //     ldout(async_msgr->cct, 1)
  //         << __func__ << " stop myself to swap existing" << dendl;
  //     existing->can_write = WriteStatus::REPLACING;
  //     existing->replacing = true;
  //     existing->state_offset = 0;
  //     // avoid previous thread modify event
  //     existing->state = STATE_NONE;
  //     // Discard existing prefetch buffer in `recv_buf`
  //     existing->recv_start = existing->recv_end = 0;
  //     // there shouldn't exist any buffer
  //     assert(recv_start == recv_end);

  //     auto deactivate_existing = std::bind(
  //         [existing, new_worker, new_center, connect, reply,
  //          authorizer_reply](ConnectedSocket &cs) mutable {
  //           // we need to delete time event in original thread
  //           {
  //             std::lock_guard<std::mutex> l(existing->lock);
  //             existing->write_lock.lock();
  //             existing->requeue_sent();
  //             existing->outcoming_bl.clear();
  //             existing->open_write = false;
  //             existing->write_lock.unlock();
  //             if (existing->state == STATE_NONE) {
  //               existing->shutdown_socket();
  //               existing->cs = std::move(cs);
  //               existing->worker->references--;
  //               new_worker->references++;
  //               existing->logger = new_worker->get_perf_counter();
  //               existing->worker = new_worker;
  //               existing->center = new_center;
  //               if (existing->delay_state)
  //                 existing->delay_state->set_center(new_center);
  //             } else if (existing->state == STATE_CLOSED) {
  //               auto back_to_close =
  //                   std::bind([](ConnectedSocket &cs) mutable { cs.close();
  //                   },
  //                             std::move(cs));
  //               new_center->submit_to(new_center->get_id(),
  //                                     std::move(back_to_close), true);
  //               return;
  //             } else {
  //               ceph_abort();
  //             }
  //           }

  //           // Before changing existing->center, it may already exists some
  //           events
  //           // in existing->center's queue. Then if we mark down `existing`,
  //           it
  //           // will execute in another thread and clean up connection.
  //           Previous
  //           // event will result in segment fault
  //           auto transfer_existing = [existing, connect, reply,
  //                                     authorizer_reply]() mutable {
  //             std::lock_guard<std::mutex> l(existing->lock);
  //             if (existing->state == STATE_CLOSED) return;
  //             assert(existing->state == STATE_NONE);

  //             existing->state = STATE_ACCEPTING_WAIT_CONNECT_MSG;
  //             existing->center->create_file_event(
  //                 existing->cs.fd(), EVENT_READABLE, existing->read_handler);
  //             reply.global_seq = existing->peer_global_seq;
  //             if (existing->_reply_accept(CEPH_MSGR_TAG_RETRY_GLOBAL,
  //             connect,
  //                                         reply, authorizer_reply) < 0) {
  //               // handle error
  //               existing->fault();
  //             }
  //           };
  //           if (existing->center->in_thread())
  //             transfer_existing();
  //           else
  //             existing->center->submit_to(existing->center->get_id(),
  //                                         std::move(transfer_existing),
  //                                         true);
  //         },
  //         std::move(temp_cs));

  //     existing->center->submit_to(existing->center->get_id(),
  //                                 std::move(deactivate_existing), true);
  //     existing->write_lock.unlock();
  //     existing->lock.unlock();
  //     return 0;
  //   }
  //   existing->lock.unlock();

  // open:
  //   connect_seq = connect.connect_seq + 1;
  //   peer_global_seq = connect.global_seq;
  //   ldout(async_msgr->cct, 10)
  //       << __func__ << " accept success, connect_seq = " << connect_seq
  //       << " in_seq=" << in_seq << ", sending READY" << dendl;

  //   int next_state;

  //   // if it is a hard reset from peer, we don't need a round-trip to
  //   negotiate
  //   // in/out sequence
  //   if ((connect.features & CEPH_FEATURE_RECONNECT_SEQ) &&
  //   !is_reset_from_peer) {
  //     reply.tag = CEPH_MSGR_TAG_SEQ;
  //     next_state = STATE_ACCEPTING_WAIT_SEQ;
  //   } else {
  //     reply.tag = CEPH_MSGR_TAG_READY;
  //     next_state = STATE_ACCEPTING_READY;
  //     discard_requeued_up_to(0);
  //     is_reset_from_peer = false;
  //     in_seq = 0;
  //   }

  //   // send READY reply
  //   reply.features = policy.features_supported;
  //   reply.global_seq = async_msgr->get_global_seq();
  //   reply.connect_seq = connect_seq;
  //   reply.flags = 0;
  //   reply.authorizer_len = authorizer_reply.length();
  //   if (policy.lossy) reply.flags = reply.flags | CEPH_MSG_CONNECT_LOSSY;

  //   set_features((uint64_t)reply.features & (uint64_t)connect.features);
  //   ldout(async_msgr->cct, 10)
  //       << __func__ << " accept features " << get_features() << dendl;

  //   session_security.reset(get_auth_session_handler(async_msgr->cct,
  //                                                   connect.authorizer_protocol,
  //                                                   session_key,
  //                                                   get_features()));

  //   reply_bl.append((char *)&reply, sizeof(reply));

  //   if (reply.authorizer_len)
  //     reply_bl.append(authorizer_reply.c_str(), authorizer_reply.length());

  //   if (reply.tag == CEPH_MSGR_TAG_SEQ) {
  //     uint64_t s = in_seq;
  //     reply_bl.append((char *)&s, sizeof(s));
  //   }

  //   lock.unlock();
  //   // Because "replacing" will prevent other connections preempt this addr,
  //   // it's safe that here we don't acquire Connection's lock
  //   r = async_msgr->accept_conn(this);

  //   inject_delay();

  //   lock.lock();
  //   replacing = false;
  //   if (r < 0) {
  //     ldout(async_msgr->cct, 1)
  //         << __func__ << " existing race replacing process for addr=" <<
  //         peer_addr
  //         << " just fail later one(this)" << dendl;
  //     goto fail_registered;
  //   }
  //   if (state != STATE_ACCEPTING_WAIT_CONNECT_MSG_AUTH) {
  //     ldout(async_msgr->cct, 1)
  //         << __func__ << " state changed while accept_conn, it must be
  //         mark_down"
  //         << dendl;
  //     assert(state == STATE_CLOSED || state == STATE_NONE);
  //     goto fail_registered;
  //   }

  //   r = try_send(reply_bl);
  //   if (r < 0) goto fail_registered;

  //   // notify
  //   dispatch_queue->queue_accept(this);
  //   async_msgr->ms_deliver_handle_fast_accept(this);
  //   once_ready = true;

  //   if (r == 0) {
  //     state = next_state;
  //     ldout(async_msgr->cct, 2)
  //         << __func__ << " accept write reply msg done" << dendl;
  //   } else {
  //     state = STATE_WAIT_SEND;
  //     state_after_send = next_state;
  //   }

  //   return 0;

  // fail_registered:
  //   ldout(async_msgr->cct, 10)
  //       << __func__ << " accept fault after register" << dendl;
  //   inject_delay();

  // fail:
  //   ldout(async_msgr->cct, 10) << __func__ << " failed to accept." << dendl;
  //   return -1;
  // }

  ldout(messenger->cct, 20) << __func__ << " END" << dendl;
}

void ServerProtocolV1::send_connect_message_reply(char tag) {
  ldout(messenger->cct, 20) << __func__ << " BEGIN" << dendl;
  bufferlist reply_bl;
  reply.tag = tag;
  reply.features = ((uint64_t)connection->connect_msg.features &
                    connection->policy.features_supported) |
                   connection->policy.features_required;
  reply.authorizer_len = authorizer_reply.length();
  reply_bl.append((char *)&reply, sizeof(reply));

  if (reply.authorizer_len) {
    reply_bl.append(authorizer_reply.c_str(), authorizer_reply.length());
  }

  connection->write(
      reply_bl, std::bind(&ServerProtocolV1::handle_connect_message_reply_write,
                          this, std::placeholders::_1));

  ldout(messenger->cct, 20) << __func__ << " END" << dendl;
}

void ServerProtocolV1::handle_connect_message_reply_write(int r) {
  ldout(messenger->cct, 20) << __func__ << " BEGIN" << dendl;
  if (r < 0) {
    connection->inject_delay();
    handle_failure(r);
    ldout(messenger->cct, 20) << __func__ << " END" << dendl;
    return;
  }

  ldout(messenger->cct, 20) << __func__ << " END" << dendl;
  wait_connect_message();
}

void ServerProtocolV1::open() {
  ldout(messenger->cct, 20) << __func__ << " BEGIN" << dendl;

  connection->connect_seq = connection->connect_msg.connect_seq + 1;
  connection->peer_global_seq = connection->connect_msg.global_seq;
  ldout(messenger->cct, 10) << __func__ << " accept success, connect_seq = "
                             << connection->connect_seq << " in_seq=" << connection->in_seq << ", sending READY" << dendl;

  int next_state;

  // if it is a hard reset from peer, we don't need a round-trip to negotiate in/out sequence
  if ((connection->connect_msg.features & CEPH_FEATURE_RECONNECT_SEQ) && !connection->is_reset_from_peer) {
    reply.tag = CEPH_MSGR_TAG_SEQ;
    next_state = STATE_ACCEPTING_WAIT_SEQ;
  } else {
    reply.tag = CEPH_MSGR_TAG_READY;
    next_state = STATE_ACCEPTING_READY;
    connection->discard_requeued_up_to(0);
    connection->is_reset_from_peer = false;
    connection->in_seq = 0;
  }

  // send READY reply
  reply.features = connection->policy.features_supported;
  reply.global_seq = messenger->get_global_seq();
  reply.connect_seq = connection->connect_seq;
  reply.flags = 0;
  reply.authorizer_len = authorizer_reply.length();
  if (connection->policy.lossy)
    reply.flags = reply.flags | CEPH_MSG_CONNECT_LOSSY;

  // set_features((uint64_t)reply.features & (uint64_t)connect.features);
  // ldout(async_msgr->cct, 10) << __func__ << " accept features " << get_features() << dendl;

  // session_security.reset(
  //     get_auth_session_handler(async_msgr->cct, connect.authorizer_protocol,
  //                              session_key, get_features()));

  // reply_bl.append((char*)&reply, sizeof(reply));

  // if (reply.authorizer_len)
  //   reply_bl.append(authorizer_reply.c_str(), authorizer_reply.length());

  // if (reply.tag == CEPH_MSGR_TAG_SEQ) {
  //   uint64_t s = in_seq;
  //   reply_bl.append((char*)&s, sizeof(s));
  // }

  // lock.unlock();
  // // Because "replacing" will prevent other connections preempt this addr,
  // // it's safe that here we don't acquire Connection's lock
  // r = async_msgr->accept_conn(this);

  // inject_delay();

  // lock.lock();
  // replacing = false;
  // if (r < 0) {
  //   ldout(async_msgr->cct, 1) << __func__ << " existing race replacing process for addr=" << peer_addr
  //                             << " just fail later one(this)" << dendl;
  //   goto fail_registered;
  // }
  // if (state != STATE_ACCEPTING_WAIT_CONNECT_MSG_AUTH) {
  //   ldout(async_msgr->cct, 1) << __func__ << " state changed while accept_conn, it must be mark_down" << dendl;
  //   assert(state == STATE_CLOSED || state == STATE_NONE);
  //   goto fail_registered;
  // }

  // r = try_send(reply_bl);
  // if (r < 0)
  //   goto fail_registered;

  // // notify
  // dispatch_queue->queue_accept(this);
  // async_msgr->ms_deliver_handle_fast_accept(this);
  // once_ready = true;

  // if (r == 0) {
  //   state = next_state;
  //   ldout(async_msgr->cct, 2) << __func__ << " accept write reply msg done" << dendl;
  // } else {
  //   state = STATE_WAIT_SEND;
  //   state_after_send = next_state;
  // }

  ldout(messenger->cct, 20) << __func__ << " END" << dendl;
}