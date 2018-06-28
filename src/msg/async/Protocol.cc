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

ProtocolV1::ProtocolV1(AsyncConnection *connection) : Protocol(connection), _abort(false) {}

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
  bufferlist bl;
  bl.append(CEPH_BANNER, strlen(CEPH_BANNER));

  connection->write(bl, std::bind(&ClientProtocolV1::handle_banner_write, this,
                                  std::placeholders::_1));
}

void ClientProtocolV1::handle_banner_write(int r) {
  std::lock_guard<std::mutex> l(connection->lock);
  if (r < 0) {
    handle_failure(r);
    return;
  }
  ldout(messenger->cct, 10)
      << __func__
      << " connect write banner done: " << connection->get_peer_addr() << dendl;

  wait_server_banner();
}

void ClientProtocolV1::wait_server_banner() {
  bufferlist myaddrbl;
  unsigned banner_len = strlen(CEPH_BANNER);
  unsigned need_len = banner_len + sizeof(ceph_entity_addr) * 2;
  connection->read(need_len,
                   std::bind(&ClientProtocolV1::handle_server_banner, this,
                             std::placeholders::_1, std::placeholders::_2));
}

void ClientProtocolV1::handle_server_banner(char *buffer, int r) {
  std::lock_guard<std::mutex> l(connection->lock);

  if (r < 0) {
    ldout(messenger->cct, 1)
        << __func__ << " read banner and identify addresses failed" << dendl;
    handle_failure(r);
    return;
  }

  unsigned banner_len = strlen(CEPH_BANNER);
  if (memcmp(buffer, CEPH_BANNER, banner_len)) {
    ldout(messenger->cct, 0)
        << __func__ << " connect protocol error (bad banner) on peer "
        << connection->get_peer_addr() << dendl;
    handle_failure();
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
    return;
  }

  bufferlist myaddrbl;
  encode(messenger->get_myaddr(), myaddrbl, 0);  // legacy
  connection->write(myaddrbl, std::bind(&ClientProtocolV1::handle_my_addr_write,
                                        this, std::placeholders::_1));
}

void ClientProtocolV1::handle_my_addr_write(int r) {
  std::lock_guard<std::mutex> l(connection->lock);
  if (r < 0) {
    ldout(messenger->cct, 2) << __func__ << " connect couldn't write my addr, "
                             << cpp_strerror(r) << dendl;
    handle_failure(r);
  }
  ldout(messenger->cct, 10) << __func__ << " connect sent my addr "
                            << messenger->get_myaddr() << dendl;

  send_connect_message();
}

void ClientProtocolV1::send_connect_message() {
}

/**
 * Server Protocol V1
 **/
ServerProtocolV1::ServerProtocolV1(AsyncConnection *connection)
    : ProtocolV1(connection) {}

void ServerProtocolV1::init() { accept(); }

void ServerProtocolV1::accept() {
  bufferlist bl;

  bl.append(CEPH_BANNER, strlen(CEPH_BANNER));

  encode(messenger->get_myaddr(), bl, 0);  // legacy
  connection->port = messenger->get_myaddr().get_port();
  encode(connection->socket_addr, bl, 0);  // legacy

  ldout(messenger->cct, 1) << __func__ << " sd=" << connection->cs.fd() << " "
                           << connection->socket_addr << dendl;

  connection->write(bl, std::bind(&ServerProtocolV1::handle_banner_write, this,
                                  std::placeholders::_1));
}

void ServerProtocolV1::handle_banner_write(int r) {
  std::lock_guard<std::mutex> l(connection->lock);
  if (r < 0) {
    handle_failure(r);
    return;
  }
  ldout(messenger->cct, 10) << __func__ << " write banner and addr done: "
                            << connection->get_peer_addr() << dendl;
  wait_client_banner();
}

void ServerProtocolV1::wait_client_banner() {
  connection->read(strlen(CEPH_BANNER) + sizeof(ceph_entity_addr),
                   std::bind(&ServerProtocolV1::handle_client_banner, this,
                             std::placeholders::_1, std::placeholders::_2));
}

void ServerProtocolV1::handle_client_banner(char *buffer, int r) {
  std::lock_guard<std::mutex> l(connection->lock);
  if (r < 0) {
    ldout(messenger->cct, 1)
        << __func__ << " read peer banner and addr failed" << dendl;
    handle_failure(r);
    return;
  }

  if (memcmp(buffer, CEPH_BANNER, strlen(CEPH_BANNER))) {
    ldout(messenger->cct, 1)
        << __func__ << " accept peer sent bad banner '" << buffer
        << "' (should be '" << CEPH_BANNER << "')" << dendl;
    connection->fault();
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

  wait_connect_message();
}

void ServerProtocolV1::wait_connect_message() {
  // r = read_until(sizeof(connect_msg), state_buffer);
  // if (r < 0) {
  //   ldout(async_msgr->cct, 1)
  //       << __func__ << " read connect msg failed" << dendl;
  //   goto fail;
  // } else if (r > 0) {
  //   break;
  // }

  // connect_msg = *((ceph_msg_connect *)state_buffer);
  // state = STATE_ACCEPTING_WAIT_CONNECT_MSG_AUTH;
}