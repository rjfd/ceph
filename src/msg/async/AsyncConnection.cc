// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab
/*
 * Ceph - scalable distributed file system
 *
 * Copyright (C) 2014 UnitedStack <haomai@unitedstack.com>
 *
 * Author: Haomai Wang <haomaiwang@gmail.com>
 *
 * This is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License version 2.1, as published by the Free Software
 * Foundation.  See file COPYING.
 *
 */

#include <unistd.h>

#include "include/Context.h"
#include "include/random.h"
#include "common/errno.h"
#include "AsyncMessenger.h"
#include "AsyncConnection.h"

#include "Protocol.h"

#include "messages/MOSDOp.h"
#include "messages/MOSDOpReply.h"
#include "common/EventTrace.h"

// Constant to limit starting sequence number to 2^31.  Nothing special about it, just a big number.  PLR
#define SEQ_MASK  0x7fffffff

#define dout_subsys ceph_subsys_ms
#undef dout_prefix
#define dout_prefix _conn_prefix(_dout)
ostream& AsyncConnection::_conn_prefix(std::ostream *_dout) {
  return *_dout << "-- " << async_msgr->get_myaddr() << " >> " << peer_addr << " conn(" << this
                << " :" << port
                << " s=" << get_state_name(state)
                << " l=" << policy.lossy
                << ").";
}

// Notes:
// 1. Don't dispatch any event when closed! It may cause AsyncConnection alive even if AsyncMessenger dead

const uint32_t AsyncConnection::TCP_PREFETCH_MIN_SIZE = 512;
const int ASYNC_COALESCE_THRESHOLD = 256;

class C_time_wakeup : public EventCallback {
  AsyncConnectionRef conn;

 public:
  explicit C_time_wakeup(AsyncConnectionRef c): conn(c) {}
  void do_request(uint64_t fd_or_id) override {
    conn->wakeup_from(fd_or_id);
  }
};

class C_handle_read : public EventCallback {
  AsyncConnectionRef conn;

 public:
  explicit C_handle_read(AsyncConnectionRef c): conn(c) {}
  void do_request(uint64_t fd_or_id) override {
    conn->continue_read();
  }
};

class C_handle_write : public EventCallback {
  AsyncConnectionRef conn;

 public:
  explicit C_handle_write(AsyncConnectionRef c): conn(c) {}
  void do_request(uint64_t fd) override {
    conn->handle_write();
  }
};

class C_handle_write_callback : public EventCallback {
  AsyncConnectionRef conn;

public:
  explicit C_handle_write_callback(AsyncConnectionRef c) : conn(c) {}
  void do_request(uint64_t fd) override { conn->handle_write_callback(); }
};

class C_clean_handler : public EventCallback {
  AsyncConnectionRef conn;
 public:
  explicit C_clean_handler(AsyncConnectionRef c): conn(c) {}
  void do_request(uint64_t id) override {
    conn->cleanup();
    delete this;
  }
};

class C_tick_wakeup : public EventCallback {
  AsyncConnectionRef conn;

 public:
  explicit C_tick_wakeup(AsyncConnectionRef c): conn(c) {}
  void do_request(uint64_t fd_or_id) override {
    conn->tick(fd_or_id);
  }
};

class C_handle_connection : public EventCallback {
  AsyncConnectionRef conn;
  public:
  explicit C_handle_connection(AsyncConnectionRef c): conn(c) {}
  void do_request(uint64_t fd_or_id) override {
    conn->process();
  }
};

AsyncConnection::AsyncConnection(CephContext *cct, AsyncMessenger *m, DispatchQueue *q,
                                 Worker *w)
  : Connection(cct, m), delay_state(NULL), async_msgr(m), conn_id(q->get_id()),
    logger(w->get_perf_counter()),
    state(STATE_NONE), port(-1),
    dispatch_queue(q), recv_buf(NULL),
    recv_max_prefetch(std::max<int64_t>(msgr->cct->_conf->ms_tcp_prefetch_max_size, TCP_PREFETCH_MIN_SIZE)),
    recv_start(0), recv_end(0),
    last_active(ceph::coarse_mono_clock::now()),
    inactive_timeout_us(cct->_conf->ms_tcp_read_timeout*1000*1000),
    msg_left(0), cur_msg_size(0), state_offset(0),
    worker(w), center(&w->center), read_buffer(nullptr)
{
  read_handler = new C_handle_read(this);
  write_handler = new C_handle_write(this);
  write_callback_handler = new C_handle_write_callback(this);
  wakeup_handler = new C_time_wakeup(this);
  tick_handler = new C_tick_wakeup(this);
  connection_handler = new C_handle_connection(this);
  // double recv_max_prefetch see "read_until"
  recv_buf = new char[2*recv_max_prefetch];
  logger->inc(l_msgr_created_connections);
}

AsyncConnection::~AsyncConnection()
{
  if (recv_buf)
    delete[] recv_buf;
  assert(!delay_state);
}

void AsyncConnection::maybe_start_delay_thread()
{
  if (!delay_state) {
    async_msgr->cct->_conf->with_val<std::string>(
      "ms_inject_delay_type",
      [this](const string& s) {
	if (s.find(ceph_entity_type_name(peer_type)) != string::npos) {
	  ldout(msgr->cct, 1) << __func__ << " setting up a delay queue"
			      << dendl;
	  delay_state = new DelayedDelivery(async_msgr, center, dispatch_queue,
					    conn_id);
	}
      });
  }
}

/* return -1 means `fd` occurs error or closed, it should be closed
 * return 0 means EAGAIN or EINTR */
ssize_t AsyncConnection::read_bulk(char *buf, unsigned len)
{
  ssize_t nread;
 again:
  nread = cs.read(buf, len);
  if (nread < 0) {
    if (nread == -EAGAIN) {
      nread = 0;
    } else if (nread == -EINTR) {
      goto again;
    } else {
      ldout(async_msgr->cct, 1) << __func__ << " reading from fd=" << cs.fd()
                          << " : "<< strerror(nread) << dendl;
      return -1;
    }
  } else if (nread == 0) {
    ldout(async_msgr->cct, 1) << __func__ << " peer close file descriptor "
                              << cs.fd() << dendl;
    return -1;
  }
  return nread;
}

void AsyncConnection::write(bufferlist &bl,
                            std::function<void(ssize_t)> callback, bool more) {
    std::unique_lock<std::mutex> l(write_lock);
    writeCallback = callback;
    outcoming_bl.claim_append(bl);
    ssize_t r = _try_send(more);
    if (r <= 0) {
      // either finish writting, or returned an error
      writeCallback.reset();
      l.unlock();
      last_active = ceph::coarse_mono_clock::now();
      callback(r);
      return;
    }
}

// return the remaining bytes, it may larger than the length of ptr
// else return < 0 means error
ssize_t AsyncConnection::_try_send(bool more)
{
  if (async_msgr->cct->_conf->ms_inject_socket_failures && cs) {
    if (rand() % async_msgr->cct->_conf->ms_inject_socket_failures == 0) {
      ldout(async_msgr->cct, 0) << __func__ << " injecting socket failure" << dendl;
      cs.shutdown();
    }
  }

  assert(center->in_thread());
  ssize_t r = cs.send(outcoming_bl, more);
  if (r < 0) {
    ldout(async_msgr->cct, 1) << __func__ << " send error: " << cpp_strerror(r) << dendl;
    return r;
  }

  ldout(async_msgr->cct, 10) << __func__ << " sent bytes " << r
                             << " remaining bytes " << outcoming_bl.length() << dendl;

  if (!open_write && is_queued()) {
    center->create_file_event(cs.fd(), EVENT_WRITABLE, write_handler);
    open_write = true;
  }

  if (open_write && !is_queued()) {
    center->delete_file_event(cs.fd(), EVENT_WRITABLE);
    open_write = false;
    if (writeCallback) {
      center->dispatch_event_external(write_callback_handler);
    }
  }

  return outcoming_bl.length();
}


void AsyncConnection::read(unsigned len, char *buffer,
                           std::function<void(char *, ssize_t)> callback) {
  readCallback = callback;
  pendingReadLen = len;
  read_buffer = buffer;
  ssize_t r = read_until(len, buffer);
  if (r <= 0) {
    // read all bytes, or an error occured
    pendingReadLen.reset();
    read_buffer = nullptr;
    last_active = ceph::coarse_mono_clock::now();
    callback(buffer, r);
  }
}

void AsyncConnection::continue_read() {
  std::lock_guard<std::mutex> l(lock);
  if (pendingReadLen) {
    read(*pendingReadLen, read_buffer, readCallback);
  }
}

// Because this func will be called multi times to populate
// the needed buffer, so the passed in bufferptr must be the same.
// Normally, only "read_message" will pass existing bufferptr in
//
// And it will uses readahead method to reduce small read overhead,
// "recv_buf" is used to store read buffer
//
// return the remaining bytes, 0 means this buffer is finished
// else return < 0 means error
ssize_t AsyncConnection::read_until(unsigned len, char *p)
{
  ldout(async_msgr->cct, 25) << __func__ << " len is " << len << " state_offset is "
                             << state_offset << dendl;

  if (async_msgr->cct->_conf->ms_inject_socket_failures && cs) {
    if (rand() % async_msgr->cct->_conf->ms_inject_socket_failures == 0) {
      ldout(async_msgr->cct, 0) << __func__ << " injecting socket failure" << dendl;
      cs.shutdown();
    }
  }

  ssize_t r = 0;
  uint64_t left = len - state_offset;
  if (recv_end > recv_start) {
    uint64_t to_read = std::min<uint64_t>(recv_end - recv_start, left);
    memcpy(p, recv_buf+recv_start, to_read);
    recv_start += to_read;
    left -= to_read;
    ldout(async_msgr->cct, 25) << __func__ << " got " << to_read << " in buffer "
                               << " left is " << left << " buffer still has "
                               << recv_end - recv_start << dendl;
    if (left == 0) {
      return 0;
    }
    state_offset += to_read;
  }

  recv_end = recv_start = 0;
  /* nothing left in the prefetch buffer */
  if (len > recv_max_prefetch) {
    /* this was a large read, we don't prefetch for these */
    do {
      r = read_bulk(p+state_offset, left);
      ldout(async_msgr->cct, 25) << __func__ << " read_bulk left is " << left << " got " << r << dendl;
      if (r < 0) {
        ldout(async_msgr->cct, 1) << __func__ << " read failed" << dendl;
        return -1;
      } else if (r == static_cast<int>(left)) {
        state_offset = 0;
        return 0;
      }
      state_offset += r;
      left -= r;
    } while (r > 0);
  } else {
    do {
      r = read_bulk(recv_buf+recv_end, recv_max_prefetch);
      ldout(async_msgr->cct, 25) << __func__ << " read_bulk recv_end is " << recv_end
                                 << " left is " << left << " got " << r << dendl;
      if (r < 0) {
        ldout(async_msgr->cct, 1) << __func__ << " read failed" << dendl;
        return -1;
      }
      recv_end += r;
      if (r >= static_cast<int>(left)) {
        recv_start = len - state_offset;
        memcpy(p+state_offset, recv_buf, recv_start);
        state_offset = 0;
        return 0;
      }
      left -= r;
    } while (r > 0);
    memcpy(p+state_offset, recv_buf, recv_end-recv_start);
    state_offset += (recv_end - recv_start);
    recv_end = recv_start = 0;
  }
  ldout(async_msgr->cct, 25) << __func__ << " need len " << len << " remaining "
                             << len - state_offset << " bytes" << dendl;
  return len - state_offset;
}

void AsyncConnection::inject_delay() {
  if (async_msgr->cct->_conf->ms_inject_internal_delays) {
    ldout(async_msgr->cct, 10) << __func__ << " sleep for " <<
      async_msgr->cct->_conf->ms_inject_internal_delays << dendl;
    utime_t t;
    t.set_from_double(async_msgr->cct->_conf->ms_inject_internal_delays);
    t.sleep();
  }
}

void AsyncConnection::process() {
  std::lock_guard<std::mutex> l(lock);
  last_active = ceph::coarse_mono_clock::now();

  switch (state) {
    case STATE_STANDBY:
      ldout(async_msgr->cct, 20) << __func__ << " enter STANDBY" << dendl;
      break;

    case STATE_NONE:
      ldout(async_msgr->cct, 20) << __func__ << " enter none state" << dendl;
      break;

    case STATE_CONNECTING: {
      if (policy.server) {
        ldout(async_msgr->cct, 1) << "BIG ERROR!" << dendl;
      }
      assert(!policy.server);

      if (cs) {
        center->delete_file_event(cs.fd(), EVENT_READABLE | EVENT_WRITABLE);
        cs.close();
      }

      SocketOptions opts;
      opts.priority = async_msgr->get_socket_priority();
      opts.connect_bind_addr = msgr->get_myaddr();
      ssize_t r = worker->connect(get_peer_addr(), opts, &cs);
      if (r < 0) {
        protocol->fault();
        return;
      }

      center->create_file_event(cs.fd(), EVENT_READABLE, read_handler);

      r = cs.is_connected();
      if (r < 0) {
        ldout(async_msgr->cct, 1) << __func__ << " reconnect failed " << dendl;
        if (r == -ECONNREFUSED) {
          ldout(async_msgr->cct, 2)
              << __func__ << " connection refused!" << dendl;
          dispatch_queue->queue_refused(this);
        }
        protocol->fault();
        return;
      } else if (r == 0) {
        ldout(async_msgr->cct, 10)
            << __func__ << " nonblock connect inprogress" << dendl;
        if (async_msgr->get_stack()->nonblock_connect_need_writable_event())
          center->create_file_event(cs.fd(), EVENT_WRITABLE,
                                    connection_handler);
        break;
      }

      center->delete_file_event(cs.fd(), EVENT_WRITABLE);
      ldout(async_msgr->cct, 10)
          << __func__ << " connect successfully, ready to send banner" << dendl;

      protocol->notify();
      break;
    }

    case STATE_ACCEPTING: {
      bufferlist bl;
      center->create_file_event(cs.fd(), EVENT_READABLE, read_handler);
      protocol->notify();
      break;
    }

    default:
      protocol->notify();
  }
}

bool AsyncConnection::is_connected() {
  return protocol->is_connected();
}

void AsyncConnection::_connect()
{
  ldout(async_msgr->cct, 10) << __func__ << dendl;

  state = STATE_CONNECTING;
  if (!protocol) {
    protocol = std::unique_ptr<Protocol>(new ClientProtocolV1(this));
  }
  // rescheduler connection in order to avoid lock dep
  // may called by external thread(send_message)
  center->dispatch_event_external(connection_handler);
}

void AsyncConnection::accept(ConnectedSocket socket, entity_addr_t &addr)
{
  ldout(async_msgr->cct, 10) << __func__ << " sd=" << socket.fd() << dendl;
  assert(socket.fd() >= 0);

  std::lock_guard<std::mutex> l(lock);
  cs = std::move(socket);
  socket_addr = addr;
  state = STATE_ACCEPTING;
  protocol = std::unique_ptr<Protocol>(new ServerProtocolV1(this));
  // rescheduler connection in order to avoid lock dep
  center->dispatch_event_external(connection_handler);
}

int AsyncConnection::send_message(Message *m)
{
  FUNCTRACE(async_msgr->cct);
  lgeneric_subdout(async_msgr->cct, ms,
		   1) << "-- " << async_msgr->get_myaddr() << " --> "
		      << get_peer_addr() << " -- "
		      << *m << " -- " << m << " con "
		      << m->get_connection().get()
		      << dendl;

  // optimistic think it's ok to encode(actually may broken now)
  if (!m->get_priority())
    m->set_priority(async_msgr->get_default_send_priority());

  m->get_header().src = async_msgr->get_myname();
  m->set_connection(this);

  if (m->get_type() == CEPH_MSG_OSD_OP)
    OID_EVENT_TRACE_WITH_MSG(m, "SEND_MSG_OSD_OP_BEGIN", true);
  else if (m->get_type() == CEPH_MSG_OSD_OPREPLY)
    OID_EVENT_TRACE_WITH_MSG(m, "SEND_MSG_OSD_OPREPLY_BEGIN", true);

  if (async_msgr->get_myaddr() == get_peer_addr()) { //loopback connection
    ldout(async_msgr->cct, 20) << __func__ << " " << *m << " local" << dendl;
    std::lock_guard<std::mutex> l(write_lock);
    if (protocol->writes_allowed()) {
      dispatch_queue->local_delivery(m, m->get_priority());
    } else {
      ldout(async_msgr->cct, 10) << __func__ << " loopback connection closed."
                                 << " Drop message " << m << dendl;
      m->put();
    }
    return 0;
  }

  last_active = ceph::coarse_mono_clock::now();
  // we don't want to consider local message here, it's too lightweight which
  // may disturb users
  logger->inc(l_msgr_send_messages);

  protocol->send_message(m);
  return 0;
}


void AsyncConnection::fault()
{
  //write_lock.lock();

  shutdown_socket();
  open_write = false;

  // queue delayed items immediately
  if (delay_state)
    delay_state->flush();

  recv_start = recv_end = 0;
  state_offset = 0;
  outcoming_bl.clear();
  reset_recv_state();

  // if (policy.standby && !is_queued() && state != STATE_WAIT) {
  //   ldout(async_msgr->cct, 10) << __func__ << " with nothing to send, going to standby" << dendl;
  //   state = STATE_STANDBY;
  //   write_lock.unlock();
  //   return;
  // }

  // write_lock.unlock();
  // if (!(state >= STATE_CONNECTING && state < STATE_CONNECTING_READY) &&
  //     state != STATE_WAIT) { // STATE_WAIT is coming from STATE_CONNECTING_*
  //   // policy maybe empty when state is in accept
  //   if (policy.server) {
  //     ldout(async_msgr->cct, 0) << __func__ << " server, going to standby" << dendl;
  //     state = STATE_STANDBY;
  //   } else {
  //     ldout(async_msgr->cct, 0) << __func__ << " initiating reconnect" << dendl;
  //     protocol->reconnect();
  //     state = STATE_CONNECTING;
  //   }
  //   backoff = utime_t();
  //   center->dispatch_event_external(connection_handler);
  // } else {
  //   if (state == STATE_WAIT) {
  //     backoff.set_from_double(async_msgr->cct->_conf->ms_max_backoff);
  //   } else if (backoff == utime_t()) {
  //     backoff.set_from_double(async_msgr->cct->_conf->ms_initial_backoff);
  //   } else {
  //     backoff += backoff;
  //     if (backoff > async_msgr->cct->_conf->ms_max_backoff)
  //       backoff.set_from_double(async_msgr->cct->_conf->ms_max_backoff);
  //   }

  //   state = STATE_CONNECTING;
  //   ldout(async_msgr->cct, 10) << __func__ << " waiting " << backoff << dendl;
  //   // woke up again;
  //   register_time_events.insert(center->create_time_event(
  //           backoff.to_nsec()/1000, wakeup_handler));
  // }
}

void AsyncConnection::_stop()
{
  if (state == STATE_CLOSED)
    return ;

  if (delay_state)
    delay_state->flush();

  ldout(async_msgr->cct, 2) << __func__ << dendl;
  std::lock_guard<std::mutex> l(write_lock);

  writeCallback.reset();
  reset_recv_state();
  dispatch_queue->discard_queue(conn_id);
  async_msgr->unregister_conn(this);
  worker->release_worker();

  state = STATE_CLOSED;
  if (protocol) {
    protocol->abort();
  }
  open_write = false;

  state_offset = 0;
  // Make sure in-queue events will been processed
  center->dispatch_event_external(EventCallbackRef(new C_clean_handler(this)));
}

void AsyncConnection::prepare_send_message(uint64_t features, Message *m, bufferlist &bl)
{
  ldout(async_msgr->cct, 20) << __func__ << " m" << " " << *m << dendl;

  // associate message with Connection (for benefit of encode_payload)
  if (m->empty_payload())
    ldout(async_msgr->cct, 20) << __func__ << " encoding features "
                               << features << " " << m << " " << *m << dendl;
  else
    ldout(async_msgr->cct, 20) << __func__ << " half-reencoding features "
                               << features << " " << m << " " << *m << dendl;

  // encode and copy out of *m
  m->encode(features, msgr->crcflags);

  bl.append(m->get_payload());
  bl.append(m->get_middle());
  bl.append(m->get_data());
}

bool AsyncConnection::is_queued() const {
  return protocol->has_queued_writes() || outcoming_bl.length();
}

void AsyncConnection::shutdown_socket() {
  for (auto &&t : register_time_events) center->delete_time_event(t);
  register_time_events.clear();
  if (last_tick_id) {
    center->delete_time_event(last_tick_id);
    last_tick_id = 0;
  }
  if (cs) {
    center->delete_file_event(cs.fd(), EVENT_READABLE | EVENT_WRITABLE);
    cs.shutdown();
    cs.close();
  }
}

void AsyncConnection::reset_recv_state()
{
  // clean up state internal variables and states
  if (state >= STATE_CONNECTING_SEND_CONNECT_MSG &&
      state <= STATE_CONNECTING_READY) {
    //delete authorizer;
    //authorizer = NULL;
    //got_bad_auth = false;
  }

  if (state > STATE_OPEN_MESSAGE_THROTTLE_MESSAGE &&
      state <= STATE_OPEN_MESSAGE_READ_FOOTER_AND_DISPATCH
      && policy.throttler_messages) {
    ldout(async_msgr->cct, 10) << __func__ << " releasing " << 1
                               << " message to policy throttler "
                               << policy.throttler_messages->get_current() << "/"
                               << policy.throttler_messages->get_max() << dendl;
    policy.throttler_messages->put();
  }
  if (state > STATE_OPEN_MESSAGE_THROTTLE_BYTES &&
      state <= STATE_OPEN_MESSAGE_READ_FOOTER_AND_DISPATCH) {
    if (policy.throttler_bytes) {
      ldout(async_msgr->cct, 10) << __func__ << " releasing " << cur_msg_size
                                 << " bytes to policy throttler "
                                 << policy.throttler_bytes->get_current() << "/"
                                 << policy.throttler_bytes->get_max() << dendl;
      policy.throttler_bytes->put(cur_msg_size);
    }
  }
  if (state > STATE_OPEN_MESSAGE_THROTTLE_DISPATCH_QUEUE &&
      state <= STATE_OPEN_MESSAGE_READ_FOOTER_AND_DISPATCH) {
    ldout(async_msgr->cct, 10) << __func__ << " releasing " << cur_msg_size
                               << " bytes to dispatch_queue throttler "
                               << dispatch_queue->dispatch_throttler.get_current() << "/"
                               << dispatch_queue->dispatch_throttler.get_max() << dendl;
    dispatch_queue->dispatch_throttle_release(cur_msg_size);
  }
}

void AsyncConnection::DelayedDelivery::do_request(uint64_t id)
{
  Message *m = nullptr;
  {
    std::lock_guard<std::mutex> l(delay_lock);
    register_time_events.erase(id);
    if (stop_dispatch)
      return ;
    if (delay_queue.empty())
      return ;
    m = delay_queue.front();
    delay_queue.pop_front();
  }
  if (msgr->ms_can_fast_dispatch(m)) {
    dispatch_queue->fast_dispatch(m);
  } else {
    dispatch_queue->enqueue(m, m->get_priority(), conn_id);
  }
}

void AsyncConnection::DelayedDelivery::discard() {
  stop_dispatch = true;
  center->submit_to(center->get_id(),
                    [this]() mutable {
                      std::lock_guard<std::mutex> l(delay_lock);
                      while (!delay_queue.empty()) {
                        Message *m = delay_queue.front();
                        dispatch_queue->dispatch_throttle_release(
                            m->get_dispatch_throttle_size());
                        m->put();
                        delay_queue.pop_front();
                      }
                      for (auto i : register_time_events)
                        center->delete_time_event(i);
                      register_time_events.clear();
                      stop_dispatch = false;
                    },
                    true);
}

void AsyncConnection::DelayedDelivery::flush() {
  stop_dispatch = true;
  center->submit_to(
      center->get_id(), [this] () mutable {
    std::lock_guard<std::mutex> l(delay_lock);
    while (!delay_queue.empty()) {
      Message *m = delay_queue.front();
      if (msgr->ms_can_fast_dispatch(m)) {
        dispatch_queue->fast_dispatch(m);
      } else {
        dispatch_queue->enqueue(m, m->get_priority(), conn_id);
      }
      delay_queue.pop_front();
    }
    for (auto i : register_time_events)
      center->delete_time_event(i);
    register_time_events.clear();
    stop_dispatch = false;
  }, true);
}

void AsyncConnection::send_keepalive()
{
  protocol->send_keepalive();
}

void AsyncConnection::mark_down()
{
  ldout(async_msgr->cct, 1) << __func__ << dendl;
  std::lock_guard<std::mutex> l(lock);
  _stop();
}

void AsyncConnection::_append_keepalive_or_ack(bool ack, utime_t *tp)
{
  ldout(async_msgr->cct, 10) << __func__ << dendl;
  if (ack) {
    assert(tp);
    struct ceph_timespec ts;
    tp->encode_timeval(&ts);
    outcoming_bl.append(CEPH_MSGR_TAG_KEEPALIVE2_ACK);
    outcoming_bl.append((char*)&ts, sizeof(ts));
  } else if (has_feature(CEPH_FEATURE_MSGR_KEEPALIVE2)) {
    struct ceph_timespec ts;
    utime_t t = ceph_clock_now();
    t.encode_timeval(&ts);
    outcoming_bl.append(CEPH_MSGR_TAG_KEEPALIVE2);
    outcoming_bl.append((char*)&ts, sizeof(ts));
  } else {
    outcoming_bl.append(CEPH_MSGR_TAG_KEEPALIVE);
  }
}

void AsyncConnection::handle_write()
{
  protocol->write_event();
}

void AsyncConnection::handle_write_callback() {
  std::lock_guard<std::mutex> l(lock);
  write_lock.lock();
  if (writeCallback) {
    auto callback = *writeCallback;
    write_lock.unlock();
    last_active = ceph::coarse_mono_clock::now();
    callback(0);
    return;
  }
  write_lock.unlock();
}

void AsyncConnection::stop(bool queue_reset) {
  lock.lock();
  bool need_queue_reset = (state != STATE_CLOSED) && queue_reset;
  _stop();
  lock.unlock();
  if (need_queue_reset) dispatch_queue->queue_reset(this);
}

void AsyncConnection::init_loopback_protocol() {
  protocol = std::unique_ptr<Protocol>(new LoopbackProtocolV1(this));
}

void AsyncConnection::wakeup_from(uint64_t id)
{
  lock.lock();
  register_time_events.erase(id);
  lock.unlock();
  process();
}

void AsyncConnection::tick(uint64_t id)
{
  auto now = ceph::coarse_mono_clock::now();
  ldout(async_msgr->cct, 20) << __func__ << " last_id=" << last_tick_id
                             << " last_active" << last_active << dendl;
  std::lock_guard<std::mutex> l(lock);
  last_tick_id = 0;
  auto idle_period = std::chrono::duration_cast<std::chrono::microseconds>(now - last_active).count();
  if (inactive_timeout_us < (uint64_t)idle_period) {
    ldout(async_msgr->cct, 1) << __func__ << " idle(" << idle_period << ") more than "
                              << inactive_timeout_us
                              << " us, mark self fault." << dendl;
    protocol->fault();
  } else if (is_connected()) {
    last_tick_id = center->create_time_event(inactive_timeout_us, tick_handler);
  }
}
