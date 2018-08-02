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

#ifndef CEPH_MSG_ASYNCCONNECTION_H
#define CEPH_MSG_ASYNCCONNECTION_H

#include <atomic>
#include <pthread.h>
#include <climits>
#include <list>
#include <mutex>
#include <map>
#include <functional>
#include <optional>

#include "auth/AuthSessionHandler.h"
#include "common/ceph_time.h"
#include "common/perf_counters.h"
#include "include/buffer.h"
#include "msg/Connection.h"
#include "msg/Messenger.h"

#include "Event.h"
#include "Stack.h"

class AsyncMessenger;
class DispatchQueue;
class Worker;
class Protocol;

static const int ASYNC_IOV_MAX = (IOV_MAX >= 1024 ? IOV_MAX / 4 : IOV_MAX);

/*
 * AsyncConnection maintains a logic session between two endpoints. In other
 * word, a pair of addresses can find the only AsyncConnection. AsyncConnection
 * will handle with network fault or read/write transactions. If one file
 * descriptor broken, AsyncConnection will maintain the message queue and
 * sequence, try to reconnect peer endpoint.
 */
class AsyncConnection : public Connection {

  ssize_t read_bulk(char *buf, unsigned len);
  ssize_t do_sendmsg(struct msghdr &msg, unsigned len, bool more);
  ssize_t try_send(bufferlist &bl, bool more=false) {
    std::lock_guard<std::mutex> l(write_lock);
    outcoming_bl.claim_append(bl);
    return _try_send(more);
  }
  void write(bufferlist &bl, std::function<void(ssize_t)> callback,
             bool more=false);
  ssize_t _try_send(bool more=false);
  ssize_t _send(Message *m);
  void prepare_send_message(uint64_t features, Message *m, bufferlist &bl);
  void read(unsigned len, char *buffer,
            std::function<void(char *, ssize_t)> callback);
  ssize_t read_until(unsigned needed, char *p);
  void _connect();
  void _stop();
  void fault();
  void _append_keepalive_or_ack(bool ack=false, utime_t *t=NULL);
  void inject_delay();

  bool is_queued() const;
  void shutdown_socket();

  void reset_recv_state();

   /**
   * The DelayedDelivery is for injecting delays into Message delivery off
   * the socket. It is only enabled if delays are requested, and if they
   * are then it pulls Messages off the DelayQueue and puts them into the
   * AsyncMessenger event queue.
   */
  class DelayedDelivery : public EventCallback {
    std::set<uint64_t> register_time_events; // need to delete it if stop
    std::deque<Message*> delay_queue;
    std::mutex delay_lock;
    AsyncMessenger *msgr;
    EventCenter *center;
    DispatchQueue *dispatch_queue;
    uint64_t conn_id;
    std::atomic_bool stop_dispatch;

   public:
    explicit DelayedDelivery(AsyncMessenger *omsgr, EventCenter *c,
                             DispatchQueue *q, uint64_t cid)
      : msgr(omsgr), center(c), dispatch_queue(q), conn_id(cid),
        stop_dispatch(false) { }
    ~DelayedDelivery() override {
      assert(register_time_events.empty());
      assert(delay_queue.empty());
    }
    void set_center(EventCenter *c) { center = c; }
    void do_request(uint64_t id) override;
    void queue(double delay_period, Message *m) {
      std::lock_guard<std::mutex> l(delay_lock);
      delay_queue.push_back(m);
      register_time_events.insert(center->create_time_event(delay_period*1000000, this));
    }
    void discard();
    bool ready() const { return !stop_dispatch && delay_queue.empty() && register_time_events.empty(); }
    void flush();
  } *delay_state;

 public:
  AsyncConnection(CephContext *cct, AsyncMessenger *m, DispatchQueue *q, Worker *w);
  ~AsyncConnection() override;
  void maybe_start_delay_thread();

  ostream& _conn_prefix(std::ostream *_dout);

  bool is_connected() override;

  // Only call when AsyncConnection first construct
  void connect(const entity_addr_t& addr, int type) {
    set_peer_type(type);
    set_peer_addr(addr);
    policy = msgr->get_policy(type);
    _connect();
  }
  // Only call when AsyncConnection first construct
  void accept(ConnectedSocket socket, entity_addr_t &addr);
  int send_message(Message *m) override;

  void send_keepalive() override;
  void mark_down() override;
  void mark_disposable() override {
    std::lock_guard<std::mutex> l(lock);
    policy.lossy = true;
  }

 private:
  enum {
    STATE_NONE,
    STATE_OPEN,
    STATE_OPEN_KEEPALIVE2,
    STATE_OPEN_KEEPALIVE2_ACK,
    STATE_OPEN_TAG_ACK,
    STATE_OPEN_MESSAGE_HEADER,
    STATE_OPEN_MESSAGE_THROTTLE_MESSAGE,
    STATE_OPEN_MESSAGE_THROTTLE_BYTES,
    STATE_OPEN_MESSAGE_THROTTLE_DISPATCH_QUEUE,
    STATE_OPEN_MESSAGE_READ_FRONT,
    STATE_OPEN_MESSAGE_READ_MIDDLE,
    STATE_OPEN_MESSAGE_READ_DATA_PREPARE,
    STATE_OPEN_MESSAGE_READ_DATA,
    STATE_OPEN_MESSAGE_READ_FOOTER_AND_DISPATCH,
    STATE_OPEN_TAG_CLOSE,
    STATE_WAIT_SEND,
    STATE_CONNECTING,
    STATE_CONNECTING_RE,
    STATE_CONNECTING_WAIT_BANNER_AND_IDENTIFY,
    STATE_CONNECTING_SEND_CONNECT_MSG,
    STATE_CONNECTING_WAIT_CONNECT_REPLY,
    STATE_CONNECTING_WAIT_CONNECT_REPLY_AUTH,
    STATE_CONNECTING_WAIT_ACK_SEQ,
    STATE_CONNECTING_READY,
    STATE_ACCEPTING,
    STATE_ACCEPTING_WAIT_BANNER_ADDR,
    STATE_ACCEPTING_WAIT_CONNECT_MSG,
    STATE_ACCEPTING_WAIT_CONNECT_MSG_AUTH,
    STATE_ACCEPTING_WAIT_SEQ,
    STATE_ACCEPTING_READY,
    STATE_STANDBY,
    STATE_CLOSED,
    STATE_WAIT,       // just wait for racing connection
  };

  static const uint32_t TCP_PREFETCH_MIN_SIZE;
  static const char *get_state_name(int state) {
      const char* const statenames[] = {"STATE_NONE",
                                        "STATE_OPEN",
                                        "STATE_OPEN_KEEPALIVE2",
                                        "STATE_OPEN_KEEPALIVE2_ACK",
                                        "STATE_OPEN_TAG_ACK",
                                        "STATE_OPEN_MESSAGE_HEADER",
                                        "STATE_OPEN_MESSAGE_THROTTLE_MESSAGE",
                                        "STATE_OPEN_MESSAGE_THROTTLE_BYTES",
                                        "STATE_OPEN_MESSAGE_THROTTLE_DISPATCH_QUEUE",
                                        "STATE_OPEN_MESSAGE_READ_FRONT",
                                        "STATE_OPEN_MESSAGE_READ_MIDDLE",
                                        "STATE_OPEN_MESSAGE_READ_DATA_PREPARE",
                                        "STATE_OPEN_MESSAGE_READ_DATA",
                                        "STATE_OPEN_MESSAGE_READ_FOOTER_AND_DISPATCH",
                                        "STATE_OPEN_TAG_CLOSE",
                                        "STATE_WAIT_SEND",
                                        "STATE_CONNECTING",
                                        "STATE_CONNECTING_RE",
                                        "STATE_CONNECTING_WAIT_BANNER_AND_IDENTIFY",
                                        "STATE_CONNECTING_SEND_CONNECT_MSG",
                                        "STATE_CONNECTING_WAIT_CONNECT_REPLY",
                                        "STATE_CONNECTING_WAIT_CONNECT_REPLY_AUTH",
                                        "STATE_CONNECTING_WAIT_ACK_SEQ",
                                        "STATE_CONNECTING_READY",
                                        "STATE_ACCEPTING",
                                        "STATE_ACCEPTING_WAIT_BANNER_ADDR",
                                        "STATE_ACCEPTING_WAIT_CONNECT_MSG",
                                        "STATE_ACCEPTING_WAIT_CONNECT_MSG_AUTH",
                                        "STATE_ACCEPTING_WAIT_SEQ",
                                        "STATE_ACCEPTING_READY",
                                        "STATE_STANDBY",
                                        "STATE_CLOSED",
                                        "STATE_WAIT"};
      return statenames[state];
  }

  AsyncMessenger *async_msgr;
  uint64_t conn_id;
  PerfCounters *logger;
  int state;
  ConnectedSocket cs;
  int port;
  Messenger::Policy policy;

  DispatchQueue *dispatch_queue;

  // lockfree, only used in own thread
  bufferlist outcoming_bl;
  bool open_write = false;

  std::mutex write_lock;

  std::mutex lock;
  utime_t backoff;         // backoff time
  EventCallbackRef read_handler;
  EventCallbackRef write_handler;
  EventCallbackRef write_callback_handler;
  EventCallbackRef wakeup_handler;
  EventCallbackRef tick_handler;
  EventCallbackRef connection_handler;
  char *recv_buf;
  uint32_t recv_max_prefetch;
  uint32_t recv_start;
  uint32_t recv_end;
  set<uint64_t> register_time_events; // need to delete it if stop
  ceph::coarse_mono_clock::time_point last_active;
  uint64_t last_tick_id = 0;
  const uint64_t inactive_timeout_us;

  // Tis section are temp variables used by state transition

  // Open state
  utime_t recv_stamp;
  utime_t throttle_stamp;
  unsigned msg_left;
  uint64_t cur_msg_size;
  ceph_msg_header current_header;
  // Accepting state
  entity_addr_t socket_addr;
  CryptoKey session_key;

  // used only by "read_until"
  uint64_t state_offset;
  Worker *worker;
  EventCenter *center;
  ceph::shared_ptr<AuthSessionHandler> session_security;

  std::unique_ptr<Protocol> protocol;

  std::optional<std::function<void(ssize_t)>> writeCallback;
  std::function<void(char *, ssize_t)> readCallback;
  std::optional<unsigned> pendingReadLen;
  char *read_buffer;

 public:
  // used by eventcallback
  void handle_write();
  void handle_write_callback();
  void continue_read();
  void process();
  void wakeup_from(uint64_t id);
  void tick(uint64_t id);
  void local_deliver();
  void stop(bool queue_reset);
  void cleanup() {
    shutdown_socket();
    delete read_handler;
    delete write_handler;
    delete write_callback_handler;
    delete wakeup_handler;
    delete tick_handler;
    delete connection_handler;
    if (delay_state) {
      delete delay_state;
      delay_state = NULL;
    }
  }
  void init_loopback_protocol();
  PerfCounters *get_perf_counter() {
    return logger;
  }

  friend class Protocol;
  friend class ProtocolV1;
  friend class ClientProtocolV1;
  friend class ServerProtocolV1;
}; /* AsyncConnection */

typedef boost::intrusive_ptr<AsyncConnection> AsyncConnectionRef;

#endif
