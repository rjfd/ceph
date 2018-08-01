#include "Protocol.h"

#include "AsyncMessenger.h"
#include "include/random.h"
#include "common/EventTrace.h"

#define dout_subsys ceph_subsys_ms
#undef dout_prefix
#define dout_prefix _conn_prefix(_dout)
ostream &ProtocolV1::_conn_prefix(std::ostream *_dout) {
  return *_dout << "-- " << messenger->get_myaddr() << " >> "
                << connection->peer_addr << " conn(" << this << " :"
                << connection->port << " s=" << state
                << " pgs=" << peer_global_seq << " cs=" << connect_seq
                << " l=" << connection->policy.lossy << ").";
}

#define WRITE(B, F) \
  connection->write(B, std::bind(F, this, std::placeholders::_1))

#define READ(L, F)  \
  connection->read( \
      L, std::bind(F, this, std::placeholders::_1, std::placeholders::_2))

// Constant to limit starting sequence number to 2^31.  Nothing special about
// it, just a big number.  PLR
#define SEQ_MASK 0x7fffffff

const int ASYNC_COALESCE_THRESHOLD = 256;

static void alloc_aligned_buffer(bufferlist &data, unsigned len, unsigned off) {
  // create a buffer to read into that matches the data alignment
  unsigned alloc_len = 0;
  unsigned left = len;
  unsigned head = 0;
  if (off & ~CEPH_PAGE_MASK) {
    // head
    alloc_len += CEPH_PAGE_SIZE;
    head = std::min<uint64_t>(CEPH_PAGE_SIZE - (off & ~CEPH_PAGE_MASK), left);
    left -= head;
  }
  alloc_len += left;
  bufferptr ptr(buffer::create_page_aligned(alloc_len));
  if (head) ptr.set_offset(CEPH_PAGE_SIZE - head);
  data.push_back(std::move(ptr));
}

Protocol::Protocol(AsyncConnection *connection)
    : connection(connection),
      messenger(connection->async_msgr),
      cct(connection->async_msgr->cct) {}

Protocol::~Protocol() {}

/**
 * Protocol V1
 **/

ProtocolV1::ProtocolV1(AsyncConnection *connection)
    : Protocol(connection),
      connect_seq(0),
      peer_global_seq(0),
      msg_left(0),
      cur_msg_size(0),
      state(NOT_INITIATED),
      _abort(false) {}

void ProtocolV1::handle_failure(int r) {
  if (state == NOT_INITIATED || state == CLOSED) {
    ldout(cct, 10) << __func__ << " connection is already closed" << dendl;
    return;
  }

  if (connection->policy.lossy && state != INITIATING) {
    ldout(cct, 1) << __func__ << " on lossy channel, failing" << dendl;
    connection->lock.unlock();
    connection->stop(true);
    connection->lock.lock();
    return;
  }

  // requeue sent items
  out_seq -= connection->requeue_sent();

  connection->fault();
}

void ProtocolV1::abort() {
  _abort = true;
  state = CLOSED;
}

void ProtocolV1::reconnect() {
  state = NOT_INITIATED;
  connect_seq++;
}

void ProtocolV1::notify() {
  ldout(cct, 20) << __func__ << " BEGIN" << dendl;
  ldout(cct, 20) << __func__ << " state=" << state << dendl;
  ldout(cct, 20) << __func__ << " BEGIN" << dendl;
  switch (state) {
    case NOT_INITIATED:
      init();
      break;
    case OPENED:
      wait_message();
      break;
    default:
      break;
  }
}

void ProtocolV1::wait_message() {
  ldout(cct, 20) << __func__ << " BEGIN" << dendl;

  READ(sizeof(char), &ProtocolV1::handle_message);

  ldout(cct, 20) << __func__ << " END" << dendl;
}

void ProtocolV1::handle_message(char *buffer, int r) {
  ldout(cct, 20) << __func__ << " BEGIN" << dendl;

  if (r < 0) {
    ldout(cct, 1) << __func__ << " read tag failed" << dendl;
    handle_failure(r);
    return;
  }

  char tag = buffer[0];
  ldout(cct, 20) << __func__ << " process tag " << (int)tag << dendl;

  if (tag == CEPH_MSGR_TAG_KEEPALIVE) {
    ldout(cct, 20) << __func__ << " got KEEPALIVE" << dendl;
    connection->set_last_keepalive(ceph_clock_now());
  } else if (tag == CEPH_MSGR_TAG_KEEPALIVE2) {
    READ(sizeof(ceph_timespec), &ProtocolV1::handle_keepalive2);
  } else if (tag == CEPH_MSGR_TAG_KEEPALIVE2_ACK) {
    READ(sizeof(ceph_timespec), &ProtocolV1::handle_keepalive2_ack);
  } else if (tag == CEPH_MSGR_TAG_ACK) {
    READ(sizeof(ceph_le64), &ProtocolV1::handle_tag_ack);
  } else if (tag == CEPH_MSGR_TAG_MSG) {
#if defined(WITH_LTTNG) && defined(WITH_EVENTTRACE)
    ltt_recv_stamp = ceph_clock_now();
#endif
    recv_stamp = ceph_clock_now();
    ldout(cct, 20) << __func__ << " begin MSG" << dendl;
    READ(sizeof(ceph_msg_header), &ProtocolV1::handle_message_header);
  } else if (tag == CEPH_MSGR_TAG_CLOSE) {
    ldout(cct, 20) << __func__ << " got CLOSE" << dendl;
    connection->_stop();
  } else {
    ldout(cct, 0) << __func__ << " bad tag " << (int)tag << dendl;
    handle_failure();
  }

  ldout(cct, 20) << __func__ << " END" << dendl;
}

void ProtocolV1::handle_keepalive2(char *buffer, int r) {
  ldout(cct, 20) << __func__ << " BEGIN" << dendl;

  if (r < 0) {
    ldout(cct, 1) << __func__ << " read keeplive timespec failed" << dendl;
    handle_failure(r);
    ldout(cct, 20) << __func__ << " END" << dendl;
    return;
  }

  ldout(cct, 30) << __func__ << " got KEEPALIVE2 tag ..." << dendl;

  ceph_timespec *t;
  t = (ceph_timespec *)buffer;
  utime_t kp_t = utime_t(*t);
  connection->write_lock.lock();
  connection->_append_keepalive_or_ack(true, &kp_t);
  connection->write_lock.unlock();

  ldout(cct, 20) << __func__ << " got KEEPALIVE2 " << kp_t << dendl;
  connection->set_last_keepalive(ceph_clock_now());

  if (connection->is_connected()) {
    connection->center->dispatch_event_external(connection->write_handler);
  }

  ldout(cct, 20) << __func__ << " END" << dendl;

  wait_message();
}

void ProtocolV1::handle_keepalive2_ack(char *buffer, int r) {
  ldout(cct, 20) << __func__ << " BEGIN" << dendl;

  if (r < 0) {
    ldout(cct, 1) << __func__ << " read keeplive timespec failed" << dendl;
    handle_failure(r);
    ldout(cct, 20) << __func__ << " END" << dendl;
    return;
  }

  ceph_timespec *t;
  t = (ceph_timespec *)buffer;
  connection->set_last_keepalive_ack(utime_t(*t));
  ldout(cct, 20) << __func__ << " got KEEPALIVE_ACK" << dendl;

  ldout(cct, 20) << __func__ << " END" << dendl;

  wait_message();
}

void ProtocolV1::handle_tag_ack(char *buffer, int r) {
  ldout(cct, 20) << __func__ << " BEGIN" << dendl;

  if (r < 0) {
    ldout(cct, 1) << __func__ << " read ack seq failed" << dendl;
    handle_failure(r);
    ldout(cct, 20) << __func__ << " END" << dendl;
    return;
  }

  ceph_le64 *seq;
  seq = (ceph_le64 *)buffer;
  ldout(cct, 20) << __func__ << " got ACK" << dendl;
  connection->handle_ack(*seq);

  ldout(cct, 20) << __func__ << " END" << dendl;

  wait_message();
}

void ProtocolV1::handle_message_header(char *buffer, int r) {
  ldout(cct, 20) << __func__ << " BEGIN" << dendl;

  if (r < 0) {
    ldout(cct, 1) << __func__ << " read message header failed" << dendl;
    handle_failure(r);
    return;
  }

  ldout(cct, 20) << __func__ << " got MSG header" << dendl;

  ceph_msg_header header;
  header = *((ceph_msg_header *)buffer);

  ldout(cct, 20) << __func__ << " got envelope type=" << header.type << " src "
                 << entity_name_t(header.src) << " front=" << header.front_len
                 << " data=" << header.data_len << " off " << header.data_off
                 << dendl;

  if (messenger->crcflags & MSG_CRC_HEADER) {
    __u32 header_crc = 0;
    header_crc = ceph_crc32c(0, (unsigned char *)&header,
                             sizeof(header) - sizeof(header.crc));
    // verify header crc
    if (header_crc != header.crc) {
      ldout(cct, 0) << __func__ << " got bad header crc " << header_crc
                    << " != " << header.crc << dendl;
      handle_failure();
      return;
    }
  }

  // Reset state
  data_buf.clear();
  front.clear();
  middle.clear();
  data.clear();
  current_header = header;

  ldout(cct, 20) << __func__ << " END" << dendl;

  throttle_message();
}

void ProtocolV1::throttle_message() {
  ldout(cct, 20) << __func__ << " BEGIN" << dendl;

  if (connection->policy.throttler_messages) {
    ldout(cct, 10) << __func__ << " wants " << 1
                   << " message from policy throttler "
                   << connection->policy.throttler_messages->get_current()
                   << "/" << connection->policy.throttler_messages->get_max()
                   << dendl;
    if (!connection->policy.throttler_messages->get_or_fail()) {
      ldout(cct, 10) << __func__ << " wants 1 message from policy throttle "
                     << connection->policy.throttler_messages->get_current()
                     << "/" << connection->policy.throttler_messages->get_max()
                     << " failed, just wait." << dendl;
      // following thread pool deal with th full message queue isn't a
      // short time, so we can wait a ms.
      if (connection->register_time_events.empty()) {
        connection->register_time_events.insert(
            connection->center->create_time_event(1000,
                                                  connection->wakeup_handler));
      }
      return;
    }
  }

  cur_msg_size = current_header.front_len + current_header.middle_len +
                 current_header.data_len;
  if (cur_msg_size) {
    if (connection->policy.throttler_bytes) {
      ldout(cct, 10) << __func__ << " wants " << cur_msg_size
                     << " bytes from policy throttler "
                     << connection->policy.throttler_bytes->get_current() << "/"
                     << connection->policy.throttler_bytes->get_max() << dendl;
      if (!connection->policy.throttler_bytes->get_or_fail(cur_msg_size)) {
        ldout(cct, 10) << __func__ << " wants " << cur_msg_size
                       << " bytes from policy throttler "
                       << connection->policy.throttler_bytes->get_current()
                       << "/" << connection->policy.throttler_bytes->get_max()
                       << " failed, just wait." << dendl;
        // following thread pool deal with th full message queue isn't a
        // short time, so we can wait a ms.
        if (connection->register_time_events.empty()) {
          connection->register_time_events.insert(
              connection->center->create_time_event(
                  1000, connection->wakeup_handler));
        }
        return;
      }
    }
  }

  if (cur_msg_size) {
    if (!connection->dispatch_queue->dispatch_throttler.get_or_fail(
            cur_msg_size)) {
      ldout(cct, 10)
          << __func__ << " wants " << cur_msg_size
          << " bytes from dispatch throttle "
          << connection->dispatch_queue->dispatch_throttler.get_current() << "/"
          << connection->dispatch_queue->dispatch_throttler.get_max()
          << " failed, just wait." << dendl;
      // following thread pool deal with th full message queue isn't a
      // short time, so we can wait a ms.
      if (connection->register_time_events.empty()) {
        connection->register_time_events.insert(
            connection->center->create_time_event(1000,
                                                  connection->wakeup_handler));
      }
      return;
    }
  }

  throttle_stamp = ceph_clock_now();

  ldout(cct, 20) << __func__ << " END" << dendl;

  read_message_front();
}

void ProtocolV1::read_message_front() {
  ldout(cct, 20) << __func__ << " BEGIN" << dendl;
  ldout(cct, 20) << __func__ << " END" << dendl;

  if (current_header.front_len) {
    READ(current_header.front_len, &ProtocolV1::handle_message_front);
  } else {
    read_message_middle();
  }
}

void ProtocolV1::handle_message_front(char *buffer, int r) {
  ldout(cct, 20) << __func__ << " BEGIN" << dendl;

  if (r < 0) {
    ldout(cct, 1) << __func__ << " read message front failed" << dendl;
    handle_failure(r);
  }

  if (!front.length()) {
    front.push_back(buffer::create(current_header.front_len));
  }
  memcpy(front.c_str(), buffer, current_header.front_len);
  ldout(cct, 20) << __func__ << " got front " << front.length() << dendl;

  ldout(cct, 20) << __func__ << " END" << dendl;

  read_message_middle();
}

void ProtocolV1::read_message_middle() {
  ldout(cct, 20) << __func__ << " BEGIN" << dendl;
  ldout(cct, 20) << __func__ << " END" << dendl;

  if (current_header.middle_len) {
    READ(current_header.middle_len, &ProtocolV1::handle_message_middle);
  } else {
    read_message_data_prepare();
  }
}

void ProtocolV1::handle_message_middle(char *buffer, int r) {
  ldout(cct, 20) << __func__ << " BEGIN" << dendl;

  if (r < 0) {
    ldout(cct, 1) << __func__ << " read message middle failed" << dendl;
    handle_failure(r);
  }

  if (!middle.length()) {
    middle.push_back(buffer::create(current_header.middle_len));
  }
  memcpy(middle.c_str(), buffer, current_header.middle_len);
  ldout(cct, 20) << __func__ << " got middle " << middle.length() << dendl;

  ldout(cct, 20) << __func__ << " END" << dendl;

  read_message_data_prepare();
}

void ProtocolV1::read_message_data_prepare() {
  ldout(cct, 20) << __func__ << " BEGIN" << dendl;

  unsigned data_len = le32_to_cpu(current_header.data_len);
  unsigned data_off = le32_to_cpu(current_header.data_off);

  if (data_len) {
    // get a buffer
    map<ceph_tid_t, pair<bufferlist, int> >::iterator p =
        connection->rx_buffers.find(current_header.tid);
    if (p != connection->rx_buffers.end()) {
      ldout(cct, 10) << __func__ << " seleting rx buffer v " << p->second.second
                     << " at offset " << data_off << " len "
                     << p->second.first.length() << dendl;
      data_buf = p->second.first;
      // make sure it's big enough
      if (data_buf.length() < data_len)
        data_buf.push_back(buffer::create(data_len - data_buf.length()));
      data_blp = data_buf.begin();
    } else {
      ldout(cct, 20) << __func__ << " allocating new rx buffer at offset "
                     << data_off << dendl;
      alloc_aligned_buffer(data_buf, data_len, data_off);
      data_blp = data_buf.begin();
    }
  }

  msg_left = data_len;

  ldout(cct, 20) << __func__ << " END" << dendl;

  read_message_data();
}

void ProtocolV1::read_message_data() {
  ldout(cct, 20) << __func__ << " BEGIN" << dendl;
  ldout(cct, 20) << __func__ << " END" << dendl;

  if (msg_left > 0) {
    bufferptr bp = data_blp.get_current_ptr();
    unsigned read_len = std::min(bp.length(), msg_left);

    READ(read_len, &ProtocolV1::handle_message_data);
  } else {
    read_message_footer();
  }
}

void ProtocolV1::handle_message_data(char *buffer, int r) {
  ldout(cct, 20) << __func__ << " BEGIN" << dendl;

  if (r < 0) {
    ldout(cct, 1) << __func__ << " read data error " << dendl;
    handle_failure(r);
    return;
  }

  bufferptr bp = data_blp.get_current_ptr();
  unsigned read_len = std::min(bp.length(), msg_left);
  memcpy(bp.c_str(), buffer, read_len);

  data_blp.advance(read_len);
  data.append(bp, 0, read_len);
  msg_left -= read_len;

  ldout(cct, 20) << __func__ << " END" << dendl;

  read_message_data();
}

void ProtocolV1::read_message_footer() {
  ldout(cct, 20) << __func__ << " BEGIN" << dendl;
  ldout(cct, 20) << __func__ << " END" << dendl;

  unsigned len;
  if (connection->has_feature(CEPH_FEATURE_MSG_AUTH)) {
    len = sizeof(ceph_msg_footer);
  } else {
    len = sizeof(ceph_msg_footer_old);
  }

  READ(len, &ProtocolV1::handle_message_footer);
}

void ProtocolV1::handle_message_footer(char *buffer, int r) {
  ldout(cct, 20) << __func__ << " BEGIN" << dendl;

  if (r < 0) {
    ldout(cct, 1) << __func__ << " read footer data error " << dendl;
    handle_failure(r);
    return;
  }

  ceph_msg_footer footer;
  ceph_msg_footer_old old_footer;

  if (connection->has_feature(CEPH_FEATURE_MSG_AUTH)) {
    footer = *((ceph_msg_footer *)buffer);
  } else {
    old_footer = *((ceph_msg_footer_old *)buffer);
    footer.front_crc = old_footer.front_crc;
    footer.middle_crc = old_footer.middle_crc;
    footer.data_crc = old_footer.data_crc;
    footer.sig = 0;
    footer.flags = old_footer.flags;
  }

  int aborted = (footer.flags & CEPH_MSG_FOOTER_COMPLETE) == 0;
  ldout(cct, 10) << __func__ << " aborted = " << aborted << dendl;
  if (aborted) {
    ldout(cct, 0) << __func__ << " got " << front.length() << " + "
                  << middle.length() << " + " << data.length()
                  << " byte message.. ABORTED" << dendl;
    handle_failure();
    return;
  }

  ldout(cct, 20) << __func__ << " got " << front.length() << " + "
                 << middle.length() << " + " << data.length() << " byte message"
                 << dendl;
  Message *message = decode_message(cct, messenger->crcflags, current_header,
                                    footer, front, middle, data, connection);
  if (!message) {
    ldout(cct, 1) << __func__ << " decode message failed " << dendl;
    handle_failure();
    return;
  }

  //
  //  Check the signature if one should be present.  A zero return indicates
  //  success. PLR
  //

  if (connection->session_security.get() == NULL) {
    ldout(cct, 10) << __func__ << " no session security set" << dendl;
  } else {
    if (connection->session_security->check_message_signature(message)) {
      ldout(cct, 0) << __func__ << " Signature check failed" << dendl;
      message->put();
      handle_failure();
      return;
    }
  }
  message->set_byte_throttler(connection->policy.throttler_bytes);
  message->set_message_throttler(connection->policy.throttler_messages);

  // store reservation size in message, so we don't get confused
  // by messages entering the dispatch queue through other paths.
  message->set_dispatch_throttle_size(cur_msg_size);

  message->set_recv_stamp(recv_stamp);
  message->set_throttle_stamp(throttle_stamp);
  message->set_recv_complete_stamp(ceph_clock_now());

  // check received seq#.  if it is old, drop the message.
  // note that incoming messages may skip ahead.  this is convenient for the
  // client side queueing because messages can't be renumbered, but the (kernel)
  // client will occasionally pull a message out of the sent queue to send
  // elsewhere.  in that case it doesn't matter if we "got" it or not.
  uint64_t cur_seq = in_seq;
  if (message->get_seq() <= cur_seq) {
    ldout(cct, 0) << __func__ << " got old message " << message->get_seq()
                  << " <= " << cur_seq << " " << message << " " << *message
                  << ", discarding" << dendl;
    message->put();
    if (connection->has_feature(CEPH_FEATURE_RECONNECT_SEQ) &&
        cct->_conf->ms_die_on_old_message) {
      assert(0 == "old msgs despite reconnect_seq feature");
    }
    return;
  }
  if (message->get_seq() > cur_seq + 1) {
    ldout(cct, 0) << __func__ << " missed message?  skipped from seq "
                  << cur_seq << " to " << message->get_seq() << dendl;
    if (cct->_conf->ms_die_on_skipped_message) {
      assert(0 == "skipped incoming seq");
    }
  }

  message->set_connection(connection);

#if defined(WITH_LTTNG) && defined(WITH_EVENTTRACE)
  if (message->get_type() == CEPH_MSG_OSD_OP ||
      message->get_type() == CEPH_MSG_OSD_OPREPLY) {
    utime_t ltt_processed_stamp = ceph_clock_now();
    double usecs_elapsed =
        (ltt_processed_stamp.to_nsec() - ltt_recv_stamp.to_nsec()) / 1000;
    ostringstream buf;
    if (message->get_type() == CEPH_MSG_OSD_OP)
      OID_ELAPSED_WITH_MSG(message, usecs_elapsed, "TIME_TO_DECODE_OSD_OP",
                           false);
    else
      OID_ELAPSED_WITH_MSG(message, usecs_elapsed, "TIME_TO_DECODE_OSD_OPREPLY",
                           false);
  }
#endif

  // note last received message.
  in_seq = message->get_seq();
  ldout(cct, 5) << " rx " << message->get_source() << " seq "
                << message->get_seq() << " " << message << " " << *message
                << dendl;

  bool need_dispatch_writer = true;
  if (!connection->policy.lossy) {
    ack_left++;
    need_dispatch_writer = true;
  }

  connection->logger->inc(l_msgr_recv_messages);
  connection->logger->inc(
      l_msgr_recv_bytes,
      cur_msg_size + sizeof(ceph_msg_header) + sizeof(ceph_msg_footer));

  messenger->ms_fast_preprocess(message);
  auto fast_dispatch_time = ceph::mono_clock::now();
  // TODO:
  // connection->logger->tinc(l_msgr_running_recv_time,
  //                          fast_dispatch_time - recv_start_time);
  if (connection->delay_state) {
    double delay_period = 0;
    if (rand() % 10000 < cct->_conf->ms_inject_delay_probability * 10000.0) {
      delay_period =
          cct->_conf->ms_inject_delay_max * (double)(rand() % 10000) / 10000.0;
      ldout(cct, 1) << "queue_received will delay after "
                    << (ceph_clock_now() + delay_period) << " on " << message
                    << " " << *message << dendl;
    }
    connection->delay_state->queue(delay_period, message);
  } else if (messenger->ms_can_fast_dispatch(message)) {
    connection->lock.unlock();
    connection->dispatch_queue->fast_dispatch(message);
    // TODO:
    // recv_start_time = ceph::mono_clock::now();
    // connection->logger->tinc(l_msgr_running_fast_dispatch_time,
    //                          recv_start_time - fast_dispatch_time);
    connection->lock.lock();
  } else {
    connection->dispatch_queue->enqueue(message, message->get_priority(),
                                        connection->conn_id);
  }

  if (need_dispatch_writer && connection->is_connected()) {
    connection->center->dispatch_event_external(connection->write_handler);
  }

  ldout(cct, 20) << __func__ << " END" << dendl;

  wait_message();
}

void ProtocolV1::session_reset() {
  ldout(cct, 10) << __func__ << " started" << dendl;
  std::lock_guard<std::mutex> l(connection->write_lock);
  if (connection->delay_state) connection->delay_state->discard();

  connection->dispatch_queue->discard_queue(connection->conn_id);
  connection->discard_out_queue();
  // note: we need to clear outcoming_bl here, but session_reset may be
  // called by other thread, so let caller clear this itself!
  // outcoming_bl.clear();

  connection->dispatch_queue->queue_remote_reset(connection);

  randomize_out_seq();

  in_seq = 0;
  connect_seq = 0;
  // it's safe to directly set 0, double locked
  ack_left = 0;
  connection->once_ready = false;
  connection->can_write = AsyncConnection::WriteStatus::NOWRITE;
}

void ProtocolV1::randomize_out_seq() {
  if (connection->get_features() & CEPH_FEATURE_MSG_AUTH) {
    // Set out_seq to a random value, so CRC won't be predictable.
    auto rand_seq = ceph::util::generate_random_number<uint64_t>(0, SEQ_MASK);
    ldout(cct, 10) << __func__ << " randomize_out_seq " << rand_seq << dendl;
    out_seq = rand_seq;
  } else {
    // previously, seq #'s always started at 0.
    out_seq = 0;
  }
}

void ProtocolV1::prepare_send_message(uint64_t features, Message *m,
                                      bufferlist &bl) {
  ldout(cct, 20) << __func__ << " m " << *m << dendl;

  // associate message with Connection (for benefit of encode_payload)
  if (m->empty_payload()) {
    ldout(cct, 20) << __func__ << " encoding features " << features << " " << m
                   << " " << *m << dendl;
  } else {
    ldout(cct, 20) << __func__ << " half-reencoding features " << features
                   << " " << m << " " << *m << dendl;
  }

  // encode and copy out of *m
  m->encode(features, messenger->crcflags);

  bl.append(m->get_payload());
  bl.append(m->get_middle());
  bl.append(m->get_data());
}

void ProtocolV1::send_message(Message *m) {
  bufferlist bl;
  uint64_t f = connection->get_features();

  // TODO: Currently not all messages supports reencode like MOSDMap, so here
  // only let fast dispatch support messages prepare message
  bool can_fast_prepare = messenger->ms_can_fast_dispatch(m);
  if (can_fast_prepare) {
    prepare_send_message(f, m, bl);
  }

  std::lock_guard<std::mutex> l(connection->write_lock);
  // "features" changes will change the payload encoding
  if (can_fast_prepare &&
      (connection->can_write == AsyncConnection::WriteStatus::NOWRITE ||
       connection->get_features() != f)) {
    // ensure the correctness of message encoding
    bl.clear();
    m->get_payload().clear();
    ldout(cct, 5) << __func__ << " clear encoded buffer previous " << f
                  << " != " << connection->get_features() << dendl;
  }
  if (connection->can_write == AsyncConnection::WriteStatus::CLOSED) {
    ldout(cct, 10) << __func__ << " connection closed."
                   << " Drop message " << m << dendl;
    m->put();
  } else {
    m->trace.event("async enqueueing message");
    connection->out_q[m->get_priority()].emplace_back(std::move(bl), m);
    ldout(cct, 15) << __func__ << " inline write is denied, reschedule m=" << m
                   << dendl;
    if (connection->can_write != AsyncConnection::WriteStatus::REPLACING) {
      connection->center->dispatch_event_external(connection->write_handler);
    }
  }
}

ssize_t ProtocolV1::write_message(Message *m, bufferlist &bl, bool more) {
  FUNCTRACE(cct);
  assert(connection->center->in_thread());
  m->set_seq(++out_seq);

  if (messenger->crcflags & MSG_CRC_HEADER) {
    m->calc_header_crc();
  }

  ceph_msg_header &header = m->get_header();
  ceph_msg_footer &footer = m->get_footer();

  // TODO: let sign_message could be reentry?
  // Now that we have all the crcs calculated, handle the
  // digital signature for the message, if the AsyncConnection has session
  // security set up.  Some session security options do not
  // actually calculate and check the signature, but they should
  // handle the calls to sign_message and check_signature.  PLR
  if (connection->session_security.get() == NULL) {
    ldout(cct, 20) << __func__ << " no session security" << dendl;
  } else {
    if (connection->session_security->sign_message(m)) {
      ldout(cct, 20) << __func__ << " failed to sign m=" << m
                     << "): sig = " << footer.sig << dendl;
    } else {
      ldout(cct, 20) << __func__ << " signed m=" << m
                     << "): sig = " << footer.sig << dendl;
    }
  }

  connection->outcoming_bl.append(CEPH_MSGR_TAG_MSG);
  connection->outcoming_bl.append((char *)&header, sizeof(header));

  ldout(cct, 20) << __func__ << " sending message type=" << header.type
                 << " src " << entity_name_t(header.src)
                 << " front=" << header.front_len << " data=" << header.data_len
                 << " off " << header.data_off << dendl;

  if ((bl.length() <= ASYNC_COALESCE_THRESHOLD) && (bl.buffers().size() > 1)) {
    for (const auto &pb : bl.buffers()) {
      connection->outcoming_bl.append((char *)pb.c_str(), pb.length());
    }
  } else {
    connection->outcoming_bl.claim_append(bl);
  }

  // send footer; if receiver doesn't support signatures, use the old footer
  // format
  ceph_msg_footer_old old_footer;
  if (connection->has_feature(CEPH_FEATURE_MSG_AUTH)) {
    connection->outcoming_bl.append((char *)&footer, sizeof(footer));
  } else {
    if (messenger->crcflags & MSG_CRC_HEADER) {
      old_footer.front_crc = footer.front_crc;
      old_footer.middle_crc = footer.middle_crc;
      old_footer.data_crc = footer.data_crc;
    } else {
      old_footer.front_crc = old_footer.middle_crc = 0;
    }
    old_footer.data_crc =
        messenger->crcflags & MSG_CRC_DATA ? footer.data_crc : 0;
    old_footer.flags = footer.flags;
    connection->outcoming_bl.append((char *)&old_footer, sizeof(old_footer));
  }

  m->trace.event("async writing message");
  ldout(cct, 20) << __func__ << " sending " << m->get_seq() << " " << m
                 << dendl;
  ssize_t total_send_size = connection->outcoming_bl.length();
  ssize_t rc = connection->_try_send(more);
  if (rc < 0) {
    ldout(cct, 1) << __func__ << " error sending " << m << ", "
                  << cpp_strerror(rc) << dendl;
  } else {
    connection->logger->inc(
        l_msgr_send_bytes, total_send_size - connection->outcoming_bl.length());
    ldout(cct, 10) << __func__ << " sending " << m
                   << (rc ? " continuely." : " done.") << dendl;
  }
  if (m->get_type() == CEPH_MSG_OSD_OP)
    OID_EVENT_TRACE_WITH_MSG(m, "SEND_MSG_OSD_OP_END", false);
  else if (m->get_type() == CEPH_MSG_OSD_OPREPLY)
    OID_EVENT_TRACE_WITH_MSG(m, "SEND_MSG_OSD_OPREPLY_END", false);
  m->put();

  return rc;
}

void ProtocolV1::write_event() {
  ldout(cct, 10) << __func__ << dendl;
  ssize_t r = 0;

  connection->write_lock.lock();
  if (connection->can_write == AsyncConnection::WriteStatus::CANWRITE) {
    if (connection->keepalive) {
      connection->_append_keepalive_or_ack();
      connection->keepalive = false;
    }

    auto start = ceph::mono_clock::now();
    bool more;
    do {
      bufferlist data;
      Message *m = connection->_get_next_outgoing(&data);
      if (!m) {
        break;
      }

      if (!connection->policy.lossy) {
        // put on sent list
        connection->sent.push_back(m);
        m->get();
      }
      more = connection->_has_next_outgoing();
      connection->write_lock.unlock();

      // send_message or requeue messages may not encode message
      if (!data.length()) {
        prepare_send_message(connection->get_features(), m, data);
      }

      r = write_message(m, data, more);

      connection->write_lock.lock();
      if (r == 0) {
        ;
      } else if (r < 0) {
        ldout(cct, 1) << __func__ << " send msg failed" << dendl;
        break;
      } else if (r > 0)
        break;
    } while (connection->can_write == AsyncConnection::WriteStatus::CANWRITE);
    connection->write_lock.unlock();

    // if r > 0 mean data still lefted, so no need _try_send.
    connection->lock.lock();
    if (r == 0) {
      uint64_t left = ack_left;
      if (left) {
        ceph_le64 s;
        s = in_seq;
        connection->outcoming_bl.append(CEPH_MSGR_TAG_ACK);
        connection->outcoming_bl.append((char *)&s, sizeof(s));
        ldout(cct, 10) << __func__ << " try send msg ack, acked " << left
                       << " messages" << dendl;
        ack_left -= left;
        left = ack_left;
        r = connection->_try_send(left);
      } else if (connection->is_queued()) {
        r = connection->_try_send();
      }
    }
    connection->lock.unlock();

    connection->logger->tinc(l_msgr_running_send_time, ceph::mono_clock::now() - start);
    if (r < 0) {
      ldout(cct, 1) << __func__ << " send msg failed" << dendl;
      connection->lock.lock();
      handle_failure(r);
      connection->lock.unlock();
      return;
    }
  } else {
    connection->write_lock.unlock();
    connection->lock.lock();
    connection->write_lock.lock();
    if (connection->state == AsyncConnection::STATE_STANDBY &&
        !connection->policy.server && connection->is_queued()) {
      ldout(cct, 10) << __func__ << " policy.server is false" << dendl;
      connection->_connect();
    } else if (connection->cs &&
               connection->state != AsyncConnection::STATE_NONE &&
               connection->state != AsyncConnection::STATE_CONNECTING &&
               connection->state != AsyncConnection::STATE_CONNECTING_RE &&
               connection->state != AsyncConnection::STATE_CLOSED) {
      r = connection->_try_send();
      if (r < 0) {
        ldout(cct, 1) << __func__ << " send outcoming bl failed" << dendl;
        connection->write_lock.unlock();
        handle_failure(r);
        connection->lock.unlock();
        return;
      }
    }
    connection->write_lock.unlock();
    connection->lock.unlock();
  }
}

void ProtocolV1::fault() {
  handle_failure();
}

/**
 * Client Protocol V1
 **/

ClientProtocolV1::ClientProtocolV1(AsyncConnection *connection)
    : ProtocolV1(connection),
      global_seq(0),
      got_bad_auth(false),
      authorizer(nullptr) {}

void ClientProtocolV1::init() {
  state = INITIATING;

  _abort = false;
  authorizer_buf.clear();
  memset(&connect_msg, 0, sizeof(connect_msg));
  memset(&connect_reply, 0, sizeof(connect_reply));

  global_seq = messenger->get_global_seq();
  got_bad_auth = false;
  delete authorizer;
  authorizer = nullptr;

  send_banner();
}

void ClientProtocolV1::send_banner() {
  ldout(cct, 20) << __func__ << " BEGIN" << dendl;

  bufferlist bl;
  bl.append(CEPH_BANNER, strlen(CEPH_BANNER));
  WRITE(bl, &ClientProtocolV1::handle_banner_write);

  ldout(cct, 20) << __func__ << " END" << dendl;
}

void ClientProtocolV1::handle_banner_write(int r) {
  ldout(cct, 20) << __func__ << " BEGIN" << dendl;

  if (r < 0) {
    handle_failure(r);
    return;
  }
  ldout(cct, 10) << __func__ << " connect write banner done: "
                 << connection->get_peer_addr() << dendl;

  ldout(cct, 20) << __func__ << " END" << dendl;

  wait_server_banner();
}

void ClientProtocolV1::wait_server_banner() {
  ldout(cct, 20) << __func__ << " BEGIN" << dendl;

  bufferlist myaddrbl;
  unsigned banner_len = strlen(CEPH_BANNER);
  unsigned need_len = banner_len + sizeof(ceph_entity_addr) * 2;
  READ(need_len, &ClientProtocolV1::handle_server_banner);

  ldout(messenger->cct, 20) << __func__ << " END" << dendl;
}

void ClientProtocolV1::handle_server_banner(char *buffer, int r) {
  ldout(cct, 20) << __func__ << " BEGIN" << dendl;

  if (r < 0) {
    ldout(cct, 1) << __func__ << " read banner and identify addresses failed"
                  << dendl;
    handle_failure(r);
    ldout(cct, 20) << __func__ << " END" << dendl;
    return;
  }

  unsigned banner_len = strlen(CEPH_BANNER);
  if (memcmp(buffer, CEPH_BANNER, banner_len)) {
    ldout(cct, 0) << __func__ << " connect protocol error (bad banner) on peer "
                  << connection->get_peer_addr() << dendl;
    handle_failure();
    ldout(cct, 20) << __func__ << " END" << dendl;
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
    lderr(cct) << __func__ << " decode peer addr failed " << dendl;
    handle_failure();
    ldout(cct, 20) << __func__ << " END" << dendl;
    return;
  }
  ldout(cct, 20) << __func__ << " connect read peer addr " << paddr
                 << " on socket " << connection->cs.fd() << dendl;

  entity_addr_t peer_addr = connection->peer_addr;
  if (peer_addr != paddr) {
    if (paddr.is_blank_ip() && peer_addr.get_port() == paddr.get_port() &&
        peer_addr.get_nonce() == paddr.get_nonce()) {
      ldout(cct, 0) << __func__ << " connect claims to be " << paddr << " not "
                    << peer_addr << " - presumably this is the same node!"
                    << dendl;
    } else {
      ldout(cct, 10) << __func__ << " connect claims to be " << paddr << " not "
                     << peer_addr << dendl;
      handle_failure();
      ldout(cct, 20) << __func__ << " END" << dendl;
      return;
    }
  }

  ldout(cct, 20) << __func__ << " connect peer addr for me is "
                 << peer_addr_for_me << dendl;
  connection->lock.unlock();
  messenger->learned_addr(peer_addr_for_me);
  if (cct->_conf->ms_inject_internal_delays &&
      cct->_conf->ms_inject_socket_failures) {
    if (rand() % cct->_conf->ms_inject_socket_failures == 0) {
      ldout(cct, 10) << __func__ << " sleep for "
                     << cct->_conf->ms_inject_internal_delays << dendl;
      utime_t t;
      t.set_from_double(cct->_conf->ms_inject_internal_delays);
      t.sleep();
    }
  }

  connection->lock.lock();
  if (_abort) {
    ldout(cct, 1) << __func__
                  << " state changed while learned_addr, mark_down or "
                  << " replacing must be happened just now" << dendl;
    ldout(cct, 20) << __func__ << " END" << dendl;
    return;
  }

  bufferlist myaddrbl;
  encode(messenger->get_myaddr(), myaddrbl, 0);  // legacy
  WRITE(myaddrbl, &ClientProtocolV1::handle_my_addr_write);

  ldout(messenger->cct, 20) << __func__ << " END" << dendl;
}

void ClientProtocolV1::handle_my_addr_write(int r) {
  ldout(cct, 20) << __func__ << " BEGIN" << dendl;

  if (r < 0) {
    ldout(cct, 2) << __func__ << " connect couldn't write my addr, "
                  << cpp_strerror(r) << dendl;
    handle_failure(r);
    ldout(cct, 20) << __func__ << " END" << dendl;
    return;
  }
  ldout(cct, 10) << __func__ << " connect sent my addr "
                 << messenger->get_myaddr() << dendl;

  ldout(cct, 20) << __func__ << " END" << dendl;

  send_connect_message();
}

void ClientProtocolV1::send_connect_message() {
  ldout(cct, 20) << __func__ << " BEGIN" << dendl;

  if (!got_bad_auth) {
    delete authorizer;
    authorizer = messenger->get_authorizer(connection->peer_type, false);
  }

  connect_msg.features = connection->policy.features_supported;
  connect_msg.host_type = messenger->get_myname().type();
  connect_msg.global_seq = global_seq;
  connect_msg.connect_seq = connect_seq;
  connect_msg.protocol_version =
      messenger->get_proto_version(connection->peer_type, true);
  connect_msg.authorizer_protocol = authorizer ? authorizer->protocol : 0;
  connect_msg.authorizer_len = authorizer ? authorizer->bl.length() : 0;

  if (authorizer) {
    ldout(cct, 10) << __func__ << " connect_msg.authorizer_len="
                   << connect_msg.authorizer_len
                   << " protocol=" << connect_msg.authorizer_protocol << dendl;
  }

  connect_msg.flags = 0;
  if (connection->policy.lossy) {
    connect_msg.flags |=
        CEPH_MSG_CONNECT_LOSSY;  // this is fyi, actually, server decides!
  }

  bufferlist bl;
  bl.append((char *)&connect_msg, sizeof(connect_msg));
  if (authorizer) {
    bl.append(authorizer->bl.c_str(), authorizer->bl.length());
  }

  ldout(cct, 10) << __func__ << " connect sending gseq=" << global_seq
                 << " cseq=" << connect_seq
                 << " proto=" << connect_msg.protocol_version << dendl;

  WRITE(bl, &ClientProtocolV1::handle_connect_message_write);

  ldout(cct, 20) << __func__ << " END" << dendl;
}

void ClientProtocolV1::handle_connect_message_write(int r) {
  ldout(cct, 20) << __func__ << " BEGIN" << dendl;

  if (r < 0) {
    ldout(cct, 2) << __func__ << " connect couldn't send reply "
                  << cpp_strerror(r) << dendl;
    handle_failure(r);
    ldout(cct, 20) << __func__ << " END" << dendl;
    return;
  }

  ldout(cct, 20) << __func__
                 << " connect wrote (self +) cseq, waiting for reply" << dendl;

  ldout(cct, 20) << __func__ << " END" << dendl;

  wait_connect_reply();
}

void ClientProtocolV1::wait_connect_reply() {
  ldout(cct, 20) << __func__ << " BEGIN" << dendl;

  READ(sizeof(connection->connect_reply),
       &ClientProtocolV1::handle_connect_reply_1);

  ldout(cct, 20) << __func__ << " END" << dendl;
}

void ClientProtocolV1::handle_connect_reply_1(char *buffer, int r) {
  ldout(cct, 20) << __func__ << " BEGIN" << dendl;

  if (r < 0) {
    ldout(cct, 1) << __func__ << " read connect reply failed" << dendl;
    handle_failure(r);
    ldout(cct, 20) << __func__ << " END" << dendl;
    return;
  }

  connect_reply = *((ceph_msg_connect_reply *)buffer);

  ldout(cct, 20) << __func__ << " connect got reply tag "
                 << (int)connect_reply.tag << " connect_seq "
                 << connect_reply.connect_seq << " global_seq "
                 << connect_reply.global_seq << " proto "
                 << connect_reply.protocol_version << " flags "
                 << (int)connect_reply.flags << " features "
                 << connect_reply.features << dendl;

  if (connect_reply.authorizer_len) {
    ldout(cct, 20) << __func__ << " END" << dendl;
    wait_connect_reply_auth();
    return;
  }

  ldout(cct, 20) << __func__ << " END" << dendl;

  handle_connect_reply_2();
}

void ClientProtocolV1::wait_connect_reply_auth() {
  ldout(cct, 20) << __func__ << " BEGIN" << dendl;

  ldout(cct, 10) << __func__
                 << " reply.authorizer_len=" << connect_reply.authorizer_len
                 << dendl;

  assert(connect_reply.authorizer_len < 4096);

  READ(connect_reply.authorizer_len,
       &ClientProtocolV1::handle_connect_reply_auth);

  ldout(cct, 20) << __func__ << " END" << dendl;
}

void ClientProtocolV1::handle_connect_reply_auth(char *buffer, int r) {
  ldout(cct, 20) << __func__ << " BEGIN" << dendl;

  if (r < 0) {
    ldout(cct, 1) << __func__ << " read connect reply authorizer failed"
                  << dendl;
    handle_failure(r);
    ldout(cct, 20) << __func__ << " END" << dendl;
    return;
  }

  bufferlist authorizer_reply;
  authorizer_reply.append(buffer, connect_reply.authorizer_len);
  auto iter = authorizer_reply.cbegin();
  if (authorizer && !authorizer->verify_reply(iter)) {
    ldout(cct, 0) << __func__ << " failed verifying authorize reply" << dendl;
    handle_failure(-1);
    ldout(cct, 20) << __func__ << " END" << dendl;
    return;
  }

  ldout(cct, 20) << __func__ << " END" << dendl;
  handle_connect_reply_2();
}

void ClientProtocolV1::handle_connect_reply_2() {
  ldout(cct, 20) << __func__ << " BEGIN" << dendl;

  if (connect_reply.tag == CEPH_MSGR_TAG_FEATURES) {
    ldout(cct, 0) << __func__ << " connect protocol feature mismatch, my "
                  << std::hex << connect_msg.features << " < peer "
                  << connect_reply.features << " missing "
                  << (connect_reply.features &
                      ~connection->policy.features_supported)
                  << std::dec << dendl;
    handle_failure(-1);
    ldout(cct, 20) << __func__ << " END" << dendl;
    return;
  }

  if (connect_reply.tag == CEPH_MSGR_TAG_BADPROTOVER) {
    ldout(cct, 0) << __func__ << " connect protocol version mismatch, my "
                  << connect_msg.protocol_version
                  << " != " << connect_reply.protocol_version << dendl;
    handle_failure(-1);
    ldout(cct, 20) << __func__ << " END" << dendl;
    return;
  }

  if (connect_reply.tag == CEPH_MSGR_TAG_BADAUTHORIZER) {
    ldout(cct, 0) << __func__ << " connect got BADAUTHORIZER" << dendl;
    if (got_bad_auth) {
      handle_failure(-1);
      ldout(cct, 20) << __func__ << " END" << dendl;
      return;
    }
    got_bad_auth = true;
    delete authorizer;
    authorizer =
        messenger->get_authorizer(connection->peer_type, true);  // try harder
    ldout(cct, 20) << __func__ << " END" << dendl;
    send_connect_message();
    return;
  }

  if (connect_reply.tag == CEPH_MSGR_TAG_RESETSESSION) {
    ldout(cct, 0) << __func__ << " connect got RESETSESSION" << dendl;
    session_reset();
    connect_seq = 0;

    // see session_reset
    connection->outcoming_bl.clear();

    ldout(cct, 20) << __func__ << " END" << dendl;
    send_connect_message();
    return;
  }

  if (connect_reply.tag == CEPH_MSGR_TAG_RETRY_GLOBAL) {
    global_seq = messenger->get_global_seq(connect_reply.global_seq);
    ldout(cct, 5) << __func__ << " connect got RETRY_GLOBAL "
                  << connect_reply.global_seq << " chose new " << global_seq
                  << dendl;
    ldout(cct, 20) << __func__ << " END" << dendl;
    send_connect_message();
    return;
  }

  if (connect_reply.tag == CEPH_MSGR_TAG_RETRY_SESSION) {
    assert(connect_reply.connect_seq > connect_seq);
    ldout(cct, 5) << __func__ << " connect got RETRY_SESSION " << connect_seq
                  << " -> " << connect_reply.connect_seq << dendl;
    connect_seq = connect_reply.connect_seq;
    ldout(cct, 20) << __func__ << " END" << dendl;
    send_connect_message();
    return;
  }

  if (connect_reply.tag == CEPH_MSGR_TAG_WAIT) {
    ldout(cct, 1) << __func__ << " connect got WAIT (connection race)" << dendl;
    connection->state = AsyncConnection::STATE_WAIT;
    handle_failure(-1);
    ldout(cct, 20) << __func__ << " END" << dendl;
    return;
  }

  uint64_t feat_missing;
  feat_missing =
      connection->policy.features_required & ~(uint64_t)connect_reply.features;
  if (feat_missing) {
    ldout(cct, 1) << __func__ << " missing required features " << std::hex
                  << feat_missing << std::dec << dendl;
    handle_failure(-1);
    ldout(cct, 20) << __func__ << " END" << dendl;
    return;
  }

  if (connect_reply.tag == CEPH_MSGR_TAG_SEQ) {
    ldout(cct, 10)
        << __func__
        << " got CEPH_MSGR_TAG_SEQ, reading acked_seq and writing in_seq"
        << dendl;

    ldout(cct, 20) << __func__ << " END" << dendl;
    wait_ack_seq();
    return;
  }

  if (connect_reply.tag == CEPH_MSGR_TAG_READY) {
    ldout(cct, 10) << __func__ << " got CEPH_MSGR_TAG_READY " << dendl;
  }

  ldout(cct, 20) << __func__ << " END" << dendl;

  ready();
}

void ClientProtocolV1::wait_ack_seq() {
  ldout(cct, 20) << __func__ << " BEGIN" << dendl;

  ldout(cct, 20) << __func__ << " END" << dendl;

  READ(sizeof(uint64_t), &ClientProtocolV1::handle_ack_seq);
}

void ClientProtocolV1::handle_ack_seq(char *buffer, int r) {
  ldout(cct, 20) << __func__ << " BEGIN" << dendl;

  if (r < 0) {
    ldout(cct, 1) << __func__ << " read connect ack seq failed" << dendl;
    handle_failure(r);
    ldout(cct, 20) << __func__ << " END" << dendl;
    return;
  }

  uint64_t newly_acked_seq = 0;

  newly_acked_seq = *((uint64_t *)buffer);
  ldout(cct, 2) << __func__ << " got newly_acked_seq " << newly_acked_seq
                << " vs out_seq " << out_seq << dendl;
  out_seq = connection->discard_requeued_up_to(out_seq, newly_acked_seq);

  bufferlist bl;
  uint64_t s = in_seq;
  bl.append((char *)&s, sizeof(s));

  ldout(messenger->cct, 20) << __func__ << " END" << dendl;

  WRITE(bl, &ClientProtocolV1::handle_in_seq_write);
}

void ClientProtocolV1::handle_in_seq_write(int r) {
  ldout(cct, 20) << __func__ << " BEGIN" << dendl;

  if (r < 0) {
    ldout(cct, 10) << __func__ << " failed to send in_seq " << dendl;
    handle_failure(r);
    ldout(cct, 20) << __func__ << " END" << dendl;
    return;
  }

  ldout(cct, 10) << __func__ << " send in_seq done " << dendl;

  ldout(cct, 20) << __func__ << " END" << dendl;

  ready();
}

void ClientProtocolV1::ready() {
  ldout(cct, 20) << __func__ << " BEGIN" << dendl;

  // hooray!
  peer_global_seq = connect_reply.global_seq;
  connection->policy.lossy =
      connection->connect_reply.flags & CEPH_MSG_CONNECT_LOSSY;
  connection->state = AsyncConnection::STATE_OPEN;

  connection->once_ready = true;
  connect_seq += 1;
  assert(connect_seq == connect_reply.connect_seq);
  connection->backoff = utime_t();
  connection->set_features((uint64_t)connect_reply.features &
                           (uint64_t)connect_msg.features);
  ldout(cct, 10) << __func__ << " connect success " << connect_seq
                 << ", lossy = " << connection->policy.lossy << ", features "
                 << connection->get_features() << dendl;

  // If we have an authorizer, get a new AuthSessionHandler to deal with
  // ongoing security of the connection.  PLR
  if (authorizer != NULL) {
    connection->session_security.reset(get_auth_session_handler(
        cct, authorizer->protocol, authorizer->session_key,
        connection->get_features()));
  } else {
    // We have no authorizer, so we shouldn't be applying security to messages
    // in this AsyncConnection.  PLR
    connection->session_security.reset();
  }

  if (connection->delay_state) {
    assert(connection->delay_state->ready());
  }
  connection->dispatch_queue->queue_connect(connection);
  messenger->ms_deliver_handle_fast_connect(connection);

  // make sure no pending tick timer
  if (connection->last_tick_id) {
    connection->center->delete_time_event(connection->last_tick_id);
  }
  connection->last_tick_id = connection->center->create_time_event(
      connection->inactive_timeout_us, connection->tick_handler);

  // message may in queue between last _try_send and connection ready
  // write event may already notify and we need to force scheduler again
  connection->write_lock.lock();
  connection->can_write = AsyncConnection::WriteStatus::CANWRITE;
  if (connection->is_queued()) {
    connection->center->dispatch_event_external(connection->write_handler);
  }
  connection->write_lock.unlock();
  connection->maybe_start_delay_thread();

  ldout(cct, 20) << __func__ << " END" << dendl;

  state = OPENED;
  wait_message();
}

/**
 * Server Protocol V1
 **/
ServerProtocolV1::ServerProtocolV1(AsyncConnection *connection)
    : ProtocolV1(connection),
      existing(nullptr),
      is_reset_from_peer(false),
      wait_for_seq(false) {}

void ServerProtocolV1::init() {
  state = INITIATING;
  accept();
}

void ServerProtocolV1::accept() {
  ldout(cct, 20) << __func__ << " BEGIN" << dendl;
  bufferlist bl;

  bl.append(CEPH_BANNER, strlen(CEPH_BANNER));

  encode(messenger->get_myaddr(), bl, 0);  // legacy
  connection->port = messenger->get_myaddr().get_port();
  encode(connection->socket_addr, bl, 0);  // legacy

  ldout(cct, 1) << __func__ << " sd=" << connection->cs.fd() << " "
                << connection->socket_addr << dendl;

  WRITE(bl, &ServerProtocolV1::handle_banner_write);

  ldout(cct, 20) << __func__ << " END" << dendl;
}

void ServerProtocolV1::handle_banner_write(int r) {
  ldout(cct, 20) << __func__ << " BEGIN" << dendl;

  if (r < 0) {
    handle_failure(r);
    return;
  }
  ldout(cct, 10) << __func__ << " write banner and addr done: "
                 << connection->get_peer_addr() << dendl;

  ldout(cct, 20) << __func__ << " END" << dendl;

  wait_client_banner();
}

void ServerProtocolV1::wait_client_banner() {
  ldout(cct, 20) << __func__ << " BEGIN" << dendl;

  READ(strlen(CEPH_BANNER) + sizeof(ceph_entity_addr),
       &ServerProtocolV1::handle_client_banner);

  ldout(cct, 20) << __func__ << " END" << dendl;
}

void ServerProtocolV1::handle_client_banner(char *buffer, int r) {
  ldout(cct, 20) << __func__ << " BEGIN" << dendl;

  if (r < 0) {
    ldout(cct, 1) << __func__ << " read peer banner and addr failed" << dendl;
    handle_failure(r);
    ldout(cct, 20) << __func__ << " END" << dendl;
    return;
  }

  if (memcmp(buffer, CEPH_BANNER, strlen(CEPH_BANNER))) {
    ldout(cct, 1) << __func__ << " accept peer sent bad banner '" << buffer
                  << "' (should be '" << CEPH_BANNER << "')" << dendl;
    handle_failure();
    ldout(cct, 20) << __func__ << " END" << dendl;
    return;
  }

  bufferlist addr_bl;
  entity_addr_t peer_addr;

  addr_bl.append(buffer + strlen(CEPH_BANNER), sizeof(ceph_entity_addr));
  try {
    auto ti = addr_bl.cbegin();
    decode(peer_addr, ti);
  } catch (const buffer::error &e) {
    lderr(cct) << __func__ << " decode peer_addr failed " << dendl;
    handle_failure();
    ldout(cct, 20) << __func__ << " END" << dendl;
    return;
  }

  ldout(cct, 10) << __func__ << " accept peer addr is " << peer_addr << dendl;
  if (peer_addr.is_blank_ip()) {
    // peer apparently doesn't know what ip they have; figure it out for them.
    int port = peer_addr.get_port();
    peer_addr.u = connection->socket_addr.u;
    peer_addr.set_port(port);

    ldout(cct, 0) << __func__ << " accept peer addr is really " << peer_addr
                  << " (socket is " << connection->socket_addr << ")" << dendl;
  }
  connection->set_peer_addr(peer_addr);  // so that connection_state gets set up

  ldout(cct, 20) << __func__ << " END" << dendl;

  wait_connect_message();
}

void ServerProtocolV1::wait_connect_message() {
  ldout(cct, 20) << __func__ << " BEGIN" << dendl;

  READ(sizeof(connection->connect_msg),
       &ServerProtocolV1::handle_connect_message_1);

  ldout(cct, 20) << __func__ << " END" << dendl;
}

void ServerProtocolV1::handle_connect_message_1(char *buffer, int r) {
  ldout(cct, 20) << __func__ << " BEGIN" << dendl;

  if (r < 0) {
    ldout(cct, 1) << __func__ << " read connect msg failed" << dendl;
    handle_failure(r);
    ldout(cct, 20) << __func__ << " END" << dendl;
    return;
  }

  connect_msg = *((ceph_msg_connect *)buffer);

  if (connect_msg.authorizer_len) {
    ldout(cct, 20) << __func__ << " END" << dendl;
    wait_connect_message_auth();
    return;
  }

  ldout(cct, 20) << __func__ << " END" << dendl;

  handle_connect_message_2();
}

void ServerProtocolV1::wait_connect_message_auth() {
  ldout(cct, 20) << __func__ << " BEGIN" << dendl;

  READ(connect_msg.authorizer_len,
       &ServerProtocolV1::handle_connect_message_auth);

  ldout(cct, 20) << __func__ << " END" << dendl;
}

void ServerProtocolV1::handle_connect_message_auth(char *buffer, int r) {
  ldout(cct, 20) << __func__ << " BEGIN" << dendl;

  if (r < 0) {
    ldout(cct, 1) << __func__ << " read connect authorizer failed" << dendl;
    handle_failure(r);
    ldout(cct, 20) << __func__ << " END" << dendl;
    return;
  }

  authorizer_buf.push_back(buffer::copy(buffer, connect_msg.authorizer_len));

  ldout(cct, 20) << __func__ << " END" << dendl;

  handle_connect_message_2();
}

void ServerProtocolV1::handle_connect_message_2() {
  ldout(cct, 20) << __func__ << " BEGIN" << dendl;

  ldout(cct, 20) << __func__ << " accept got peer connect_seq "
                 << connect_msg.connect_seq << " global_seq "
                 << connect_msg.global_seq << dendl;

  connection->set_peer_type(connect_msg.host_type);
  connection->policy = messenger->get_policy(connect_msg.host_type);

  ldout(cct, 10) << __func__ << " accept of host_type " << connect_msg.host_type
                 << ", policy.lossy=" << connection->policy.lossy
                 << " policy.server=" << connection->policy.server
                 << " policy.standby=" << connection->policy.standby
                 << " policy.resetcheck=" << connection->policy.resetcheck
                 << dendl;

  memset(&connect_reply, 0, sizeof(connect_reply));
  connect_reply.protocol_version =
      messenger->get_proto_version(connection->peer_type, false);

  // mismatch?
  ldout(cct, 10) << __func__ << " accept my proto "
                 << connect_reply.protocol_version << ", their proto "
                 << connect_msg.protocol_version << dendl;

  if (connect_msg.protocol_version != connect_reply.protocol_version) {
    send_connect_message_reply(CEPH_MSGR_TAG_BADPROTOVER);
    ldout(cct, 20) << __func__ << " END" << dendl;
    return;
  }

  // require signatures for cephx?
  if (connect_msg.authorizer_protocol == CEPH_AUTH_CEPHX) {
    if (connection->peer_type == CEPH_ENTITY_TYPE_OSD ||
        connection->peer_type == CEPH_ENTITY_TYPE_MDS) {
      if (cct->_conf->cephx_require_signatures ||
          cct->_conf->cephx_cluster_require_signatures) {
        ldout(cct, 10)
            << __func__
            << " using cephx, requiring MSG_AUTH feature bit for cluster"
            << dendl;
        connection->policy.features_required |= CEPH_FEATURE_MSG_AUTH;
      }
    } else {
      if (cct->_conf->cephx_require_signatures ||
          cct->_conf->cephx_service_require_signatures) {
        ldout(cct, 10)
            << __func__
            << " using cephx, requiring MSG_AUTH feature bit for service"
            << dendl;
        connection->policy.features_required |= CEPH_FEATURE_MSG_AUTH;
      }
    }
  }

  uint64_t feat_missing =
      connection->policy.features_required & ~(uint64_t)connect_msg.features;
  if (feat_missing) {
    ldout(cct, 1) << __func__ << " peer missing required features " << std::hex
                  << feat_missing << std::dec << dendl;
    send_connect_message_reply(CEPH_MSGR_TAG_FEATURES);
    ldout(cct, 20) << __func__ << " END" << dendl;
    return;
  }

  connection->lock.unlock();

  bool authorizer_valid;
  if (!messenger->verify_authorizer(
          connection, connection->peer_type, connect_msg.authorizer_protocol,
          authorizer_buf, authorizer_reply, authorizer_valid,
          connection->session_key) ||
      !authorizer_valid) {
    connection->lock.lock();

    ldout(cct, 0) << __func__ << ": got bad authorizer" << dendl;
    connection->session_security.reset();
    send_connect_message_reply(CEPH_MSGR_TAG_BADAUTHORIZER);
    ldout(cct, 20) << __func__ << " END" << dendl;
    return;
  }

  // We've verified the authorizer for this AsyncConnection, so set up the
  // session security structure.  PLR
  ldout(cct, 10) << __func__ << " accept setting up session_security." << dendl;

  // existing?
  existing = messenger->lookup_conn(connection->peer_addr);

  connection->inject_delay();

  connection->lock.lock();
  if (_abort) {
    ldout(cct, 1) << __func__
                  << " state changed while accept, it must be mark_down"
                  << dendl;
    assert(connection->state == AsyncConnection::STATE_CLOSED);
    handle_failure(-1);
    ldout(cct, 20) << __func__ << " END" << dendl;
    return;
  }

  if (existing == connection) {
    existing = nullptr;
  }

  if (existing) {
    // There is no possible that existing connection will acquire this
    // connection's lock
    existing->lock.lock();  // skip lockdep check (we are locking a second
                            // AsyncConnection here)

    if (existing->state == AsyncConnection::STATE_CLOSED) {
      ldout(cct, 1) << __func__ << " existing already closed." << dendl;
      existing->lock.unlock();
      existing = nullptr;

      ldout(cct, 20) << __func__ << " END" << dendl;
      open();
      return;
    }

    ServerProtocolV1 *exproto =
        dynamic_cast<ServerProtocolV1 *>(existing->protocol.get());

    if (existing->replacing) {
      ldout(cct, 1) << __func__
                    << " existing racing replace happened while replacing."
                    << " existing_state="
                    << connection->get_state_name(existing->state) << dendl;
      connect_reply.global_seq = exproto->peer_global_seq;
      existing->lock.unlock();
      send_connect_message_reply(CEPH_MSGR_TAG_RETRY_GLOBAL);
      ldout(cct, 20) << __func__ << " END" << dendl;
      return;
    }

    if (connect_msg.global_seq < exproto->peer_global_seq) {
      ldout(cct, 10) << __func__ << " accept existing " << existing << ".gseq "
                     << exproto->peer_global_seq << " > "
                     << connect_msg.global_seq << ", RETRY_GLOBAL" << dendl;
      connect_reply.global_seq =
          exproto->peer_global_seq;  // so we can send it below..
      existing->lock.unlock();
      send_connect_message_reply(CEPH_MSGR_TAG_RETRY_GLOBAL);
      ldout(cct, 20) << __func__ << " END" << dendl;
      return;
    } else {
      ldout(cct, 10) << __func__ << " accept existing " << existing << ".gseq "
                     << exproto->peer_global_seq
                     << " <= " << connect_msg.global_seq << ", looks ok"
                     << dendl;
    }

    if (existing->policy.lossy) {
      ldout(cct, 0)
          << __func__
          << " accept replacing existing (lossy) channel (new one lossy="
          << connection->policy.lossy << ")" << dendl;
      exproto->session_reset();
      ldout(cct, 20) << __func__ << " END" << dendl;
      replace();
      return;
    }

    ldout(cct, 1) << __func__ << " accept connect_seq "
                  << connect_msg.connect_seq
                  << " vs existing csq=" << exproto->connect_seq
                  << " existing_state="
                  << connection->get_state_name(existing->state) << dendl;

    if (connect_msg.connect_seq == 0 && exproto->connect_seq > 0) {
      ldout(cct, 0)
          << __func__
          << " accept peer reset, then tried to connect to us, replacing"
          << dendl;
      // this is a hard reset from peer
      is_reset_from_peer = true;
      if (connection->policy.resetcheck) {
        exproto->session_reset();  // this resets out_queue, msg_ and
                                   // connect_seq #'s
      }
      ldout(cct, 20) << __func__ << " END" << dendl;
      replace();
      return;
    }

    if (connect_msg.connect_seq < exproto->connect_seq) {
      // old attempt, or we sent READY but they didn't get it.
      ldout(cct, 10) << __func__ << " accept existing " << existing << ".cseq "
                     << exproto->connect_seq << " > " << connect_msg.connect_seq
                     << ", RETRY_SESSION" << dendl;
      connect_reply.connect_seq = exproto->connect_seq + 1;
      existing->lock.unlock();
      send_connect_message_reply(CEPH_MSGR_TAG_RETRY_SESSION);
      ldout(cct, 20) << __func__ << " END" << dendl;
      return;
    }

    if (connect_msg.connect_seq == exproto->connect_seq) {
      // if the existing connection successfully opened, and/or
      // subsequently went to standby, then the peer should bump
      // their connect_seq and retry: this is not a connection race
      // we need to resolve here.
      if (existing->state == AsyncConnection::STATE_OPEN ||
          existing->state == AsyncConnection::STATE_STANDBY) {
        ldout(cct, 10) << __func__ << " accept connection race, existing "
                       << existing << ".cseq " << exproto->connect_seq
                       << " == " << connect_msg.connect_seq
                       << ", OPEN|STANDBY, RETRY_SESSION " << dendl;
        // if connect_seq both zero, dont stuck into dead lock. it's ok to
        // replace
        if (connection->policy.resetcheck && exproto->connect_seq == 0) {
          ldout(cct, 20) << __func__ << " END" << dendl;
          replace();
          return;
        }

        connect_reply.connect_seq = exproto->connect_seq + 1;
        existing->lock.unlock();
        send_connect_message_reply(CEPH_MSGR_TAG_RETRY_SESSION);
        ldout(cct, 20) << __func__ << " END" << dendl;
        return;
      }

      // connection race?
      if (connection->peer_addr < messenger->get_myaddr() ||
          existing->policy.server) {
        // incoming wins
        ldout(cct, 10) << __func__ << " accept connection race, existing "
                       << existing << ".cseq " << exproto->connect_seq
                       << " == " << connect_msg.connect_seq
                       << ", or we are server, replacing my attempt" << dendl;
        ldout(cct, 20) << __func__ << " END" << dendl;
        replace();
        return;
      } else {
        // our existing outgoing wins
        ldout(messenger->cct, 10)
            << __func__ << " accept connection race, existing " << existing
            << ".cseq " << exproto->connect_seq
            << " == " << connect_msg.connect_seq << ", sending WAIT" << dendl;
        assert(connection->peer_addr > messenger->get_myaddr());
        existing->lock.unlock();
        send_connect_message_reply(CEPH_MSGR_TAG_WAIT);
        ldout(cct, 20) << __func__ << " END" << dendl;
        return;
      }
    }

    assert(connect_msg.connect_seq > exproto->connect_seq);
    assert(connect_msg.global_seq >= exproto->peer_global_seq);
    if (connection->policy.resetcheck &&  // RESETSESSION only used by servers;
                                          // peers do not reset each other
        exproto->connect_seq == 0) {
      ldout(cct, 0) << __func__ << " accept we reset (peer sent cseq "
                    << connect_msg.connect_seq << ", " << existing
                    << ".cseq = " << exproto->connect_seq
                    << "), sending RESETSESSION " << dendl;
      existing->lock.unlock();
      send_connect_message_reply(CEPH_MSGR_TAG_RESETSESSION);
      ldout(cct, 20) << __func__ << " END" << dendl;
      return;
    }

    // reconnect
    ldout(cct, 10) << __func__ << " accept peer sent cseq "
                   << connect_msg.connect_seq << " > " << exproto->connect_seq
                   << dendl;
    ldout(cct, 20) << __func__ << " END" << dendl;
    replace();
    return;
  }  // existing
  else if (!connection->replacing && connect_msg.connect_seq > 0) {
    // we reset, and they are opening a new session
    ldout(cct, 0) << __func__ << " accept we reset (peer sent cseq "
                  << connect_msg.connect_seq << "), sending RESETSESSION"
                  << dendl;
    send_connect_message_reply(CEPH_MSGR_TAG_RESETSESSION);
    ldout(cct, 20) << __func__ << " END" << dendl;
    return;
  } else {
    // new session
    ldout(cct, 10) << __func__ << " accept new session" << dendl;
    existing = nullptr;
    ldout(cct, 20) << __func__ << " END" << dendl;
    open();
    return;
  }

  ldout(cct, 20) << __func__ << " END" << dendl;
}

void ServerProtocolV1::send_connect_message_reply(char tag) {
  ldout(cct, 20) << __func__ << " BEGIN" << dendl;
  bufferlist reply_bl;
  connect_reply.tag = tag;
  connect_reply.features =
      ((uint64_t)connect_msg.features & connection->policy.features_supported) |
      connection->policy.features_required;
  connect_reply.authorizer_len = authorizer_reply.length();
  reply_bl.append((char *)&connect_reply, sizeof(connect_reply));

  if (connect_reply.authorizer_len) {
    reply_bl.append(authorizer_reply.c_str(), authorizer_reply.length());
  }

  WRITE(reply_bl, &ServerProtocolV1::handle_connect_message_reply_write);

  ldout(cct, 20) << __func__ << " END" << dendl;
}

void ServerProtocolV1::handle_connect_message_reply_write(int r) {
  ldout(cct, 20) << __func__ << " BEGIN" << dendl;

  if (r < 0) {
    connection->inject_delay();
    handle_failure(r);
    ldout(cct, 20) << __func__ << " END" << dendl;
    return;
  }

  ldout(cct, 20) << __func__ << " END" << dendl;
  wait_connect_message();
}

void ServerProtocolV1::replace() {
  ldout(messenger->cct, 20) << __func__ << " BEGIN" << dendl;

  ldout(messenger->cct, 10)
      << __func__ << " accept replacing " << existing << dendl;

  connection->inject_delay();
  if (existing->policy.lossy) {
    // disconnect from the Connection
    ldout(messenger->cct, 1)
        << __func__ << " replacing on lossy channel, failing existing" << dendl;
    existing->_stop();
    existing->dispatch_queue->queue_reset(existing.get());
  } else {
    assert(connection->can_write == AsyncConnection::WriteStatus::NOWRITE);
    existing->write_lock.lock();

    // reset the in_seq if this is a hard reset from peer,
    // otherwise we respect our original connection's value
    ServerProtocolV1 *exproto =
        dynamic_cast<ServerProtocolV1 *>(existing->protocol.get());
    if (is_reset_from_peer) {
      exproto->is_reset_from_peer = true;
    }

    connection->center->delete_file_event(connection->cs.fd(),
                                          EVENT_READABLE | EVENT_WRITABLE);

    if (existing->delay_state) {
      existing->delay_state->flush();
      assert(!connection->delay_state);
    }
    existing->reset_recv_state();

    auto temp_cs = std::move(connection->cs);
    EventCenter *new_center = connection->center;
    Worker *new_worker = connection->worker;
    // avoid _stop shutdown replacing socket
    // queue a reset on the new connection, which we're dumping for the old
    connection->_stop();

    connection->dispatch_queue->queue_reset(connection);
    ldout(messenger->cct, 1)
        << __func__ << " stop myself to swap existing" << dendl;
    existing->can_write = AsyncConnection::WriteStatus::REPLACING;
    existing->replacing = true;
    existing->state_offset = 0;
    // avoid previous thread modify event
    existing->state = AsyncConnection::STATE_NONE;
    // Discard existing prefetch buffer in `recv_buf`
    existing->recv_start = existing->recv_end = 0;
    // there shouldn't exist any buffer
    assert(connection->recv_start == connection->recv_end);

    auto deactivate_existing = std::bind(
        [this, new_worker, new_center, exproto](ConnectedSocket &cs) mutable {
          // we need to delete time event in original thread
          {
            std::lock_guard<std::mutex> l(existing->lock);
            existing->write_lock.lock();
            existing->requeue_sent();
            existing->outcoming_bl.clear();
            existing->open_write = false;
            existing->write_lock.unlock();
            if (existing->state == AsyncConnection::STATE_NONE) {
              existing->shutdown_socket();
              existing->cs = std::move(cs);
              existing->worker->references--;
              new_worker->references++;
              existing->logger = new_worker->get_perf_counter();
              existing->worker = new_worker;
              existing->center = new_center;
              if (existing->delay_state)
                existing->delay_state->set_center(new_center);
            } else if (existing->state == AsyncConnection::STATE_CLOSED) {
              auto back_to_close =
                  std::bind([](ConnectedSocket &cs) mutable { cs.close(); },
                            std::move(cs));
              new_center->submit_to(new_center->get_id(),
                                    std::move(back_to_close), true);
              return;
            } else {
              ceph_abort();
            }
          }

          // Before changing existing->center, it may already exists some
          // events in existing->center's queue. Then if we mark down
          // `existing`, it will execute in another thread and clean up
          // connection. Previous event will result in segment fault
          auto transfer_existing = [this, exproto]() mutable {
            std::lock_guard<std::mutex> l(existing->lock);
            if (existing->state == AsyncConnection::STATE_CLOSED) return;
            assert(existing->state == AsyncConnection::STATE_NONE);

            existing->state = AsyncConnection::STATE_ACCEPTING_WAIT_CONNECT_MSG;
            exproto->state = INITIATING;
            existing->center->create_file_event(
                existing->cs.fd(), EVENT_READABLE, existing->read_handler);
            connect_reply.global_seq = exproto->peer_global_seq;
            exproto->send_connect_message_reply(CEPH_MSGR_TAG_RETRY_GLOBAL);
          };
          if (existing->center->in_thread())
            transfer_existing();
          else
            existing->center->submit_to(existing->center->get_id(),
                                        std::move(transfer_existing), true);
        },
        std::move(temp_cs));

    existing->center->submit_to(existing->center->get_id(),
                                std::move(deactivate_existing), true);
    existing->write_lock.unlock();
    existing->lock.unlock();
    return;
  }
  existing->lock.unlock();

  ldout(messenger->cct, 20) << __func__ << " END" << dendl;

  open();
}

void ServerProtocolV1::open() {
  ldout(cct, 20) << __func__ << " BEGIN" << dendl;

  connect_seq = connect_msg.connect_seq + 1;
  peer_global_seq = connect_msg.global_seq;
  ldout(cct, 10) << __func__ << " accept success, connect_seq = " << connect_seq
                 << " in_seq=" << in_seq << ", sending READY" << dendl;

  // if it is a hard reset from peer, we don't need a round-trip to negotiate
  // in/out sequence
  if ((connect_msg.features & CEPH_FEATURE_RECONNECT_SEQ) &&
      !is_reset_from_peer) {
    connect_reply.tag = CEPH_MSGR_TAG_SEQ;
    wait_for_seq = true;
  } else {
    connect_reply.tag = CEPH_MSGR_TAG_READY;
    wait_for_seq = false;
    out_seq = connection->discard_requeued_up_to(out_seq, 0);
    is_reset_from_peer = false;
    in_seq = 0;
  }

  // send READY reply
  connect_reply.features = connection->policy.features_supported;
  connect_reply.global_seq = messenger->get_global_seq();
  connect_reply.connect_seq = connect_seq;
  connect_reply.flags = 0;
  connect_reply.authorizer_len = authorizer_reply.length();
  if (connection->policy.lossy)
    connect_reply.flags = connect_reply.flags | CEPH_MSG_CONNECT_LOSSY;

  connection->set_features((uint64_t)connect_reply.features &
                           (uint64_t)connect_msg.features);
  ldout(cct, 10) << __func__ << " accept features "
                 << connection->get_features() << dendl;

  connection->session_security.reset(get_auth_session_handler(
      cct, connect_msg.authorizer_protocol, connection->session_key,
      connection->get_features()));

  bufferlist reply_bl;
  reply_bl.append((char *)&connect_reply, sizeof(connect_reply));

  if (connect_reply.authorizer_len) {
    reply_bl.append(authorizer_reply.c_str(), authorizer_reply.length());
  }

  if (connect_reply.tag == CEPH_MSGR_TAG_SEQ) {
    uint64_t s = in_seq;
    reply_bl.append((char *)&s, sizeof(s));
  }

  connection->lock.unlock();
  // Because "replacing" will prevent other connections preempt this addr,
  // it's safe that here we don't acquire Connection's lock
  ssize_t r = messenger->accept_conn(connection);

  connection->inject_delay();

  connection->lock.lock();
  bool replacing = false;
  if (r < 0) {
    ldout(cct, 1) << __func__ << " existing race replacing process for addr = "
                  << connection->peer_addr << " just fail later one(this)"
                  << dendl;
    ldout(cct, 10) << "accept fault after register" << dendl;
    connection->inject_delay();
    handle_failure();
    return;
  }
  if (state != INITIATING) {
    ldout(cct, 1) << __func__
                  << " state changed while accept_conn, it must be mark_down"
                  << dendl;
    assert(connection->state == AsyncConnection::STATE_CLOSED ||
           connection->state == AsyncConnection::STATE_NONE);
    ldout(cct, 10) << "accept fault after register" << dendl;
    connection->inject_delay();
    handle_failure();
    return;
  }

  WRITE(reply_bl, &ServerProtocolV1::handle_ready_connect_message_reply_write);

  ldout(cct, 20) << __func__ << " END" << dendl;
}

void ServerProtocolV1::handle_ready_connect_message_reply_write(int r) {
  ldout(cct, 20) << __func__ << " BEGIN" << dendl;

  if (r < 0) {
    handle_failure(r);
    ldout(cct, 20) << __func__ << " END" << dendl;
    return;
  }

  // notify
  connection->dispatch_queue->queue_accept(connection);
  messenger->ms_deliver_handle_fast_accept(connection);
  connection->once_ready = true;

  if (wait_for_seq) {
    wait_seq();
  } else {
    ready();
  }

  ldout(cct, 20) << __func__ << " END" << dendl;
}

void ServerProtocolV1::wait_seq() {
  ldout(cct, 20) << __func__ << " BEGIN" << dendl;

  READ(sizeof(uint64_t), &ServerProtocolV1::handle_seq);

  ldout(cct, 20) << __func__ << " END" << dendl;
}

void ServerProtocolV1::handle_seq(char *buffer, int r) {
  ldout(cct, 20) << __func__ << " BEGIN" << dendl;

  if (r < 0) {
    ldout(cct, 1) << __func__ << " read ack seq failed" << dendl;
    handle_failure(r);
    ldout(cct, 20) << __func__ << " END" << dendl;
    return;
  }

  uint64_t newly_acked_seq = *(uint64_t *)buffer;
  ldout(cct, 2) << __func__ << " accept get newly_acked_seq " << newly_acked_seq
                << dendl;
  out_seq = connection->discard_requeued_up_to(out_seq, newly_acked_seq);

  ldout(cct, 20) << __func__ << " END" << dendl;

  ready();
}

void ServerProtocolV1::ready() {
  ldout(cct, 20) << __func__ << " BEGIN" << dendl;

  ldout(cct, 20) << __func__ << " accept done" << dendl;
  connection->state = AsyncConnection::STATE_OPEN;
  memset(&connect_msg, 0, sizeof(connect_msg));

  if (connection->delay_state) {
    assert(connection->delay_state->ready());
  }
  // make sure no pending tick timer
  if (connection->last_tick_id) {
    connection->center->delete_time_event(connection->last_tick_id);
  }
  connection->last_tick_id = connection->center->create_time_event(
      connection->inactive_timeout_us, connection->tick_handler);

  connection->write_lock.lock();
  connection->can_write = AsyncConnection::WriteStatus::CANWRITE;
  if (connection->is_queued()) {
    connection->center->dispatch_event_external(connection->write_handler);
  }
  connection->write_lock.unlock();
  connection->maybe_start_delay_thread();

  ldout(cct, 20) << __func__ << " END" << dendl;

  state = OPENED;
  wait_message();
}
