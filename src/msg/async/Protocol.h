#ifndef _MSG_ASYNC_PROTOCOL_
#define _MSG_ASYNC_PROTOCOL_

#include <list>
#include <map>

#include "AsyncConnection.h"
#include "include/buffer.h"
#include "include/msgr.h"

class AsyncMessenger;

class Protocol {
protected:
  AsyncConnection *connection;
  AsyncMessenger *messenger;
  CephContext *cct;

public:
  Protocol(AsyncConnection *connection);
  virtual ~Protocol();
  virtual void init() = 0;
  virtual void abort() = 0;
  virtual void notify() = 0;
  virtual void reconnect() = 0;

  virtual void send_message(Message *m) = 0;
  virtual void write_event() = 0;
  virtual void fault() = 0;
  virtual bool has_queued_writes() = 0;
  virtual bool is_connected() = 0;
  virtual bool writes_allowed() = 0;
  virtual void send_keepalive() = 0;
};

class ProtocolV1 : public Protocol {
protected:
  enum State { NOT_INITIATED, INITIATING, OPENED, CLOSED };

  char *temp_buffer;

  enum class WriteStatus { NOWRITE, REPLACING, CANWRITE, CLOSED };
  std::atomic<WriteStatus> can_write;
  std::list<Message *> sent;  // the first bufferlist need to inject seq
  // priority queue for outbound msgs
  std::map<int, std::list<std::pair<bufferlist, Message *>>> out_q;
  bool keepalive;

  __u32 connect_seq, peer_global_seq;
  std::atomic<uint64_t> in_seq{0};
  std::atomic<uint64_t> out_seq{0};
  std::atomic<uint64_t> ack_left{0};

  // Open state
  ceph_msg_connect connect_msg;
  ceph_msg_connect_reply connect_reply;
  bufferlist authorizer_buf;

  utime_t recv_stamp;
  utime_t throttle_stamp;
  unsigned msg_left;
  uint64_t cur_msg_size;
  ceph_msg_header current_header;
  bufferlist data_buf;
  bufferlist::iterator data_blp;
  bufferlist front, middle, data;

  bool replacing;    // when replacing process happened, we will reply connect
                     // side with RETRY tag and accept side will clear replaced
                     // connection. So when connect side reissue connect_msg,
                     // there won't exists conflicting connection so we use
                     // "replacing" to skip RESETSESSION to avoid detect wrong
                     // presentation
  bool is_reset_from_peer;
  bool once_ready;

  State state;

  void handle_failure(int r = 0);
  bool _abort;

  void wait_message();
  void handle_message(char *buffer, int r);

  void handle_keepalive2(char *buffer, int r);
  void handle_keepalive2_ack(char *buffer, int r);
  void handle_tag_ack(char *buffer, int r);

  void handle_message_header(char *buffer, int r);
  void throttle_message();
  void read_message_front();
  void handle_message_front(char *buffer, int r);
  void read_message_middle();
  void handle_message_middle(char *buffer, int r);
  void read_message_data_prepare();
  void read_message_data();
  void handle_message_data(char *buffer, int r);
  void read_message_footer();
  void handle_message_footer(char *buffer, int r);

  void session_reset();
  void randomize_out_seq();

  Message *_get_next_outgoing(bufferlist *bl);
  bool _has_next_outgoing() const;

  void prepare_send_message(uint64_t features, Message *m, bufferlist &bl);
  ssize_t write_message(Message *m, bufferlist &bl, bool more);

  void requeue_sent();
  uint64_t discard_requeued_up_to(uint64_t out_seq, uint64_t seq);
  void discard_out_queue();

  ostream &_conn_prefix(std::ostream *_dout);

public:
  ProtocolV1(AsyncConnection *connection);
  virtual ~ProtocolV1();

  virtual void init() = 0;
  virtual void abort();
  virtual void notify();
  virtual void reconnect();

  virtual void send_message(Message *m);
  virtual void write_event();
  virtual void fault();
  virtual bool has_queued_writes();
  virtual bool is_connected();
  virtual bool writes_allowed();
  virtual void send_keepalive();
};

class LoopbackProtocolV1 : public ProtocolV1 {
public:
  LoopbackProtocolV1(AsyncConnection *connection) : ProtocolV1(connection) {
    this->can_write = WriteStatus::CANWRITE;
  }

  void init() override {}
};

class ClientProtocolV1 : public ProtocolV1 {
private:
  int global_seq;

  // Connecting state
  bool got_bad_auth;
  AuthAuthorizer *authorizer;

  void send_banner();
  void handle_banner_write(int r);
  void wait_server_banner();
  void handle_server_banner(char *buffer, int r);
  void handle_my_addr_write(int r);
  void send_connect_message();
  void handle_connect_message_write(int r);
  void wait_connect_reply();
  void handle_connect_reply_1(char *buffer, int r);

  void wait_connect_reply_auth();
  void handle_connect_reply_auth(char *buffer, int r);

  void handle_connect_reply_2();

  void wait_ack_seq();
  void handle_ack_seq(char *buffer, int r);
  void handle_in_seq_write(int r);

  void ready();

public:
  ClientProtocolV1(AsyncConnection *connection);

  virtual void init();
};

class ServerProtocolV1 : public ProtocolV1 {
private:
  bufferlist authorizer_reply;
  AsyncConnectionRef existing;
  bool is_reset_from_peer;
  bool wait_for_seq;

  void accept();
  void handle_banner_write(int r);
  void wait_client_banner();
  void handle_client_banner(char *buffer, int r);
  void wait_connect_message();
  void handle_connect_message_1(char *buffer, int r);

  void wait_connect_message_auth();
  void handle_connect_message_auth(char *buffer, int r);

  void handle_connect_message_2();

  void send_connect_message_reply(char tag);
  void handle_connect_message_reply_write(int r);

  void replace();
  void open();
  void handle_ready_connect_message_reply_write(int r);

  void wait_seq();
  void handle_seq(char *buffer, int r);

  void ready();

public:
  ServerProtocolV1(AsyncConnection *connection);
  virtual void init();
};

#endif /* _MSG_ASYNC_PROTOCOL_V1_ */