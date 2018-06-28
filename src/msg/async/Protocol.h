#ifndef _MSG_ASYNC_PROTOCOL_
#define _MSG_ASYNC_PROTOCOL_

class AsyncConnection;
class AsyncMessenger;

class Protocol {
protected:
  AsyncConnection *connection;
  AsyncMessenger *messenger;

public:
  Protocol(AsyncConnection *connection);
  virtual ~Protocol();
  virtual void init() = 0;
  virtual void abort() = 0;
};

class ProtocolV1 : public Protocol {
protected:
  enum {
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
    STATE_CONNECTING,
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
  };

  void handle_failure(int r=0);
  bool _abort;

public:
  ProtocolV1(AsyncConnection *connection);

  virtual void init() = 0;
  virtual void abort();
};

class ClientProtocolV1 : public ProtocolV1 {
private:
  void send_banner();
  void handle_banner_write(int r);
  void wait_server_banner();
  void handle_server_banner(char *buffer, int r);
  void handle_my_addr_write(int r);
  void send_connect_message();

public:
  ClientProtocolV1(AsyncConnection *connection);

  virtual void init();
};

class ServerProtocolV1 : public ProtocolV1 {
private:
  void accept();
  void handle_banner_write(int r);
  void wait_client_banner();
  void handle_client_banner(char *buffer, int r);
  void wait_connect_message();

public:
  ServerProtocolV1(AsyncConnection *connection);
  virtual void init();
};

#endif /* _MSG_ASYNC_PROTOCOL_V1_ */