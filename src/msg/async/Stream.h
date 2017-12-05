#ifndef CEPH_MSG_STREAM_H
#define CEPH_MSG_STREAM_H

#include "msg/Connection.h"
#include "AsyncConnection.h"

/**
 * A Stream is a logical connection between two endpoints.
 * A connection is "physical" connection between two endpoints.
 * A connection may host several streams.
 * A stream is associated with a single connection
 */
class Stream : public Connection {
  private:
    AsyncConnectionRef conn;
  public:
    Stream(CephContext *cct, Messenger *m, AsyncConnectionRef conn) :
      Connection(cct, m),
      conn(conn) {
    }

    virtual ~Stream() override {
      Connection::~Connection();
    }

    virtual int send_message(Message *m) {
      return conn->send_message(m);
    }

    virtual void send_keepalive() {
      conn->send_keepalive();
    }

    virtual void mark_down() {
      conn->mark_down();
    }

    virtual void mark_disposable() {
      conn->mark_disposable();
    }
};

#endif /* CEPH_MSG_STREAM_H */
