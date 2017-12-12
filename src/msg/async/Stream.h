#ifndef CEPH_MSG_STREAM_H
#define CEPH_MSG_STREAM_H

#include "msg/Connection.h"

class AsyncConnection;

/**
 * A Stream is a logical connection between two endpoints.
 * A connection is "physical" connection between two endpoints.
 * A connection may host several streams.
 * A stream is associated with a single connection
 */
class Stream : public Connection {
  private:
    uint32_t stream_id;
    uint64_t features;
    AsyncConnection *conn;

  public:
    Stream(CephContext *cct, Messenger *m);

    virtual ~Stream();

    virtual int send_message(Message *m);

    virtual void send_keepalive();

    virtual void mark_down();

    virtual void mark_disposable();

    virtual bool is_connected();

}; /* Stream */

typedef boost::intrusive_ptr<Stream> StreamRef;

#endif /* CEPH_MSG_STREAM_H */
