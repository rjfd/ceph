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
    AsyncConnection *conn;
    uint32_t stream_id;
    uint64_t features;

    ostream& _conn_prefix(std::ostream *_dout);

  public:
    Stream(AsyncConnection *conn, uint32_t stream_id);

    virtual ~Stream();

    virtual int send_message(Message *m);

    virtual void send_keepalive();

    virtual void mark_down();

    virtual void mark_disposable();

    virtual bool is_connected();

    int process_frame(char *payload, uint32_t len);

}; /* Stream */

typedef boost::intrusive_ptr<Stream> StreamRef;

#endif /* CEPH_MSG_STREAM_H */
