#ifndef CEPH_MSG_STREAM_H
#define CEPH_MSG_STREAM_H

#include <mutex>

#include "msg/Connection.h"

class AsyncConnection;

/**
 * A Stream is a logical connection between two endpoints.
 * A connection is "physical" connection between two endpoints.
 * A connection may host several streams.
 * A stream is associated with a single connection
 */
class Stream : public Connection {
  protected:
    enum class State : int {
      STATE_WAITING_AUTH_SETUP,
      STATE_AUTH_SETUP
    };

    enum class Tag : char {
      TAG_AUTH_SET_METHOD,
      TAG_AUTH_BAD_METHOD,
      TAG_AUTH_REQUEST,
      TAG_AUTH_REPLY
    };

    struct TagMsg {
      Tag tag;
      char *payload;
      uint32_t len;
    };

    AsyncConnection *conn;
    uint32_t stream_id;
    uint64_t features;
    State state;
    std::mutex lock;

    uint32_t auth_method;

    ostream& _conn_prefix(std::ostream *_dout);

    int send_message(Tag tag, char *payload, uint32_t len);

    virtual void process_message(TagMsg &msg) = 0;

  public:
    Stream(AsyncConnection *conn, uint32_t stream_id);

    virtual ~Stream();

    virtual int send_message(Message *m);

    virtual void send_keepalive();

    virtual void mark_down();

    virtual void mark_disposable();

    virtual bool is_connected();

    int process_frame(char *payload, uint32_t len);

    virtual void connection_ready();

}; /* Stream */

typedef boost::intrusive_ptr<Stream> StreamRef;

#endif /* CEPH_MSG_STREAM_H */
