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
  private:
    enum class State : int {
      STATE_SERVER_WAITING_AUTH_SETUP,
      STATE_CLIENT_WAITING_AUTH_SETUP,
      STATE_SET_AUTH_METHOD
    };

    enum class Tag : char {
      TAG_NEW_STREAM = 0,
      TAG_AUTH_METHODS,
      TAG_AUTH_SET_METHOD,
      TAG_AUTH_BAD_METHOD
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

    void execute_server_waiting_auth_setup_state(TagMsg &msg);
    void execute_client_waiting_auth_setup_state(TagMsg &msg);

    void process_message(TagMsg &msg);
    int send_message(Tag tag, char *payload, uint32_t len);

    void send_new_stream();
    void send_auth_methods();
    void send_set_auth_method(__le32 *allowed_methods, uint32_t num_methods);

    void handle_auth_methods(__le32 *allowed_methods, uint32_t num_methods);
    void handle_auth_set_method(__le32 method);
    void handle_auth_bad_method(__le32 method, __le32 num_methods,
                                __le32 *allowed_methods);

  public:
    Stream(AsyncConnection *conn, uint32_t stream_id);

    virtual ~Stream();

    virtual int send_message(Message *m);

    virtual void send_keepalive();

    virtual void mark_down();

    virtual void mark_disposable();

    virtual bool is_connected();

    int process_frame(char *payload, uint32_t len);

    void connection_ready();

}; /* Stream */

typedef boost::intrusive_ptr<Stream> StreamRef;

#endif /* CEPH_MSG_STREAM_H */
