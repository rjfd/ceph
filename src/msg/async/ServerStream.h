#ifndef CEPH_MSG_SERVER_STREAM_H
#define CEPH_MSG_SERVER_STREAM_H

#include "Stream.h"

class ServerStream : public Stream {
  protected:
    uint32_t peer_type;

  public:
    ServerStream(AsyncConnection *conn, uint32_t stream_id);

  protected:
    virtual void process_message(TagMsg &msg);

    void execute_new_stream_state(TagMsg &msg);
    void execute_waiting_auth_setup_state(TagMsg &msg);
    void execute_auth_setup_state(TagMsg &msg);

    void handle_new_stream(__le32 peer_type);
    int handle_auth_set_method(__le32 method);
    int handle_auth_request(__le32 len, char *auth_payload);
};

#endif /* CEPH_MSG_SERVER_STREAM_H */
