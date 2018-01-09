#ifndef CEPH_MSG_SERVER_STREAM_H
#define CEPH_MSG_SERVER_STREAM_H

#include "Stream.h"

class ServerStream : public Stream {
  public:
    ServerStream(AsyncConnection *conn, uint32_t stream_id);

  protected:
    virtual void process_message(TagMsg &msg);
  
    void execute_waiting_auth_setup_state(TagMsg &msg);

    void handle_auth_set_method(__le32 method);
};

#endif /* CEPH_MSG_SERVER_STREAM_H */
