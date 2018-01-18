#ifndef CEPH_MSG_CLIENT_STREAM_H
#define CEPH_MSG_CLIENT_STREAM_H

#include "Stream.h"

class ClientStream : public Stream {
  public:
    ClientStream(AsyncConnection *conn, uint32_t stream_id);

    virtual void connection_ready();

  protected:
    virtual void process_message(TagMsg &msg);

    void execute_waiting_auth_setup_state(TagMsg &msg);

    void send_new_stream();
    void send_set_auth_method(__le32 *allowed_methods, uint32_t num_methods);

    void handle_auth_bad_method(__le32 method, __le32 num_methods,
                                __le32 *allowed_methods);
};

#endif /* CEPH_MSG_CLIENT_STREAM_H */
