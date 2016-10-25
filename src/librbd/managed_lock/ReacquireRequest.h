// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab

#ifndef CEPH_LIBRBD_LOCK_REACQUIRE_REQUEST_H
#define CEPH_LIBRBD_LOCK_REACQUIRE_REQUEST_H

#include "include/rados/librados.hpp"
#include "include/int_types.h"
#include <string>

class Context;

namespace librbd {

template <typename> class ManagedLock;

namespace managed_lock {

template <typename Watcher>
class ReacquireRequest {
public:

  static ReacquireRequest *create(ManagedLock<Watcher> *managed_lock,
                                  const std::string &new_cookie,
                                  Context *on_finish) {
    return new ReacquireRequest(managed_lock, new_cookie, on_finish);
  }

  ReacquireRequest(ManagedLock<Watcher> * ManagedLock,
                   const std::string &new_cookie, Context *on_finish);

  void send();

private:
  /**
   * @verbatim
   *
   * <start>
   *    |
   *    v
   * SET_COOKIE
   *    |
   *    v
   * <finish>
   *
   * @endverbatim
   */
  librados::IoCtx& m_ioctx;
  std::string m_oid;
  std::string m_old_cookie;
  std::string m_new_cookie;
  Context *m_on_finish;

  void set_cookie();
  void handle_set_cookie(int r);

};

} // namespace managed_lock
} // namespace librbd

#endif // CEPH_LIBRBD_LOCK_REACQUIRE_REQUEST_H
