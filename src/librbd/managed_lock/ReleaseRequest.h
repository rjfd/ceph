// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab

#ifndef CEPH_LIBRBD_LOCK_RELEASE_REQUEST_H
#define CEPH_LIBRBD_LOCK_RELEASE_REQUEST_H

#include "include/rados/librados.hpp"
#include <string>

class Context;
class ContextWQ;

namespace librbd {

template <typename> class ManagedLock;

namespace managed_lock {

template <typename Watcher>
class ReleaseRequest {
public:
  static ReleaseRequest* create(ManagedLock<Watcher> *managed_lock,
                                Context *on_finish);

  ~ReleaseRequest();
  void send();

private:
  /**
   * @verbatim
   *
   * <start>
   *    |
   *    v
   * UNLOCK
   *    |
   *    v
   * <finish>
   *
   * @endverbatim
   */

  ReleaseRequest(ManagedLock<Watcher> *managed_lock, Context *on_finish);

  librados::IoCtx& m_ioctx;
  Watcher *m_watcher;
  std::string m_oid;
  std::string m_cookie;
  Context *m_on_finish;

  void send_unlock();
  void handle_unlock(int r);

  void finish();

};

} // namespace managed_lock
} // namespace librbd

#endif // CEPH_LIBRBD_LOCK_RELEASE_REQUEST_H
