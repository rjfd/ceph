// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab

#ifndef CEPH_LIBRBD_EXCLUSIVE_LOCK_ACQUIRE_REQUEST_H
#define CEPH_LIBRBD_EXCLUSIVE_LOCK_ACQUIRE_REQUEST_H

#include "include/int_types.h"
#include "include/buffer.h"
#include "librbd/ImageCtx.h"
#include "msg/msg_types.h"
#include <string>

class Context;

namespace librbd {

template <typename> class Journal;
template <typename> class ManagedLock;

namespace exclusive_lock {

template <typename ImageCtxT = ImageCtx>
class AcquireRequest {
private:
  ImageCtxT &m_image_ctx;

public:
  typedef ManagedLock<typename std::decay<decltype(*m_image_ctx.image_watcher)>::type> LockT;

  static AcquireRequest* create(ImageCtxT &image_ctx, LockT *managed_lock,
                                Context *on_acquire, Context *on_finish);

  ~AcquireRequest();
  void send();

private:

  /**
   * @verbatim
   *
   * <start>
   *    |
   *    v
   * PREPARE_LOCK
   *    |
   *    v
   * FLUSH_NOTIFIES
   *    |
   *    |
   *    |
   *    \--> LOCK_IMAGE
   *              |
   *              v
   *         REFRESH (skip if not
   *              |   needed)
   *              v
   *         OPEN_OBJECT_MAP (skip if
   *              |           disabled)
   *              v
   *         OPEN_JOURNAL (skip if
   *              |   *     disabled)
   *              |   *
   *              |   * * * * * * * *
   *              v                 *
   *          ALLOCATE_JOURNAL_TAG  *
   *              |            *    *
   *              |            *    *
   *              |            v    v
   *              |         CLOSE_JOURNAL
   *              |               |
   *              |               v
   *              |         CLOSE_OBJECT_MAP
   *              |               |
   *              |               v
   *              |         UNLOCK_IMAGE
   *              |               |
   *              v               |
   *          <finish> <----------/
   *
   * @endverbatim
   */

  AcquireRequest(ImageCtxT &image_ctx, LockT *managed_lock,
                 Context *on_acquire, Context *on_finish);

  LockT *m_managed_lock;
  Context *m_on_acquire;
  Context *m_on_finish;

  decltype(m_image_ctx.object_map) m_object_map;
  decltype(m_image_ctx.journal) m_journal;

  int m_error_result;
  bool m_prepare_lock_completed = false;

  void send_prepare_lock();
  void handle_prepare_lock(int r);

  void send_flush_notifies();
  void handle_flush_notifies(int r);

  void send_lock();
  void handle_lock(int r);

  void send_refresh();
  void handle_refresh(int r);

  void send_open_journal();
  void handle_open_journal(int r);

  void send_allocate_journal_tag();
  void handle_allocate_journal_tag(int r);

  void send_open_object_map();
  void handle_open_object_map(int r);

  void send_close_journal();
  void handle_close_journal(int r);

  void send_close_object_map();
  void handle_close_object_map(int r);

  void send_unlock();
  void handle_unlock(int r);

  void send_get_lockers();
  void handle_get_lockers(int r);

  void send_get_watchers();
  void handle_get_watchers(int r);

  void send_blacklist();
  void handle_blacklist(int r);

  void send_break_lock();
  void handle_break_lock(int r);

  void apply();
  void revert(int r);

  void finish();

  void save_result(int result) {
    if (m_error_result == 0 && result < 0) {
      m_error_result = result;
    }
  }
};

} // namespace exclusive_lock
} // namespace librbd

extern template class librbd::exclusive_lock::AcquireRequest<librbd::ImageCtx>;

#endif // CEPH_LIBRBD_EXCLUSIVE_LOCK_ACQUIRE_REQUEST_H
