// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab

#include "librbd/managed_lock/ReacquireRequest.h"
#include "librbd/ManagedLock.h"
#include "cls/lock/cls_lock_client.h"
#include "cls/lock/cls_lock_types.h"
#include "common/dout.h"
#include "common/errno.h"
#include "librbd/Utils.h"

#include "librbd/ImageWatcher.h"
#include "librbd/ImageCtx.h"

#define dout_subsys ceph_subsys_rbd
#undef dout_prefix
#define dout_prefix *_dout << "librbd::managed_lock::ReacquireRequest: " \
                           << this << ": " << __func__

using std::string;

namespace librbd {
namespace managed_lock {

using librbd::util::create_rados_safe_callback;

template <typename W>
ReacquireRequest<W>::ReacquireRequest(ManagedLock<W> *managed_lock,
                                   const std::string &new_cookie,
                                   Context *on_finish)
  : m_ioctx(managed_lock->io_ctx()), m_oid(managed_lock->oid()),
    m_old_cookie(managed_lock->cookie()), m_new_cookie(new_cookie),
    m_on_finish(on_finish) {
}


template <typename W>
void ReacquireRequest<W>::send() {
  set_cookie();
}

template <typename W>
void ReacquireRequest<W>::set_cookie() {
  CephContext *cct = reinterpret_cast<CephContext *>(m_ioctx.cct());
  ldout(cct, 10) << dendl;

  librados::ObjectWriteOperation op;
  rados::cls::lock::set_cookie(&op, RBD_LOCK_NAME, LOCK_EXCLUSIVE, m_old_cookie,
                               ManagedLock<W>::WATCHER_LOCK_TAG, m_new_cookie);

  librados::AioCompletion *rados_completion = create_rados_safe_callback<
    ReacquireRequest, &ReacquireRequest::handle_set_cookie>(this);
  int r = m_ioctx.aio_operate(m_oid, rados_completion, &op);
  assert(r == 0);
  rados_completion->release();
}

template <typename W>
void ReacquireRequest<W>::handle_set_cookie(int r) {
  CephContext *cct = reinterpret_cast<CephContext *>(m_ioctx.cct());
  ldout(cct, 10) << ": r=" << r << dendl;

  if (r == -EOPNOTSUPP) {
    ldout(cct, 10) << ": OSD doesn't support updating lock" << dendl;
  } else if (r < 0) {
    lderr(cct) << ": failed to update lock: " << cpp_strerror(r) << dendl;
  }

  m_on_finish->complete(r);
  delete this;
}

} // namespace managed_lock
} // namespace librbd

template class librbd::managed_lock::ReacquireRequest<
  librbd::ImageWatcher<librbd::ImageCtx>>;
