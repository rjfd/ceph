// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab

#include "librbd/managed_lock/ReleaseRequest.h"
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
#define dout_prefix *_dout << "librbd::managed_lock::ReleaseRequest: "

namespace librbd {
namespace managed_lock {

using util::detail::C_AsyncCallback;
using util::create_context_callback;
using util::create_rados_safe_callback;

template <typename W>
ReleaseRequest<W>* ReleaseRequest<W>::create(ManagedLock<W> *managed_lock,
                                       Context *on_finish) {
  return new ReleaseRequest(managed_lock, on_finish);
}

template <typename W>
ReleaseRequest<W>::ReleaseRequest(ManagedLock<W> *managed_lock,
                                  Context *on_finish)
  : m_ioctx(managed_lock->io_ctx()), m_watcher(managed_lock->watcher()),
    m_oid(managed_lock->oid()), m_cookie(managed_lock->cookie()),
    m_on_finish(new C_AsyncCallback<ContextWQ>(managed_lock->work_queue(),
                                               on_finish)) {
}

template <typename W>
ReleaseRequest<W>::~ReleaseRequest() {
}


template <typename W>
void ReleaseRequest<W>::send() {
  send_unlock();
}

template <typename W>
void ReleaseRequest<W>::send_unlock() {
  CephContext *cct = reinterpret_cast<CephContext *>(m_ioctx.cct());
  ldout(cct, 10) << __func__ << dendl;

  librados::ObjectWriteOperation op;
  rados::cls::lock::unlock(&op, RBD_LOCK_NAME, m_cookie);

  using klass = ReleaseRequest;
  librados::AioCompletion *rados_completion =
    create_rados_safe_callback<klass, &klass::handle_unlock>(this);
  int r = m_ioctx.aio_operate(m_oid, rados_completion, &op);
  assert(r == 0);
  rados_completion->release();
}

template <typename W>
void ReleaseRequest<W>::handle_unlock(int r) {
  CephContext *cct = reinterpret_cast<CephContext *>(m_ioctx.cct());
  ldout(cct, 10) << __func__ << ": r=" << r << dendl;

  if (r < 0 && r != -ENOENT) {
    lderr(cct) << "failed to unlock: " << cpp_strerror(r) << dendl;
  }

  finish();
}

template <typename W>
void ReleaseRequest<W>::finish() {
  m_on_finish->complete(0);
  delete this;
}

} // namespace managed_lock
} // namespace librbd

template class librbd::managed_lock::ReleaseRequest<
  librbd::ImageWatcher<librbd::ImageCtx>>;

