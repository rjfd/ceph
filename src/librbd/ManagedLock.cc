// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab

#include "librbd/ManagedLock.h"
#include "librbd/managed_lock/AcquireRequest.h"
#include "librbd/managed_lock/ReleaseRequest.h"
#include "librbd/managed_lock/ReacquireRequest.h"
#include "cls/lock/cls_lock_client.h"
#include "common/dout.h"
#include "common/errno.h"
#include "common/WorkQueue.h"
#include "librbd/Utils.h"
#include <sstream>

#include "librbd/ImageWatcher.h"
#include "librbd/ImageCtx.h"

#define dout_subsys ceph_subsys_rbd
#undef dout_prefix
#define dout_prefix *_dout << "librbd::ManagedLock: "

namespace librbd {

using namespace managed_lock;
using std::string;
using util::detail::C_AsyncCallback;

namespace {

const std::string WATCHER_LOCK_COOKIE_PREFIX = "auto";

template <typename R>
struct C_SendRequest : public Context {
  R* request;
  explicit C_SendRequest(R* request) : request(request) {
  }
  virtual void finish(int r) override {
    request->send();
  }
};

} // anonymous namespace

template <typename W>
const std::string ManagedLock<W>::WATCHER_LOCK_TAG("internal");

template <typename W>
ManagedLock<W>::ManagedLock(librados::IoCtx &ioctx, ContextWQ *work_queue,
                            const string& oid, W *watcher)
  : m_ioctx(ioctx), m_cct(reinterpret_cast<CephContext *>(ioctx.cct())),
    m_work_queue(work_queue),
    m_oid(oid),
    m_watcher(watcher),
    m_lock(util::unique_lock_name("librbd::ManagedLock<W>::m_lock", this)),
    m_state(STATE_UNLOCKED) {
}

template <typename W>
ManagedLock<W>::~ManagedLock() {
  Mutex::Locker locker(m_lock);
  assert(m_state == STATE_SHUTDOWN || m_state == STATE_UNLOCKED);
}

template <typename W>
bool ManagedLock<W>::is_lock_owner() const {
  Mutex::Locker locker(m_lock);

  bool lock_owner;

  switch (m_state) {
  case STATE_LOCKED:
  case STATE_REACQUIRING:
  case STATE_PRE_SHUTTING_DOWN:
    lock_owner = true;
    break;
  default:
    lock_owner = false;
    break;
  }

  ldout(m_cct, 20) << this << " " << __func__ << "=" << lock_owner
                   << dendl;
  return lock_owner;
}

template <typename W>
void ManagedLock<W>::shut_down(Context *on_shut_down) {
  ldout(m_cct, 10) << this << " " << __func__ << dendl;

  Mutex::Locker locker(m_lock);
  assert(!is_shutdown_locked());
  execute_action(ACTION_SHUT_DOWN, on_shut_down);
}

template <typename W>
void ManagedLock<W>::acquire_lock(Context *on_acquired) {
  int r = 0;
  {
    Mutex::Locker locker(m_lock);
    if (is_shutdown_locked()) {
      r = -ESHUTDOWN;
    } else if (m_state != STATE_LOCKED || !m_actions_contexts.empty()) {
      ldout(m_cct, 10) << this << " " << __func__ << dendl;
      execute_action(ACTION_ACQUIRE_LOCK, on_acquired);
      return;
    }
  }

  on_acquired->complete(r);
}

template <typename W>
void ManagedLock<W>::release_lock(Context *on_released) {
  int r = 0;
  {
    Mutex::Locker locker(m_lock);
    if (is_shutdown_locked()) {
      r = -ESHUTDOWN;
    } else if (m_state != STATE_UNLOCKED || !m_actions_contexts.empty()) {
      ldout(m_cct, 10) << this << " " << __func__ << dendl;
      execute_action(ACTION_RELEASE_LOCK, on_released);
      return;
    }
  }

  on_released->complete(r);
}

template <typename W>
void ManagedLock<W>::reacquire_lock(Context *on_reacquired) {
  {
    Mutex::Locker locker(m_lock);

    if (!is_shutdown_locked() &&
        (m_state == STATE_LOCKED || m_state == STATE_ACQUIRING)) {
      // interlock the lock operation with other state ops
      ldout(m_cct, 10) << this << " " << __func__ << dendl;
      execute_action(ACTION_REACQUIRE_LOCK, on_reacquired);
      return;
    }
  }

  // ignore request if shutdown or not in a locked-related state
  if (on_reacquired != nullptr) {
    on_reacquired->complete(0);
  }
}

template <typename W>
void ManagedLock<W>::assert_locked(librados::ObjectWriteOperation *op,
                          ClsLockType type) {
  Mutex::Locker locker(m_lock);
  rados::cls::lock::assert_locked(op, RBD_LOCK_NAME, type, m_cookie,
                                  WATCHER_LOCK_TAG);
}

template <typename W>
bool ManagedLock<W>::decode_lock_cookie(const std::string &tag,
                                        uint64_t *handle) {
  std::string prefix;
  std::istringstream ss(tag);
  if (!(ss >> prefix >> *handle) || prefix != WATCHER_LOCK_COOKIE_PREFIX) {
    return false;
  }
  return true;
}

template <typename W>
string ManagedLock<W>::encode_lock_cookie(uint64_t watch_handle) {
  assert(watch_handle != 0);
  std::ostringstream ss;
  ss << WATCHER_LOCK_COOKIE_PREFIX << " " << watch_handle;
  return ss.str();
}

template <typename W>
bool ManagedLock<W>::is_transition_state() const {
  switch (m_state) {
  case STATE_ACQUIRING:
  case STATE_REACQUIRING:
  case STATE_RELEASING:
  case STATE_PRE_SHUTTING_DOWN:
  case STATE_SHUTTING_DOWN:
    return true;
  case STATE_UNLOCKED:
  case STATE_LOCKED:
  case STATE_SHUTDOWN:
    break;
  }
  return false;
}

template <typename W>
void ManagedLock<W>::append_context(Action action, Context *ctx) {
  assert(m_lock.is_locked());

  for (auto &action_ctxs : m_actions_contexts) {
    if (action == action_ctxs.first) {
      if (ctx != nullptr) {
        action_ctxs.second.push_back(ctx);
      }
      return;
    }
  }

  Contexts contexts;
  if (ctx != nullptr) {
    contexts.push_back(ctx);
  }
  m_actions_contexts.push_back({action, std::move(contexts)});
}

template <typename W>
void ManagedLock<W>::execute_action(Action action, Context *ctx) {
  assert(m_lock.is_locked());

  append_context(action, ctx);
  if (!is_transition_state()) {
    execute_next_action();
  }
}

template <typename W>
void ManagedLock<W>::execute_next_action() {
  assert(m_lock.is_locked());
  assert(!m_actions_contexts.empty());
  switch (get_active_action()) {
  case ACTION_ACQUIRE_LOCK:
    send_acquire_lock();
    break;
  case ACTION_REACQUIRE_LOCK:
    send_reacquire_lock();
    break;
  case ACTION_RELEASE_LOCK:
    send_release_lock();
    break;
  case ACTION_SHUT_DOWN:
    send_shutdown();
    break;
  default:
    assert(false);
    break;
  }
}

template <typename W>
typename ManagedLock<W>::Action ManagedLock<W>::get_active_action() const {
  assert(m_lock.is_locked());
  assert(!m_actions_contexts.empty());
  return m_actions_contexts.front().first;
}

template <typename W>
void ManagedLock<W>::complete_active_action(State next_state, int r) {
  assert(m_lock.is_locked());
  assert(!m_actions_contexts.empty());

  ActionContexts action_contexts(std::move(m_actions_contexts.front()));
  m_actions_contexts.pop_front();
  m_state = next_state;

  m_lock.Unlock();
  for (auto ctx : action_contexts.second) {
    ctx->complete(r);
  }
  m_lock.Lock();

  if (!is_transition_state() && !m_actions_contexts.empty()) {
    execute_next_action();
  }
}

template <typename W>
bool ManagedLock<W>::is_shutdown_locked() const {
  assert(m_lock.is_locked());

  return ((m_state == STATE_SHUTDOWN) ||
          (!m_actions_contexts.empty() &&
           m_actions_contexts.back().first == ACTION_SHUT_DOWN));
}

template <typename W>
void ManagedLock<W>::send_acquire_lock() {
  assert(m_lock.is_locked());
  if (m_state == STATE_LOCKED) {
    complete_active_action(STATE_LOCKED, 0);
    return;
  }

  ldout(m_cct, 10) << this << " " << __func__ << dendl;
  m_state = STATE_ACQUIRING;

  assert(m_watcher->is_registered());
  uint64_t watch_handle = m_watcher->get_watch_handle();

  m_cookie = ManagedLock<W>::encode_lock_cookie(watch_handle);
  AcquireRequest<W>* req = AcquireRequest<W>::create(this,
    util::create_context_callback<
      ManagedLock<W>, &ManagedLock<W>::handle_acquire_lock>(this));
  m_work_queue->queue(new C_SendRequest<AcquireRequest<W>>(req), 0);
}

template <typename W>
void ManagedLock<W>::handle_acquire_lock(int r) {
  ldout(m_cct, 10) << this << " " << __func__ << ": r=" << r << dendl;

  if (r == -EBUSY || r == -EAGAIN) {
    ldout(m_cct, 5) << "unable to acquire exclusive lock" << dendl;
  } else if (r < 0) {
    lderr(m_cct) << "failed to acquire exclusive lock:" << cpp_strerror(r)
               << dendl;
  } else {
    ldout(m_cct, 5) << "successfully acquired exclusive lock" << dendl;
  }

  State next_state = (r < 0 ? STATE_UNLOCKED : STATE_LOCKED);
  if (r == -EAGAIN) {
    r = 0;
  }

  Mutex::Locker locker(m_lock);
  complete_active_action(next_state, r);
}

template <typename W>
void ManagedLock<W>::send_reacquire_lock() {
  assert(m_lock.is_locked());

  if (m_state != STATE_LOCKED) {
    complete_active_action(m_state, 0);
    return;
  }

  uint64_t watch_handle = m_watcher->get_watch_handle();
  if (watch_handle == 0) {
     // watch (re)failed while recovering
     lderr(m_cct) << this << " " << __func__ << ": "
                  << "aborting reacquire due to invalid watch handle" << dendl;
     complete_active_action(STATE_LOCKED, 0);
     return;
  }

  m_new_cookie = ManagedLock<W>::encode_lock_cookie(watch_handle);
  if (m_cookie == m_new_cookie) {
    ldout(m_cct, 10) << this << " " << __func__ << ": "
                   << "skipping reacquire since cookie still valid" << dendl;
    complete_active_action(STATE_LOCKED, 0);
    return;
  }

  ldout(m_cct, 10) << this << " " << __func__ << dendl;
  m_state = STATE_REACQUIRING;

  ReacquireRequest<W>* req = ReacquireRequest<W>::create(this, m_new_cookie,
    util::create_context_callback<
      ManagedLock, &ManagedLock<W>::handle_reacquire_lock>(this));
  req->send();
}

template <typename W>
void ManagedLock<W>::handle_reacquire_lock(int r) {
  Mutex::Locker locker(m_lock);

  ldout(m_cct, 10) << this << " " << __func__ << ": r=" << r << dendl;

  assert(m_state == STATE_REACQUIRING);
  if (r < 0) {
    if (r == -EOPNOTSUPP) {
      ldout(m_cct, 10) << this << " " << __func__ << ": "
                     << "updating lock is not supported" << dendl;
    } else {
      lderr(m_cct) << this << " " << __func__ << ": "
                 << "failed to update lock cookie: " << cpp_strerror(r)
                 << dendl;
    }

    if (!is_shutdown_locked()) {
      // queue a release and re-acquire of the lock since cookie cannot
      // be updated on older OSDs
      execute_action(ACTION_RELEASE_LOCK, nullptr);

      assert(!m_actions_contexts.empty());
      ActionContexts &action_contexts(m_actions_contexts.front());

      // reacquire completes when the request lock completes
      Contexts contexts;
      std::swap(contexts, action_contexts.second);
      if (contexts.empty()) {
        execute_action(ACTION_ACQUIRE_LOCK, nullptr);
      } else {
        for (auto ctx : contexts) {
          ctx = new FunctionContext([ctx, r](int acquire_ret_val) {
              if (acquire_ret_val >= 0) {
                acquire_ret_val = r;
              }
              ctx->complete(acquire_ret_val);
            });
          execute_action(ACTION_ACQUIRE_LOCK, ctx);
        }
      }
    }
  } else {
    m_cookie = m_new_cookie;
  }

  complete_active_action(STATE_LOCKED, 0);
}

template <typename W>
void ManagedLock<W>::send_release_lock() {
  assert(m_lock.is_locked());
  if (m_state == STATE_UNLOCKED) {
    complete_active_action(STATE_UNLOCKED, 0);
    return;
  }

  ldout(m_cct, 10) << this << " " << __func__ << dendl;
  m_state = STATE_RELEASING;

  ReleaseRequest<W>* req = ReleaseRequest<W>::create(this,
    util::create_context_callback<
      ManagedLock<W>, &ManagedLock<W>::handle_release_lock>(this));
  m_work_queue->queue(new C_SendRequest<ReleaseRequest<W>>(req), 0);
}

template <typename W>
void ManagedLock<W>::handle_release_lock(int r) {
  Mutex::Locker locker(m_lock);
  ldout(m_cct, 10) << this << " " << __func__ << ": r=" << r
                             << dendl;

  assert(m_state == STATE_RELEASING);
  if (r >= 0) {
    m_cookie = "";
  }
  complete_active_action(r < 0 ? STATE_LOCKED : STATE_UNLOCKED, r);
}

template <typename W>
void ManagedLock<W>::send_shutdown() {
  assert(m_lock.is_locked());
  if (m_state == STATE_UNLOCKED) {
    m_state = STATE_SHUTTING_DOWN;
    m_work_queue->queue(util::create_context_callback<
      ManagedLock, &ManagedLock<W>::complete_shutdown>(this), 0);
    return;
  }

  ldout(m_cct, 10) << this << " " << __func__ << dendl;
  assert(m_state == STATE_LOCKED);
  m_state = STATE_PRE_SHUTTING_DOWN;

  m_lock.Unlock();
  m_work_queue->queue(new C_ShutDownRelease(this), 0);
  m_lock.Lock();
}

template <typename W>
void ManagedLock<W>::send_shutdown_release() {
  std::string cookie;
  {
    Mutex::Locker locker(m_lock);
    cookie = m_cookie;
  }

  ReleaseRequest<W>* req = ReleaseRequest<W>::create(this,
    util::create_context_callback<
      ManagedLock, &ManagedLock<W>::complete_shutdown>(this));
  req->send();
}

template <typename W>
void ManagedLock<W>::complete_shutdown(int r) {
  ldout(m_cct, 10) << this << " " << __func__ << ": r=" << r << dendl;

  if (r < 0) {
    lderr(m_cct) << "failed to shut down lock: " << cpp_strerror(r)
               << dendl;
  }

  ActionContexts action_contexts;
  {
    Mutex::Locker locker(m_lock);
    assert(m_lock.is_locked());
    assert(m_actions_contexts.size() == 1);

    action_contexts = std::move(m_actions_contexts.front());
    m_actions_contexts.pop_front();
    m_state = STATE_SHUTDOWN;
  }

  // expect to be destroyed after firing callback
  for (auto ctx : action_contexts.second) {
    ctx->complete(r);
  }
}

} // namespace librbd

template class librbd::ManagedLock<librbd::ImageWatcher<librbd::ImageCtx>>;

