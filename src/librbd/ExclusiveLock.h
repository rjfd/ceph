#ifndef CEPH_LIBRBD_EXCLUSIVE_LOCK_H
#define CEPH_LIBRBD_EXCLUSIVE_LOCK_H

#include "librbd/ManagedLock.h"
#include "librbd/ImageCtx.h"

namespace librbd {

template <typename ImageCtxT = ImageCtx>
class ExclusiveLock : public ManagedLock<ImageCtxT> {
public:
  static ExclusiveLock *create(ImageCtxT &image_ctx) {
    return new ExclusiveLock<ImageCtxT>(image_ctx);
  }

  ExclusiveLock(ImageCtxT &image_ctx);
  virtual ~ExclusiveLock();

  bool accept_requests(int *ret_val) const;

  void block_requests(int r);
  void unblock_requests();

  void init(uint64_t features, Context *on_init);
  void shut_down(Context *on_shutdown);
  virtual void shutdown_handler(int r, Context *on_finish);

  void try_lock(Context *on_tried_lock);
  void request_lock(Context *on_locked);
  virtual void pre_acquire_lock_handler(Context *on_finish);
  virtual void post_acquire_lock_handler(int r, Context *on_finish);

  void release_lock(Context *on_released);
  virtual void pre_release_lock_handler(bool shutting_down,
                                         Context *on_finish);
  virtual void post_release_lock_handler(bool shutting_down, int r,
                                          Context *on_finish);

  void reacquire_lock(Context *on_reacquired = nullptr);

  void handle_peer_notification();

  void assert_header_locked(librados::ObjectWriteOperation *op);

private:

  struct C_InitComplete : public Context {
    ExclusiveLock *exclusive_lock;
    Context *on_init;
    C_InitComplete(ExclusiveLock *exclusive_lock, Context *on_init)
      : exclusive_lock(exclusive_lock), on_init(on_init) {
    }
    virtual void finish(int r) override {
      if (r == 0) {
        exclusive_lock->handle_init_complete();
      }
      on_init->complete(r);
    }
  };

  ImageCtxT& m_image_ctx;

  uint32_t m_request_blocked_count = 0;
  int m_request_blocked_ret_val = 0;

  void handle_init_complete();
};

} // namespace librbd

#endif // CEPH_LIBRBD_EXCLUSIVE_LOCK_H
