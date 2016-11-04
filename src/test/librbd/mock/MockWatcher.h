// -*- mode:C; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab

#ifndef CEPH_TEST_LIBRBD_MOCK_WATCHER_H
#define CEPH_TEST_LIBRBD_MOCK_WATCHER_H

#include "librbd/Watcher.h"
#include "gmock/gmock.h"

class Context;

namespace librbd {

struct MockWatcher : public Watcher {

  MockWatcher(librados::IoCtx& ioctx) : Watcher(ioctx, nullptr, "test_oid") {}

  MOCK_CONST_METHOD0(is_registered, bool());
  MOCK_METHOD0(unregister_watch, void());
  MOCK_METHOD1(flush, void(Context *));

  MOCK_CONST_METHOD0(get_watch_handle, uint64_t());

  MOCK_METHOD0(notify_acquired_lock, void());
  MOCK_METHOD0(notify_released_lock, void());
  MOCK_METHOD0(notify_request_lock, void());

  MOCK_METHOD3(handle_notify, void(uint64_t, uint64_t, bufferlist&));
};

} // namespace librbd

#endif // CEPH_TEST_LIBRBD_MOCK_WATCHER_H
