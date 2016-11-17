// -*- mode:C; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab

#include "test/librbd/test_mock_fixture.h"
#include "test/librbd/test_support.h"
#include "test/librbd/mock/MockImageCtx.h"
#include "test/librbd/mock/MockImageWatcher.h"
#include "test/librbd/mock/MockJournal.h"
#include "test/librbd/mock/MockObjectMap.h"
#include "test/librados_test_stub/MockTestMemIoCtxImpl.h"
#include "librbd/exclusive_lock/ReleaseRequest.h"
#include "librbd/ManagedLock.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include <list>

// template definitions
#include "librbd/exclusive_lock/ReleaseRequest.cc"
template class librbd::exclusive_lock::ReleaseRequest<librbd::MockImageCtx>;

#include "librbd/ManagedLock.cc"
template class librbd::ManagedLock<librbd::MockImageWatcher>;

namespace librbd {

using librbd::ManagedLock;
using librbd::MockImageWatcher;

namespace exclusive_lock {

namespace {

struct MockContext : public Context {
  MOCK_METHOD1(complete, void(int));
  MOCK_METHOD1(finish, void(int));
};

} // anonymous namespace

using ::testing::_;
using ::testing::InSequence;
using ::testing::Invoke;
using ::testing::Return;
using ::testing::StrEq;

static const std::string TEST_COOKIE("auto 123");

class TestMockExclusiveLockReleaseRequest : public TestMockFixture {
public:
  typedef ReleaseRequest<MockImageCtx> MockReleaseRequest;
  typedef ManagedLock<MockImageWatcher> MockManagedLock;

  void expect_complete_context(MockContext &mock_context, int r) {
    EXPECT_CALL(mock_context, complete(r));
  }

  void expect_test_features(MockImageCtx &mock_image_ctx, uint64_t features,
                            bool enabled) {
    EXPECT_CALL(mock_image_ctx, test_features(features))
                  .WillOnce(Return(enabled));
  }

  void expect_set_require_lock_on_read(MockImageCtx &mock_image_ctx) {
    EXPECT_CALL(*mock_image_ctx.aio_work_queue, set_require_lock_on_read());
  }

  void expect_block_writes(MockImageCtx &mock_image_ctx, int r) {
    expect_test_features(mock_image_ctx, RBD_FEATURE_JOURNALING,
                         ((mock_image_ctx.features & RBD_FEATURE_JOURNALING) != 0));
    if ((mock_image_ctx.features & RBD_FEATURE_JOURNALING) != 0) {
      expect_set_require_lock_on_read(mock_image_ctx);
    }
    EXPECT_CALL(*mock_image_ctx.aio_work_queue, block_writes(_))
                  .WillOnce(CompleteContext(r, mock_image_ctx.image_ctx->op_work_queue));
  }

  void expect_unblock_writes(MockImageCtx &mock_image_ctx) {
    EXPECT_CALL(*mock_image_ctx.aio_work_queue, unblock_writes());
  }

  void expect_cancel_op_requests(MockImageCtx &mock_image_ctx, int r) {
    EXPECT_CALL(mock_image_ctx, cancel_async_requests(_))
                  .WillOnce(CompleteContext(r, mock_image_ctx.image_ctx->op_work_queue));
  }

  void expect_unlock(MockImageCtx &mock_image_ctx, int r) {
    EXPECT_CALL(get_mock_io_ctx(mock_image_ctx.md_ctx),
                exec(mock_image_ctx.header_oid, _, StrEq("lock"), StrEq("unlock"), _, _, _))
                  .WillOnce(Return(r));
  }

  void expect_get_watch_handle(MockImageCtx &mock_image_ctx,
                               uint64_t watch_handle = 1234567890) {
    EXPECT_CALL(*mock_image_ctx.image_watcher, is_registered())
      .WillOnce(Return(true));
    EXPECT_CALL(*mock_image_ctx.image_watcher, get_watch_handle())
                  .WillRepeatedly(Return(watch_handle));
  }

  void expect_lock(MockImageCtx &mock_image_ctx, int r) {
    EXPECT_CALL(get_mock_io_ctx(mock_image_ctx.md_ctx),
                exec(mock_image_ctx.header_oid, _, StrEq("lock"), StrEq("lock"), _, _, _))
                  .WillOnce(Return(r));
  }


  void expect_close_journal(MockImageCtx &mock_image_ctx,
                           MockJournal &mock_journal, int r) {
    EXPECT_CALL(mock_journal, close(_))
                  .WillOnce(CompleteContext(r, mock_image_ctx.image_ctx->op_work_queue));
  }

  void expect_close_object_map(MockImageCtx &mock_image_ctx,
                               MockObjectMap &mock_object_map) {
    EXPECT_CALL(mock_object_map, close(_))
                  .WillOnce(CompleteContext(0, mock_image_ctx.image_ctx->op_work_queue));
  }

  void expect_flush_notifies(MockImageCtx &mock_image_ctx) {
    EXPECT_CALL(*mock_image_ctx.image_watcher, flush(_))
                  .WillOnce(CompleteContext(0, mock_image_ctx.image_ctx->op_work_queue));
  }

  void expect_prepare_lock(MockImageCtx &mock_image_ctx) {
    EXPECT_CALL(*mock_image_ctx.state, prepare_lock(_))
      .WillOnce(Invoke([](Context *on_ready) {
                  on_ready->complete(0);
                }));
  }

  void expect_handle_prepare_lock_complete(MockImageCtx &mock_image_ctx) {
    EXPECT_CALL(*mock_image_ctx.state, handle_prepare_lock_complete());
  }

  MockManagedLock *lock_initialize(MockImageCtx &mock_image_ctx,
                                   ContextWQ *work_queue) {
    MockManagedLock *managed_lock = new MockManagedLock(
      mock_image_ctx.md_ctx, work_queue,
      mock_image_ctx.header_oid, mock_image_ctx.image_watcher);
    C_SaferCond lock_ctx;
    managed_lock->acquire_lock(&lock_ctx);
    lock_ctx.wait();
    return managed_lock;
  }

  void lock_shut_down(MockManagedLock *managed_lock, MockImageCtx &mock_image_ctx,
                      bool expect = false) {
    if (expect) {
      expect_unlock(mock_image_ctx, 0);
    }
    C_SaferCond ctx2;
    managed_lock->shut_down(&ctx2);
    ctx2.wait();
    delete managed_lock;
  }

};

TEST_F(TestMockExclusiveLockReleaseRequest, Success) {
  REQUIRE_FEATURE(RBD_FEATURE_EXCLUSIVE_LOCK);

  librbd::ImageCtx *ictx;
  ASSERT_EQ(0, open_image(m_image_name, &ictx));

  MockImageCtx mock_image_ctx(*ictx);
  expect_op_work_queue(mock_image_ctx);
  expect_get_watch_handle(mock_image_ctx);

  InSequence seq;
  expect_lock(mock_image_ctx, 0);

  expect_prepare_lock(mock_image_ctx);
  expect_cancel_op_requests(mock_image_ctx, 0);
  expect_block_writes(mock_image_ctx, 0);
  expect_flush_notifies(mock_image_ctx);

  MockJournal *mock_journal = new MockJournal();
  mock_image_ctx.journal = mock_journal;
  expect_close_journal(mock_image_ctx, *mock_journal, -EINVAL);

  MockObjectMap *mock_object_map = new MockObjectMap();
  mock_image_ctx.object_map = mock_object_map;
  expect_close_object_map(mock_image_ctx, *mock_object_map);

  MockContext mock_releasing_ctx;
  expect_complete_context(mock_releasing_ctx, 0);
  expect_unlock(mock_image_ctx, 0);
  expect_handle_prepare_lock_complete(mock_image_ctx);

  MockManagedLock *managed_lock = lock_initialize(mock_image_ctx,
                                                  ictx->op_work_queue);
  C_SaferCond ctx;
  MockReleaseRequest *req = MockReleaseRequest::create(mock_image_ctx,
                                                       managed_lock,
                                                       &mock_releasing_ctx,
                                                       &ctx, false);
  req->send();
  ASSERT_EQ(0, ctx.wait());

  lock_shut_down(managed_lock, mock_image_ctx);
}

TEST_F(TestMockExclusiveLockReleaseRequest, SuccessJournalDisabled) {
  REQUIRE_FEATURE(RBD_FEATURE_EXCLUSIVE_LOCK);

  librbd::ImageCtx *ictx;
  ASSERT_EQ(0, open_image(m_image_name, &ictx));

  MockImageCtx mock_image_ctx(*ictx);
  expect_block_writes(mock_image_ctx, 0);
  expect_op_work_queue(mock_image_ctx);
  expect_get_watch_handle(mock_image_ctx);

  InSequence seq;
  expect_lock(mock_image_ctx, 0);
  expect_prepare_lock(mock_image_ctx);
  expect_cancel_op_requests(mock_image_ctx, 0);
  expect_flush_notifies(mock_image_ctx);

  MockObjectMap *mock_object_map = new MockObjectMap();
  mock_image_ctx.object_map = mock_object_map;
  expect_close_object_map(mock_image_ctx, *mock_object_map);

  expect_unlock(mock_image_ctx, 0);
  expect_handle_prepare_lock_complete(mock_image_ctx);

  MockManagedLock *managed_lock = lock_initialize(mock_image_ctx,
                                                  ictx->op_work_queue);

  C_SaferCond release_ctx;
  C_SaferCond ctx;
  MockReleaseRequest *req = MockReleaseRequest::create(mock_image_ctx,
                                                       managed_lock,
                                                       &release_ctx, &ctx,
                                                       false);
  req->send();
  ASSERT_EQ(0, release_ctx.wait());
  ASSERT_EQ(0, ctx.wait());
  lock_shut_down(managed_lock, mock_image_ctx);
}

TEST_F(TestMockExclusiveLockReleaseRequest, SuccessObjectMapDisabled) {
  REQUIRE_FEATURE(RBD_FEATURE_EXCLUSIVE_LOCK);

  librbd::ImageCtx *ictx;
  ASSERT_EQ(0, open_image(m_image_name, &ictx));

  MockImageCtx mock_image_ctx(*ictx);
  expect_block_writes(mock_image_ctx, 0);
  expect_op_work_queue(mock_image_ctx);
  expect_get_watch_handle(mock_image_ctx);

  InSequence seq;
  expect_lock(mock_image_ctx, 0);
  expect_cancel_op_requests(mock_image_ctx, 0);
  expect_flush_notifies(mock_image_ctx);

  expect_unlock(mock_image_ctx, 0);

  MockManagedLock *managed_lock = lock_initialize(mock_image_ctx,
                                                  ictx->op_work_queue);

  C_SaferCond release_ctx;
  C_SaferCond ctx;
  MockReleaseRequest *req = MockReleaseRequest::create(mock_image_ctx,
                                                       managed_lock,
                                                       &release_ctx, &ctx,
                                                       true);
  req->send();
  ASSERT_EQ(0, release_ctx.wait());
  ASSERT_EQ(0, ctx.wait());
  lock_shut_down(managed_lock, mock_image_ctx);
}

TEST_F(TestMockExclusiveLockReleaseRequest, BlockWritesError) {
  REQUIRE_FEATURE(RBD_FEATURE_EXCLUSIVE_LOCK);

  librbd::ImageCtx *ictx;
  ASSERT_EQ(0, open_image(m_image_name, &ictx));

  MockImageCtx mock_image_ctx(*ictx);
  expect_op_work_queue(mock_image_ctx);
  expect_get_watch_handle(mock_image_ctx);

  InSequence seq;
  expect_lock(mock_image_ctx, 0);
  expect_cancel_op_requests(mock_image_ctx, 0);
  expect_block_writes(mock_image_ctx, -EINVAL);
  expect_unblock_writes(mock_image_ctx);

  C_SaferCond ctx;
  MockManagedLock *managed_lock = lock_initialize(mock_image_ctx, ictx->op_work_queue);
  MockReleaseRequest *req = MockReleaseRequest::create(mock_image_ctx,
                                                       managed_lock,
                                                       nullptr, &ctx,
                                                       true);
  req->send();
  ASSERT_EQ(-EINVAL, ctx.wait());
  lock_shut_down(managed_lock, mock_image_ctx, true);
}

TEST_F(TestMockExclusiveLockReleaseRequest, UnlockError) {
  REQUIRE_FEATURE(RBD_FEATURE_EXCLUSIVE_LOCK);

  librbd::ImageCtx *ictx;
  ASSERT_EQ(0, open_image(m_image_name, &ictx));

  MockImageCtx mock_image_ctx(*ictx);
  expect_op_work_queue(mock_image_ctx);
  expect_get_watch_handle(mock_image_ctx);

  InSequence seq;
  expect_lock(mock_image_ctx, 0);
  expect_cancel_op_requests(mock_image_ctx, 0);
  expect_block_writes(mock_image_ctx, 0);
  expect_flush_notifies(mock_image_ctx);

  expect_unlock(mock_image_ctx, -EINVAL);

  C_SaferCond ctx;
  MockManagedLock *managed_lock = lock_initialize(mock_image_ctx, ictx->op_work_queue);
  MockReleaseRequest *req = MockReleaseRequest::create(mock_image_ctx,
                                                       managed_lock,
                                                       nullptr, &ctx,
                                                       true);
  req->send();
  ASSERT_EQ(0, ctx.wait());
  lock_shut_down(managed_lock, mock_image_ctx);
}

} // namespace exclusive_lock
} // namespace librbd
