// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*- 
// vim: ts=8 sw=2 smarttab

#include "ScrubStore.h"
#include "osd_types.h"
#include "common/scrub_types.h"
#include "include/rados/rados_types.hpp"

namespace Scrub {

Store::Store(const coll_t& coll, const hobject_t& oid, ObjectStore* store)
  : driver(store, coll, ghobject_t(oid)),
    backend(&driver)
{}

Store::~Store()
{
  assert(results.empty());
}

void Store::add_object_error(int64_t pool, const inconsistent_obj_wrapper& e)
{
  bufferlist bl;
  e.encode(bl);
  results[Scrub::to_object_key(pool, e.object)] = bl;
}

void Store::add_snap_error(int64_t pool, const inconsistent_snapset_wrapper& e)
{
  bufferlist bl;
  e.encode(bl);
  results[to_snap_key(pool, e.object)] = bl;
}

bool Store::empty() const
{
  return results.empty();
}

void Store::flush(ObjectStore::Transaction *t)
{
  OSDriver::OSTransaction txn = driver.get_transaction(t);
  backend.set_keys(results, &txn);
  results.clear();
}

string to_object_key(int64_t pool, const librados::object_id_t& oid)
{
  return ("SCRUB_OBJ_" +
	  std::to_string(pool) + "." +
	  oid.name + oid.nspace + std::to_string(oid.snap));
}

string to_snap_key(int64_t pool, const librados::object_id_t& oid)
{
  return "SCRUB_SS_" + std::to_string(pool) + "." + oid.name + oid.nspace;
}


} // namespace Scrub
