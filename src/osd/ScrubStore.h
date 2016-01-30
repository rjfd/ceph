// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab

#ifndef CEPH_SCRUB_RESULT_H
#define CEPH_SCRUB_RESULT_H

#include "SnapMapper.h"		// for OSDriver
#include "common/map_cacher.hpp"

namespace librados {
  struct object_id_t;
}

struct inconsistent_obj_wrapper;

namespace Scrub {

class Store {
public:
  Store(const coll_t& coll, const hobject_t& oid, ObjectStore* store);
  ~Store();
  void add_object_error(int64_t pool, const inconsistent_obj_wrapper& e);
  bool empty() const;
  void flush(ObjectStore::Transaction *);

private:
  // a temp object holding mappings from seq-id to inconsistencies found in
  // scrubbing
  OSDriver driver;
  MapCacher::MapCacher<std::string, bufferlist> backend;
  map<string, bufferlist> results;
};

inline hobject_t make_scrub_object(const spg_t& pgid)
{
  ostringstream ss;
  ss << "scrub_" << pgid;
  return pgid.make_temp_object(ss.str());
}

inline string first_object_key(int64_t pool)
{
  return "SCRUB_OBJ_" + std::to_string(pool) + "-";
}

// the object_key should be unique across pools
string to_object_key(int64_t pool, const librados::object_id_t& oid);

inline string last_object_key(int64_t pool)
{
  return "SCRUB_OBJ_" + std::to_string(pool) + "/";
}

}

#endif // CEPH_SCRUB_RESULT_H
