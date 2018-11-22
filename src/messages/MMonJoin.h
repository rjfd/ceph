// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*- 
// vim: ts=8 sw=2 smarttab
/*
 * Ceph - scalable distributed file system
 *
 * Copyright (C) 2004-2006 Sage Weil <sage@newdream.net>
 *
 * This is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License version 2.1, as published by the Free Software 
 * Foundation.  See file COPYING.
 * 
 */

#ifndef CEPH_MMONJOIN_H
#define CEPH_MMONJOIN_H

#include "messages/PaxosServiceMessage.h"

#include <vector>
using std::vector;

class MMonJoin : public MessageInstance<MMonJoin, PaxosServiceMessage> {
public:
  friend factory;

  const static int HEAD_VERSION = 2;
  const static int COMPAT_VERSION = 2;

  uuid_d fsid;
  string name;
  entity_addrvec_t addrs;

  MMonJoin() : MessageInstance(MSG_MON_JOIN, 0) {}
  MMonJoin(uuid_d &f, string n, const entity_addrvec_t& av)
    : MessageInstance(MSG_MON_JOIN, 0),
      fsid(f), name(n), addrs(av)
  { }
  
private:
  ~MMonJoin() override {}

public:  
  const char *get_type_name() const override { return "mon_join"; }
  void print(ostream& o) const override {
    o << "mon_join(" << name << " " << addrs << ")";
  }
  
  void encode_payload(uint64_t features) override {
    using ceph::encode;
    paxos_encode();
    encode(fsid, payload);
    encode(name, payload);
    if (HAVE_FEATURE(features, SERVER_NAUTILUS)) {
      header.version = HEAD_VERSION;
      header.compat_version = COMPAT_VERSION;
      encode(addrs, payload, features);
    } else {
      header.version = 1;
      header.compat_version = 1;
      encode(addrs.legacy_addr(), payload, features);
    }
  }
  void decode_payload() override {
    auto p = payload.cbegin();
    paxos_decode(p);
    decode(fsid, p);
    decode(name, p);
    decode(addrs, p);
  }
};

#endif
