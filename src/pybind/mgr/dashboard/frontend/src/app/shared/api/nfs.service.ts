import { HttpClient } from '@angular/common/http';
import { Injectable } from '@angular/core';

import { ApiModule } from './api.module';

@Injectable({
  providedIn: ApiModule
})
export class NfsService {
  apiPath = 'api/nfs-ganesha';
  uiApiPath = 'ui-api/nfs-ganesha';

  constructor(private http: HttpClient) {}

  list() {
    return this.http.get(`${this.apiPath}/export`);
  }

  get(host, exportId) {
    return this.http.get(`${this.apiPath}/export/${host}/${exportId}`);
  }

  create(nfs) {
    return this.http.post(`${this.apiPath}/export`, nfs, { observe: 'response' });
  }

  update(host, id, nfs) {
    return this.http.put(`${this.apiPath}/export/${host}/${id}`, nfs, { observe: 'response' });
  }

  copy(host, id, nfs) {
    return this.http.post(`${this.apiPath}/export/${host}/${id}/copy`, nfs, { observe: 'response' });
  }

  delete(host, exportId) {
    return this.http.delete(`${this.apiPath}/export/${host}/${exportId}`, { observe: 'response' });
  }

  lsDir(root_dir, userid) {
    return this.http.get(`${this.uiApiPath}/lsdir`);
  }

  buckets(userid) {
    return this.http.get(`${this.uiApiPath}/buckets`);
  }

  fsals() {
    return this.http.get(`${this.uiApiPath}/fsals`);
  }

  services() {
    return this.http.get(`${this.apiPath}/service`);
  }

  start(host_name: string) {
    return this.http.put(`${this.apiPath}/service/${host_name}/start`, null, { observe: 'response' });
  }

  stop(host_name: string) {
    return this.http.put(`${this.apiPath}/service/${host_name}/stop`, null, { observe: 'response' });
  }
}
