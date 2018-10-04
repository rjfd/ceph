import { HttpClient } from '@angular/common/http';
import { Injectable } from '@angular/core';

import { ApiModule } from './api.module';

@Injectable({
  providedIn: ApiModule
})
export class NfsService {
  apiPath = 'api/nfs';

  constructor(private http: HttpClient) {}

  list() {
    return this.http.get(`${this.apiPath}`);
  }

  get(host, exportId) {
    return this.http.get(`${this.apiPath}/${host}/${exportId}`);
  }

  create(nfs) {
    return this.http.post(`${this.apiPath}`, nfs, { observe: 'response' });
  }

  update(host, id, nfs) {
    return this.http.put(`${this.apiPath}/${host}/${id}`, nfs, { observe: 'response' });
  }

  copy(host, id, nfs) {
    return this.http.post(`${this.apiPath}/${host}/${id}`, nfs, { observe: 'response' });
  }

  delete(host, exportId) {
    return this.http.delete(`${this.apiPath}/${host}/${exportId}`, { observe: 'response' });
  }

  lsDir(root_dir, userid) {
    return this.http.get(`${this.apiPath}/lsdir`);
  }

  buckets(userid) {
    return this.http.get(`${this.apiPath}/buckets`);
  }

  hosts() {
    return this.http.get(`${this.apiPath}/host`);
  }

  fsals() {
    return this.http.get(`${this.apiPath}/fsals`);
  }

  status() {
    return this.http.get(`${this.apiPath}/host/status`);
  }

  start(host_name: string) {
    return this.http.put(`${this.apiPath}/host/${host_name}/start`, null, { observe: 'response' });
  }

  stop(host_name: string) {
    return this.http.put(`${this.apiPath}/host/${host_name}/stop`, null, { observe: 'response' });
  }
}
