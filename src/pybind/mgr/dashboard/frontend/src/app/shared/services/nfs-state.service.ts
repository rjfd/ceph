import { Injectable } from '@angular/core';

import * as _ from 'lodash';
import { BehaviorSubject, Subscription } from 'rxjs';

import { NfsService } from '../api/nfs.service';
import { SummaryService } from './summary.service';

@Injectable({ providedIn: 'root' })
export class NfsStateService {
  // Observable sources
  private stateDataSource = new BehaviorSubject(null);

  // Observable streams
  stateData$ = this.stateDataSource.asObservable();

  pooling = false;

  stopTaskDescr = 'NFS-Ganesha stop exports';
  deployTaskDescr = 'NFS-Ganesha deploy exports';

  constructor(private nfsService: NfsService, private summaryService: SummaryService) {
    this.summaryService.subscribe((summary) => {
      if (this.pooling) {
        this.updateStates(summary);
      }
    });
  }

  startPooling() {
    this.pooling = true;
    this.updateStates({ executing_tasks: [] });
  }

  stopPooling() {
    this.stateDataSource.next(null);
    this.pooling = false;
  }

  subscribe(host: string, call: (state: string) => void): Subscription {
    return this.stateData$.subscribe((hosts: any) => {
      if (!hosts || !hosts[host] || !hosts[host].state) {
        return 'LOADING';
      }

      call(hosts[host].state);
    });
  }

  getState(host, hostname, executing_tasks) {
    const startingHosts = {};
    const stoppingHosts = {};

    executing_tasks.forEach((element) => {
      if (element.name === 'nfs/host/stop') {
        stoppingHosts[element.metadata.host_name] = true;
      } else {
        startingHosts[element.metadata.host_name] = true;
      }
    });

    if (startingHosts[hostname]) {
      return 'STARTING';
    }
    if (stoppingHosts[hostname]) {
      return 'STOPPING';
    }
    if (host.active === true) {
      return 'ACTIVE';
    }
    if (host.active === false) {
      return 'INACTIVE';
    }
    if (host.active === undefined) {
      return 'LOADING';
    }
    return 'UNKNOWN';
  }

  updateStates(summary: any = null) {
    const executing_tasks = summary
      ? summary.executing_tasks.filter((task) =>
          ['nfs/host/start', 'nfs/host/stop'].includes(task.name)
        )
      : [];

    this.nfsService.status().subscribe((hosts: any) => {
      _.forIn(hosts, (host, hostname) => {
        host.state = this.getState(host, hostname, executing_tasks);
        const exports = {};
        if (host.state === 'ACTIVE') {
          host.exports.forEach((exportItem) => {
            exports[exportItem.export_id] = {
              state: exportItem.active ? 'ACTIVE' : 'INACTIVE',
              message: exportItem.message
            };
          });
        }
        host.exports = exports;
      });

      this.stateDataSource.next(hosts);
    });
  }

  start(host, hostname) {
    host.active = undefined;
    host.state = 'STARTING';
    delete host.message;
    delete host.messages;

    return this.nfsService.start(hostname);
  }

  stop(host, hostname) {
    host.active = undefined;
    host.state = 'STOPPING';
    delete host.message;
    delete host.messages;

    return this.nfsService.stop(hostname);
  }
}
