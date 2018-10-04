import { Component, OnInit } from '@angular/core';

import * as _ from 'lodash';
import { BsModalRef } from 'ngx-bootstrap';

import { NfsService } from '../../../shared/api/nfs.service';
import { FinishedTask } from '../../../shared/models/finished-task';
import { NfsStateService } from '../../../shared/services/nfs-state.service';
import { TaskWrapperService } from '../../../shared/services/task-wrapper.service';

@Component({
  selector: 'cd-nfs-manage-service-modal',
  templateUrl: './nfs-manage-service-modal.component.html',
  styleUrls: ['./nfs-manage-service-modal.component.scss']
})
export class NfsManageServiceModalComponent implements OnInit {
  hostnames: any[] = undefined;
  hosts: any;
  dirty: boolean;

  constructor(
    public modalRef: BsModalRef,
    private nfsService: NfsService,
    private taskWrapper: TaskWrapperService,
    private nfsStateService: NfsStateService
  ) {}

  ngOnInit() {
    this.nfsService.hosts().subscribe((res: any) => {
      this.hosts = {};
      this.hostnames = res;
      this._updateStates();
    });
  }

  _updateStates() {
    this.hostnames.forEach((hostname) => {
      if (_.isUndefined(this.hosts[hostname])) {
        this.hosts[hostname] = {};
      }
      this.nfsStateService.subscribe(hostname, (state: string) => {
        this.hosts[hostname].state = state;
      });
      // this.hosts[hostname].state = this.nfsStateService.hosts[hostname].state;
    });
    // this.nfsStateService.updateStates((hostsToUpdate) => {
    //   _.forIn(this.hosts, (host, hostname) => {
    //     const hostToUpdate = hostsToUpdate[hostname];
    //     if (_.isObjectLike(hostToUpdate)) {
    //       host.state = hostToUpdate.state;
    //       host.messages = [];
    //       _.forIn(hostToUpdate.exports, (exportItem) => {
    //         if (exportItem.state === 'INACTIVE' && _.isString(exportItem.message)) {
    //           host.messages.push(exportItem.message);
    //         }
    //       });
    //     }
    //   });
    // });
  }

  start(hostname) {
    this.taskWrapper
      .wrapTaskAroundCall({
        task: new FinishedTask('nfs/host/start', {
          host_name: hostname
        }),
        call: this.nfsStateService.start(this.hosts[hostname], hostname)
      })
      .subscribe();
  }

  stop(hostname) {
    this.taskWrapper
      .wrapTaskAroundCall({
        task: new FinishedTask('nfs/host/stop', {
          host_name: hostname
        }),
        call: this.nfsStateService.stop(this.hosts[hostname], hostname)
      })
      .subscribe();
  }

  close() {
    this.modalRef.hide();
  }
}
