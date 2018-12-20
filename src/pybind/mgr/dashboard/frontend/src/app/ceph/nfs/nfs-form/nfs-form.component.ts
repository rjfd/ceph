import { Component, OnInit } from '@angular/core';
import { FormControl, Validators } from '@angular/forms';
import { ActivatedRoute, Router } from '@angular/router';

import * as _ from 'lodash';
import { forkJoin, Observable, of } from 'rxjs';
import { mergeMap } from 'rxjs/operators';

import { NfsService } from '../../../shared/api/nfs.service';
import { RgwUserService } from '../../../shared/api/rgw-user.service';
import { CdFormBuilder } from '../../../shared/forms/cd-form-builder';
import { CdFormGroup } from '../../../shared/forms/cd-form-group';
import { CdValidators } from '../../../shared/forms/cd-validators';
import { FinishedTask } from '../../../shared/models/finished-task';
import { Permission } from '../../../shared/models/permissions';
import { AuthStorageService } from '../../../shared/services/auth-storage.service';
import { TaskWrapperService } from '../../../shared/services/task-wrapper.service';
import { nfsAccessType, nfsFsal, nfsSquash } from '../nfs-shared';

@Component({
  selector: 'cd-nfs-form',
  templateUrl: './nfs-form.component.html',
  styleUrls: ['./nfs-form.component.scss']
})
export class NfsFormComponent implements OnInit {
  permission: Permission;
  nfsForm: CdFormGroup;
  isEdit = false;
  isCopy = false;

  hostname = null;
  exportId = null;

  isNewDirectory = false;
  isNewBucket = false;

  allHosts: any[] = null;
  allFsals: any[] = [];
  allRgwUsers: any[] = [];

  nfsAccessType: any[] = nfsAccessType;
  nfsSquash: any[] = nfsSquash;

  pathDataSource: Observable<any> = Observable.create((observer: any) => {
    observer.next(this.nfsForm.getValue('path'));
  }).pipe(mergeMap((token: string) => this.getPathTypeahead(token)));

  bucketDataSource: Observable<any> = Observable.create((observer: any) => {
    observer.next(this.nfsForm.getValue('rgwUserId'));
  }).pipe(mergeMap((token: string) => this.getBucketTypeahead(token)));

  constructor(
    private authStorageService: AuthStorageService,
    private nfsService: NfsService,
    private route: ActivatedRoute,
    private router: Router,
    private rgwUserService: RgwUserService,
    private formBuilder: CdFormBuilder,
    private taskWrapper: TaskWrapperService
  ) {
    this.permission = this.authStorageService.getPermissions().pool;
    this.createForm();
  }

  ngOnInit() {
    const promises: any[] = [this.nfsService.services(), this.nfsService.fsals()];

    if (this.router.url.startsWith('/nfs/edit')) {
      this.isEdit = true;
    } else if (this.router.url.startsWith('/nfs/copy')) {
      this.isCopy = true;
    }

    if (this.isEdit || this.isCopy) {
      this.route.params.subscribe((params: { host: string; exportId: string }) => {
        const host = decodeURIComponent(params.host);
        const exportId = decodeURIComponent(params.exportId);
        this.hostname = host;
        this.exportId = exportId;
        promises.push(this.nfsService.get(host, exportId));

        this.getData(promises);
      });
    } else {
      this.getData(promises);
    }
  }

  getData(promises) {
    forkJoin(promises).subscribe(
      (data: any[]) => {
        this.resolveHosts(data[0]);
        this.resolvefsals(data[1]);
        if (data[2]) {
          this.resolveModel(data[2]);
        }
      },
      (error) => {
        // this.error = error;
      }
    );
  }

  createForm() {
    this.nfsForm = new CdFormGroup({
      host: new FormControl('', {
        validators: [Validators.required]
      }),
      fsal: new FormControl('', {
        validators: [Validators.required]
      }),
      rgwUserId: new FormControl('', {
        validators: [
          CdValidators.requiredIf({
            fsal: 'RGW'
          })
        ]
      }),
      path: new FormControl('', {
        validators: [
          CdValidators.requiredIf({
            fsal: 'CEPH'
          })
        ]
      }),
      bucket: new FormControl(''),
      protocolNfsv3: new FormControl(true, {
        validators: [
          CdValidators.requiredIf({ protocolNfsv4: false }, (value) => {
            return !value;
          })
        ]
      }),
      protocolNfsv4: new FormControl(true, {
        validators: [
          CdValidators.requiredIf({ protocolNfsv3: false }, (value) => {
            return !value;
          })
        ]
      }),
      tag: new FormControl(''),
      pseudo: new FormControl('', {
        validators: [Validators.required]
      }),
      accessType: new FormControl('RW', {
        validators: [Validators.required]
      }),
      squash: new FormControl('None', {
        validators: [Validators.required]
      }),
      transportUDP: new FormControl(true, {
        validators: [
          CdValidators.requiredIf({ transportTCP: false }, (value) => {
            return !value;
          })
        ]
      }),
      transportTCP: new FormControl(true, {
        validators: [
          CdValidators.requiredIf({ transportUDP: false }, (value) => {
            return !value;
          })
        ]
      }),
      clients: this.formBuilder.array([])
    });
  }

  resolveModel(res) {
    if (res.fsal === 'RGW') {
      res.bucket = res.path;
      delete res.path;
    }

    if (res.tag !== this._generateTag()) {
      // this.nfsForm.tag.$dirty = true;
    }

    if (res.pseudo !== this._generatePseudo()) {
      // this.nfsForm.pseudo.$dirty = true;
    }

    res.protocolNfsv3 = res.protocols.indexOf('NFSv3') !== -1;
    res.protocolNfsv4 = res.protocols.indexOf('NFSv4') !== -1;
    delete res.protocols;

    res.transportTCP = res.transports.indexOf('TCP') !== -1;
    res.transportUDP = res.transports.indexOf('UDP') !== -1;
    delete res.transports;

    res.clients.forEach((client) => {
      let addressStr = '';
      client.addresses.forEach((address) => {
        addressStr += address + ', ';
      });
      if (addressStr.length >= 2) {
        addressStr = addressStr.substring(0, addressStr.length - 2);
      }
      client.addresses = addressStr;
    });

    // if (this.$state.current.name === 'cephNfs-clone') {
    //   delete res.id;
    //   delete res.exportId;
    // }

    this.nfsForm.patchValue(res);
  }

  resolveHosts(services) {
    this.allHosts = [];
    services.forEach(service => {
      this.allHosts.push(service.hostname);
    });

    if (
      _.isArray(this.allHosts) &&
      this.allHosts.length === 1 &&
      _.isUndefined(this.nfsForm.getValue('host'))
    ) {
      this.nfsForm.patchValue({
        host: this.allHosts[0]
      });
    }
  }

  resolvefsals(res: string[]) {
    res.forEach((fsal) => {
      const fsalItem = nfsFsal.find((currentFsalItem) => {
        return fsal === currentFsalItem.value;
      });

      if (_.isObjectLike(fsalItem)) {
        this.allFsals.push(fsalItem);
        if (fsalItem.value === 'RGW') {
          this.rgwUserService.list().subscribe((result: any) => {
            result.forEach((user) => {
              if (user.suspended === 0) {
                this.allRgwUsers.push(user.user_id);
              }
            });
          });
        }
      }
    });

    if (this.allFsals.length === 1 && _.isUndefined(this.nfsForm.getValue('fsal'))) {
      this.nfsForm.patchValue({
        fsal: this.allFsals[0]
      });
    }
  }

  fsalChangeHandler() {
    this.nfsForm.patchValue({
      tag: this._generateTag(),
      pseudo: this._generatePseudo()
    });
  }

  rgwUserIdChangeHandler() {
    this.nfsForm.patchValue({
      pseudo: this._generatePseudo()
    });
  }

  getAccessTypeHelp(accessType) {
    const accessTypeItem = this.nfsAccessType.find((currentAccessTypeItem) => {
      if (accessType === currentAccessTypeItem.value) {
        return currentAccessTypeItem;
      }
    });
    return _.isObjectLike(accessTypeItem) ? accessTypeItem.help : '';
  }

  getId() {
    if (_.isString(this.nfsForm.getValue('host')) && _.isString(this.nfsForm.getValue('path'))) {
      return this.nfsForm.getValue('host') + ':' + this.nfsForm.getValue('path');
    }
    return '';
  }

  getPathTypeahead(path) {
    let rootDir = '/';
    if (_.isString(path) && path.length > 1 && path[0] === '/') {
      rootDir = path.substring(0, path.lastIndexOf('/') + 1);
    }

    return this.nfsService.lsDir(rootDir, this.nfsForm.getValue('rgwUserId'));
  }

  pathChangeHandler() {
    this.nfsForm.patchValue({
      pseudo: this._generatePseudo()
    });

    const path = this.nfsForm.getValue('path');
    this.getPathTypeahead(path).subscribe((res: any) => {
      this.isNewDirectory = path !== '/' && res.paths.indexOf(path) === -1;
    });
  }

  bucketChangeHandler() {
    this.nfsForm.patchValue({
      tag: this._generateTag(),
      pseudo: this._generatePseudo()
    });

    const bucket = this.nfsForm.getValue('bucket');
    this.getBucketTypeahead(bucket).subscribe((res: any) => {
      this.isNewBucket = bucket !== '' && res.indexOf(bucket) === -1;
    });
  }

  getBucketTypeahead(rgwUserId: string): Observable<any> {
    if (_.isString(rgwUserId)) {
      return this.nfsService.buckets(this.nfsForm.getValue('rgwUserId'));
    } else {
      return of([]);
    }
  }

  _generateTag() {
    let newTag = this.nfsForm.getValue('tag');
    if (!this.nfsForm.get('tag').dirty) {
      newTag = undefined;
      if (this.nfsForm.getValue('fsal') === 'RGW') {
        newTag = this.nfsForm.getValue('bucket');
      }
    }
    return newTag;
  }

  _generatePseudo() {
    let newPseudo = this.nfsForm.getValue('pseudo');
    if (this.nfsForm.get('pseudo') && !this.nfsForm.get('pseudo').dirty) {
      newPseudo = undefined;
      if (this.nfsForm.getValue('fsal') === 'CEPH') {
        newPseudo = '/cephfs';
        if (_.isString(this.nfsForm.getValue('path'))) {
          newPseudo += this.nfsForm.getValue('path');
        }
      } else if (this.nfsForm.getValue('fsal') === 'RGW') {
        if (_.isString(this.nfsForm.getValue('rgwUserId'))) {
          newPseudo = '/' + this.nfsForm.getValue('rgwUserId');
          if (_.isString(this.nfsForm.getValue('bucket'))) {
            newPseudo += '/' + this.nfsForm.getValue('bucket');
          }
        }
      }
    }
    return newPseudo;
  }

  submitAction() {
    let action: Observable<any>;
    const requestModel = this._buildRequest();
    const host = this.route.snapshot.params['host'];
    const exportId = this.route.snapshot.params['exportId'];

    if (this.isEdit) {
      action = this.taskWrapper.wrapTaskAroundCall({
        task: new FinishedTask('nfs/edit', {
          host_name: host,
          export_id: exportId
        }),
        call: this.nfsService.update(host, exportId, requestModel)
      });
    } else if (this.isCopy) {
      action = this.taskWrapper.wrapTaskAroundCall({
        task: new FinishedTask('nfs/copy', {
          host_name: host,
          export_id: exportId
        }),
        call: this.nfsService.copy(host, exportId, requestModel)
      });
    } else {
      // Add
      action = this.taskWrapper.wrapTaskAroundCall({
        task: new FinishedTask('nfs/create', {
          host_name: host
        }),
        call: this.nfsService.create(requestModel)
      });
    }

    action.subscribe(
      undefined,
      () => this.nfsForm.setErrors({ cdSubmitButton: true }),
      () => this.router.navigate(['/nfs'])
    );
  }

  _buildRequest() {
    const requestModel: any = _.cloneDeep(this.nfsForm.value);

    if (requestModel.fsal === 'RGW') {
      requestModel.path = requestModel.bucket;
    }
    delete requestModel.bucket;

    if (_.isUndefined(requestModel.tag) || requestModel.tag === '') {
      requestModel.tag = null;
    }

    requestModel.protocols = [];
    if (requestModel.protocolNfsv3) {
      delete requestModel.protocolNfsv3;
      requestModel.protocols.push('NFSv3');
    } else {
      requestModel.tag = null;
    }
    if (requestModel.protocolNfsv4) {
      delete requestModel.protocolNfsv4;
      requestModel.protocols.push('NFSv4');
    } else {
      requestModel.pseudo = null;
    }

    requestModel.transports = [];
    if (requestModel.transportTCP) {
      delete requestModel.transportTCP;
      requestModel.transports.push('TCP');
    }
    if (requestModel.transportUDP) {
      delete requestModel.transportUDP;
      requestModel.transports.push('UDP');
    }

    requestModel.clients.forEach((clients) => {
      if (_.isString(clients.addresses)) {
        let addresses = clients.addresses.replace(/\s/g, '');
        addresses = '"' + addresses.replace(/,/g, '","') + '"';
        clients.addresses = JSON.parse('[' + addresses + ']');
      } else {
        clients.addresses = [];
      }
    });

    return requestModel;
  }

  cancelAction() {
    this.router.navigate(['/nfs']);
  }
}
