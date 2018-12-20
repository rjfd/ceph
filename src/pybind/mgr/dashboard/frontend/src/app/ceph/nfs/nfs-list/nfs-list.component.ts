import { Component, OnDestroy, OnInit, TemplateRef, ViewChild } from '@angular/core';

import { I18n } from '@ngx-translate/i18n-polyfill';
import * as _ from 'lodash';
import { BsModalRef, BsModalService } from 'ngx-bootstrap';
import { Subscription } from 'rxjs';

import { NfsService } from '../../../shared/api/nfs.service';
import { CriticalConfirmationModalComponent } from '../../../shared/components/critical-confirmation-modal/critical-confirmation-modal.component';
import { TableComponent } from '../../../shared/datatable/table/table.component';
import { CellTemplate } from '../../../shared/enum/cell-template.enum';
import { ViewCacheStatus } from '../../../shared/enum/view-cache-status.enum';
import { CdTableAction } from '../../../shared/models/cd-table-action';
import { CdTableColumn } from '../../../shared/models/cd-table-column';
import { CdTableSelection } from '../../../shared/models/cd-table-selection';
import { FinishedTask } from '../../../shared/models/finished-task';
import { Permission } from '../../../shared/models/permissions';
import { AuthStorageService } from '../../../shared/services/auth-storage.service';
import { NfsStateService } from '../../../shared/services/nfs-state.service';
import { TaskListService } from '../../../shared/services/task-list.service';
import { TaskWrapperService } from '../../../shared/services/task-wrapper.service';
import { NfsManageServiceModalComponent } from '../nfs-manage-service-modal/nfs-manage-service-modal.component';

@Component({
  selector: 'cd-nfs-list',
  templateUrl: './nfs-list.component.html',
  styleUrls: ['./nfs-list.component.scss'],
  providers: [TaskListService]
})
export class NfsListComponent implements OnInit, OnDestroy {
  @ViewChild(TableComponent)
  table: TableComponent;
  @ViewChild('nfsState')
  nfsState: TemplateRef<any>;
  @ViewChild('nfsFsal')
  nfsFsal: TemplateRef<any>;

  columns: CdTableColumn[];
  permission: Permission;
  selection = new CdTableSelection();
  summaryDataSubscription: Subscription;
  viewCacheStatus: any;
  images: any[];
  tableActions: CdTableAction[];

  modalRef: BsModalRef;

  builders = {
    'nfs/create': (metadata) => {
      return {
        // path: '',
        host: metadata['host_name']
        // fsal: '',
        // accessType: ''
      };
    }
  };

  constructor(
    private authStorageService: AuthStorageService,
    private i18n: I18n,
    private modalService: BsModalService,
    private nfsService: NfsService,
    private taskListService: TaskListService,
    private taskWrapper: TaskWrapperService,
    public nfsStateService: NfsStateService
  ) {
    this.nfsStateService.startPooling();
    this.permission = this.authStorageService.getPermissions().nfs;
    const getNfsUri = () =>
      this.selection.first() &&
      `${encodeURI(this.selection.first().host)}/${encodeURI(this.selection.first().exportId)}`;

    const addAction: CdTableAction = {
      permission: 'create',
      icon: 'fa-plus',
      routerLink: () => '/nfs/add',
      canBePrimary: (selection: CdTableSelection) => !selection.hasSingleSelection,
      name: this.i18n('Add')
    };

    const editAction: CdTableAction = {
      permission: 'update',
      icon: 'fa-pencil',
      routerLink: () => `/nfs/edit/${getNfsUri()}`,
      name: this.i18n('Edit')
    };

    const copyAction: CdTableAction = {
      permission: 'create',
      canBePrimary: (selection: CdTableSelection) => selection.hasSingleSelection,
      disable: (selection: CdTableSelection) => !selection.hasSingleSelection,
      icon: 'fa-copy',
      routerLink: () => `/nfs/copy/${getNfsUri()}`,
      name: this.i18n('Copy')
    };

    const deleteAction: CdTableAction = {
      permission: 'delete',
      icon: 'fa-times',
      click: () => this.deleteNfsModal(),
      name: this.i18n('Delete')
    };

    this.tableActions = [addAction, editAction, copyAction, deleteAction];
  }

  ngOnInit() {
    this.columns = [
      {
        name: this.i18n('Export'),
        prop: 'path',
        flexGrow: 2,
        cellTransformation: CellTemplate.executing
      },
      {
        name: this.i18n('Host'),
        prop: 'host',
        flexGrow: 2
      },
      {
        name: this.i18n('State'),
        prop: 'host',
        flexGrow: 2,
        cellTemplate: this.nfsState
      },
      {
        name: this.i18n('Storage Backend'),
        prop: 'fsal',
        flexGrow: 2,
        cellTemplate: this.nfsFsal
      },
      {
        name: this.i18n('Access Type'),
        prop: 'accessType',
        flexGrow: 2
      }
    ];

    this.taskListService.init(
      () => this.nfsService.list(),
      (resp) => this.prepareResponse(resp),
      (images) => (this.images = images),
      () => this.onFetchError(),
      this.taskFilter,
      this.itemFilter,
      this.builders
    );
  }

  ngOnDestroy() {
    this.nfsStateService.stopPooling();

    if (this.summaryDataSubscription) {
      this.summaryDataSubscription.unsubscribe();
    }
  }

  prepareResponse(resp: any): any[] {
    let result = [];
    resp.forEach((nfs) => {
      nfs.id = `${nfs.host}:${nfs.exportId}`;
      nfs.state = 'LOADING';
      result = result.concat(nfs);
    });

    return result;
  }

  onFetchError() {
    this.table.reset(); // Disable loading indicator.
    this.viewCacheStatus = { status: ViewCacheStatus.ValueException };
  }

  itemFilter(entry, task) {
    return (
      entry.host === task.metadata['host_name'] && entry.exportId === task.metadata['export_id']
    );
  }

  taskFilter(task) {
    return ['nfs/create', 'nfs/delete', 'nfs/edit'].includes(task.name);
  }

  updateSelection(selection: CdTableSelection) {
    this.selection = selection;
  }

  deleteNfsModal() {
    const host = this.selection.first().host;
    const exportId = this.selection.first().exportId;

    this.modalRef = this.modalService.show(CriticalConfirmationModalComponent, {
      initialState: {
        itemDescription: this.i18n('NFS'),
        submitActionObservable: () =>
          this.taskWrapper.wrapTaskAroundCall({
            task: new FinishedTask('nfs/delete', {
              host_name: host,
              export_id: exportId
            }),
            call: this.nfsService.delete(host, exportId)
          })
      }
    });
  }

  stateAction() {
    this.modalRef = this.modalService.show(NfsManageServiceModalComponent, {
      initialState: {
        nfsStateService: this.nfsStateService
      }
    });
  }
}
