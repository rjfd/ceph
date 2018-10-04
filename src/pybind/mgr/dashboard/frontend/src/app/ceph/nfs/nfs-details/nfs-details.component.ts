import { Component, Input, OnChanges } from '@angular/core';

import * as _ from 'lodash';

import { NfsService } from '../../../shared/api/nfs.service';
import { CdTableSelection } from '../../../shared/models/cd-table-selection';
import { nfsAccessType, nfsFsal } from '../nfs-shared';

@Component({
  selector: 'cd-nfs-details',
  templateUrl: './nfs-details.component.html',
  styleUrls: ['./nfs-details.component.scss']
})
export class NfsDetailsComponent implements OnChanges {
  @Input()
  selection: CdTableSelection;

  selectedItem: any;
  data: any;

  constructor(private nfsService: NfsService) {}

  ngOnChanges() {
    if (this.selection.hasSelection) {
      this.selectedItem = this.selection.first();
      this.data = {
        Host: this.selectedItem.host,
        'Storage Backend': this.selectedItem.fsal,
        'Object Gateway User': this.selectedItem.rgwUserId,
        Bucket: this.selectedItem.path,
        'NFS Protocol': this.selectedItem.protocols,
        Pseudo: this.selectedItem.pseudo,
        'Access Type': this.selectedItem.accessType,
        Squash: this.selectedItem.squash,
        Transport: this.selectedItem.transports
      };
    }
  }

  getFsalDesc(fsal) {
    const fsalItem = nfsFsal.find((currentFsalItem) => {
      return fsal === currentFsalItem.value;
    });
    return _.isObjectLike(fsalItem) ? fsalItem.descr : fsal;
  }

  getAccessTypeHelp(accessType) {
    const accessTypeItem = nfsAccessType.find((currentAccessTypeItem) => {
      return accessType === currentAccessTypeItem.value;
    });
    return _.isObjectLike(accessTypeItem) ? accessTypeItem.help : '';
  }

  getMountCommand() {
    if (this.selection.hasSelection) {
      const selected = this.selection.first();
      const device = selected.pseudo || selected.tag || selected.path || '';
      return `# mount.nfs ${selected.host}:${device} /mnt`;
    }
    return '';
  }
}
