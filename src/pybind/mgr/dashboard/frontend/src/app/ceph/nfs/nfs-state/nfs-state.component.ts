import { Component, Input, OnChanges } from '@angular/core';

import { NfsStateService } from '../../../shared/services/nfs-state.service';

@Component({
  selector: 'cd-nfs-state',
  templateUrl: './nfs-state.component.html',
  styleUrls: ['./nfs-state.component.scss']
})
export class NfsStateComponent implements OnChanges {
  @Input()
  host;

  state: string;

  constructor(private nfsStateService: NfsStateService) {}

  ngOnChanges() {
    this.nfsStateService.subscribe(this.host, (state: string) => {
      this.state = state;
    });
  }
}
