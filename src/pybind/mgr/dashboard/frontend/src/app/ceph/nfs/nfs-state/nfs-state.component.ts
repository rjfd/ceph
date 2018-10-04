import { Component, Input, OnInit } from '@angular/core';

import { NfsStateService } from '../../../shared/services/nfs-state.service';

@Component({
  selector: 'cd-nfs-state',
  templateUrl: './nfs-state.component.html',
  styleUrls: ['./nfs-state.component.scss']
})
export class NfsStateComponent implements OnInit {
  @Input()
  host;

  state: string;

  constructor(private nfsStateService: NfsStateService) {}

  ngOnInit() {
    this.nfsStateService.subscribe(this.host, (state: string) => {
      this.state = state;
    });
  }
}
