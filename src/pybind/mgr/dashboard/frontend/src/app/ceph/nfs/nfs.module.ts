import { CommonModule } from '@angular/common';
import { NgModule } from '@angular/core';
import { RouterModule } from '@angular/router';

import { TabsModule } from 'ngx-bootstrap/tabs';
import { TypeaheadModule } from 'ngx-bootstrap/typeahead';

import { ReactiveFormsModule } from '@angular/forms';
import { SharedModule } from '../../shared/shared.module';
import { NfsDetailsComponent } from './nfs-details/nfs-details.component';
import { NfsFormClientComponent } from './nfs-form-client/nfs-form-client.component';
import { NfsFormComponent } from './nfs-form/nfs-form.component';
import { NfsListComponent } from './nfs-list/nfs-list.component';
import { NfsManageServiceModalComponent } from './nfs-manage-service-modal/nfs-manage-service-modal.component';
import { NfsStateComponent } from './nfs-state/nfs-state.component';

@NgModule({
  imports: [
    ReactiveFormsModule,
    RouterModule,
    SharedModule,
    TabsModule.forRoot(),
    CommonModule,
    TypeaheadModule.forRoot()
  ],
  declarations: [
    NfsListComponent,
    NfsDetailsComponent,
    NfsFormComponent,
    NfsFormClientComponent,
    NfsManageServiceModalComponent,
    NfsStateComponent
  ],
  entryComponents: [NfsManageServiceModalComponent]
})
export class NfsModule {}
