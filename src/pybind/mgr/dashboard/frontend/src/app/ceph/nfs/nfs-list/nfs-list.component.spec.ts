import { HttpClientTestingModule } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { RouterTestingModule } from '@angular/router/testing';

import { ToastModule } from 'ng2-toastr';
import { TabsModule } from 'ngx-bootstrap/tabs';

import { configureTestBed } from '../../../../testing/unit-test-helper';
import { SharedModule } from '../../../shared/shared.module';
import { NfsDetailsComponent } from '../nfs-details/nfs-details.component';
import { NfsStateComponent } from '../nfs-state/nfs-state.component';
import { NfsListComponent } from './nfs-list.component';

describe('NfsListComponent', () => {
  let component: NfsListComponent;
  let fixture: ComponentFixture<NfsListComponent>;

  configureTestBed({
    declarations: [NfsListComponent, NfsDetailsComponent, NfsStateComponent],
    imports: [
      HttpClientTestingModule,
      RouterTestingModule,
      SharedModule,
      ToastModule.forRoot(),
      TabsModule.forRoot()
    ]
  });

  beforeEach(() => {
    fixture = TestBed.createComponent(NfsListComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
