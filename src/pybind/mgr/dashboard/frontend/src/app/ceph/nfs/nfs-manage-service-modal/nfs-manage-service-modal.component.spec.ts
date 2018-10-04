import { HttpClientTestingModule } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { RouterTestingModule } from '@angular/router/testing';

import { ToastModule } from 'ng2-toastr';
import { BsModalRef } from 'ngx-bootstrap';

import { configureTestBed } from '../../../../testing/unit-test-helper';
import { SharedModule } from '../../../shared/shared.module';
import { NfsStateComponent } from '../nfs-state/nfs-state.component';
import { NfsManageServiceModalComponent } from './nfs-manage-service-modal.component';

describe('NfsManageServiceModalComponent', () => {
  let component: NfsManageServiceModalComponent;
  let fixture: ComponentFixture<NfsManageServiceModalComponent>;

  configureTestBed({
    declarations: [NfsManageServiceModalComponent, NfsStateComponent],
    imports: [HttpClientTestingModule, RouterTestingModule, SharedModule, ToastModule.forRoot()],
    providers: [BsModalRef]
  });

  beforeEach(() => {
    fixture = TestBed.createComponent(NfsManageServiceModalComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
