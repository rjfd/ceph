import { HttpClientTestingModule } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { RouterTestingModule } from '@angular/router/testing';

import { ToastModule } from 'ng2-toastr';

import { configureTestBed } from '../../../../testing/unit-test-helper';
import { SharedModule } from '../../../shared/shared.module';
import { NfsStateComponent } from './nfs-state.component';

describe('NfsStateComponent', () => {
  let component: NfsStateComponent;
  let fixture: ComponentFixture<NfsStateComponent>;

  configureTestBed({
    declarations: [NfsStateComponent],
    imports: [HttpClientTestingModule, RouterTestingModule, SharedModule, ToastModule.forRoot()]
  });

  beforeEach(() => {
    fixture = TestBed.createComponent(NfsStateComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
