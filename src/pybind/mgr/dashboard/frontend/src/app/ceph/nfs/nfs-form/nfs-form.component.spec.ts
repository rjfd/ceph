import { HttpClientTestingModule } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { ReactiveFormsModule } from '@angular/forms';
import { RouterTestingModule } from '@angular/router/testing';

import { ToastModule } from 'ng2-toastr';
import { TypeaheadModule } from 'ngx-bootstrap/typeahead';

import { configureTestBed } from '../../../../testing/unit-test-helper';
import { SharedModule } from '../../../shared/shared.module';
import { NfsFormClientComponent } from '../nfs-form-client/nfs-form-client.component';
import { NfsFormComponent } from './nfs-form.component';

describe('NfsFormComponent', () => {
  let component: NfsFormComponent;
  let fixture: ComponentFixture<NfsFormComponent>;

  configureTestBed({
    declarations: [NfsFormComponent, NfsFormClientComponent],
    imports: [
      HttpClientTestingModule,
      ReactiveFormsModule,
      RouterTestingModule,
      SharedModule,
      ToastModule.forRoot(),
      TypeaheadModule.forRoot(),
    ]
  });

  beforeEach(() => {
    fixture = TestBed.createComponent(NfsFormComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
