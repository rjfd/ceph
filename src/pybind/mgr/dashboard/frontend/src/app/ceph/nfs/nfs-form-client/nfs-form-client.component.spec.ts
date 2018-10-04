import { ComponentFixture, TestBed } from '@angular/core/testing';
import { ReactiveFormsModule } from '@angular/forms';

import { configureTestBed } from '../../../../testing/unit-test-helper';
import { CdFormBuilder } from '../../../shared/forms/cd-form-builder';
import { CdFormGroup } from '../../../shared/forms/cd-form-group';
import { SharedModule } from '../../../shared/shared.module';
import { NfsFormClientComponent } from './nfs-form-client.component';

describe('NfsFormClientComponent', () => {
  let component: NfsFormClientComponent;
  let fixture: ComponentFixture<NfsFormClientComponent>;

  configureTestBed({
    declarations: [NfsFormClientComponent],
    imports: [ReactiveFormsModule, SharedModule]
  });

  beforeEach(() => {
    fixture = TestBed.createComponent(NfsFormClientComponent);
    const formBuilder = TestBed.get(CdFormBuilder);
    component = fixture.componentInstance;

    component.form = this.nfsForm = new CdFormGroup({
      clientBlocks: formBuilder.array([])
    });

    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
