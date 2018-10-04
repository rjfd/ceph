import { ComponentFixture, TestBed } from '@angular/core/testing';

import { HttpClientTestingModule } from '@angular/common/http/testing';
import { TabsModule } from 'ngx-bootstrap';
import { configureTestBed } from '../../../../testing/unit-test-helper';
import { SharedModule } from '../../../shared/shared.module';
import { NfsDetailsComponent } from './nfs-details.component';

describe('NfsDetailsComponent', () => {
  let component: NfsDetailsComponent;
  let fixture: ComponentFixture<NfsDetailsComponent>;

  configureTestBed({
    declarations: [NfsDetailsComponent],
    imports: [SharedModule, TabsModule.forRoot(), HttpClientTestingModule]
  });

  beforeEach(() => {
    fixture = TestBed.createComponent(NfsDetailsComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
