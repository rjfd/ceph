import { HttpClientTestingModule, HttpTestingController } from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';
import { RouterTestingModule } from '@angular/router/testing';

import { ToastModule } from 'ng2-toastr';

import { configureTestBed } from '../../../testing/unit-test-helper';
import { NfsService } from '../api/nfs.service';
import { SharedModule } from '../shared.module';
import { NfsStateService } from './nfs-state.service';

describe('NfsStateService', () => {
  let service: NfsStateService;
  let httpTesting: HttpTestingController;
  const executing_tasks = [
    { name: 'nfs/host/stop', metadata: { host_name: 'host_stop' } },
    { name: 'nfs/host/start', metadata: { host_name: 'host_start' } }
  ];

  configureTestBed({
    providers: [NfsStateService],
    imports: [HttpClientTestingModule, SharedModule, ToastModule.forRoot(), RouterTestingModule]
  });

  beforeEach(() => {
    httpTesting = TestBed.get(HttpTestingController);
    service = TestBed.get(NfsStateService);
    service.pooling = true;
  });

  it('should be created', () => {
    expect(service).toBeTruthy();
  });

  it('should enable pooling', () => {
    service.pooling = false;
    expect(service.pooling).toBeFalsy();
    service.startPooling();
    expect(service.pooling).toBeTruthy();
    httpTesting.expectOne('api/nfs/host/status');
  });

  it('should disable pooling', () => {
    expect(service.pooling).toBeTruthy();
    service.stopPooling();
    expect(service.pooling).toBeFalsy();
  });

  describe('should test getState', () => {
    it('should return "STARTING"', () => {
      const state = service.getState({ active: false }, 'host_start', executing_tasks);
      expect(state).toBe('STARTING');
    });

    it('should return "STOPPING"', () => {
      const state = service.getState({ active: true }, 'host_stop', executing_tasks);
      expect(state).toBe('STOPPING');
    });

    it('should return "ACTIVE"', () => {
      const state = service.getState({ active: true }, 'other_host', executing_tasks);
      expect(state).toBe('ACTIVE');
    });

    it('should return "INACTIVE"', () => {
      const state = service.getState({ active: false }, 'other_host', executing_tasks);
      expect(state).toBe('INACTIVE');
    });

    it('should return "LOADING"', () => {
      const state = service.getState({ active: undefined }, 'hostname', executing_tasks);
      expect(state).toBe('LOADING');
    });

    it('should return "UNKNOWN"', () => {
      const state = service.getState({ active: null }, 'hostname', executing_tasks);
      expect(state).toBe('UNKNOWN');
    });
  });

  describe('Use nfsService', () => {
    let nfsService: NfsService;
    let host: any;

    beforeEach(() => {
      nfsService = TestBed.get(NfsService);
      host = {
        active: undefined,
        state: undefined,
        message: 'foo',
        messages: 'foo'
      };
    });

    it('should update states with no summary', () => {
      let result;

      spyOn(nfsService, 'status').and.callThrough();
      service.subscribe('host_name', (data) => {
        result = data;
      });

      service.updateStates();

      const req = httpTesting.expectOne('api/nfs/host/status');
      req.flush({
        host_name: {
          active: true,
          exports: [{ active: true, message: undefined, export_id: 1 }]
        }
      });

      expect(result).toEqual('ACTIVE');
    });

    it('should update states with summary', () => {
      let result;
      const summary = {
        executing_tasks: executing_tasks
      };

      spyOn(nfsService, 'status').and.callThrough();
      service.subscribe('host_start', (data) => {
        result = data;
      });

      service.updateStates(summary);

      const req = httpTesting.expectOne('api/nfs/host/status');
      req.flush({
        host_start: {
          active: true,
          exports: [{ active: true, message: undefined, export_id: 1 }]
        }
      });

      expect(result).toEqual('STARTING');
    });

    it('should start host', () => {
      spyOn(nfsService, 'start').and.callThrough();

      service.start(host, 'hostname');

      expect(host).toEqual({ active: undefined, state: 'STARTING' });
      expect(nfsService.start).toHaveBeenCalledTimes(1);
    });

    it('should stop host', () => {
      spyOn(nfsService, 'stop').and.callThrough();

      service.stop(host, 'hostname');

      expect(host).toEqual({ active: undefined, state: 'STOPPING' });
      expect(nfsService.stop).toHaveBeenCalledTimes(1);
    });
  });
});
