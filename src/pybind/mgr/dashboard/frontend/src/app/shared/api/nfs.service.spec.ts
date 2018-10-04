import { HttpClientTestingModule, HttpTestingController } from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';

import { configureTestBed } from '../../../testing/unit-test-helper';
import { NfsService } from './nfs.service';

describe('NfsService', () => {
  let service: NfsService;
  let httpTesting: HttpTestingController;

  configureTestBed({
    providers: [NfsService],
    imports: [HttpClientTestingModule]
  });

  beforeEach(() => {
    service = TestBed.get(NfsService);
    httpTesting = TestBed.get(HttpTestingController);
  });

  afterEach(() => {
    httpTesting.verify();
  });

  it('should be created', () => {
    expect(service).toBeTruthy();
  });

  it('should call list', () => {
    service.list().subscribe();
    const req = httpTesting.expectOne('api/nfs');
    expect(req.request.method).toBe('GET');
  });

  it('should call get', () => {
    service.get('hostName', 'exportId').subscribe();
    const req = httpTesting.expectOne('api/nfs/hostName/exportId');
    expect(req.request.method).toBe('GET');
  });

  it('should call create', () => {
    service.create('foo').subscribe();
    const req = httpTesting.expectOne('api/nfs');
    expect(req.request.method).toBe('POST');
    expect(req.request.body).toEqual('foo');
  });

  it('should call update', () => {
    service.update('hostName', 'exportId', 'foo').subscribe();
    const req = httpTesting.expectOne('api/nfs/hostName/exportId');
    expect(req.request.body).toEqual('foo');
    expect(req.request.method).toBe('PUT');
  });

  it('should call copy', () => {
    service.copy('hostName', 'exportId', 'foo').subscribe();
    const req = httpTesting.expectOne('api/nfs/hostName/exportId');
    expect(req.request.body).toEqual('foo');
    expect(req.request.method).toBe('POST');
  });

  it('should call delete', () => {
    service.delete('hostName', 'exportId').subscribe();
    const req = httpTesting.expectOne('api/nfs/hostName/exportId');
    expect(req.request.method).toBe('DELETE');
  });

  it('should call lsDir', () => {
    service.lsDir('root_dir', 'userid').subscribe();
    const req = httpTesting.expectOne('api/nfs/lsdir');
    expect(req.request.method).toBe('GET');
  });

  it('should call buckets', () => {
    service.buckets('userid').subscribe();
    const req = httpTesting.expectOne('api/nfs/buckets');
    expect(req.request.method).toBe('GET');
  });

  it('should call status', () => {
    service.status().subscribe();
    const req = httpTesting.expectOne('api/nfs/host/status');
    expect(req.request.method).toBe('GET');
  });

  it('should call start', () => {
    service.start('host_name').subscribe();
    const req = httpTesting.expectOne('api/nfs/host/host_name/start');
    expect(req.request.method).toBe('PUT');
  });

  it('should call stop', () => {
    service.stop('host_name').subscribe();
    const req = httpTesting.expectOne('api/nfs/host/host_name/stop');
    expect(req.request.method).toBe('PUT');
  });
});
