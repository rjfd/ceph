// TODO: I18N
const nfsAccessType = [
  {
    value: 'RW',
    help: 'Allows all operations'
  },
  {
    value: 'RO',
    help: 'Allows only operations that do not modify the server'
  },
  {
    value: 'MDONLY',
    help: 'Does not allow read or write operations, but allows any other operation'
  },
  {
    value: 'MDONLY_RO',
    help:
      'Does not allow read, write, or any operation that modifies file \
     attributes or directory content'
  },
  {
    value: 'NONE',
    help: 'Allows no access at all'
  }
];

const nfsFsal = [
  {
    value: 'CEPH',
    descr: 'CephFS'
  },
  {
    value: 'RGW',
    descr: 'Object Gateway'
  }
];

const nfsSquash = ['None', 'Root', 'All'];

export { nfsAccessType, nfsFsal, nfsSquash };
