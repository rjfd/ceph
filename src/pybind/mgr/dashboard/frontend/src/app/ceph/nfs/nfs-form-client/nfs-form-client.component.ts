import { Component, Input } from '@angular/core';

import { I18n } from '@ngx-translate/i18n-polyfill';
import * as _ from 'lodash';

import { FormArray, FormControl, Validators } from '@angular/forms';
import { CdFormGroup } from '../../../shared/forms/cd-form-group';
import { CdValidators } from '../../../shared/forms/cd-validators';
import { nfsAccessType, nfsSquash } from '../nfs-shared';

@Component({
  selector: 'cd-nfs-form-client',
  templateUrl: './nfs-form-client.component.html',
  styleUrls: ['./nfs-form-client.component.scss']
})
export class NfsFormClientComponent {
  @Input()
  form: CdFormGroup;

  nfsSquash: any[] = nfsSquash;
  nfsAccessType: any[] = nfsAccessType;

  constructor(private i18n: I18n) {}

  getNoAccessTypeDescr() {
    if (this.form.getValue('accessType')) {
      return this.form.getValue('accessType') + ' (inherited from global config)';
    }
    return '-- Select the access type --';
  }

  getAccessTypeHelp(index) {
    const accessTypeItem = nfsAccessType.find((currentAccessTypeItem) => {
      return this.getValue(index, 'accessType') === currentAccessTypeItem.value;
    });
    return _.isObjectLike(accessTypeItem) ? accessTypeItem.help : '';
  }

  getNoSquashDescr() {
    if (this.form.getValue('squash')) {
      return `${this.form.getValue('squash')} (${this.i18n('inherited from global config')})`;
    }
    return this.i18n('-- Select what kind of user id squashing is performed --');
  }

  addClient() {
    const clients = this.form.get('clients') as FormArray;

    const fg = new CdFormGroup({
      clients: new FormControl('', {
        validators: [
          Validators.required,
          CdValidators.custom('stringArray', (cls) => {
            if (!cls) {
              return true;
            }

            try {
              const value = '"' + cls.replace(/,/g, '","') + '"';
              return JSON.parse('[' + value + ']').every((item) => {
                return item.trim() !== '';
              });
            } catch (err) {
              return false;
            }
          })
        ]
      }),
      accessType: new FormControl(''),
      squash: new FormControl('')
    });

    clients.push(fg);
  }

  removeClient(index) {
    const clients = this.form.get('clients') as FormArray;
    clients.removeAt(index);
  }

  showError(index, control, formDir, x) {
    return (<any>this.form.controls.clients).controls[index].showError(control, formDir, x);
  }

  getValue(index, control) {
    const clients = this.form.get('clients') as FormArray;
    const client = clients.at(index) as CdFormGroup;
    return client.getValue(control);
  }

  trackByFn(index, item) {
    return index; // or item.id
  }
}
