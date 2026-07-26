export class DeviceRevokedError extends Error {
  constructor() {
    super('此扩展设备已被撤销，请重新配对');
    this.name = 'DeviceRevokedError';
  }
}
