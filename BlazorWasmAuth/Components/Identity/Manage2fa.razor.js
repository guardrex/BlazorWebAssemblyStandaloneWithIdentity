export function setQrCode(qrCodeElement, uri) {
  if (qrCodeElement !== null) {
    QrCreator.render({
      text: uri,
      radius: 0,
      ecLevel: 'H',
      fill: '#000000',
      background: null,
      size: 190
    }, qrCodeElement);
  }
}
