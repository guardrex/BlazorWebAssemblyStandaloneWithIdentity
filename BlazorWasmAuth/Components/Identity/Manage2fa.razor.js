export function setQrCode(qrCodeElement, uri) {
  if (qrCodeElement !== null &&
      qrCodeElement.innerHTML !== undefined &&
      !qrCodeElement.innerHTML.trim()) {
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
