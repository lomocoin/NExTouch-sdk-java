package im.status.keycard.android;

import android.nfc.tech.IsoDep;
import android.util.Log;
import im.status.keycard.io.APDUCommand;
import im.status.keycard.io.APDUResponse;
import im.status.keycard.io.CardChannel;

import java.io.IOException;
import java.math.BigInteger;

/**
 * Implementation of the CardChannel interface using the Android NFC API.
 */
public class NFCCardChannel implements CardChannel {
  private static final String TAG = "CardChannel";
  private static final byte[] GET_RESPONSE_COMMAND = {0x00, (byte) 0xc0, 0x00, 0x00, (byte) 0x00};


  private IsoDep isoDep;

  public NFCCardChannel(IsoDep isoDep) {
    this.isoDep = isoDep;
  }

  @Override
  public APDUResponse send(APDUCommand cmd) throws IOException {




    byte[] apdu = cmd.serialize();
    int status = 0x6100;
    byte[] data = new byte[0];
    byte[] resp = new byte[0];
    while ((status & 0xff00) == 0x6100) {
      resp = this.isoDep.transceive(apdu);
      status = ((0xff & resp[resp.length - 2]) << 8) | (0xff & resp[resp.length - 1]);
      data = concat(data, resp, resp.length - 2);
      apdu = GET_RESPONSE_COMMAND;
    }
    byte[] statusBytes = {resp[resp.length - 2], resp[resp.length - 1]};
    byte[] fullData = concat(data, statusBytes, statusBytes.length);


    return new APDUResponse(fullData);

  }

  private static byte[] concat(byte[] a, byte[] b, int length) {
    byte[] res = new byte[a.length + length];
    System.arraycopy(a, 0, res, 0, a.length);
    System.arraycopy(b, 0, res, a.length, length);
    return res;
  }


  @Override
  public boolean isConnected() {
    return this.isoDep.isConnected();
  }
}
