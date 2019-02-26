package im.status.keycard.applet;


import org.bouncycastle.util.encoders.Hex;

import java.io.IOException;
import java.util.Arrays;


import im.status.keycard.io.APDUCommand;
import im.status.keycard.io.APDUException;
import im.status.keycard.io.APDUResponse;
import im.status.keycard.io.CardChannel;

/**
 * This class is used to send APDU to the applet. Each method corresponds to an APDU as defined in the APPLICATION.md
 * file. Some APDUs map to multiple methods for the sake of convenience since their payload or response require some
 * pre/post processing.
 */
public class NExTouchCommandSet {
  static final byte INS_INIT = (byte) 0xFE;

  private final CardChannel apduChannel;
  private SecureChannelSession secureChannel;

  /**
   * Creates a KeycardCommandSet using the given APDU Channel
   * @param apduChannel APDU channel
   */
  public NExTouchCommandSet(CardChannel apduChannel) {
    this.apduChannel = apduChannel;
    this.secureChannel = new SecureChannelSession();
  }

  /**
   * Set the SecureChannel object
   * @param secureChannel secure channel
   */
  protected void setSecureChannel(SecureChannelSession secureChannel) {
    this.secureChannel = secureChannel;
  }

  public APDUResponse select() throws IOException {
    APDUCommand selectApplet = new APDUCommand(0x00, 0xA4, 4, 0, Identifiers.U2F_AID);
    APDUResponse resp =  apduChannel.send(selectApplet);
//
//    if (resp.getSw() == 0x9000) {
//      this.setAttestationCert();
//    }

    return resp;
  }

  public APDUResponse enroll(byte[] param) throws IOException {
    APDUCommand cmd = new APDUCommand(0x00, 0x01, 0x03, 0, param);
    APDUResponse resp =  apduChannel.send(cmd);
    return resp;
  }

  public APDUResponse sign(byte[] param) throws IOException {
    APDUCommand cmd = new APDUCommand(0x00, 0x02, 0x03, 0, param);
    APDUResponse resp =  apduChannel.send(cmd);
    return resp;
  }

  public void setAttestationCert(String cert) throws IOException, APDUException {

    APDUCommand setCertPart1 = new APDUCommand(0xf0, 0x01, 00, 00, Hex.decode(cert.substring(0, 256)));
    APDUCommand setCertPart2 = new APDUCommand(0xf0, 0x01, 00, 0x80, Hex.decode(cert.substring(256, 512)));
    APDUCommand setCertPart3 = new APDUCommand(0xf0, 0x01, 01, 00, Hex.decode(cert.substring(512, cert.length())));
    apduChannel.send(setCertPart1).checkOK();
    apduChannel.send(setCertPart2).checkOK();
    apduChannel.send(setCertPart3).checkOK();

  }

  public APDUResponse init(String pin, String puk, byte[] sharedSecret) throws IOException {
    byte[] initData = Arrays.copyOf(pin.getBytes(), pin.length() + puk.length() + sharedSecret.length);
    System.arraycopy(puk.getBytes(), 0, initData, pin.length(), puk.length());
    System.arraycopy(sharedSecret, 0, initData, pin.length() + puk.length(), sharedSecret.length);
    APDUCommand init = new APDUCommand(0x80, INS_INIT, 0, 0, secureChannel.oneShotEncrypt(initData));
    return apduChannel.send(init);
  }


}
