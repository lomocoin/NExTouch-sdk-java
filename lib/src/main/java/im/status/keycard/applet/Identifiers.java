package im.status.keycard.applet;

import org.bouncycastle.util.encoders.Hex;

import java.util.Arrays;

public class Identifiers {
  public static final byte[] PACKAGE_AID = Hex.decode("A0000008040001");

  public static final byte[] KEYCARD_AID = Hex.decode("A000000804000101");
  public static final int KEYCARD_DEFAULT_INSTANCE_IDX = 1;

  public static final byte[] NDEF_AID = Hex.decode("A000000804000102");
  public static final byte[] NDEF_INSTANCE_AID = Hex.decode("D2760000850101");

  public static final byte[] U2F_PACKAGE_AID = Hex.decode("A0000006472F0000");
  public static final byte[] U2F_AID = Hex.decode("A0000006472F0001");
  public static final byte[] U2F_INSTANCE_AID = Hex.decode("A0000006472F0001");

  /**
   * Gets the instance AID of the default instance of the Keycard applet.
   *
   * @return the instance AID of the Keycard applet
   */
  public static byte[] getKeycardInstanceAID() {
    return getKeycardInstanceAID(KEYCARD_DEFAULT_INSTANCE_IDX);
  }

  /**
   * Gets the instance AID of the Keycard applet with the given index. Since multiple instances of the Keycard applet
   * could be installed in parallel, this method allows selecting a specific instance. The index is between 01 and ff
   *
   * @return the instance AID of the Keycard applet
   */
  public static byte[] getKeycardInstanceAID(int instanceIdx) {
    if (instanceIdx < 0x01 || instanceIdx > 0xff) {
      throw new IllegalArgumentException("The instance index must be between 1 and 255");
    }

    byte[] instanceAID = Arrays.copyOf(KEYCARD_AID, KEYCARD_AID.length + 1);
    instanceAID[KEYCARD_AID.length] = (byte) instanceIdx;
    return instanceAID;
  }
}
