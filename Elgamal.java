import java.math.BigInteger;
import java.util.Arrays;
import java.util.Random;
import java.util.stream.Collectors;

public class Elgamal {
    public static void main(String[] args) {
        // Primzahlen und Erzäuger
        BigInteger n = new BigInteger("FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1 29024E08 8A67CC74 020BBEA6" +
                "3B139B22 514A0879 8E3404DD EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245 E485B576" +
                "625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651" +
                "ECE45B3D C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F 83655D23 DCA3AD96 1C62F356" +
                "208552BB 9ED52907 7096966D 670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B E39E772C" +
                "180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9 DE2BCBF6 95581718 3995497C EA956AE5 15D22618" +
                "98FA0510 15728E5A 8AACAA68 FFFFFFFF FFFFFFFF", 16);
        BigInteger g = BigInteger.valueOf(2);

        // Schlüsselpaare generieren
        BigInteger[] keys = generateKeys(n, g);
        BigInteger publicKey = keys[0];
        BigInteger privateKey = keys[1];

        // Eine Nachricht ver und entschlüsseln
        String msg = "Mit Ovomaltine geht alles!";
        String encryptedMsg = encrypt(n, g, publicKey, msg);
        String decryptedMsg = decrypt(n, g, privateKey, encryptedMsg);

        // Hier werden die Ergebnisse ausgegeben
        System.out.println("Original message: " + msg);
        System.out.println("Encrypted message: " + encryptedMsg);
        System.out.println("Decrypted message: " + decryptedMsg);
    }

    // Generiert ein Schlüsselpaar aus dem öffentlichen und privaten Schlüssel
    private static BigInteger[] generateKeys(BigInteger n, BigInteger g) {
        BigInteger privateKey = getRandomBigInteger(n);
        BigInteger publicKey = g.modPow(privateKey, n);
        return new BigInteger[]{publicKey, privateKey};
    }

    // Verschlüsseln
    private static String encrypt(BigInteger n, BigInteger g, BigInteger publicKey, String msg) {
        return Arrays.stream(msg.split(""))
                .map(m -> BigInteger.valueOf(m.charAt(0)))
                .map(x -> {
                    // Generiert zufälligen Wert a im Bereich [0, n-1]
                    BigInteger a = getRandomBigInteger(n);
                    // y1 = g^a mod n
                    BigInteger y1 = g.modPow(a, n);
                    // y2 = publicKey^a * x mod n
                    BigInteger y2 = publicKey.modPow(a, n).multiply(x).mod(n);
                    return "(" + y1 + "," + y2 + ")";
                })
                .collect(Collectors.joining(";"));
    }

    // Entschüsseln
    private static String decrypt(BigInteger n, BigInteger g, BigInteger privateKey, String encryptedMsg) {
        // Verschüsselte Nachricht wird bei ";" gesplittet
        return Arrays.stream(encryptedMsg.split(";"))
                // Äussere Klammern und Leerzeichen werden entfernt
                .map(s -> s.substring(1, s.length() - 1).trim())
                .map(s -> {
                    // String beim Komma splitten
                    String[] paare = s.split(",");
                    BigInteger y1 = new BigInteger(paare[0]);
                    BigInteger y2 = new BigInteger(paare[1]);
                    // x = y2 * (y1^(-privateKey)) mod n
                    BigInteger x = y2.multiply(y1.modPow(privateKey.negate(), n)).mod(n);
                    return Character.toString((char) x.intValue());
                })
                .collect(Collectors.joining());
    }

    // Random BigInteger generieren, welches die Range [0, n-1] hat
    private static BigInteger getRandomBigInteger(BigInteger n) {
        BigInteger maxRange = n.subtract(BigInteger.ONE);
        BigInteger randomBigInteger;
        do {
            randomBigInteger = new BigInteger(maxRange.bitLength(), new Random());
        } while (randomBigInteger.compareTo(maxRange) >= 0);
        return randomBigInteger;
    }
}
