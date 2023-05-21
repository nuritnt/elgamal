import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.Arrays;
import java.util.Random;
import java.util.stream.Collectors;


public class Elgamal {

    public static void main(String[] args) {
        String hex = "FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1 29024E08 8A67CC74 " +
                "020BBEA6 3B139B22 514A0879 8E3404DD EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245 " +
                "E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 " +
                "49286651 ECE45B3D C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F 83655D23 DCA3AD96 " +
                "1C62F356 208552BB 9ED52907 7096966D 670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B " +
                "E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9 DE2BCBF6 95581718 3995497C EA956AE5 " +
                "15D22618 98FA0510 15728E5A 8AACAA68 FFFFFFFF FFFFFFFF";

        // Whitespaces vom String entfernen
        hex = hex.replaceAll("\\s", "");

        // Hex String in BigInt konvertieren
        BigInteger n = new BigInteger(hex, 16);
        BigInteger g = BigInteger.valueOf(2);

        // Schlüsselpaare generieren
        // Für Unsere
        BigInteger[] keys = generateKeys(n, g);
        BigInteger chosenPubKey = keys[0];
        BigInteger chosenPrivKey = keys[1];

        // Nur ausführen, für unser eigenen Chiffre!
        // Eigene Chiffre ver- und entschlüsseln
        saveKeyToFile("chosenPk.txt", chosenPubKey);
        saveKeyToFile("chosenSk.txt", chosenPrivKey);


        try {
            // Für Gegebene Key holen
            BigInteger givenPubKey = new BigInteger(readFileAsString("pk.txt"));
            BigInteger givenPrivKey = new BigInteger(readFileAsString("sk.txt"));

            // 3. Text aus text.txt verschüsseln
            // Holt Text von "text.txt"
            String msg = readFileAsString("text.txt");
            // Verschlüsselt Text mit öffentlichen Schlüssel
            String encryptedMsg = encrypt(n, g, chosenPubKey, msg);
            // Verschlüsselten Text >> "chiffre_gruppe.txt"
            writeFile("chiffre_gruppe.txt", encryptedMsg);

            // 4. Text aus chiffre.txt mit dem privaten Schlüssel aus sk.txt entschlüsseln
            // Holt Text von "chiffre.txt"
            String encryptedMsgFile = readFileAsString("chiffre_gruppe.txt");
            // Text entschlüsseln mit private Key
            String decryptedMsg = decrypt(n, g, chosenPrivKey, encryptedMsgFile);
            // Entschlüsselten Text >> "text-d.txt"
            writeFile("text-d.txt", decryptedMsg);
            System.out.println("Entschlüsselung aus text.txt: " + decryptedMsg);

            // 5. Text aus chiffre.txt und chiffre_gruppe.txt mit den gegebenen Schlüsseln entschlüsseln
            // Text mit private Key entschlüsseln
            // Entschlüsselte Nachricht ausgeben
            String encryptedContent = readFileAsString("chiffre.txt");
            String decryptedContent = decrypt(n, g, givenPrivKey, encryptedContent);
            System.out.println("Entschlüsselung aus chiffre.txt: " + decryptedContent);
        } catch (IOException e) {
            e.printStackTrace();
        }

//        try {
//            // Text aus "text.txt" lesen
//            String msg = readFileAsString("text.txt");
//            // Text mit dem öffentlichen Schlüssel verschlüsseln
//            String encryptedMsg = encrypt(n, g, pubKey, msg);
//            // Verschlüsselten Text in "chiffre.txt" schreiben
//            writeFile("chiffre.txt", encryptedMsg);
//
//            // Verschlüsselten Text aus "chiffre.txt" lesen
//            String encryptedMsgFile = readFileAsString("chiffre.txt");
//            // Text mit dem privaten Schlüssel entschlüsseln
//            String decryptedMsg = decrypt(n, g, privKey, encryptedMsgFile);
//            // Entschlüsselten Text in "text-d.txt" schreiben
//            writeFile("text-d.txt", decryptedMsg);
//
//            // Verschlüsselten Text erneut aus "chiffre.txt" lesen
//            String computedEncryptedMsg = readFileAsString("chiffre.txt");
//            // Text mit dem privaten Schlüssel erneut entschlüsseln
//            String computedDecryptedMsg = decrypt(n, g, privKey, computedEncryptedMsg);
//            // Entschlüsselten Text ausgeben
//            System.out.println("Entschlüsselung aus chiffre.txt: " + computedDecryptedMsg);
//        } catch (IOException e) {
//            e.printStackTrace();
//        }
    }

    // Generiert Schlüsselpaar aus öff. und priv. Keys
    private static BigInteger[] generateKeys(BigInteger n, BigInteger g) {
        BigInteger privKey = getRandomBigInt(n);
        BigInteger pubKey = g.modPow(privKey, n);
        return new BigInteger[]{pubKey, privKey};
    }

    // Verschlüsseln
    private static String encrypt(BigInteger n, BigInteger g, BigInteger pubKey, String msg) {
        return Arrays.stream(msg.split(""))
                .map(m -> BigInteger.valueOf((int) m.charAt(0)))
                .map(x -> {
                    // Random Wert gemäss Methode generieren
                    BigInteger a = getRandomBigInt(n);
                    // y1 = g^a mod n
                    BigInteger y1 = g.modPow(a, n);
                    // y2 = pubKey^a * x mod n
                    BigInteger y2 = pubKey.modPow(a, n).multiply(x).mod(n);
                    return "(" + y1 + "," + y2 + ")";
                })
                .collect(Collectors.joining(";"));
    }

    // Entschüsseln
    private static String decrypt(BigInteger n, BigInteger g, BigInteger privKey, String encryptedMsg) {
        // Verschüsselte Nachricht wird bei ";" gesplittet
        return Arrays.stream(encryptedMsg.split(";"))
                // Äussere Klammern und Leerzeichen werden entfernt
                .map(s -> s.substring(1, s.length() - 1).trim())
                .map(s -> {
                    // String beim Komma splitten
                    String[] pairs = s.split(",");
                    BigInteger y1 = new BigInteger(pairs[0]);
                    BigInteger y2 = new BigInteger(pairs[1]);
                    // x = y2 * (y1^(-privKey)) mod n
                    BigInteger x = y2.multiply(y1.modPow(privKey.negate(), n)).mod(n);
                    return Character.toString((char) x.intValue());
                })
                .collect(Collectors.joining());
    }

    // Random BigInteger generieren mit Range [0, n-1]
    private static BigInteger getRandomBigInt(BigInteger n) {
        BigInteger maxRange = n.subtract(BigInteger.ONE);
        BigInteger randomBigInt;
        do {
            randomBigInt = new BigInteger(maxRange.bitLength(), new Random());
        } while (randomBigInt.compareTo(maxRange) >= 0);
        return randomBigInt;
    }

    // File helpers
    // Hier haben wir uns mit Google helfen lassen.
    private static void saveKeyToFile(String fileName, BigInteger key) {
        writeFile(fileName, key.toString());
    }

    //writeToFile
    private static void writeFile(String fileName, String content) {
        try {
            Files.writeString(Paths.get(fileName), content);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    //private static void writeFile(String fileName, String content) {
    //    try {
    //        Files.writeString(Paths.get(fileName), content);
    //    } catch (IOException e) {
    //        e.printStackTrace();
    //    }
    //}

    private static String readFileAsString(String fileName) throws IOException {
        return Files.readString(Paths.get(fileName));
    }
}
