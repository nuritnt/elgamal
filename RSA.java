import java.io.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.util.List;

public class RSA {

    public static void main(String[] args) {
        // Schlüsselpaar generieren
        generateKeyPair();

        // Verschlüsseln
         encryptFile("text.txt", "pk.txt", "chiffre.txt");

        // Entschlüsseln
        decryptFile("chiffre.txt", "sk.txt", "text-d.txt");
    }

    public static void generateKeyPair() {
        // 1.a) Mit Hilfe der Klasse BigInteger zwei unterschiedliche Primzahlen zufällig generieren und multiplizieren
        SecureRandom random = new SecureRandom();
        BigInteger p = BigInteger.probablePrime(1024, random);
        BigInteger q = BigInteger.probablePrime(1024, random);

        // 1.b)
        // phi(n)=(p-1)*(q-1)
        BigInteger n = p.multiply(q);
        BigInteger phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));

        // "e" so wählen, dass 1 < e < φ(n) und e und φ(n) ggT sind.
        BigInteger e;
        do {
            e = new BigInteger(phi.bitLength(), random);
        } while (e.compareTo(BigInteger.ONE) == 0 || e.compareTo(phi) == 0 || !e.gcd(phi).equals(BigInteger.ONE));

        // Entschlüssungszahl mit dem erweiterten euklidischen Algo finden.
        BigInteger[] result = extEuclid(phi, e);
        BigInteger d = result[2];

        // Generierte Keys in die zugehörigen Files reinschreiben.
        try {
            Files.write(Paths.get("pk.txt"), (n.toString() + "," + e.toString()).getBytes(StandardCharsets.UTF_8));
            Files.write(Paths.get("sk.txt"), ("(" + n.toString() + "," + d.toString() + ")").getBytes(StandardCharsets.UTF_8));
        } catch (IOException ex) {

            // Falls failt, wird diese Fehlermeldung angezeigt.
            System.err.println("Fehler beim Speichern der Schlüssel: " + ex.getMessage());
        }
    }

    // Erweiterter euklidischer Algorithmus
    private static BigInteger[] extEuclid(BigInteger a, BigInteger b) {
        BigInteger x0 = BigInteger.ONE;
        BigInteger y0 = BigInteger.ZERO;
        BigInteger x1 = BigInteger.ZERO;
        BigInteger y1 = BigInteger.ONE;
        BigInteger gcd = a;

        while (!b.equals(BigInteger.ZERO)) {
            BigInteger[] div = a.divideAndRemainder(b);
            BigInteger q = div[0];
            BigInteger tmp = b;
            b = div[1];
            a = tmp;

            BigInteger x2 = x0.subtract(q.multiply(x1));
            x0 = x1;
            x1 = x2;

            BigInteger y2 = y0.subtract(q.multiply(y1));
            y0 = y1;
            y1 = y2;
        }

        BigInteger[] result = {  gcd, x0, y0 };
        return result;
}

    public static BigInteger fastExpCalc(BigInteger x, BigInteger e, BigInteger n) { // (x^e) % n
        String binaryE = e.toString(2);
        BigInteger k, h;
        k = x;
        h = BigInteger.ONE; // wird zur Berechnung benötigt
        int i = binaryE.length() - 1;

        while (i >= 0) {
            if (binaryE.charAt(i) == '1') {
                h = k.multiply(h).mod(n);
            }
            k = k.multiply(k).mod(n);
            i--;
        }
        return h;
    }

    // Verschlüsseln mit schneller Exponentation und jedes Zeichen in ASCII-Code umwandeln
    // x^e mod n
    // inputFileName: "text.txt",
    // publicKeyFilename: "pk.txt",
    // outputFilename: "chiffre.txt"
    public static void encryptFile(String inputFilename, String publicKeyFilename, String outputFilename) {
        try {
            String content = new String(Files.readAllBytes(Paths.get(inputFilename)), StandardCharsets.UTF_8);
            List<String> lines = Files.readAllLines(Paths.get(publicKeyFilename), StandardCharsets.UTF_8);
            String[] parts = lines.get(0).split(",");
            BigInteger n = new BigInteger(parts[0]);
            BigInteger e = new BigInteger(parts[1]);

            StringBuilder cipherText = new StringBuilder();
            for (char ch : content.toCharArray()) {
                BigInteger encryptedChar = BigInteger.valueOf(ch).modPow(e, n);
                cipherText.append(encryptedChar.toString()).append(",");
            }

            Files.write(Paths.get(outputFilename), cipherText.toString().getBytes(StandardCharsets.UTF_8));
        } catch (IOException ex) {
            System.err.println("Fehler beim Verschlüsseln der Datei: " + ex.getMessage());
        }
    }


    // Entschlüsseln mit schneller Exponentation
    // y^d mod n
    // inputFileName: "text.txt",
    // publicKeyFilename: "pk.txt",
    // outputFilename: "chiffre.txt"
    public static void decryptFile(String inputFilename, String privateKeyFilename, String outputFilename) {
        try {
            List<String> encryptedLines = Files.readAllLines(Paths.get(inputFilename), StandardCharsets.UTF_8);
            String[] encryptedChars = encryptedLines.get(0).split(",");
            List<String> privateKeyLines = Files.readAllLines(Paths.get(privateKeyFilename), StandardCharsets.UTF_8);

            // Zuerst Klammern vom Key entfernen, dann splitten nach dem Komma.
            String[] parts = privateKeyLines.get(0).substring(1, privateKeyLines.get(0).length() - 1).split(",");
            BigInteger n = new BigInteger(parts[0]);
            BigInteger d = new BigInteger(parts[1]);

            StringBuilder plainText = new StringBuilder();
            for (String encryptedChar : encryptedChars) {
                if (!encryptedChar.isEmpty()) {
                    BigInteger y = new BigInteger(encryptedChar);
                    BigInteger decryptedChar = fastExpCalc(y, d, n);
                    plainText.append((char) decryptedChar.intValue());
                }
            }

            Files.write(Paths.get(outputFilename), plainText.toString().getBytes(StandardCharsets.UTF_8));
        } catch (IOException ex) {
            System.err.println("Fehler beim Entschlüsseln der Datei: " + ex.getMessage());
        }
    }

}
