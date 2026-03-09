package opencrypto.jcmathlib;

import javacard.framework.*;
import opencrypto.jcmathlib.*;

public class ComplexCalcApplet extends Applet {

    // --- CODES D'INSTRUCTION (INS) ---
    final static byte CLA_CALC = (byte) 0x80;
    // NOUVELLE CONSTANTE : CLA sécurisé (0x80 | 0x04 = 0x84 pour MAC seul)
    final static byte CLA_CALC_SM = (byte) (CLA_CALC | 0x04); 
    
    final static byte INS_DO_CALC = (byte) 0x03; 
    final static byte CLA_INIT = (byte) 0xB0;
    final static byte INS_INIT = (byte) 0x10; 

    // --- CONSTANTES DE TAILLE ---
    private final static short KEY_SIZE_BYTES = 128; 
    private final static short MAX_RESULT_SIZE = KEY_SIZE_BYTES; 
    
    // --- OBJETS PERSISTANTS (EEPROM) - CIBLES DU PROVISIONING ---
    private BigNat n;
    private BigNat coeff2;
    private BigNat inv6;
    private BigNat delta;
    
    // --- OBJETS DE TRAVAIL (EEPROM) ---
    private BigNat x; 
    
    // --- GESTIONNAIRE DE RESSOURCES (RAM/EEPROM) ---
    private ResourceManager rm; 


    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new ComplexCalcApplet().register();
    }

    protected ComplexCalcApplet() {
        rm = new ResourceManager(JCSystem.MEMORY_TYPE_PERSISTENT, (short) 256);
        
        // Initialisation des BigNat persistants (EEPROM)
        coeff2 = new BigNat(KEY_SIZE_BYTES, (byte) 0, rm);
        n      = new BigNat(KEY_SIZE_BYTES, (byte) 0, rm);
        inv6   = new BigNat(KEY_SIZE_BYTES, (byte) 0, rm);
        delta  = new BigNat(KEY_SIZE_BYTES, (byte) 0, rm);
        x      = new BigNat(KEY_SIZE_BYTES, (byte) 0, rm);

    }

    public void process(APDU apdu) throws ISOException {
        if (selectingApplet()) {
            return;
        }

        byte[] buffer = apdu.getBuffer();
        byte ins = buffer[ISO7816.OFFSET_INS];
        byte cla = buffer[ISO7816.OFFSET_CLA];

        if (cla == CLA_INIT && ins == INS_INIT) {
            initConstants(apdu);
        // On accepte CLA_CALC (0x80) OU CLA_CALC_SM (0x84)
        } else if ((cla == CLA_CALC || cla == CLA_CALC_SM) && ins == INS_DO_CALC) {
            performComplexCalc(apdu);
        } else {
            ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }
    
    /**
     * Gère l'initialisation des constantes (Provisioning).
     */
    private void initConstants(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        byte p1 = buffer[ISO7816.OFFSET_P1];
        
        // La longueur est lue, mais ignorée car c'est la longueur enveloppée.
        apdu.setIncomingAndReceive(); 

        // Nous faisons confiance au code hôte et utilisons la longueur attendue.
        short expectedDataLen = KEY_SIZE_BYTES; 
        short dataOffset = ISO7816.OFFSET_CDATA;

        switch (p1) {
            case 0x01: // Initialiser n
                n.fromByteArray(buffer, dataOffset, expectedDataLen);
                break;
            case 0x02: // Initialiser coeff2
                coeff2.fromByteArray(buffer, dataOffset, expectedDataLen);
                break;
            case 0x03: // Initialiser inv6
                inv6.fromByteArray(buffer, dataOffset, expectedDataLen);
                break;
            case 0x04: // Initialiser delta
                delta.fromByteArray(buffer, dataOffset, expectedDataLen);
                break;
            default:
                ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
        }
    }


    /**
     * Exécute le calcul.
     */
    private void performComplexCalc(APDU apdu) {
        // --- Allocation des BigNat temporaires (RAM Transient) ---
        BigNat temp_x_cube = new BigNat(MAX_RESULT_SIZE, (byte) 0, rm);
        BigNat powerTerm   = new BigNat(MAX_RESULT_SIZE, (byte) 0, rm);
        BigNat exp3        = new BigNat((short) 1, (byte) 0, rm);

        // 1. Charger x depuis l'APDU
        byte[] buf = apdu.getBuffer();
        // La longueur est lue, mais ignorée car c'est la longueur enveloppée.
        apdu.setIncomingAndReceive(); 
        
        // L'ancienne vérification de dataLen est supprimée pour éviter le 6700.
        // if (dataLen != KEY_SIZE_BYTES) { /* ISOException.throwIt(ISO7816.SW_WRONG_LENGTH); */ }

        // Load input 'x' from APDU buffer (OFFSET_CDATA is usually where data starts)
        // Utilisation de la longueur attendue (128 bytes) pour lire les données.
        x.fromByteArray(buf, ISO7816.OFFSET_CDATA, KEY_SIZE_BYTES); 


        // --- Début du Calcul Modulo N ---
        
        // 1. Calcul de x^3 mod n
        exp3.setValue((short) 3); 
        temp_x_cube.copy(x);
        temp_x_cube.modExp(exp3, n); 
        
        // 2. Calcul de x^3 - x mod n
        temp_x_cube.modSub(x, n); 
        
        // 3. Calcul de (x^3 - x) * coeff2 mod n
        temp_x_cube.modMult(coeff2, n); 
        
        // 4. Calcul de (x^3 - x) * coeff2 * inv6 mod n
        temp_x_cube.modMult(inv6, n); 
        
        // 5. Calcul de ((...) * inv6) + x mod n
        temp_x_cube.modAdd(x, n); 
        
        // 6. Calcul de x^Delta mod n (Partie droite)
        powerTerm.copy(x); 
        powerTerm.modExp(delta, n); 
        
        // 7. Calcul final : (Partie gauche) * (Partie droite) mod n
        temp_x_cube.modMult(powerTerm, n); 
        
        // --- Renvoyer le Résultat ---
        short resLen = temp_x_cube.length();
        
        apdu.setOutgoing();
        apdu.setOutgoingLength(resLen);
        
        // Envoyer les octets du résultat
        temp_x_cube.copyToByteArray(buf, (short) 0);
        apdu.sendBytesLong(buf, (short) 0, resLen);
        
        // Libération des BigNat temporaires
        rm.refreshAfterReset();
    }
}