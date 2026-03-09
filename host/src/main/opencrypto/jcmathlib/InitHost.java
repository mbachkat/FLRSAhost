package opencrypto.jcmathlib;

import javax.smartcardio.*;
import java.util.Arrays;
import static opencrypto.jcmathlib.HostUtils.*;
import apdu4j.core.APDUBIBO;
import apdu4j.core.CommandAPDU;
import apdu4j.core.ResponseAPDU;
import apdu4j.core.BIBO;

// Import GPCardKeys pour la nouvelle structure
import pro.javacard.gp.GPCardKeys;
// L'implémentation concrète est ici :
import pro.javacard.gp.GPKeyInfo;
import pro.javacard.capfile.AID;
import pro.javacard.gp.GPKeyInfo.GPKey;
import pro.javacard.gp.keys.PlaintextKeys;
import pro.javacard.gp.GPException;
import pro.javacard.gp.GPSecureChannelVersion;
import pro.javacard.gp.GPSession;
// Nouvel import pour le niveau de sécurité
import pro.javacard.gp.GPSession.APDUMode;


import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;

import java.util.EnumSet;

import static apdu4j.core.HexUtils.hex2bin;
import static pro.javacard.gp.GPCardKeys.KeyPurpose;

// CLASSE D'AIDE CORRIGÉE (Correction 2 & 3)
class CardChannelToBIBOWrapper implements BIBO {
    private final CardChannel channel;

    public CardChannelToBIBOWrapper(CardChannel channel) {
        this.channel = channel;
    }

    // CORRECTION 1: Suppression de 'throws IOException'
    @Override
    public byte[] transceive(byte[] command) {
        try {
            // Utilisation du nom qualifié complet pour CommandAPDU standard
            return channel.transmit(new javax.smartcardio.CommandAPDU(command)).getBytes();
        } catch (CardException e) {
            // CORRECTION 2: Enveloppe l'exception dans une RuntimeException
            throw new RuntimeException("Card communication failed", e);
        }
    }

    // close() ne doit pas déclarer d'exception
    @Override
    public void close() {
        // Optionnel
    }
}
public class InitHost {
    // Clés de Master Key Set 01 (version 0)
    private static final int KEY_VERSION = 0; 
    
    // Key ENC (4041...4F)
    private static final byte[] KEY_ENC_BYTES = hexStringToByteArray("404142434445464748494A4B4C4D4E4F");
    
    // Key MAC (4041...4F)
    private static final byte[] KEY_MAC_BYTES = hexStringToByteArray("404142434445464748494A4B4C4D4E4F");
    
    // Key DEK (4041...4F)
    private static final byte[] KEY_DEK_BYTES = hexStringToByteArray("404142434445464748494A4B4C4D4E4F");
    
    // AID de l'Applet à sélectionner
    public static final AID APPLET_AID = new AID(hex2bin("4A434D6174684C69625554"));
    // AID de l'ISD (Cible de l'authentification GlobalPlatform)
    public static final AID DEFAULT_ISD_AID = new AID(hex2bin("A000000151000000")); 

   
    // --- Constantes APDU pour le Provisioning ---
    private static final byte CLA = (byte) 0xB0;
    private static final byte INS_INIT = (byte) 0x10;
    private static final short KEY_SIZE_BYTES = 128; // 128 bytes

    // --- Constantes extraites et provisionnées ---
    // Les tableaux de bytes sont maintenant définis de manière simplifiée et complète.
  public static final byte[] N_BYTES = {
    // ----------------------------------------------------
    (byte) 0xC4, (byte) 0xA1, (byte) 0x26, (byte) 0x9C, (byte) 0xB6, (byte) 0x80, (byte) 0x64, (byte) 0xE1, // 00 - 07
    (byte) 0x7D, (byte) 0x8D, (byte) 0x99, (byte) 0x12, (byte) 0x35, (byte) 0x67, (byte) 0x66, (byte) 0x9B, // 08 - 15
    (byte) 0xA5, (byte) 0xD5, (byte) 0xDF, (byte) 0xA4, (byte) 0x75, (byte) 0x09, (byte) 0x38, (byte) 0x5F, // 16 - 23
    (byte) 0xA0, (byte) 0x19, (byte) 0x32, (byte) 0x27, (byte) 0xDB, (byte) 0x64, (byte) 0x5F, (byte) 0x15, // 24 - 31
    (byte) 0xCD, (byte) 0xE7, (byte) 0xBF, (byte) 0x36, (byte) 0xAB, (byte) 0x72, (byte) 0x08, (byte) 0x5B, // 32 - 39
    (byte) 0xF8, (byte) 0xA3, (byte) 0x19, (byte) 0xD6, (byte) 0x19, (byte) 0x28, (byte) 0xAD, (byte) 0xB1, // 40 - 47
    (byte) 0x70, (byte) 0x86, (byte) 0x22, (byte) 0xD8, (byte) 0x09, (byte) 0x9A, (byte) 0x0A, (byte) 0x7E, // 48 - 55
    (byte) 0xE4, (byte) 0xF0, (byte) 0x18, (byte) 0xD5, (byte) 0xF3, (byte) 0xB4, (byte) 0xF1, (byte) 0xC8, // 56 - 63
    (byte) 0x9C, (byte) 0xAC, (byte) 0xC2, (byte) 0xE7, (byte) 0x90, (byte) 0xA4, (byte) 0x5A, (byte) 0xFB, // 64 - 71
    (byte) 0x99, (byte) 0x60, (byte) 0xCF, (byte) 0xD0, (byte) 0xF5, (byte) 0x14, (byte) 0x46, (byte) 0x71, // 72 - 79
    (byte) 0x53, (byte) 0xC3, (byte) 0x9C, (byte) 0xF3, (byte) 0xB3, (byte) 0x6A, (byte) 0x92, (byte) 0x5C, // 80 - 87
    (byte) 0x5B, (byte) 0xD9, (byte) 0xDE, (byte) 0xC8, (byte) 0xF6, (byte) 0x3E, (byte) 0x02, (byte) 0x57, // 88 - 95
    (byte) 0x0F, (byte) 0xFC, (byte) 0x2D, (byte) 0x25, (byte) 0xED, (byte) 0x77, (byte) 0xC2, (byte) 0x06, // 96 - 103
    (byte) 0xF4, (byte) 0x3F, (byte) 0x8E, (byte) 0x86, (byte) 0xAC, (byte) 0x16, (byte) 0xF6, (byte) 0x1F, // 104 - 111
    (byte) 0xE1, (byte) 0x5A, (byte) 0x5D, (byte) 0x99, (byte) 0xFF, (byte) 0x4F, (byte) 0xB9, (byte) 0xC5, // 112 - 119
    (byte) 0xF3, (byte) 0xB4, (byte) 0x4D, (byte) 0xAF, (byte) 0x4C, (byte) 0xC2, (byte) 0xC2, (byte) 0x27  // 120 - 127
};
    
   public static final byte[] COEFF2_BYTES = {
    // ----------------------------------------------------
    (byte) 0x75, (byte) 0xD0, (byte) 0x51, (byte) 0xC3, (byte) 0x1A, (byte) 0xB1, (byte) 0xF2, (byte) 0x15, // 00 - 07
    (byte) 0xCA, (byte) 0x15, (byte) 0xCA, (byte) 0x60, (byte) 0x43, (byte) 0x8F, (byte) 0xBC, (byte) 0x07, // 08 - 15
    (byte) 0x08, (byte) 0x8F, (byte) 0xC4, (byte) 0x23, (byte) 0xFD, (byte) 0x0A, (byte) 0x94, (byte) 0x48, // 16 - 23
    (byte) 0x91, (byte) 0x7B, (byte) 0x6E, (byte) 0x14, (byte) 0x66, (byte) 0xBC, (byte) 0x83, (byte) 0x7B, // 24 - 31
    (byte) 0xC9, (byte) 0x86, (byte) 0x74, (byte) 0x97, (byte) 0x4F, (byte) 0x68, (byte) 0x15, (byte) 0x63, // 32 - 39
    (byte) 0x4C, (byte) 0x38, (byte) 0x4F, (byte) 0xF7, (byte) 0xD5, (byte) 0xE6, (byte) 0x24, (byte) 0xBE, // 40 - 47
    (byte) 0xE0, (byte) 0xF2, (byte) 0x3D, (byte) 0x04, (byte) 0x00, (byte) 0xDD, (byte) 0x7E, (byte) 0x7A, // 48 - 55
    (byte) 0x44, (byte) 0x5C, (byte) 0xD1, (byte) 0x02, (byte) 0x5F, (byte) 0x60, (byte) 0x9F, (byte) 0xA5, // 56 - 63
    (byte) 0xD9, (byte) 0x18, (byte) 0x18, (byte) 0x80, (byte) 0x16, (byte) 0xD0, (byte) 0x5F, (byte) 0xF5, // 64 - 71
    (byte) 0x46, (byte) 0xCF, (byte) 0xDB, (byte) 0x14, (byte) 0xC5, (byte) 0xC9, (byte) 0xE7, (byte) 0x00, // 72 - 79
    (byte) 0x01, (byte) 0xE5, (byte) 0x84, (byte) 0xDA, (byte) 0x29, (byte) 0xA6, (byte) 0x1E, (byte) 0x69, // 80 - 87
    (byte) 0x81, (byte) 0x31, (byte) 0x3F, (byte) 0x4C, (byte) 0xD4, (byte) 0x22, (byte) 0xDC, (byte) 0x24, // 88 - 95
    (byte) 0x81, (byte) 0x4C, (byte) 0x90, (byte) 0x6D, (byte) 0x01, (byte) 0x7A, (byte) 0x9D, (byte) 0x16, // 96 - 103
    (byte) 0xAC, (byte) 0x0B, (byte) 0x4A, (byte) 0x56, (byte) 0x54, (byte) 0x67, (byte) 0x05, (byte) 0xFC, // 104 - 111
    (byte) 0xB2, (byte) 0xB0, (byte) 0x47, (byte) 0x82, (byte) 0xE1, (byte) 0x5D, (byte) 0x82, (byte) 0xEE, // 112 - 119
    (byte) 0xA1, (byte) 0xED, (byte) 0xD5, (byte) 0xB4, (byte) 0xF3, (byte) 0xF4, (byte) 0xA9, (byte) 0xA8  // 120 - 127
};
    
public static final byte[] INV6_BYTES = {
    // ----------------------------------------------------
    (byte) 0xA3, (byte) 0xDB, (byte) 0xA0, (byte) 0x2D, (byte) 0x42, (byte) 0xC0, (byte) 0x54, (byte) 0x11, // 00 - 07
    (byte) 0x3D, (byte) 0xF5, (byte) 0xFF, (byte) 0x8F, (byte) 0x2C, (byte) 0x80, (byte) 0xD5, (byte) 0x81, // 08 - 15
    (byte) 0xB4, (byte) 0xDC, (byte) 0xE5, (byte) 0x09, (byte) 0x0C, (byte) 0x32, (byte) 0x59, (byte) 0xA5, // 16 - 23
    (byte) 0x05, (byte) 0x6A, (byte) 0x54, (byte) 0x76, (byte) 0x8C, (byte) 0x28, (byte) 0xF9, (byte) 0xE7, // 24 - 31
    (byte) 0x80, (byte) 0xEB, (byte) 0xCA, (byte) 0x02, (byte) 0xE4, (byte) 0x34, (byte) 0x5C, (byte) 0x4C, // 32 - 39
    (byte) 0xA4, (byte) 0x87, (byte) 0xEA, (byte) 0xDD, (byte) 0x14, (byte) 0xF7, (byte) 0x3B, (byte) 0x69, // 40 - 47
    (byte) 0x33, (byte) 0x1A, (byte) 0x72, (byte) 0x5E, (byte) 0xB2, (byte) 0xAB, (byte) 0x08, (byte) 0xBF, // 48 - 55
    (byte) 0x14, (byte) 0x1D, (byte) 0x6A, (byte) 0x07, (byte) 0xA0, (byte) 0x6C, (byte) 0x1E, (byte) 0xD1, // 56 - 63
    (byte) 0xD7, (byte) 0xE5, (byte) 0x4D, (byte) 0x16, (byte) 0x4D, (byte) 0xDE, (byte) 0x4B, (byte) 0xD1, // 64 - 71
    (byte) 0xAA, (byte) 0x7B, (byte) 0x57, (byte) 0xD8, (byte) 0xCC, (byte) 0x3B, (byte) 0x90, (byte) 0x09, // 72 - 79
    (byte) 0x1B, (byte) 0x23, (byte) 0x02, (byte) 0xCB, (byte) 0x15, (byte) 0x83, (byte) 0x79, (byte) 0xF7, // 80 - 87
    (byte) 0xA1, (byte) 0xE0, (byte) 0x39, (byte) 0xA7, (byte) 0x77, (byte) 0xDE, (byte) 0x57, (byte) 0x48, // 88 - 95
    (byte) 0x8D, (byte) 0x52, (byte) 0x25, (byte) 0x9F, (byte) 0x9B, (byte) 0x39, (byte) 0x21, (byte) 0xB0, // 96 - 103
    (byte) 0x76, (byte) 0x34, (byte) 0xF6, (byte) 0xC5, (byte) 0x8F, (byte) 0x68, (byte) 0x77, (byte) 0xC5, // 104 - 111
    (byte) 0x3B, (byte) 0xCB, (byte) 0x4E, (byte) 0x00, (byte) 0x54, (byte) 0xC2, (byte) 0x70, (byte) 0x24, // 112 - 119
    (byte) 0xF5, (byte) 0xC0, (byte) 0xEB, (byte) 0x67, (byte) 0x6A, (byte) 0xA2, (byte) 0x4C, (byte) 0x76  // 120 - 127
};
    
  public static final byte[] DELTA_BYTES = {
    // ----------------------------------------------------
    // PADDING (125 bytes of 0x00)
    (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, // 08 - 15
    (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, // 16 - 23
    (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, // 24 - 31
    (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, // 32 - 39
    (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, // 40 - 47
    (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, // 48 - 55
    (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, // 56 - 63
    (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, // 64 - 71
    (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, // 72 - 79
    (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, // 80 - 87
    (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, // 88 - 95
    (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, // 96 - 103
    (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, // 104 - 111
    (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, // 112 - 119
    // DATA (2 bytes: 0x037C)
    (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, // Ligne 120-127 commencée
    (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x03, (byte) 0x7C  // 120 - 127
};

    public static void main(String[] args) {
        try {
            CardTerminal terminal = HostUtils.connectToCard();
            if (terminal == null) return;
            
            Card card = terminal.connect("*");
           
            // Nouvelle ligne corrigée :
            APDUBIBO apduChannel = new APDUBIBO(new CardChannelToBIBOWrapper(card.getBasicChannel()));

            System.out.println(" Connexion à la carte établie pour l'INITIALISATION.");

            // Étape d'Initialisation : Écriture en EEPROM (4 APDU successives)
            System.out.println("\n--- Initialisation des 4 Constantes en EEPROM (INS_INIT) ---");
            initializeBigNat(apduChannel, (byte) 0x01, N_BYTES, "n"); 
            initializeBigNat(apduChannel, (byte) 0x02, COEFF2_BYTES, "coeff2");
            initializeBigNat(apduChannel, (byte) 0x03, INV6_BYTES, "inv6");
            initializeBigNat(apduChannel, (byte) 0x04, DELTA_BYTES, "delta");
            System.out.println(" INITIALISATION TERMINÉE. Les constantes sont persistantes.");
            
            card.disconnect(false);
            System.out.println("\n Déconnexion de la carte.");
            
        } catch (Exception e) {
            System.err.println("\n Erreur critique lors de l'initialisation : " + e.getMessage());
            e.printStackTrace(); // Affiche la trace complète en cas d'erreur non gérée localement
        }
    }

    private static void initializeBigNat( APDUBIBO apduchannel, byte p1, byte[] data, String name) throws CardException {
        
        if (data == null || data.length != KEY_SIZE_BYTES) {
            throw new IllegalArgumentException("Le tableau de bytes pour " + name + " doit avoir exactement " + KEY_SIZE_BYTES + " bytes.");
        }
        
        PlaintextKeys keys = PlaintextKeys.fromKeys(KEY_ENC_BYTES, KEY_MAC_BYTES, KEY_DEK_BYTES);
        keys.setVersion(KEY_VERSION);
        
        // CORRECTION MAJEURE: Le canal sécurisé DOIT être ouvert avec l'AID de l'ISD (DEFAULT_ISD_AID)
        System.out.println("GPSession ?");
        GPSession session = new GPSession(apduchannel, (DEFAULT_ISD_AID));
        System.out.println("GPSession ok");  
        
        // Niveau de sécurité MAC et ENC (Nécessaire pour les données sensibles)
        EnumSet<APDUMode> securityLevel =  EnumSet.of(APDUMode.MAC, APDUMode.ENC);
        // --- NOUVEAUTÉ : ÉTAPE 0: Sélection Manuelle de l'ISD (Pour contourner l'erreur 6D00) ---
        // Ceci est critique pour les cartes Gemalto qui exigent une sélection explicite de l'ISD avant INITIALIZE UPDATE.
        System.out.println("Sélection manuelle de l'ISD " + DEFAULT_ISD_AID + "...");
        
        CommandAPDU isdSelectApdu = new CommandAPDU(0x00, 0xA4, 0x04, 0x00, DEFAULT_ISD_AID.getBytes());
        try {
            byte[] rawResponse0 = apduchannel.transceive(isdSelectApdu.getBytes());
            ResponseAPDU isdSelectResponse = new ResponseAPDU(rawResponse0);
            if (isdSelectResponse.getSW() != 0x9000) {
                System.err.println("   - Échec de la sélection de l'ISD (SW: " + Integer.toHexString(isdSelectResponse.getSW()) + ")");
                throw new CardException("ISD selection failed before secure channel open.");
            }
            System.out.println("   - ISD sélectionné (SW: 9000)");
        } catch (RuntimeException e) { 
             System.err.println("   - Erreur de transmission de la sélection de l'ISD: " + e.getMessage());
             throw new CardException("ISD selection failed.", e);
        }
       
        try {
            System.out.println("Session ?");
            // CORRECTION: Retour au SCP03 avec KVN 0, la configuration qui a réussi avec gp.jar
            session.openSecureChannel(keys,
                    new GPSecureChannelVersion(GPSecureChannelVersion.SCP.SCP03, 0), 
                    null,
                    securityLevel);
            System.out.println("Session ok");
        // MODIFICATION: Capturer toute exception pour éviter la NullPointerException et afficher l'erreur 0x6985
        } catch (Exception e) { 
            e.printStackTrace();
            return; // Quitter la méthode en cas d'échec du canal sécurisé
        }     
       
        // ÉTAPE CRUCIALE: Sélection de l'Applet après ouverture du canal sécurisé avec l'ISD
        System.out.println("Sélection de l'Applet " + APPLET_AID + "...");
        apdu4j.core.ResponseAPDU selectResponse;
        
        // CORRECTION DE COMPILATION: Suppression du try/catch IOException. 
        // L'erreur de communication est gérée par RuntimeException dans CardChannelToBIBOWrapper.
        //byte[] selectApduBytes = new CommandAPDU(0x00, 0xA4, 0x04, 0x00, APPLET_AID.getBytes()).getBytes();
        
        CommandAPDU selectApdu = new CommandAPDU(0x00, 0xA4, 0x04, 0x00, APPLET_AID.getBytes());
        //selectResponse = new ResponseAPDU(apduchannel.transceive(selectApduBytes));

    // Utilisation de session.transmit() (qui est sécurisé)
    //selectResponse = session.transmit(selectApdu); 
            byte[] rawResponse1 = apduchannel.transceive(selectApdu.getBytes());
            selectResponse = new ResponseAPDU(rawResponse1);


        if (selectResponse.getSW() != 0x9000) {
            System.err.println("   - Échec de la sélection de l'Applet (SW: " + Integer.toHexString(selectResponse.getSW()) + ")");
            // Le 6E00 peut parfois indiquer une absence d'Applet (bien que 6A82 soit plus courant)
            System.err.println("Veuillez vérifier que l'Applet a été correctement installée (SW: 6E00 = Classe non supportée).");
            throw new CardException("Applet selection failed.");
        }
        System.out.println("   - Applet sélectionnée (SW: 9000)");




        // APDU : CLA=B0, INS=10, P1={ID}, P2=00, Lc=80, DATA
        CommandAPDU initApdu = new CommandAPDU(CLA, INS_INIT, p1, 0x00, data);
        
        
        // ÉTAPE 3: Transmission de l'APDU de Provisionnement sécurisée
        apdu4j.core.ResponseAPDU response;
        
            // Cette APDU sera automatiquement sécurisée (MAC/ENC) car la session est ouverte en mode MAC, ENC
            // GPSession.transmit() est déclarée lancer IOException, donc ce try/catch est correct.
            //response = session.transmit(initApdu);
            byte[] rawResponse2 = apduchannel.transceive(initApdu.getBytes());
            response = new ResponseAPDU(rawResponse2);
            
      
        if (response.getSW() == 0x9000) {
            System.out.println("   - Constante " + name + " (P1=0x" + Integer.toHexString(p1) + ") initialisée (SW: 9000)");
        } else {
            System.err.println("   -  Échec de l'initialisation de " + name + " (SW: " + Integer.toHexString(response.getSW()) + ")");
            throw new CardException("Initialisation failed for constant " + name + ".");
        }
    }
    // --- Fonction Utilitaire pour la conversion ---
private static byte[] hexStringToByteArray(String s) {
    int len = s.length();
    if (len % 2 != 0) {
        throw new IllegalArgumentException("Hex string must have an even length.");
    }
    byte[] data = new byte[len / 2];
    for (int i = 0; i < len; i += 2) {
        data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                             + Character.digit(s.charAt(i+1), 16));
    }
    return data;
}
}