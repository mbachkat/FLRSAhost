/*

FLRSAhost Project

Copyright (c) 2026 Mohamed BACHKAT

Permission is hereby granted, free of charge, to any person obtaining a copy

of this software and associated documentation files (the "Software"), to deal

in the Software without restriction, including without limitation the rights

to use, copy, modify, merge, publish, distribute, sublicense, and/or sell

copies of the Software, and to permit persons to whom the Software is

furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all

copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR

IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,

FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE

AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER

LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,

OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE

SOFTWARE.
*/

package opencrypto.jcmathlib;

import java.math.BigInteger;
import javax.smartcardio.*;
import java.security.SecureRandom;
import static opencrypto.jcmathlib.HostUtils.*;
 
import apdu4j.core.APDUBIBO;
import apdu4j.core.CommandAPDU;
import apdu4j.core.ResponseAPDU;
import apdu4j.core.BIBO;

// Imports GlobalPlatform
import pro.javacard.gp.GPCardKeys;
import pro.javacard.capfile.AID;
import pro.javacard.gp.GPKeyInfo;
import pro.javacard.gp.keys.PlaintextKeys;
import pro.javacard.gp.GPException;
import pro.javacard.gp.GPSecureChannelVersion;
import pro.javacard.gp.GPSession;
import pro.javacard.gp.GPSession.APDUMode;


import java.io.IOException;
import java.security.GeneralSecurityException;


import java.util.EnumSet;

import static apdu4j.core.HexUtils.hex2bin;
import static pro.javacard.gp.GPCardKeys.KeyPurpose;

// NOTE : La classe CardChannelToBIBOWrapper a été supprimée comme demandé 
// (elle est supposée être définie dans InitHost.java ou une classe utilitaire commune).

public class CalculateHost {
    public static final AID APPLET_AID = new AID(hex2bin("4A434D6174684C69625554"));
    public static final AID DEFAULT_ISD_AID = new AID(hex2bin("A000000151000000")); // AID de l'ISD

    private static final int KEY_VERSION = 0; 
    
    // Clés par défaut (4041...4F)
    private static final byte[] KEY_ENC_BYTES = hexStringToByteArray("404142434445464748494A4B4C4D4E4F");
    private static final byte[] KEY_MAC_BYTES = hexStringToByteArray("404142434445464748494A4B4C4D4E4F");
    private static final byte[] KEY_DEK_BYTES = hexStringToByteArray("404142434445464748494A4B4C4D4E4F");
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

public static final byte[] E_BYTES = {
    // ----------------------------------------------------
    (byte) 0x34, (byte) 0x80, (byte) 0x67, (byte) 0x02, (byte) 0xFD, (byte) 0x97, (byte) 0x4C, (byte) 0x53, // 00 - 07
    (byte) 0x20, (byte) 0x60, (byte) 0x24, (byte) 0xE3, (byte) 0x41, (byte) 0x25, (byte) 0x2B, (byte) 0xE6, // 08 - 15
    (byte) 0x36, (byte) 0x82, (byte) 0x97, (byte) 0x75, (byte) 0x2C, (byte) 0x59, (byte) 0x36, (byte) 0x21, // 16 - 23
    (byte) 0x23, (byte) 0x2E, (byte) 0x17, (byte) 0xF5, (byte) 0x85, (byte) 0x7A, (byte) 0xCC, (byte) 0x79, // 24 - 31
    (byte) 0xC6, (byte) 0xB2, (byte) 0x7C, (byte) 0x73, (byte) 0x60, (byte) 0x70, (byte) 0xE3, (byte) 0x46, // 32 - 39
    (byte) 0x9A, (byte) 0x6F, (byte) 0x99, (byte) 0xCF, (byte) 0x84, (byte) 0x36, (byte) 0x74, (byte) 0x55, // 40 - 47
    (byte) 0x24, (byte) 0x25, (byte) 0x0C, (byte) 0x99, (byte) 0x6D, (byte) 0x7F, (byte) 0xE9, (byte) 0x93, // 48 - 55
    (byte) 0xB8, (byte) 0x37, (byte) 0xAD, (byte) 0x23, (byte) 0x96, (byte) 0xF2, (byte) 0x73, (byte) 0x94, // 56 - 63
    (byte) 0xB5, (byte) 0x9E, (byte) 0x4E, (byte) 0xA9, (byte) 0x14, (byte) 0x3B, (byte) 0xC5, (byte) 0x58, // 64 - 71
    (byte) 0x5D, (byte) 0x93, (byte) 0xB0, (byte) 0x23, (byte) 0x46, (byte) 0x63, (byte) 0x5E, (byte) 0x2F, // 72 - 79
    (byte) 0xFE, (byte) 0x1C, (byte) 0xE8, (byte) 0x78, (byte) 0x03, (byte) 0x8A, (byte) 0x43, (byte) 0x5D, // 80 - 87
    (byte) 0x25, (byte) 0x6C, (byte) 0xB3, (byte) 0x64, (byte) 0x36, (byte) 0x72, (byte) 0x30, (byte) 0x3F, // 88 - 95
    (byte) 0xBE, (byte) 0x1F, (byte) 0x73, (byte) 0x90, (byte) 0xCC, (byte) 0xF3, (byte) 0x64, (byte) 0x3B, // 96 - 103
    (byte) 0xE1, (byte) 0x74, (byte) 0x63, (byte) 0x31, (byte) 0x5A, (byte) 0x2F, (byte) 0xF0, (byte) 0xDB, // 104 - 111
    (byte) 0x56, (byte) 0x3E, (byte) 0xBC, (byte) 0xF5, (byte) 0x39, (byte) 0x36, (byte) 0xFB, (byte) 0x9F, // 112 - 119
    (byte) 0x1C, (byte) 0x7C, (byte) 0x92, (byte) 0x58, (byte) 0x3E, (byte) 0xCD, (byte) 0x87, (byte) 0xF9  // 120 - 127
};
    
    // --- Constantes APDU pour le Calcul (ORIGINALES) ---
    private static final byte CLA_CALC = (byte) 0x80; 
    private static final byte INS_DO_CALC = (byte) 0x03;
    private static final int KEY_SIZE_BYTES = 128; 

    public static void main(String[] args) {
        try {
            CardTerminal terminal = HostUtils.connectToCard();
            if (terminal == null) return;
            
            Card card = terminal.connect("*");
            
            // L'instanciation suivante dépend de votre implémentation du wrapper
            APDUBIBO apduChannel = new APDUBIBO(new CardChannelToBIBOWrapper(card.getBasicChannel())); 
            
            System.out.println("Connexion à la carte établie pour le CALCUL.");

            // --- Phase de Calcul ---
            System.out.println("\nDéclenchement du Calcul Complexe (CLA=80, INS=03) ---");
            
            // 1. Générer une entité x aléatoire de 128 bytes
            byte[] x_bytes = new byte[KEY_SIZE_BYTES]; 
            new SecureRandom().nextBytes(x_bytes);
            System.out.println("Entité x (" + KEY_SIZE_BYTES + " bytes) générée aléatoirement.");

            // 2. Exécuter le calcul
            doComplexCalculation(apduChannel, x_bytes); 

            card.disconnect(false);
            System.out.println("\nDéconnexion de la carte.");
            
        } catch (Exception e) {
            System.err.println("\nErreur critique lors du calcul : " + e.getMessage());
            e.printStackTrace();
        }
    }

    /**
     * Déclenche l'APDU INS_DO_CALC avec l'entité x en DATA.
     */
    private static void doComplexCalculation(APDUBIBO apduchannel, byte[] x_data) throws CardException {
        
        PlaintextKeys keys = PlaintextKeys.fromKeys(KEY_ENC_BYTES, KEY_MAC_BYTES, KEY_DEK_BYTES);
        keys.setVersion(KEY_VERSION);
        
        // La session est créée avec l'AID de l'ISD pour l'authentification
        GPSession session = new GPSession(apduchannel, DEFAULT_ISD_AID);
        
        // Mode de session à MAC SEULEMENT (pour l'étape 2)
        EnumSet<APDUMode> sessionSecurityLevel = EnumSet.of(APDUMode.MAC); 
        
        // Déclaration des variables de réponse
        byte[] rawResponse;
        apdu4j.core.ResponseAPDU response;
        
        // --- ÉTAPE 1: Sélection Manuelle de l'ISD (Mode PLAIN) ---
        System.out.println("Sélection manuelle de l'ISD " + DEFAULT_ISD_AID + "...");
        
        CommandAPDU isdSelectApdu = new CommandAPDU(0x00, 0xA4, 0x04, 0x00, DEFAULT_ISD_AID.getBytes());
        try {
            rawResponse = apduchannel.transceive(isdSelectApdu.getBytes());
            ResponseAPDU isdSelectResponse = new ResponseAPDU(rawResponse);
            if (isdSelectResponse.getSW() != 0x9000) {
                System.err.println("   - Échec de la sélection de l'ISD (SW: " + Integer.toHexString(isdSelectResponse.getSW()) + ")");
                throw new CardException("ISD selection failed before secure channel open.");
            }
            System.out.println("   - ISD sélectionné (SW: 9000)");
        } catch (RuntimeException e) { 
             System.err.println("   - Erreur de transmission de la sélection de l'ISD: " + e.getMessage());
             throw new CardException("ISD selection failed.", e);
        }

        // --- ÉTAPE 2: Ouverture du Canal Sécurisé (sur l'ISD) ---
        try {
            System.out.println("Ouverture Session Sécurisée (MAC SEULEMENT pour établissement)...");
            session.openSecureChannel(keys,
            new GPSecureChannelVersion(GPSecureChannelVersion.SCP.SCP03, KEY_VERSION),
            null,
            sessionSecurityLevel); 
            System.out.println("Session Sécurisée OK (MAC SEULEMENT).");
        } catch (Exception e) { 
             System.err.println("Échec de l'ouverture du canal sécurisé. Erreur: " + e.getMessage());
             e.printStackTrace();
             throw new CardException("Échec de l'ouverture du canal sécurisé.", e);
        }
        
        // --- ÉTAPE 3: Sélection de l'Applet (Mode PLAIN) ---
        System.out.println("Sélection de l'Applet " + APPLET_AID + "...");
        CommandAPDU selectApdu = new CommandAPDU(0x00, 0xA4, 0x04, 0x00, APPLET_AID.getBytes());
        
        try {
            // Utiliser le canal APDU brut (PLAIN) pour la sélection de l'Applet
            rawResponse = apduchannel.transceive(selectApdu.getBytes()); 
            ResponseAPDU selectResponse = new ResponseAPDU(rawResponse);
            
            if (selectResponse.getSW() != 0x9000) {
                 System.err.println("   - Échec de la sélection de l'Applet (SW: " + Integer.toHexString(selectResponse.getSW()) + ")");
                 throw new CardException("Applet selection failed in secure channel.");
            }
            System.out.println("   - Applet sélectionnée (SW: 9000)");
        } catch (RuntimeException e) { 
             System.err.println("   - Erreur de transmission de la sélection de l'Applet: " + e.getMessage());
             throw new CardException("Applet selection failed (IO Error).", e);
        }


        // --- ÉTAPE 4: Transmission de la commande de Calcul (SECURISÉE via session.transmit()) ---
        
        CommandAPDU calcApdu = new CommandAPDU(CLA_CALC, INS_DO_CALC, 0x00, 0x00, x_data); 
        
        try {
            System.out.println("Envoi de la commande de Calcul (80 03 00 00) via canal sécurisé (session.transmit())...");
            // REVERT : Réutilisation de session.transmit() (corrige 7010)
            // Cette méthode sécurise l'APDU avec MAC (défini à l'étape 2)
            response = session.transmit(calcApdu);
        
        // Correction : IOException est l'exception correcte pour session.transmit()
        } catch (IOException e) { 
            System.err.println("Erreur de transmission pour la commande de calcul.");
            e.printStackTrace();
            throw new CardException("Calcul failed due to secure channel error.", e);
        }


        if (response.getSW() != 0x9000) {
            System.err.println("Échec de l'exécution du calcul (SW: " + Integer.toHexString(response.getSW()) + ")");
            // On s'attend à ce que le 6D00 revienne ici.
            return;
        }

        // Récupérer et afficher le résultat
        byte[] resultBytes = response.getData();
        BigInteger n = new BigInteger(1, N_BYTES);
        BigInteger coeff2 = new BigInteger(1,COEFF2_BYTES);
        BigInteger inv6 = new BigInteger(1,INV6_BYTES);
        BigInteger delta = new BigInteger(1,DELTA_BYTES);
         BigInteger x = new BigInteger(1,x_data);
        BigInteger result = calculateT(x, n, coeff2, inv6,delta);
        BigInteger e = new BigInteger(1,E_BYTES);
        BigInteger identifiantx = result.modPow(e,n);
        

       
        


        BigInteger resultOnCard = new BigInteger(1, resultBytes);
        //BigInteger result = calculateT(x, n, coeff2, inv6,delta);
       
        System.out.println("\nRÉSULTAT REÇU ---");
        System.out.println("Longueur : " + resultBytes.length + " bytes");
        // Afficher seulement le début pour lisibilité
        String hexResult = resultOnCard.toString(16);
        System.out.println("Début du résultat (hex) : " + (hexResult.length() > 40 ? hexResult.substring(0, 40) + "..." : hexResult));
        System.out.println("Succès (SW: 9000).");

        String hexResultcomp = result.toString(16);
        System.out.println("Début du résultat (hex) : " + (hexResultcomp.length() > 40 ? hexResultcomp.substring(0, 40) + "..." : hexResultcomp));
        System.out.println("Succès (SW: 9000).");

        
        String hexx = x.toString(16);
        System.out.println("Début du résultat (hex) : " + (hexx.length() > 40 ? hexx.substring(0, 40) + "..." : hexx));
        System.out.println("Succès (SW: 9000).");

        String hexidentifiantx =identifiantx.toString(16);
        System.out.println("Début du résultat (hex) : " + (hexidentifiantx.length() > 40 ? hexidentifiantx.substring(0, 40) + "..." : hexidentifiantx));
        System.out.println("Succès (SW: 9000).");

        if((x.compareTo(identifiantx))==0) {
            System.out.println("Identification OK!, Carte OK!");

        }


        
    }
    
    // --- Fonction Utilitaire pour la conversion Hex -> Byte[] ---
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

    public static BigInteger calculateT(BigInteger x, BigInteger n, BigInteger coeff2, BigInteger inv6, BigInteger delta) {
        
        // La formule à implémenter est: T = (((x^3 - x) * coeff2 * inv6) + x) mod n
        
        // 1. Calcul de x^3 (x au cube)
        // x.pow(3) est équivalent à x.multiply(x).multiply(x)
        BigInteger x_cubed = x.pow(3);
        
        // 2. Calcul de (x^3 - x)
        BigInteger term1 = x_cubed.subtract(x);
        
        // 3. Application du modulo n (essentiel si le résultat intermédiaire est négatif ou trop grand)
        term1 = term1.mod(n);
        
        // 4. Calcul de (x^3 - x) * coeff2
        BigInteger term2 = term1.multiply(coeff2).mod(n);
        
        // 5. Calcul de (... ) * inv6
        term2 = term2.multiply(inv6).mod(n);
        
        // 6. Calcul de (... + x)
        BigInteger final_T = term2.add(x);
        
        // 7. Application du modulo final
        final_T = final_T.mod(n);

        BigInteger term3 = x.modPow(delta,n);

        final_T = final_T.multiply(term3).mod(n);
        
        return final_T;
    }
}
